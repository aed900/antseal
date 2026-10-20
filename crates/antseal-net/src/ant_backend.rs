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
//! transfer per blob under the median-×3 rule ⇒ 256 blobs/tx). Each tx is
//! signed and its hash computed here before it is broadcast, and its receipt
//! is read by that hash under three deadlines — the chain, not an RPC error,
//! settles a broadcast's fate (S51, D208); block and status come from that
//! receipt (D33's primary flow). The **capture hook** fires with the
//! cumulative receipt **before the next sub-batch is submitted** (S10/S12),
//! and a mid-sequence failure surfaces as [`StorageError::StrandedPayment`]
//! only after the hook has delivered every landed sub-batch's record.
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
//! [`DynProvider`]; broadcasts, receipt reads, the chain-id guard and the
//! backfill ride it, and `pay` signs on a fresh `to_provider()` first, whose
//! `fill` the erased one lacks (S51) — the same S5-configured RPC D33 names.
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
        chain_id_guard(&provider, config, BROADCAST_DEADLINE).await?;

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
        fill_block_numbers(&self.provider, receipt, BROADCAST_DEADLINE).await
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
        // The gas price is a payment-RPC read outside the submission step: it
        // is bounded and its error redacted in `gas_price_wei` (S57 + S58,
        // D208 R13-R14), so a gateway that accepts and never answers cannot
        // hang a quote and a failed read cannot print the RPC's URL, which can
        // carry a credential in its path. Its failure keeps its class: network.
        // (The gas model above is unchanged.)
        let gas_price = gas_price_wei(&self.provider, BROADCAST_DEADLINE).await?;
        Ok(u128::from(units).saturating_mul(gas_price))
    }

    /// ANT (ERC-20) and ETH balances of the session wallet, in
    /// (atto-ANT, wei). Values above `u128::MAX` saturate (comparisons
    /// stay correct: a saturated balance still covers any representable
    /// requirement).
    async fn raw_balances(&self) -> Result<(u128, u128), StorageError> {
        // Both balances are payment-RPC reads outside the submission step, so
        // each is bounded and its error redacted in its own function (S57 +
        // S58, D208 R13-R14), and each fails in the network class it always
        // had — the ANT read first, then the gas read, as before. evmlib builds
        // a fresh key-less provider over the same RPC for each of them
        // (`evmlib-0.9.0/src/wallet.rs` `balance_of_tokens`), and its reqwest
        // client sets no request timeout, so this deadline is the only bound
        // either read has: a gateway that accepts and never answers would
        // otherwise hold the consent screen (U14) open, or `pay`'s preflight,
        // forever. A balance above `u128::MAX` still saturates (comparisons
        // stay correct at saturation: a saturated balance covers any
        // representable requirement).
        let ant = ant_balance(&self.wallet, BROADCAST_DEADLINE).await?;
        let gas = gas_balance(&self.wallet, BROADCAST_DEADLINE).await?;
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
        // A payment-RPC read outside the submission step: bounded and its
        // error redacted in `standing_allowance` (S57 + S58, D208 R13-R14), its
        // failure the network class it always had. As before, the standing
        // allowance alone decides below whether an approve is emitted at all,
        // and the comparison is made at saturation (`saturate_u256`, verdict-
        // preserving, see this method's docs).
        let current = standing_allowance(&self.wallet, vault, BROADCAST_DEADLINE).await?;
        let Some(amount_atto) = allowance_to_approve(saturate_u256(current), total_atto) else {
            return Ok(0);
        };
        // An approve that fails moves no ANT; its reason is redacted like every
        // payment-RPC error's, URLs included (`approve_failure`, S57).
        let tx_hash = self
            .wallet
            .approve_to_spend_tokens(vault, U256::from(amount_atto))
            .await
            .map_err(|e| approve_failure(&e))?;
        // The approve's own gas, for the receipt's gas summary — read from
        // its receipt (the approve is fully awaited by upstream: evmlib's own
        // send has a 5 s broadcast timeout and a bounded, retried watch). The
        // read is a payment-RPC read outside the submission step, so it is
        // bounded (`approve_gas_wei`, S58, D208 R14): a gateway that accepts
        // and never answers would otherwise hold the payment between its
        // approve and its first sub-batch forever. A read that fails, or that
        // does not answer in time, counts the approve's gas as 0 — what a
        // failed read always counted — because the gas figure is a summary,
        // never a money decision.
        Ok(approve_gas_wei(&self.provider, tx_hash, BROADCAST_DEADLINE).await)
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
        // S51 (D208 R1): every sub-batch is signed before a byte of it is
        // sent, on the wallet's own filler stack. `fill` belongs to the
        // concrete provider `to_provider()` returns and the session's is
        // type-erased, so the signer is built here, once per payment, over the
        // same payment RPC; the broadcast and every lookup ride the session's.
        let signer = self.wallet.to_provider();

        let mut so_far = PayLoop {
            records: (0..priced.len()).map(|_| None).collect(),
            remaining: priced.into_iter().map(Some).collect(),
            ready_after,
            tx_map: BTreeMap::new(),
            txs: Vec::new(),
            gas_cost_wei,
        };

        // Blobs with no non-zero transfer (theoretical zero-price quote)
        // are proof-ready immediately, with no tx hashes. This runs before
        // any sub-batch is submitted, so a proof failure here moved no ANT.
        finalize_ready_blobs(
            &mut so_far.remaining,
            &so_far.ready_after,
            usize::MAX,
            &so_far.tx_map,
            &mut so_far.records,
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
                    so_far.confirmed(),
                    format!(
                        "calldata build failed: {}",
                        redact_evm_error(&e.to_string())
                    ),
                )
            })?;

            // Sign, broadcast, and settle what the chain says — the receipt
            // read by the local hash IS the D33 primary-flow capture source
            // (block number in-band). Journaled via the hook BEFORE the next
            // submission (S46, S49, S50 — D204; S51, S54 — D208).
            let request = TransactionRequest::default()
                .with_from(from)
                .with_to(to)
                .with_input(calldata);
            let sub_batch = SubBatch {
                index: batch_index,
                count: sub_batches.len(),
                quote_hashes: batch.iter().map(|(_, qh, ..)| *qh).collect(),
            };
            pay_sub_batch(
                &signer,
                &self.provider,
                request,
                &sub_batch,
                &mut so_far,
                &self.staged,
                self.capture_hook.as_ref(),
                SubmitDeadlines::PAYMENT_RPC,
            )
            .await?;
        }

        let blobs: Vec<BlobPaymentRecord> = so_far.records.into_iter().flatten().collect();
        let receipt = PaymentReceipt {
            blobs,
            tx_map: so_far.tx_map,
            txs: so_far.txs,
            storage_cost_atto: total,
            gas: GasSummary {
                gas_cost_wei: so_far.gas_cost_wei,
            },
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

    /// D208 R8 over this session's payment RPC: the receipt by hash, and —
    /// when there is none — the transaction by hash, each lookup bounded by
    /// [`BROADCAST_DEADLINE`] ([`read_payment_tx_state`]).
    async fn payment_tx_state(&self, tx_hash: &TxHash) -> crate::PaymentTxState {
        read_payment_tx_state(&self.provider, tx_hash, BROADCAST_DEADLINE).await
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
        chain_id_guard(&provider, config, BROADCAST_DEADLINE).await?;
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
    /// [`StorageError::Network`] only when the RPC itself is unreachable or a
    /// read does not answer within 30 s (S58, D208 R14); an individual
    /// not-yet-visible receipt is not an error.
    pub async fn backfill_block_numbers(
        &self,
        receipt: &mut PaymentReceipt,
    ) -> Result<usize, StorageError> {
        fill_block_numbers(&self.provider, receipt, BROADCAST_DEADLINE).await
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
    limit: Duration,
) -> Result<(), StorageError> {
    // Bounded and redacted (S57 + S58, D208 R13-R14): the read happens before
    // any socket of the storage session, so a hung RPC here held `connect`.
    let chain_id = bounded_read(
        "payment RPC unreachable (eth_chainId)",
        limit,
        provider.get_chain_id(),
    )
    .await?;
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
    limit: Duration,
) -> Result<usize, StorageError> {
    let mut filled = 0usize;
    for tx in &mut receipt.txs {
        if tx.block_number.is_some() {
            continue;
        }
        let hash = alloy::primitives::B256::from(*tx.tx_hash.as_bytes());
        // Bounded and redacted (S57 + S58, D208 R13-R14). A read that does not
        // answer fails like one the RPC refused — the documented network class
        // — and `status`'s host skips it silently, as every backfill failure
        // (U67); a receipt not yet visible is still no error.
        let fetched = bounded_read(
            "eth_getTransactionReceipt failed",
            limit,
            provider.get_transaction_receipt(hash),
        )
        .await?;
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

// ---------------------------------------------------------------------------
// The submission step (S51, S54 — D208): sign first, broadcast under a
// deadline, and let the chain, asked by the locally computed hash, say what
// became of the transaction — never the error that interrupted the asking
// ---------------------------------------------------------------------------

/// How long one broadcast of the signed bytes may go unacknowledged (D208 R2);
/// also the bound on preparing a sub-batch and on each single lookup, so a
/// slow answer inside a window still counts as one. Generous: antseal never
/// re-sends blind, so a slow acknowledgement costs a resolution, never a second
/// transaction.
const BROADCAST_DEADLINE: Duration = Duration::from_secs(30);

/// How long an acknowledged broadcast is awaited for its receipt (D208 R3) —
/// about as long as upstream's own payer watches one (evmlib 0.9.0's
/// `TX_TIMEOUT` with its retries, D208 R7).
const RECEIPT_DEADLINE: Duration = Duration::from_secs(120);

/// How long an unacknowledged broadcast is looked up by its hash before the
/// payment step decides what it did (D208 R4).
const RESOLVE_WINDOW: Duration = Duration::from_secs(120);

/// The pause between two receipt lookups while awaiting or resolving.
const RECEIPT_POLL: Duration = Duration::from_secs(1);

/// The submission step's bounds (D208 R7): adapter constants in production,
/// milliseconds in tests — never config keys.
#[derive(Debug, Clone, Copy)]
struct SubmitDeadlines {
    /// One broadcast; also preparing, and each single lookup.
    broadcast: Duration,
    /// Awaiting an acknowledged broadcast's receipt.
    receipt: Duration,
    /// Resolving an unacknowledged broadcast by its hash.
    resolve_window: Duration,
    /// Between two receipt lookups.
    poll: Duration,
}

impl SubmitDeadlines {
    /// The bounds `pay` runs under.
    const PAYMENT_RPC: Self = Self {
        broadcast: BROADCAST_DEADLINE,
        receipt: RECEIPT_DEADLINE,
        resolve_window: RESOLVE_WINDOW,
        poll: RECEIPT_POLL,
    };
}

/// What `pay`'s loop carries from one sub-batch to the next — the
/// receipt-so-far and the blobs still waiting for a proof — in one value, so
/// the submission step can be driven by a test with no Autonomi client.
struct PayLoop {
    /// Each priced blob not yet proof-ready, by slot.
    remaining: Vec<Option<PricedBlobSlot>>,
    /// Each slot's ready-after sub-batch index (`usize::MAX`: no transfer).
    ready_after: Vec<usize>,
    /// Each slot's record, once its proof is built.
    records: Vec<Option<BlobPaymentRecord>>,
    /// The quote→tx map so far.
    tx_map: BTreeMap<QuoteHash, TxHash>,
    /// This call's transactions, in submission order.
    txs: Vec<TxRecord>,
    /// Gas spent so far, wei.
    gas_cost_wei: u128,
}

impl PayLoop {
    /// This call's confirmed landings: the count every stranded class reports.
    fn confirmed(&self) -> usize {
        self.txs
            .iter()
            .filter(|tx| tx.status == TxStatus::Confirmed)
            .count()
    }
}

/// One sub-batch, as the submission step takes it.
struct SubBatch {
    /// Its position in the payment, from 0.
    index: usize,
    /// How many sub-batches the payment has.
    count: usize,
    /// The quote hashes its transaction pays.
    quote_hashes: Vec<QuoteHash>,
}

/// Pay one sub-batch: sign it, broadcast it, and settle what the chain says
/// (D208 R1–R5).
///
/// - **Preparing** — the gas estimate (where a would-revert lands), fee
///   history, nonce, chain id, the signature — sends nothing, so its failure is
///   [`StorageError::Payment`] before any landing (R1).
/// - The hash journaled is ALWAYS the one computed here from the signed bytes,
///   never an RPC's echo (R2).
/// - **A receipt for that hash** takes the landed path — [`settle_sub_batch`],
///   unchanged — whether or not the broadcast was acknowledged (R3, R4).
/// - **A broadcast not acknowledged, that the chain answered for and never
///   showed** within the window, moved nothing: [`StorageError::Payment`]
///   before any landing (R4).
/// - **Anything else may have moved money** — an acknowledged broadcast never
///   seen to land, a chain that could not be asked, a transaction it holds
///   unmined — and takes the unobserved shape, [`strand_unobserved`] (R5).
///
/// Never a classifier over error text or error variants: an RPC error object
/// can mean "refused" or "I already hold it" (`already known`) with the same
/// code — measured against alloy 1.8.3 when D208 was ruled.
#[allow(clippy::too_many_arguments)] // the signer, the session's provider, the
// request, the loop state, the hook and the bounds: bundling them would move
// the same fields behind a name that explains nothing.
async fn pay_sub_batch<F, P>(
    signer: &alloy::providers::fillers::FillProvider<F, P, alloy::network::Ethereum>,
    provider: &DynProvider,
    request: TransactionRequest,
    sub_batch: &SubBatch,
    so_far: &mut PayLoop,
    staged: &Mutex<Staged>,
    hook: Option<&CaptureHook>,
    deadlines: SubmitDeadlines,
) -> Result<(), StorageError>
where
    F: alloy::providers::fillers::TxFiller<alloy::network::Ethereum>,
    P: Provider<alloy::network::Ethereum>,
{
    let confirmed = so_far.confirmed();
    let signed = sign_sub_batch(signer, request, deadlines.broadcast)
        .await
        .map_err(|detail| {
            stranded_or_payment(
                confirmed,
                format!("sub-batch tx could not be prepared: {detail}"),
            )
        })?;
    let evm_receipt = match submit_signed(provider, &signed, deadlines).await {
        Submission::Landed(receipt) => receipt,
        Submission::NotAccepted { detail } => {
            return Err(stranded_or_payment(
                confirmed,
                format!(
                    "the payment transaction was not accepted ({detail}), and the chain did not \
                     show it within {}",
                    span(deadlines.resolve_window)
                ),
            ));
        }
        Submission::Unresolved { reason } => {
            return Err(strand_unobserved(
                signed.hash,
                sub_batch,
                so_far,
                staged,
                hook,
                reason,
            ));
        }
    };

    let landed = evm_receipt.status();
    so_far.gas_cost_wei = so_far.gas_cost_wei.saturating_add(
        u128::from(evm_receipt.gas_used).saturating_mul(evm_receipt.effective_gas_price),
    );
    so_far.txs.push(TxRecord {
        tx_hash: signed.hash,
        block_number: evm_receipt.block_number,
        status: if landed {
            TxStatus::Confirmed
        } else {
            TxStatus::Reverted
        },
        quote_hashes: sub_batch.quote_hashes.clone(),
    });

    // A reverted payForQuotes moved no ANT: its quotes are NOT mapped (they
    // are unpaid). A confirmed one maps its quotes and builds the proofs that
    // became complete with this landing (per-blob `finalize_batch_payment` —
    // pure, `batch.rs:337-343`); a proof failure is data here, because after a
    // landing it is not a payment that moved nothing (S49).
    let outcome = if landed {
        for quote_hash in &sub_batch.quote_hashes {
            so_far.tx_map.insert(*quote_hash, signed.hash);
        }
        let finalized = finalize_ready_blobs(
            &mut so_far.remaining,
            &so_far.ready_after,
            sub_batch.index,
            &so_far.tx_map,
            &mut so_far.records,
            &mut lock_staged(staged).paid,
        );
        SubBatchOutcome::Confirmed { finalized }
    } else {
        SubBatchOutcome::Reverted
    };
    // Journal via the hook BEFORE the next submission, and decide whether the
    // payment goes on (S46, S49, S50 — D204).
    settle_sub_batch(
        outcome,
        hook,
        &so_far.records,
        &so_far.tx_map,
        &so_far.txs,
        so_far.gas_cost_wei,
        sub_batch.index,
        sub_batch.count,
    )
}

/// The unobserved-landing shape (D208 R5) — ONE body for both of its
/// producers: an acknowledged broadcast never seen to land, and a broadcast
/// whose fate the chain could not tell. Money may have moved, so the
/// sub-batch is journaled as paid by the local hash — a `Submitted` record,
/// its quotes mapped, and (S54) its blobs' records and proofs built over that
/// hash — BEFORE the capture, so a resume that finds the transaction mined
/// finalizes those blobs instead of buying them again: storers check the
/// quote's payment on the contract (`completedPayments`), not the hash a proof
/// carries (ant-node 0.15.0 `src/payment/verifier.rs`, D208).
///
/// Then [`StorageError::StrandedPayment`] with this call's confirmed count — 0
/// for a first sub-batch, deliberately: never "before any ANT moved". A proof
/// that cannot be built leaves its blob without a record (a resume re-buys
/// that one, S49's rule) and is named in the reason.
fn strand_unobserved(
    tx_hash: TxHash,
    sub_batch: &SubBatch,
    so_far: &mut PayLoop,
    staged: &Mutex<Staged>,
    hook: Option<&CaptureHook>,
    reason: String,
) -> StorageError {
    let landed_tx_count = so_far.confirmed();
    so_far.txs.push(TxRecord {
        tx_hash,
        block_number: None,
        status: TxStatus::Submitted,
        quote_hashes: sub_batch.quote_hashes.clone(),
    });
    for quote_hash in &sub_batch.quote_hashes {
        so_far.tx_map.insert(*quote_hash, tx_hash);
    }
    let finalized = finalize_ready_blobs(
        &mut so_far.remaining,
        &so_far.ready_after,
        sub_batch.index,
        &so_far.tx_map,
        &mut so_far.records,
        &mut lock_staged(staged).paid,
    );
    emit_capture(
        hook,
        &so_far.records,
        &so_far.tx_map,
        &so_far.txs,
        so_far.gas_cost_wei,
    );
    let reason = match finalized {
        Ok(()) => reason,
        Err(detail) => format!("{reason}; and a proof could not be built: {detail}"),
    };
    StorageError::StrandedPayment {
        landed_tx_count,
        reason,
    }
}

/// A sub-batch transaction signed here and not yet sent (D208 R1).
struct SignedTx {
    /// Computed from the signed bytes before any of them left: the hash every
    /// lookup asks about and the journal records.
    hash: TxHash,
    /// The EIP-2718 bytes `eth_sendRawTransaction` carries.
    raw: Vec<u8>,
}

/// Fill and sign `request` on the wallet's own filler stack — the gas
/// estimate, fee history, nonce and chain id `send_transaction` would read,
/// then the wallet's signature (`FillProvider::fill`, the same filler loop
/// `send_transaction` runs before its raw send) — and send nothing. Bounded by
/// `limit`; `Err` carries the redacted detail.
async fn sign_sub_batch<F, P>(
    signer: &alloy::providers::fillers::FillProvider<F, P, alloy::network::Ethereum>,
    request: TransactionRequest,
    limit: Duration,
) -> Result<SignedTx, String>
where
    F: alloy::providers::fillers::TxFiller<alloy::network::Ethereum>,
    P: Provider<alloy::network::Ethereum>,
{
    match within(limit, signer.fill(request)).await {
        Some(Ok(alloy::providers::SendableTx::Envelope(envelope))) => Ok(SignedTx {
            hash: TxHash::from_bytes(envelope.tx_hash().0),
            raw: alloy::network::eip2718::Encodable2718::encoded_2718(&envelope),
        }),
        Some(Ok(alloy::providers::SendableTx::Builder(_))) => {
            Err("the wallet's fillers left the transaction unsigned".to_owned())
        }
        Some(Err(e)) => Err(redact_rpc_error(&e.to_string())),
        None => Err(format!(
            "the payment RPC did not answer within {}",
            span(limit)
        )),
    }
}

/// What became of a signed sub-batch transaction (D208 R2–R4).
enum Submission {
    /// The payment RPC returned a receipt for the local hash.
    Landed(Box<alloy::rpc::types::TransactionReceipt>),
    /// The broadcast was not acknowledged, every lookup in the window was
    /// answered without a receipt, and at its end the RPC did not return the
    /// transaction by hash either: it moved nothing. `detail` says why the
    /// broadcast was not acknowledged (redacted).
    NotAccepted {
        /// Why the broadcast was not acknowledged.
        detail: String,
    },
    /// Neither: money may have moved. `reason` is the strand's (redacted).
    Unresolved {
        /// The stranded error's reason.
        reason: String,
    },
}

/// Broadcast the signed bytes under the broadcast deadline (R2) — an
/// acknowledgement echoing another hash is no acknowledgement — then await the
/// receipt by the local hash (R3) or, unacknowledged, resolve it (R4).
async fn submit_signed(
    provider: &DynProvider,
    signed: &SignedTx,
    deadlines: SubmitDeadlines,
) -> Submission {
    let local = alloy::primitives::B256::from(*signed.hash.as_bytes());
    let unacknowledged = match within(
        deadlines.broadcast,
        provider.send_raw_transaction(&signed.raw),
    )
    .await
    {
        Some(Ok(pending)) if *pending.tx_hash() == local => None,
        Some(Ok(_)) => Some("the payment RPC acknowledged a different transaction hash".to_owned()),
        Some(Err(e)) => Some(redact_rpc_error(&e.to_string())),
        None => Some(format!(
            "no acknowledgement within {}",
            span(deadlines.broadcast)
        )),
    };
    match unacknowledged {
        None => await_receipt(provider, local, deadlines).await,
        Some(detail) => {
            resolve_unacknowledged(provider, local, &signed.raw, detail, deadlines).await
        }
    }
}

/// R3: an acknowledged broadcast, awaited by the local hash until the receipt
/// deadline. A lookup that fails is not an answer, so the polling goes on, and
/// the loop always looks once more before it checks the deadline; with no
/// receipt by then, the landing was not observed — never "nothing moved": the
/// node acknowledged the transaction.
async fn await_receipt(
    provider: &DynProvider,
    local: alloy::primitives::B256,
    deadlines: SubmitDeadlines,
) -> Submission {
    let ends = deadline_instant(deadlines.receipt);
    let mut last_failure: Option<String> = None;
    loop {
        match within(deadlines.broadcast, provider.get_transaction_receipt(local)).await {
            Some(answer) => match classify_receipt(answer, local) {
                Lookup::Found(receipt) => return Submission::Landed(receipt),
                Lookup::NotYet => {}
                Lookup::Unanswered(why) => last_failure = Some(why),
            },
            None => last_failure = Some(no_answer(deadlines.broadcast)),
        }
        let left = ends.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        Deadline::after(left.min(deadlines.poll)).await;
    }
    let last = last_failure.map_or_else(String::new, |why| format!(" (the last lookup: {why})"));
    Submission::Unresolved {
        reason: format!(
            "sub-batch tx landing not observed: no receipt within {}{last}",
            span(deadlines.receipt)
        ),
    }
}

/// R4: a broadcast that was not acknowledged — an error of any kind, the
/// deadline, or another hash echoed — is looked up by the local hash until the
/// resolution window ends, each lookup bounded on its own so a slow answer
/// still counts as one. The identical bytes are re-broadcast once: the same
/// hash, so it cannot pay twice. A receipt is a landing; every lookup answered
/// without one and, once at the end, the RPC not returning the transaction by
/// hash means it moved nothing; anything else may have moved money.
async fn resolve_unacknowledged(
    provider: &DynProvider,
    local: alloy::primitives::B256,
    raw: &[u8],
    detail: String,
    deadlines: SubmitDeadlines,
) -> Submission {
    let ends = deadline_instant(deadlines.resolve_window);
    let mut unanswered: Option<String> = None;
    let mut rebroadcast = false;
    loop {
        match within(deadlines.broadcast, provider.get_transaction_receipt(local)).await {
            Some(answer) => match classify_receipt(answer, local) {
                Lookup::Found(receipt) => return Submission::Landed(receipt),
                Lookup::NotYet => {}
                Lookup::Unanswered(why) => {
                    unanswered.get_or_insert(why);
                }
            },
            None => {
                unanswered.get_or_insert_with(|| no_answer(deadlines.broadcast));
            }
        }
        if !rebroadcast {
            rebroadcast = true;
            let _ignored = within(deadlines.broadcast, provider.send_raw_transaction(raw)).await;
            continue;
        }
        let left = ends.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        Deadline::after(left.min(deadlines.poll)).await;
    }
    if let Some(why) = unanswered {
        return could_not_check(&detail, &why);
    }
    match transaction_by_hash(provider, local, deadlines.broadcast).await {
        ByHash::Unknown => Submission::NotAccepted { detail },
        ByHash::Held => Submission::Unresolved {
            reason: format!(
                "the payment transaction's broadcast was not acknowledged ({detail}), and after {} \
                 the payment RPC still holds it unmined",
                span(deadlines.resolve_window)
            ),
        },
        ByHash::Unanswered(why) => could_not_check(&detail, &why),
    }
}

/// R4's unaskable arm: the chain could not be asked what became of a broadcast
/// that was not acknowledged, so money may have moved.
fn could_not_check(detail: &str, why: &str) -> Submission {
    Submission::Unresolved {
        reason: format!(
            "the payment transaction's broadcast was not acknowledged ({detail}), and whether it \
             was mined could not be checked: {why}"
        ),
    }
}

/// One receipt lookup by the local hash, classified.
enum Lookup {
    /// A receipt for this very hash.
    Found(Box<alloy::rpc::types::TransactionReceipt>),
    /// Answered: no receipt (yet).
    NotYet,
    /// Not answered — an error, or a receipt for some other hash (redacted).
    Unanswered(String),
}

/// A receipt counts only for the hash that was asked about: an RPC that
/// answers with another transaction's receipt has not answered (R2's rule for
/// an echoed hash, applied to every read).
fn classify_receipt(
    answer: alloy::transports::TransportResult<Option<alloy::rpc::types::TransactionReceipt>>,
    local: alloy::primitives::B256,
) -> Lookup {
    match answer {
        Ok(Some(receipt)) if receipt.transaction_hash == local => Lookup::Found(Box::new(receipt)),
        Ok(Some(_)) => {
            Lookup::Unanswered("the payment RPC returned another transaction's receipt".to_owned())
        }
        Ok(None) => Lookup::NotYet,
        Err(e) => Lookup::Unanswered(redact_rpc_error(&e.to_string())),
    }
}

/// `eth_getTransactionByHash`, read only for whether it answers `null`.
enum ByHash {
    /// The RPC returns the transaction: it holds it (a caller that found no
    /// receipt reads that as unmined).
    Held,
    /// `null`: the RPC does not know the hash.
    Unknown,
    /// Not answered (redacted).
    Unanswered(String),
}

/// Ask the payment RPC for a transaction by hash, bounded by `limit`. The body
/// is never parsed — any JSON value but `null` is "it holds it" — so an RPC's
/// extra fields cannot turn "held" into "could not be asked".
async fn transaction_by_hash(
    provider: &DynProvider,
    local: alloy::primitives::B256,
    limit: Duration,
) -> ByHash {
    let asked = provider.raw_request::<_, Option<serde::de::IgnoredAny>>(
        "eth_getTransactionByHash".into(),
        (local,),
    );
    match within(limit, asked).await {
        Some(Ok(Some(_))) => ByHash::Held,
        Some(Ok(None)) => ByHash::Unknown,
        Some(Err(e)) => ByHash::Unanswered(redact_rpc_error(&e.to_string())),
        None => ByHash::Unanswered(no_answer(limit)),
    }
}

/// What the payment RPC says of one transaction (D208 R8, the resume's read):
/// a receipt for it is [`Landed`](crate::PaymentTxState::Landed); with none,
/// the transaction by hash is [`Pending`](crate::PaymentTxState::Pending) and
/// `null` is [`Absent`](crate::PaymentTxState::Absent); any lookup not
/// answered within `limit` is [`Unaskable`](crate::PaymentTxState::Unaskable),
/// its reason redacted.
async fn read_payment_tx_state(
    provider: &DynProvider,
    tx_hash: &TxHash,
    limit: Duration,
) -> crate::PaymentTxState {
    use crate::PaymentTxState;
    let local = alloy::primitives::B256::from(*tx_hash.as_bytes());
    let Some(answer) = within(limit, provider.get_transaction_receipt(local)).await else {
        return PaymentTxState::Unaskable {
            reason: format!("eth_getTransactionReceipt: {}", no_answer(limit)),
        };
    };
    match classify_receipt(answer, local) {
        Lookup::Found(receipt) => PaymentTxState::Landed {
            block_number: receipt.block_number,
            confirmed: receipt.status(),
        },
        Lookup::Unanswered(why) => PaymentTxState::Unaskable {
            reason: format!("eth_getTransactionReceipt: {why}"),
        },
        Lookup::NotYet => match transaction_by_hash(provider, local, limit).await {
            ByHash::Held => PaymentTxState::Pending,
            ByHash::Unknown => PaymentTxState::Absent,
            ByHash::Unanswered(why) => PaymentTxState::Unaskable {
                reason: format!("eth_getTransactionByHash: {why}"),
            },
        },
    }
}

/// A duration as the submission step's messages say it: whole seconds when it
/// is whole seconds (production), milliseconds otherwise (tests).
fn span(limit: Duration) -> String {
    if limit.subsec_nanos() == 0 {
        format!("{} s", limit.as_secs())
    } else {
        format!("{} ms", limit.as_millis())
    }
}

/// [`redact_evm_error`] for a payment-RPC error, with every URL replaced
/// first: a transport error names the URL it failed on, and a private endpoint
/// can carry a credential in its path — the reason
/// [`AntCoreReceiptReader::connect`] never echoes one.
fn redact_rpc_error(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(at) = rest.find("://") {
        let scheme_start = rest[..at]
            .char_indices()
            .rev()
            .find(|&(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |(i, c)| i + c.len_utf8());
        out.push_str(&rest[..scheme_start]);
        out.push_str("<url redacted>");
        let tail = &rest[at + 3..];
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, ')' | '(' | '"' | '\'' | '<' | '>'))
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    redact_evm_error(&out)
}

/// Run `future` until it finishes or `limit` passes, whichever is first:
/// `None` when the deadline won ([`race`] against a fresh [`Deadline`]).
async fn within<T>(limit: Duration, future: impl Future<Output = T>) -> Option<T> {
    race(&mut Deadline::after(limit), future).await
}

/// Run `future` until it finishes or `deadline` passes, whichever is first:
/// `None` when the deadline won. The future is polled first, so an answer that
/// is ready as the deadline passes still counts. The loser is dropped when this
/// returns — the future, or the deadline's wait — and nothing here blocks the
/// thread that polls it: the deadline's helper thread does the waiting.
async fn race<T>(deadline: &mut Deadline, future: impl Future<Output = T>) -> Option<T> {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|cx| {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(cx) {
            return std::task::Poll::Ready(Some(output));
        }
        std::pin::Pin::new(&mut *deadline).poll(cx).map(|()| None)
    })
    .await
}

/// The instant `limit` from now (now itself, were that to overflow — a bound
/// that has already passed).
fn deadline_instant(limit: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(limit).unwrap_or(now)
}

/// A lookup the payment RPC did not answer in time, as a reason says it.
fn no_answer(limit: Duration) -> String {
    format!("no answer within {}", span(limit))
}

// ---------------------------------------------------------------------------
// Payment-RPC reads outside the submission step (S57, S58 — D208 R13, R14):
// each bounded by the deadline helper, each error redacted, each failure the
// class the call always had
// ---------------------------------------------------------------------------

/// One payment-RPC read, bounded by `limit`: the value, or the network class
/// every such read always failed in, its reason `"{what}: {error}"` — the
/// error's URLs and hash-shaped runs redacted ([`redact_rpc_error`]) — or
/// `"{what}: no answer within {limit}"`.
async fn bounded_read<T, E: std::fmt::Display>(
    what: &str,
    limit: Duration,
    read: impl Future<Output = Result<T, E>>,
) -> Result<T, StorageError> {
    let reason = match within(limit, read).await {
        Some(Ok(value)) => return Ok(value),
        Some(Err(e)) => redact_rpc_error(&e.to_string()),
        None => no_answer(limit),
    };
    Err(StorageError::Network {
        reason: format!("{what}: {reason}"),
    })
}

/// `eth_gasPrice`, for the quote-time gas model (`estimate_gas_wei`).
async fn gas_price_wei(provider: &DynProvider, limit: Duration) -> Result<u128, StorageError> {
    bounded_read("eth_gasPrice failed", limit, provider.get_gas_price()).await
}

/// The wallet's ANT (ERC-20 `balanceOf`) balance (`raw_balances`).
async fn ant_balance(wallet: &Wallet, limit: Duration) -> Result<U256, StorageError> {
    bounded_read(
        "ANT balance query failed",
        limit,
        wallet.balance_of_tokens(),
    )
    .await
}

/// The wallet's ETH (`eth_getBalance`) balance (`raw_balances`).
async fn gas_balance(wallet: &Wallet, limit: Duration) -> Result<U256, StorageError> {
    bounded_read(
        "ETH balance query failed",
        limit,
        wallet.balance_of_gas_tokens(),
    )
    .await
}

/// The payment vault's standing allowance over the wallet's ANT
/// (`ensure_allowance`).
async fn standing_allowance(
    wallet: &Wallet,
    vault: ant_protocol::evm::Address,
    limit: Duration,
) -> Result<U256, StorageError> {
    bounded_read(
        "allowance query failed",
        limit,
        wallet.token_allowance(vault),
    )
    .await
}

/// An approve that failed (`ensure_allowance`): no ANT moved, so
/// [`StorageError::Payment`]; its reason redacted like every payment-RPC
/// error's, URLs included (S57).
fn approve_failure(error: &dyn std::fmt::Display) -> StorageError {
    StorageError::Payment {
        reason: format!(
            "token approve failed: {}",
            redact_rpc_error(&error.to_string())
        ),
    }
}

/// The approve's own gas from its receipt (`ensure_allowance`), the read
/// bounded by `limit` (S58): a read that fails, finds nothing or does not
/// answer in time counts 0, as a failed read always did.
async fn approve_gas_wei(
    provider: &DynProvider,
    tx_hash: alloy::primitives::B256,
    limit: Duration,
) -> u128 {
    within(limit, provider.get_transaction_receipt(tx_hash))
        .await
        .and_then(Result::ok)
        .flatten()
        .map_or(0, |receipt| {
            u128::from(receipt.gas_used).saturating_mul(receipt.effective_gas_price)
        })
}

/// A point in time an RPC is raced against, or slept until (D208 R7), with no
/// runtime edge.
///
/// This library takes no tokio — S6's recorded decision, its futures run on
/// the caller's runtime (`Cargo.toml`) — so the first poll that finds the
/// deadline ahead starts one helper thread that waits until then and wakes the
/// task; dropping the deadline ends that thread at once. A thread that cannot
/// be started leaves the deadline passed: an RPC antseal cannot bound counts as
/// unanswered, which no outcome reads as "nothing moved".
struct Deadline {
    at: Instant,
    alarm: Option<Alarm>,
}

impl Deadline {
    fn after(limit: Duration) -> Self {
        Self {
            at: deadline_instant(limit),
            alarm: None,
        }
    }
}

impl Future for Deadline {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        let this = self.get_mut();
        if Instant::now() >= this.at {
            return std::task::Poll::Ready(());
        }
        if this.alarm.is_none() {
            this.alarm = Alarm::start(this.at);
        }
        let Some(alarm) = &this.alarm else {
            return std::task::Poll::Ready(());
        };
        let mut state = lock_alarm(&alarm.state);
        if state.rang {
            return std::task::Poll::Ready(());
        }
        state.waker = Some(cx.waker().clone());
        std::task::Poll::Pending
    }
}

/// A [`Deadline`]'s helper thread, as the deadline holds it.
struct Alarm {
    state: Arc<Mutex<AlarmState>>,
    /// Dropped with the deadline: the thread stops waiting and wakes nobody.
    _cancel: std::sync::mpsc::Sender<()>,
}

/// Whether the alarm rang, and whom to wake when it does.
#[derive(Default)]
struct AlarmState {
    rang: bool,
    waker: Option<std::task::Waker>,
}

impl Alarm {
    /// Start the thread that rings at `at`, or `None` if none can be started.
    fn start(at: Instant) -> Option<Self> {
        let state = Arc::new(Mutex::new(AlarmState::default()));
        let (cancel, cancelled) = std::sync::mpsc::channel::<()>();
        let ringer = Arc::clone(&state);
        std::thread::Builder::new()
            .name("antseal-deadline".to_owned())
            .spawn(move || {
                let wait = at.saturating_duration_since(Instant::now());
                if matches!(
                    cancelled.recv_timeout(wait),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ) {
                    let waker = {
                        let mut state = lock_alarm(&ringer);
                        state.rang = true;
                        state.waker.take()
                    };
                    if let Some(waker) = waker {
                        waker.wake();
                    }
                }
            })
            .ok()?;
        Some(Self {
            state,
            _cancel: cancel,
        })
    }
}

/// Lock an alarm's state; a poisoned lock still holds a consistent flag.
fn lock_alarm(state: &Mutex<AlarmState>) -> std::sync::MutexGuard<'_, AlarmState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
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
    paying_block_time_within(provider, paying, BROADCAST_DEADLINE).await
}

/// [`paying_block_time`] with each of its two reads bounded by `limit` (S58,
/// D208 R14): a read that does not answer in time is a time that cannot be
/// read — `None`, which the policy reads as NOT expired (D179 R3) — so a hung
/// payment RPC costs a retry, never a payment.
async fn paying_block_time_within(
    provider: &DynProvider,
    paying: PayingTx,
    limit: Duration,
) -> Option<u64> {
    let block_number = match paying.block_number {
        Some(number) => number,
        None => {
            let hash = alloy::primitives::B256::from(*paying.tx_hash.as_bytes());
            within(limit, provider.get_transaction_receipt(hash))
                .await?
                .ok()??
                .block_number?
        }
    };
    let block = within(
        limit,
        provider
            .get_block_by_number(alloy::rpc::types::BlockNumberOrTag::Number(block_number))
            .into_future(),
    )
    .await?
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

    // ── S51 + S54 (D208): the submission step and the resolution read ─────

    /// **S51 and S54's net half (D208).** The submission step — sign first,
    /// broadcast under a deadline, let the chain say what became of the
    /// transaction — and the resolution read, over the PRODUCTION wallet
    /// provider: the vault-key import, a devnet configuration whose payment RPC
    /// is a loopback JSON-RPC stub, `WalletKey::evm_wallet`, then
    /// `Wallet::to_provider()` — the signer `pay` builds — and its erased twin,
    /// the provider the session holds.
    ///
    /// The stub plays the chain: it answers the reads `fill` makes, holds every
    /// raw transaction it receives (its pending nonce counts them), and answers
    /// the broadcast and each lookup as the test sets it. It serves each
    /// connection on its own thread, so a broadcast it holds open stalls no
    /// lookup behind it; the S43 stub above is unchanged. Nothing here leaves
    /// loopback, and each call is bounded by the test's own outer limit, so a
    /// missing deadline fails by message instead of hanging.
    mod s51_submission {
        use std::io::{Read, Write};
        use std::net::{SocketAddr, TcpListener, TcpStream};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        use std::thread::JoinHandle;
        use std::time::{Duration, Instant};

        use super::super::*;
        use antseal_core::crypto::secrets::SecretBuf;
        use antseal_core::test_util::alternate_test_secret;

        /// The deadlines the tests run under: milliseconds (D208 R7).
        const FAST: SubmitDeadlines = SubmitDeadlines {
            broadcast: Duration::from_millis(1500),
            receipt: Duration::from_millis(600),
            resolve_window: Duration::from_millis(600),
            poll: Duration::from_millis(25),
        };
        /// How long the stub holds a [`Broadcast::Hang`] connection open:
        /// beyond [`OUTER_LIMIT`], so a broadcast with no deadline of its own
        /// fails the test by message instead of ending on the stub's terms.
        const HANG: Duration = Duration::from_secs(30);
        /// The test's own bound on one submission: far above [`FAST`]'s sums.
        const OUTER_LIMIT: Duration = Duration::from_secs(20);
        /// The block every receipt the stub serves names.
        const BLOCK: u64 = 0x11;
        /// The fixture blob's one non-zero line: the median quote's price,
        /// paid 3× (upstream's single-node rule).
        const AMOUNT_ATTO: u128 = 300;
        const PRICE_ATTO: u128 = 100;

        /// How the stub answers `eth_sendRawTransaction` — always after it has
        /// read, and holds, the whole transaction.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Broadcast {
            /// Echo the transaction's own hash.
            Accept,
            /// Close the connection without a reply: the reply is lost.
            DropReply,
            /// A JSON-RPC error object, `already known`: geth's words for a
            /// transaction it already holds.
            AlreadyKnown,
            /// Echo some other hash.
            EchoOther,
            /// Hold the connection open, answering nothing, for [`HANG`].
            Hang,
        }

        /// How the stub answers a lookup of a transaction it holds; one it
        /// does not hold is always `null`.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Lookup {
            /// A receipt, mined successfully — or, by hash, the transaction.
            Show,
            /// A receipt of a transaction that reverted (receipt lookups only).
            Reverted,
            /// `null`.
            Null,
            /// Close the connection without a reply.
            Drop,
        }

        /// The stub's chain.
        /// How the stub stays quiet on one method (S57, S58).
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Quiet {
            /// Close the connection without a reply.
            Drop,
            /// Hold the connection open, answering nothing, for [`HANG`].
            Hang,
        }

        struct Chain {
            broadcast: Broadcast,
            receipts: Lookup,
            by_hash: Lookup,
            revert_estimate: bool,
            /// A method (or `"*"`, every method) the stub stays quiet on.
            quiet: Option<(&'static str, Quiet)>,
            /// Every raw transaction received, in order.
            held: Vec<Vec<u8>>,
            /// Every method asked, in order.
            asked: Vec<String>,
        }

        struct Stub {
            address: SocketAddr,
            chain: Arc<Mutex<Chain>>,
            stop: Arc<AtomicBool>,
            thread: Option<JoinHandle<()>>,
        }

        fn lock(chain: &Mutex<Chain>) -> std::sync::MutexGuard<'_, Chain> {
            match chain.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            }
        }

        impl Stub {
            fn start(broadcast: Broadcast, receipts: Lookup, by_hash: Lookup) -> Self {
                let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener");
                let address = listener.local_addr().expect("the listener's address");
                let chain = Arc::new(Mutex::new(Chain {
                    broadcast,
                    receipts,
                    by_hash,
                    revert_estimate: false,
                    quiet: None,
                    held: Vec::new(),
                    asked: Vec::new(),
                }));
                let stop = Arc::new(AtomicBool::new(false));
                let thread = {
                    let chain = Arc::clone(&chain);
                    let stop = Arc::clone(&stop);
                    std::thread::spawn(move || {
                        for stream in listener.incoming() {
                            if stop.load(Ordering::SeqCst) {
                                break;
                            }
                            if let Ok(mut stream) = stream {
                                let chain = Arc::clone(&chain);
                                std::thread::spawn(move || drop(serve(&mut stream, &chain)));
                            }
                        }
                    })
                };
                Self {
                    address,
                    chain,
                    stop,
                    thread: Some(thread),
                }
            }

            fn url(&self) -> String {
                format!("http://{}/", self.address)
            }

            /// The stub's URL with `path` — the stub answers any path.
            fn url_at(&self, path: &str) -> String {
                format!("http://{}/{path}/", self.address)
            }

            fn held(&self) -> Vec<Vec<u8>> {
                lock(&self.chain).held.clone()
            }

            fn asked(&self, method: &str) -> usize {
                lock(&self.chain)
                    .asked
                    .iter()
                    .filter(|asked| asked.as_str() == method)
                    .count()
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

        fn hex(bytes: &[u8]) -> String {
            let mut out = String::from("0x");
            for byte in bytes {
                out.push_str(&format!("{byte:02x}"));
            }
            out
        }

        fn unhex(text: &str) -> Vec<u8> {
            let digits = text.trim_start_matches("0x");
            (0..digits.len() / 2)
                .filter_map(|i| u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).ok())
                .collect()
        }

        /// A receipt for `hash` as an Arbitrum-style RPC shapes one.
        fn receipt(hash: &serde_json::Value, status: &str) -> serde_json::Value {
            serde_json::json!({
                "blockHash": hex(&[0x22; 32]),
                "blockNumber": format!("{BLOCK:#x}"),
                "contractAddress": null,
                "cumulativeGasUsed": "0x1a8f4",
                "effectiveGasPrice": "0x5f5e100",
                "from": "0x1111111111111111111111111111111111111111",
                "gasUsed": "0x1a8f4",
                "logs": [],
                "logsBloom": hex(&[0; 256]),
                "status": status,
                "to": "0x9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a",
                "transactionHash": hash,
                "transactionIndex": "0x0",
                "type": "0x2"
            })
        }

        fn read_request(stream: &mut TcpStream) -> std::io::Result<serde_json::Value> {
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 8192];
            let header_end = loop {
                let read = stream.read(&mut chunk)?;
                if read == 0 {
                    return Ok(serde_json::Value::Null);
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
            Ok(serde_json::from_slice(&buffer[header_end..body_end]).unwrap_or_default())
        }

        fn reply(stream: &mut TcpStream, body: &serde_json::Value) -> std::io::Result<()> {
            let body = body.to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )?;
            stream.flush()
        }

        fn lose_reply(stream: &TcpStream) -> std::io::Result<()> {
            stream.shutdown(std::net::Shutdown::Both)
        }

        fn serve(stream: &mut TcpStream, chain: &Mutex<Chain>) -> std::io::Result<()> {
            let request = read_request(stream)?;
            let method = request["method"].as_str().unwrap_or_default().to_owned();
            let params = request["params"].clone();
            let id = request["id"].clone();
            let ok = |result: serde_json::Value| {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id.clone(),
                    "result": result
                })
            };
            let error = |code: i64, message: &str| {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id.clone(),
                    "error": {"code": code, "message": message}
                })
            };
            let mut state = lock(chain);
            state.asked.push(method.clone());
            if let Some((target, quiet)) = state.quiet
                && (target == "*" || target == method)
            {
                drop(state);
                return match quiet {
                    Quiet::Drop => lose_reply(stream),
                    Quiet::Hang => {
                        std::thread::sleep(HANG);
                        Ok(())
                    }
                };
            }
            let (broadcast, receipts, by_hash) = (state.broadcast, state.receipts, state.by_hash);
            // Whether the hash a lookup asks about is a transaction it holds.
            let held = state.held.iter().any(|raw| {
                serde_json::json!(hex(alloy::primitives::keccak256(raw).as_slice())) == params[0]
            });
            let answer = match method.as_str() {
                "eth_chainId" => ok(serde_json::json!("0x7a69")),
                // A node that pools what it receives: the pending count moves.
                "eth_getTransactionCount" => {
                    ok(serde_json::json!(format!("{:#x}", 5 + state.held.len())))
                }
                "eth_estimateGas" if state.revert_estimate => error(3, "execution reverted"),
                "eth_estimateGas" => ok(serde_json::json!("0x30d40")),
                "eth_gasPrice" => ok(serde_json::json!("0x5f5e100")),
                "eth_getBalance" => ok(serde_json::json!("0x1")),
                // An ERC-20 `balanceOf` / `allowance`: one uint256.
                "eth_call" => ok(serde_json::json!(format!("0x{:0>64}", "1"))),
                "eth_feeHistory" => ok(serde_json::json!({
                    "oldestBlock": "0x10",
                    "baseFeePerGas": ["0x5f5e100", "0x5f5e100"],
                    "gasUsedRatio": [0.5],
                    "reward": [["0x0"]]
                })),
                "eth_sendRawTransaction" => {
                    let raw = unhex(params[0].as_str().unwrap_or_default());
                    let hash = alloy::primitives::keccak256(&raw);
                    state.held.push(raw);
                    match broadcast {
                        Broadcast::Accept => ok(serde_json::json!(hex(hash.as_slice()))),
                        Broadcast::DropReply => {
                            drop(state);
                            return lose_reply(stream);
                        }
                        Broadcast::AlreadyKnown => error(-32000, "already known"),
                        Broadcast::EchoOther => {
                            let mut other = hash.0;
                            other[0] ^= 0xFF;
                            ok(serde_json::json!(hex(&other)))
                        }
                        Broadcast::Hang => {
                            drop(state);
                            std::thread::sleep(HANG);
                            return Ok(());
                        }
                    }
                }
                "eth_getTransactionReceipt" => match receipts {
                    Lookup::Drop => {
                        drop(state);
                        return lose_reply(stream);
                    }
                    Lookup::Show if held => ok(receipt(&params[0], "0x1")),
                    Lookup::Reverted if held => ok(receipt(&params[0], "0x0")),
                    _ => ok(serde_json::Value::Null),
                },
                "eth_getTransactionByHash" => match by_hash {
                    Lookup::Drop => {
                        drop(state);
                        return lose_reply(stream);
                    }
                    Lookup::Show if held => ok(serde_json::json!({
                        "hash": params[0].clone(),
                        "blockHash": null,
                        "blockNumber": null,
                        "transactionIndex": null
                    })),
                    _ => ok(serde_json::Value::Null),
                },
                _ => ok(serde_json::Value::Null),
            };
            drop(state);
            reply(stream, &answer)
        }

        /// The production wallet over the stub: the house fixture-key
        /// convention (a derived key, never a committed literal), a devnet
        /// configuration whose payment RPC is the stub, `evm_wallet`.
        fn wallet(stub: &Stub) -> Wallet {
            wallet_at(stub.url())
        }

        /// [`wallet`], over the payment RPC URL `rpc_url`.
        fn wallet_at(rpc_url: String) -> Wallet {
            let hex: String = alternate_test_secret(b"antseal-net/S51 submission stub wallet")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let key = WalletKey::import(&SecretBuf::new(hex.into_bytes()))
                .expect("the fixture label derives a valid key");
            let config = NetworkConfig {
                rpc_url,
                ..super::devnet_base()
            };
            key.evm_wallet(&config)
                .expect("a devnet wallet over the stub")
        }

        fn quote(byte: u8) -> QuoteHash {
            QuoteHash::from_bytes([byte; 32])
        }

        /// A priced blob whose one non-zero line pays quote `byte`, staged the
        /// way `pay` holds it: our line beside upstream's `PreparedChunk`.
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

        type Seen = Arc<Mutex<Vec<PaymentReceipt>>>;

        fn recording_hook() -> (CaptureHook, Seen) {
            let seen: Seen = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&seen);
            let hook: CaptureHook = Arc::new(move |receipt: &PaymentReceipt| {
                sink.lock()
                    .expect("capture sink lock")
                    .push(receipt.clone());
                CaptureOutcome::Durable
            });
            (hook, seen)
        }

        /// What one run of the submission step left behind.
        struct Run {
            result: Result<(), StorageError>,
            so_far: PayLoop,
            captured: Vec<PaymentReceipt>,
            elapsed: Duration,
        }

        impl Run {
            /// The hash of the one transaction the stub received first — the
            /// bytes the wallet signed.
            fn signed_hash(stub: &Stub) -> TxHash {
                let held = stub.held();
                assert!(!held.is_empty(), "the stub received no transaction");
                TxHash::from_bytes(alloy::primitives::keccak256(&held[0]).0)
            }

            fn reason(&self) -> &str {
                match &self.result {
                    Err(StorageError::Payment { reason })
                    | Err(StorageError::StrandedPayment { reason, .. }) => reason,
                    other => panic!("expected a payment-class error, got {other:?}"),
                }
            }
        }

        /// `pay`'s loop at its first sub-batch — one priced blob paying quote
        /// 0xA0, nothing landed — driven through [`pay_sub_batch`].
        async fn run(stub: &Stub, deadlines: SubmitDeadlines) -> Run {
            let so_far = PayLoop {
                remaining: vec![Some(priced(0, 0xA0))],
                ready_after: vec![0],
                records: vec![None],
                tx_map: BTreeMap::new(),
                txs: Vec::new(),
                gas_cost_wei: 0,
            };
            let sub_batch = SubBatch {
                index: 0,
                count: 1,
                quote_hashes: vec![quote(0xA0)],
            };
            run_sub_batch(stub, deadlines, so_far, sub_batch).await
        }

        /// One sub-batch — its one quote paid with the real `payForQuotes`
        /// calldata — through [`pay_sub_batch`], with the production signer
        /// and provider over the stub, a recording capture hook, and
        /// `deadlines`.
        async fn run_sub_batch(
            stub: &Stub,
            deadlines: SubmitDeadlines,
            mut so_far: PayLoop,
            sub_batch: SubBatch,
        ) -> Run {
            let wallet = wallet(stub);
            let signer = wallet.to_provider();
            let provider = wallet.to_provider().erased();
            let handler = PaymentVaultHandler::new(vault_address(&wallet), provider.clone());
            let paid = sub_batch.quote_hashes[0];
            let (calldata, to) = handler
                .pay_for_quotes_calldata(vec![(
                    ant_protocol::evm::QuoteHash::from(*paid.as_bytes()),
                    ant_protocol::evm::Address::from([paid.as_bytes()[0]; 20]),
                    U256::from(AMOUNT_ATTO),
                )])
                .expect("the calldata is an offline ABI encode");
            let request = TransactionRequest::default()
                .with_from(wallet.address())
                .with_to(to)
                .with_input(calldata);
            let staged = Mutex::new(Staged::default());
            let (hook, seen) = recording_hook();
            let started = Instant::now();
            let result = tokio::time::timeout(
                OUTER_LIMIT,
                pay_sub_batch(
                    &signer,
                    &provider,
                    request,
                    &sub_batch,
                    &mut so_far,
                    &staged,
                    Some(&hook),
                    deadlines,
                ),
            )
            .await
            .expect(
                "the submission step must end on its own deadlines; it was still running at the \
                 test's outer limit",
            );
            let elapsed = started.elapsed();
            let captured = seen.lock().expect("capture sink lock").clone();
            Run {
                result,
                so_far,
                captured,
                elapsed,
            }
        }

        /// Hygiene (module docs): a reason names no hash and no URL.
        fn assert_clean(reason: &str, local: &TxHash) {
            let local_hex = hex(local.as_bytes());
            assert!(
                !reason.contains(&local_hex[2..18]),
                "the reason names the transaction hash: {reason}"
            );
            assert!(!reason.contains("://"), "the reason names a URL: {reason}");
        }

        /// The unobserved shape (D208 R5, S54): the stranded class with no
        /// landing, ONE capture carrying the `Submitted` record for the hash of
        /// the bytes the wallet signed, the quote mapped to it, and the blob's
        /// record built over it, with its cost.
        fn assert_unobserved(stub: &Stub, run: &Run, reason_has: &str) {
            let local = Run::signed_hash(stub);
            assert!(
                matches!(
                    run.result,
                    Err(StorageError::StrandedPayment {
                        landed_tx_count: 0,
                        ..
                    })
                ),
                "D208 R5: money may have moved — expected StrandedPayment with no landing, \
                 got {:?}",
                run.result
            );
            let reason = run.reason();
            assert!(reason.contains(reason_has), "{reason}");
            assert_clean(reason, &local);
            assert_eq!(run.captured.len(), 1, "one capture, before the class");
            let receipt = &run.captured[0];
            assert_eq!(receipt.txs.len(), 1);
            assert_eq!(receipt.txs[0].tx_hash, local, "journaled by the local hash");
            assert_eq!(receipt.txs[0].status, TxStatus::Submitted);
            assert_eq!(receipt.txs[0].block_number, None);
            assert_eq!(receipt.tx_map.get(&quote(0xA0)), Some(&local));
            assert_eq!(
                receipt.blobs.len(),
                1,
                "S54: the sub-batch's record is built over the local hash before the capture"
            );
            assert_eq!(receipt.blobs[0].address, Address::from_bytes([0xA0; 32]));
            assert!(!receipt.blobs[0].proof_bytes.is_empty(), "with its proof");
            assert_eq!(receipt.storage_cost_atto, AMOUNT_ATTO, "and its cost");
            assert!(receipt.covers_all_paid_quotes());
        }

        /// G1. A lost reply whose transaction the chain shows is a landing:
        /// no `Payment`, no strand — the ordinary landed path, journaled by the
        /// hash of the very bytes the node holds. The first lookup finds it,
        /// so nothing is re-broadcast.
        #[tokio::test(flavor = "multi_thread")]
        async fn s51_a_lost_reply_whose_transaction_lands_is_a_landing() {
            let stub = Stub::start(Broadcast::DropReply, Lookup::Show, Lookup::Null);
            let run = run(&stub, FAST).await;
            assert_eq!(
                run.result,
                Ok(()),
                "a broadcast whose reply was lost, and which the chain shows mined, must land"
            );
            let local = Run::signed_hash(&stub);
            assert_eq!(stub.held().len(), 1, "one broadcast, no re-broadcast");
            assert_eq!(stub.asked("eth_sendRawTransaction"), 1);
            assert_eq!(run.so_far.txs.len(), 1);
            assert_eq!(run.so_far.txs[0].tx_hash, local);
            assert_eq!(run.so_far.txs[0].status, TxStatus::Confirmed);
            assert_eq!(run.so_far.txs[0].block_number, Some(BLOCK));
            assert_eq!(run.so_far.tx_map.get(&quote(0xA0)), Some(&local));
            assert!(run.so_far.records[0].is_some(), "the blob's proof is built");
            assert_eq!(run.captured.len(), 1, "the landing's one capture");
            assert_eq!(run.captured[0].txs, run.so_far.txs);
        }

        /// G2. A lost reply the chain never shows — every lookup answered
        /// without a receipt, and at the end of the window the RPC does not
        /// know the hash — moved nothing: `Payment`, naming the window. The
        /// identical bytes were re-broadcast once.
        #[tokio::test(flavor = "multi_thread")]
        async fn s51_a_lost_reply_the_chain_never_shows_is_a_payment_that_moved_nothing() {
            let stub = Stub::start(Broadcast::DropReply, Lookup::Null, Lookup::Null);
            let run = run(&stub, FAST).await;
            let local = Run::signed_hash(&stub);
            assert!(
                matches!(run.result, Err(StorageError::Payment { .. })),
                "D208 R4: answered and absent is Payment — got {:?}",
                run.result
            );
            let reason = run.reason();
            assert!(
                reason.starts_with("the payment transaction was not accepted ("),
                "{reason}"
            );
            assert!(
                reason.ends_with("), and the chain did not show it within 600 ms"),
                "{reason}"
            );
            assert_clean(reason, &local);
            let held = stub.held();
            assert_eq!(held.len(), 2, "the broadcast and one re-broadcast");
            assert_eq!(held[0], held[1], "the re-broadcast is the identical bytes");
            assert_eq!(
                stub.asked("eth_getTransactionByHash"),
                1,
                "once, at the end"
            );
            assert!(run.captured.is_empty(), "nothing is journaled");
            assert!(run.so_far.txs.is_empty() && run.so_far.tx_map.is_empty());
            assert!(
                run.elapsed >= FAST.resolve_window,
                "it waited the window: {:?}",
                run.elapsed
            );
        }

        /// G3. A lost reply, then a chain that cannot be asked: the unobserved
        /// shape — and, under S54, the capture carries the record and the
        /// cost, so a resume that finds the transaction mined buys nothing
        /// again.
        #[tokio::test(flavor = "multi_thread")]
        async fn s51_an_unaskable_chain_after_a_lost_reply_is_the_unobserved_shape() {
            let stub = Stub::start(Broadcast::DropReply, Lookup::Drop, Lookup::Drop);
            let run = run(&stub, FAST).await;
            assert_unobserved(&stub, &run, "whether it was mined could not be checked: ");
            assert!(
                run.reason()
                    .starts_with("the payment transaction's broadcast was not acknowledged ("),
                "{}",
                run.reason()
            );
            assert_eq!(
                stub.asked("eth_getTransactionByHash"),
                0,
                "an unanswered lookup already decided"
            );
        }

        /// G4. A refusal inside `fill` — here the gas estimate, where a
        /// would-revert lands — sends nothing: `Payment`, and the stub saw no
        /// `eth_sendRawTransaction`.
        #[tokio::test(flavor = "multi_thread")]
        async fn s51_a_refusal_inside_fill_sends_nothing() {
            let stub = Stub::start(Broadcast::Accept, Lookup::Show, Lookup::Null);
            lock(&stub.chain).revert_estimate = true;
            let run = run(&stub, FAST).await;
            assert!(
                matches!(run.result, Err(StorageError::Payment { .. })),
                "{:?}",
                run.result
            );
            let reason = run.reason();
            assert!(
                reason.starts_with("sub-batch tx could not be prepared: "),
                "{reason}"
            );
            assert!(reason.contains("execution reverted"), "{reason}");
            assert!(!reason.contains("://"), "{reason}");
            assert_eq!(stub.asked("eth_estimateGas"), 1);
            assert_eq!(stub.asked("eth_sendRawTransaction"), 0, "nothing was sent");
            assert!(stub.held().is_empty());
            assert!(run.captured.is_empty() && run.so_far.txs.is_empty());
        }

        /// G5. An error object does not decide: `already known` is what a node
        /// says of a transaction it HOLDS, with the same code (-32000) as a
        /// refusal such as `nonce too low`. The chain shows the receipt: a landing.
        #[tokio::test(flavor = "multi_thread")]
        async fn s51_an_error_object_does_not_decide() {
            let stub = Stub::start(Broadcast::AlreadyKnown, Lookup::Show, Lookup::Null);
            let run = run(&stub, FAST).await;
            assert_eq!(
                run.result,
                Ok(()),
                "an `already known` error object is not a refusal: the chain shows the landing"
            );
            assert_eq!(run.so_far.txs.len(), 1);
            assert_eq!(run.so_far.txs[0].tx_hash, Run::signed_hash(&stub));
            assert_eq!(run.so_far.txs[0].status, TxStatus::Confirmed);
            assert_eq!(run.captured.len(), 1);
        }

        /// G6. The broadcast and the await are bounded: a gateway that holds
        /// the broadcast open, and an acknowledged transaction whose receipt
        /// never comes, each end on the step's own deadlines (the outer limit
        /// in `run` turns a missing one into a failure by message). The
        /// acknowledged one is never `Payment`: the node took it.
        #[tokio::test(flavor = "multi_thread")]
        async fn s51_the_broadcast_and_the_await_are_bounded() {
            let slack = Duration::from_secs(3);
            let threads_before = deadline_threads();
            let hung = Stub::start(Broadcast::Hang, Lookup::Null, Lookup::Null);
            let run_hung = run(&hung, FAST).await;
            eprintln!(
                "[S51 G6] hung broadcast ended after {:?} (broadcast 1500ms, window 600ms)",
                run_hung.elapsed
            );
            let reason = run_hung.reason();
            assert!(
                matches!(run_hung.result, Err(StorageError::Payment { .. })),
                "{:?}",
                run_hung.result
            );
            assert!(
                reason.starts_with(
                    "the payment transaction was not accepted (no acknowledgement \
                     within 1500 ms)"
                ),
                "{reason}"
            );
            assert!(
                run_hung.elapsed < FAST.broadcast * 3 + FAST.resolve_window + slack,
                "the broadcast deadline bounds a hung gateway: {:?}",
                run_hung.elapsed
            );

            let silent = Stub::start(Broadcast::Accept, Lookup::Null, Lookup::Null);
            let run_silent = run(&silent, FAST).await;
            eprintln!(
                "[S51 G6] silent receipt await ended after {:?} (receipt 600ms)",
                run_silent.elapsed
            );
            assert_unobserved(
                &silent,
                &run_silent,
                "sub-batch tx landing not observed: no receipt within 600 ms",
            );
            assert!(
                run_silent.elapsed < FAST.receipt + FAST.broadcast + slack,
                "the receipt deadline bounds the await: {:?}",
                run_silent.elapsed
            );
            assert_eq!(
                silent.asked("eth_sendRawTransaction"),
                1,
                "acknowledged once"
            );
            // Process-wide, so printed, not asserted (libtest runs other rows
            // beside this one); the per-deadline proof is
            // `s51_a_deadline_thread_ends_with_its_deadline`.
            let settling = Instant::now();
            while deadline_threads() > threads_before && settling.elapsed() < slack {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            eprintln!(
                "[S51 G6] deadline helper threads alive: {threads_before} before both runs, {} \
                 after (settled in {:?})",
                deadline_threads(),
                settling.elapsed()
            );
        }

        /// Live [`Deadline`] helper threads in this process — Linux
        /// `/proc/self/task/*/comm`, which keeps 15 bytes of the name.
        fn deadline_threads() -> usize {
            std::fs::read_dir("/proc/self/task")
                .map(|tasks| {
                    tasks
                        .flatten()
                        .filter(|task| {
                            std::fs::read_to_string(task.path().join("comm"))
                                .is_ok_and(|name| name.trim_end() == "antseal-deadlin")
                        })
                        .count()
                })
                .unwrap_or(0)
        }

        /// G6 on a current-thread runtime: the CLI drives the payer on a
        /// multi-thread runtime (`antseal-cli` `backend::ant::runtime`, D90
        /// §3.3), which the rows above use; the deadline does not depend on
        /// it — on one thread, with the stub holding the broadcast open, the
        /// step still ends on its own deadlines with the same class.
        #[tokio::test(flavor = "current_thread")]
        async fn s51_the_broadcast_deadline_holds_on_a_current_thread_runtime() {
            let hung = Stub::start(Broadcast::Hang, Lookup::Null, Lookup::Null);
            let run_hung = run(&hung, FAST).await;
            eprintln!(
                "[S51 G6/current_thread] hung broadcast ended after {:?}",
                run_hung.elapsed
            );
            assert!(
                run_hung
                    .reason()
                    .starts_with("the payment transaction was not accepted (no acknowledgement"),
                "{:?}",
                run_hung.result
            );
            assert!(
                run_hung.elapsed
                    < FAST.broadcast * 3 + FAST.resolve_window + Duration::from_secs(3),
                "{:?}",
                run_hung.elapsed
            );
        }

        /// The same rows at k ≥ 1 (D208 R4-R5: the count is this call's
        /// landings): sub-batch 2 of 2 unobserved after sub-batch 1 landed —
        /// `StrandedPayment { landed_tx_count: 1 }`, and ONE capture carrying
        /// the landed record AND the unobserved one's, each over its own hash.
        #[tokio::test(flavor = "multi_thread")]
        async fn s51_an_unobserved_later_sub_batch_strands_with_the_landed_count() {
            let stub = Stub::start(Broadcast::DropReply, Lookup::Drop, Lookup::Drop);
            let landed = TxHash::from_bytes([0x70; 32]);
            let mut remaining = vec![Some(priced(0, 0xA0)), Some(priced(1, 0xB0))];
            let ready_after = vec![0, 1];
            let mut records = vec![None, None];
            let tx_map = BTreeMap::from([(quote(0xA0), landed)]);
            finalize_ready_blobs(
                &mut remaining,
                &ready_after,
                0,
                &tx_map,
                &mut records,
                &mut HashMap::new(),
            )
            .expect("fixture: the landed blob's proof builds");
            let so_far = PayLoop {
                remaining,
                ready_after,
                records,
                tx_map,
                txs: vec![TxRecord {
                    tx_hash: landed,
                    block_number: Some(BLOCK),
                    status: TxStatus::Confirmed,
                    quote_hashes: vec![quote(0xA0)],
                }],
                gas_cost_wei: 21_000,
            };
            let sub_batch = SubBatch {
                index: 1,
                count: 2,
                quote_hashes: vec![quote(0xB0)],
            };
            let run = run_sub_batch(&stub, FAST, so_far, sub_batch).await;
            assert!(
                matches!(
                    run.result,
                    Err(StorageError::StrandedPayment {
                        landed_tx_count: 1,
                        ..
                    })
                ),
                "{:?}",
                run.result
            );
            let local = Run::signed_hash(&stub);
            assert_eq!(run.captured.len(), 1);
            let receipt = &run.captured[0];
            let statuses: Vec<TxStatus> = receipt.txs.iter().map(|tx| tx.status).collect();
            assert_eq!(statuses, [TxStatus::Confirmed, TxStatus::Submitted]);
            assert_eq!(receipt.txs[1].tx_hash, local);
            assert_eq!(receipt.tx_map.get(&quote(0xA0)), Some(&landed));
            assert_eq!(receipt.tx_map.get(&quote(0xB0)), Some(&local));
            assert_eq!(
                receipt.blobs.len(),
                2,
                "the landed record and the unobserved one's"
            );
            assert_eq!(receipt.storage_cost_atto, 2 * AMOUNT_ATTO);
            assert_eq!(receipt.gas.gas_cost_wei, 21_000);
        }

        /// G7. The journaled hash is the local one: a node that acknowledges
        /// with some other hash has not acknowledged, and the transaction is
        /// resolved — and journaled — by the hash of the bytes the wallet
        /// signed.
        #[tokio::test(flavor = "multi_thread")]
        async fn s51_the_journaled_hash_is_the_local_one() {
            let stub = Stub::start(Broadcast::EchoOther, Lookup::Show, Lookup::Null);
            let run = run(&stub, FAST).await;
            assert_eq!(run.result, Ok(()), "resolved by the local hash: a landing");
            let local = Run::signed_hash(&stub);
            let mut echoed = *local.as_bytes();
            echoed[0] ^= 0xFF;
            assert_eq!(run.so_far.txs[0].tx_hash, local);
            assert_ne!(run.so_far.txs[0].tx_hash, TxHash::from_bytes(echoed));
            assert_eq!(run.captured.len(), 1);
            assert_eq!(run.captured[0].tx_map.get(&quote(0xA0)), Some(&local));
        }

        /// G8. A transaction the chain still holds — no receipt in the window,
        /// but the RPC returns it by hash — may yet be mined: the unobserved
        /// shape, never `Payment`.
        #[tokio::test(flavor = "multi_thread")]
        async fn s51_a_transaction_the_chain_still_holds_is_the_unobserved_shape() {
            let stub = Stub::start(Broadcast::DropReply, Lookup::Null, Lookup::Show);
            let run = run(&stub, FAST).await;
            assert_unobserved(
                &stub,
                &run,
                "and after 600 ms the payment RPC still holds it unmined",
            );
            assert_eq!(stub.asked("eth_getTransactionByHash"), 1);
        }

        /// S54 (D208 R8): the payer's resolution read over the same provider
        /// — landed, reverted, held, absent, and two ways of not being asked.
        #[tokio::test(flavor = "multi_thread")]
        async fn s54_the_payment_rpc_reads_landed_reverted_pending_absent_or_unaskable() {
            let raw = b"antseal S54 held transaction".to_vec();
            let held = TxHash::from_bytes(alloy::primitives::keccak256(&raw).0);
            let stranger = TxHash::from_bytes([0x5E; 32]);
            let limit = Duration::from_millis(500);
            let rows = [
                (Lookup::Show, Lookup::Null, held, "landed"),
                (Lookup::Reverted, Lookup::Null, held, "reverted"),
                (Lookup::Null, Lookup::Show, held, "pending"),
                (Lookup::Null, Lookup::Null, held, "absent"),
                (Lookup::Show, Lookup::Show, stranger, "absent"),
                (Lookup::Drop, Lookup::Null, held, "receipt unaskable"),
                (Lookup::Null, Lookup::Drop, held, "by-hash unaskable"),
            ];
            assert_eq!(rows.len(), 7, "five answers, two of them twice");
            for (receipts, by_hash, tx_hash, case) in rows {
                let stub = Stub::start(Broadcast::Accept, receipts, by_hash);
                lock(&stub.chain).held.push(raw.clone());
                let provider = wallet(&stub).to_provider().erased();
                let state = tokio::time::timeout(
                    OUTER_LIMIT,
                    read_payment_tx_state(&provider, &tx_hash, limit),
                )
                .await
                .expect("the read ends on its own deadline");
                match (case, &state) {
                    (
                        "landed",
                        crate::PaymentTxState::Landed {
                            block_number: Some(BLOCK),
                            confirmed: true,
                        },
                    )
                    | (
                        "reverted",
                        crate::PaymentTxState::Landed {
                            block_number: Some(BLOCK),
                            confirmed: false,
                        },
                    )
                    | ("pending", crate::PaymentTxState::Pending)
                    | ("absent", crate::PaymentTxState::Absent) => {}
                    ("receipt unaskable", crate::PaymentTxState::Unaskable { reason }) => {
                        assert!(
                            reason.starts_with("eth_getTransactionReceipt: "),
                            "{reason}"
                        );
                        assert_clean(reason, &tx_hash);
                    }
                    ("by-hash unaskable", crate::PaymentTxState::Unaskable { reason }) => {
                        assert!(reason.starts_with("eth_getTransactionByHash: "), "{reason}");
                        assert_clean(reason, &tx_hash);
                    }
                    _ => panic!("{case}: got {state:?}"),
                }
            }
        }

        /// The std-only deadline (D208 R7): it ends a future that never
        /// finishes, waking its task from the helper thread, and a ready
        /// answer still wins. On a current-thread runtime, where nothing but
        /// the helper thread's wake can bring the task back.
        #[tokio::test(flavor = "current_thread")]
        async fn s51_a_deadline_bounds_a_future_that_never_finishes() {
            let started = Instant::now();
            let never = tokio::time::timeout(
                OUTER_LIMIT,
                within(Duration::from_millis(50), std::future::pending::<()>()),
            )
            .await
            .expect("the helper thread wakes the task");
            assert_eq!(never, None);
            let elapsed = started.elapsed();
            eprintln!(
                "[S51 deadline] a never-finishing future ended after {elapsed:?} (limit 50ms)"
            );
            assert!(
                elapsed >= Duration::from_millis(50) && elapsed < Duration::from_secs(5),
                "{elapsed:?}"
            );
            assert_eq!(within(Duration::ZERO, async { 7 }).await, Some(7));
        }

        /// A future that never finishes and records its own drop.
        struct Tracked(Arc<AtomicBool>);

        impl Future for Tracked {
            type Output = ();

            fn poll(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<()> {
                std::task::Poll::Pending
            }
        }

        impl Drop for Tracked {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        /// The losing future is dropped when the deadline wins, and the
        /// wait never blocks the thread that polls it: on a current-thread
        /// runtime — one thread for every task — a ticker spawned beside the
        /// wait keeps running throughout it.
        #[tokio::test(flavor = "current_thread")]
        async fn s51_a_deadline_drops_the_loser_and_never_blocks_its_thread() {
            let dropped = Arc::new(AtomicBool::new(false));
            let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let ticker = {
                let ticks = Arc::clone(&ticks);
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        ticks.fetch_add(1, Ordering::SeqCst);
                    }
                })
            };
            let started = Instant::now();
            let outcome = tokio::time::timeout(
                OUTER_LIMIT,
                within(Duration::from_millis(300), Tracked(Arc::clone(&dropped))),
            )
            .await
            .expect("the deadline ends the wait");
            let elapsed = started.elapsed();
            let ticked = ticks.load(Ordering::SeqCst);
            ticker.abort();
            eprintln!(
                "[S51 deadline] 300ms wait: {elapsed:?}, ticker ran {ticked} times meanwhile"
            );
            assert_eq!(outcome, None, "the deadline won");
            assert!(
                dropped.load(Ordering::SeqCst),
                "the losing future was dropped"
            );
            assert!(
                ticked >= 10,
                "a ticker on the same thread made {ticked} ticks in {elapsed:?}: the wait \
                 blocked the executor thread"
            );
        }

        /// No helper thread outlives its deadline (D208 R7): the thread holds
        /// the alarm's shared state until it ends, so the state's count of
        /// owners returning to one IS the thread having ended. Both ways a
        /// deadline ends: it passes (the thread rings, then ends), or the
        /// future wins and the deadline is dropped (the thread is cancelled).
        #[tokio::test(flavor = "current_thread")]
        async fn s51_a_deadline_thread_ends_with_its_deadline() {
            async fn ended(state: Arc<Mutex<AlarmState>>, case: &str) {
                let started = Instant::now();
                while Arc::strong_count(&state) > 1 {
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "{case}: the helper thread is still alive after {:?}",
                        started.elapsed()
                    );
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                eprintln!(
                    "[S51 deadline] {case}: helper thread ended {:?} later",
                    started.elapsed()
                );
            }
            let state_of = |deadline: &Deadline| {
                Arc::clone(
                    &deadline
                        .alarm
                        .as_ref()
                        .expect("a pending poll starts the helper thread")
                        .state,
                )
            };

            let mut passes = Deadline::after(Duration::from_millis(30));
            assert_eq!(race(&mut passes, std::future::pending::<()>()).await, None);
            let state = state_of(&passes);
            drop(passes);
            ended(state, "the deadline passed").await;

            let mut cancelled = Deadline::after(Duration::from_secs(60));
            let won = race(&mut cancelled, async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                "answered"
            })
            .await;
            assert_eq!(won, Some("answered"));
            let state = state_of(&cancelled);
            drop(cancelled);
            ended(state, "the future won, 60s early").await;
        }

        /// Hygiene: an RPC error names no URL — a private endpoint can carry
        /// a credential in its path — and no hash-shaped run.
        #[test]
        fn s51_rpc_error_reasons_name_no_url_and_no_hash() {
            let rows = [
                (
                    "error sending request for url (http://user:pw@rpc.example:8545/v2/k3yAbc)",
                    "error sending request for url (<url redacted>)",
                ),
                (
                    "HTTP error 502 with body: see https://x.example/a?b=c now",
                    "HTTP error 502 with body: see <url redacted> now",
                ),
                (
                    "tx 0x3789f960fcea72bcaa5a1615f585d401cea57673c23837af105060ee24e53b56 is known",
                    "tx 0x<hex redacted> is known",
                ),
                ("no url here: ok", "no url here: ok"),
                ("é://ünïcode", "é<url redacted>"),
            ];
            assert_eq!(rows.len(), 5);
            for (message, expected) in rows {
                assert_eq!(redact_rpc_error(message), expected, "{message}");
            }
        }

        /// **S57 + S58 (D208 R13, R14).** The payment-RPC reads OUTSIDE the
        /// submission step — `chain_id_guard` (connect), `gas_price_wei`
        /// (quote), `ant_balance` / `gas_balance` / `standing_allowance`
        /// (preflight), `approve_gas_wei` and `approve_failure` (the approve),
        /// `fill_block_numbers` (backfill), `paying_block_time_within`
        /// (finalize's proof-age read) — each bounded by the deadline helper
        /// and each error redacted, over the same stub: S57's rows give the
        /// stub a URL whose PATH carries a canary and make it drop the read;
        /// S58's make it accept every read and never answer.
        mod s57_s58_reads {
            use super::*;

            /// The deadline the S58 rows inject.
            const LIMIT: Duration = Duration::from_millis(300);
            /// A path segment no redaction rule knows: not hex, not a word
            /// any message says — so finding it means the URL got through.
            const CANARY: &str = "canary-s57-zqpw";

            /// A stub quiet on `method` (`"*"`: every method).
            fn quiet(method: &'static str, how: Quiet) -> Stub {
                let stub = Stub::start(Broadcast::Accept, Lookup::Null, Lookup::Null);
                lock(&stub.chain).quiet = Some((method, how));
                stub
            }

            /// S57's assertion: the reason carries neither the canary nor any
            /// URL — and it DOES carry the transport error, with its URL
            /// replaced, so the error reached the reason (anti-vacuity: a
            /// reason that never held the error would pass the first check).
            fn assert_no_url(site: &str, reason: &str) {
                assert!(
                    !reason.contains(CANARY)
                        && !reason.contains("://")
                        && !reason.contains("127.0.0.1"),
                    "{site}: the reason names the RPC URL: {reason}"
                );
                assert!(
                    reason.contains("error sending request for url (<url redacted>)"),
                    "{site}: fixture — the reason must carry the transport error: {reason}"
                );
            }

            fn network_reason(
                site: &str,
                result: Result<impl std::fmt::Debug, StorageError>,
            ) -> String {
                match result {
                    Err(StorageError::Network { reason }) => reason,
                    other => panic!("{site}: expected the network class, got {other:?}"),
                }
            }

            /// S58's driver: `read` must end on its own deadline, within the
            /// test's outer limit — a read with no bound fails here by message.
            async fn bounded<T>(site: &str, read: impl Future<Output = T>) -> (T, Duration) {
                let started = Instant::now();
                let output = tokio::time::timeout(OUTER_LIMIT, read)
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "{site}: the read must end on its own deadline; it was still waiting \
                             at the test's outer limit"
                        )
                    });
                let elapsed = started.elapsed();
                assert!(
                    elapsed >= LIMIT && elapsed < LIMIT + Duration::from_secs(3),
                    "{site}: ended after {elapsed:?} against a {LIMIT:?} deadline"
                );
                (output, elapsed)
            }

            /// A receipt with one empty block-number slot, for the backfill.
            fn unfilled() -> PaymentReceipt {
                PaymentReceipt {
                    blobs: Vec::new(),
                    tx_map: BTreeMap::new(),
                    txs: vec![TxRecord {
                        tx_hash: TxHash::from_bytes([0x5B; 32]),
                        block_number: None,
                        status: TxStatus::Submitted,
                        quote_hashes: Vec::new(),
                    }],
                    storage_cost_atto: 0,
                    gas: GasSummary { gas_cost_wei: 0 },
                }
            }

            // ── S57: no reason names the RPC URL ─────────────────────────

            #[tokio::test(flavor = "multi_thread")]
            async fn s57_the_chain_id_guard_names_no_url() {
                let stub = quiet("eth_chainId", Quiet::Drop);
                let provider = wallet_at(stub.url_at(CANARY)).to_provider().erased();
                let config = super::super::devnet_base();
                let reason = network_reason(
                    "chain_id_guard",
                    chain_id_guard(&provider, &config, LIMIT).await,
                );
                assert!(
                    reason.starts_with("payment RPC unreachable (eth_chainId): "),
                    "{reason}"
                );
                assert_no_url("chain_id_guard", &reason);
            }

            #[tokio::test(flavor = "multi_thread")]
            async fn s57_the_gas_price_read_names_no_url() {
                let stub = quiet("eth_gasPrice", Quiet::Drop);
                let provider = wallet_at(stub.url_at(CANARY)).to_provider().erased();
                let reason = network_reason("gas_price_wei", gas_price_wei(&provider, LIMIT).await);
                assert!(reason.starts_with("eth_gasPrice failed: "), "{reason}");
                assert_no_url("gas_price_wei", &reason);
            }

            #[tokio::test(flavor = "multi_thread")]
            async fn s57_the_gas_balance_read_names_no_url() {
                let stub = quiet("eth_getBalance", Quiet::Drop);
                let wallet = wallet_at(stub.url_at(CANARY));
                let reason = network_reason("gas_balance", gas_balance(&wallet, LIMIT).await);
                assert!(reason.starts_with("ETH balance query failed: "), "{reason}");
                assert_no_url("gas_balance", &reason);
            }

            /// The ANT balance and the allowance are ERC-20 calls that evmlib
            /// RETRIES — three times, 4, 16 and 36 s apart
            /// (`evmlib-0.9.0/src/contract/network_token.rs` `balance_of`,
            /// `allowance`; `retry.rs` `retry`) — so a refusing RPC's error
            /// reaches them only after ~56 s, past `BROADCAST_DEADLINE`: in
            /// production their reason is the deadline's. This row lets the
            /// error through on purpose (a 90 s limit; both reads at once, so
            /// it costs one ~56 s wait) to pin that the text is redacted when
            /// it does arrive.
            #[tokio::test(flavor = "multi_thread")]
            async fn s57_the_retried_erc20_reads_name_no_url() {
                let limit = Duration::from_secs(90);
                let stub = quiet("eth_call", Quiet::Drop);
                let wallet = wallet_at(stub.url_at(CANARY));
                let vault = vault_address(&wallet);
                let (ant, allowance) = tokio::time::timeout(Duration::from_secs(150), async {
                    tokio::join!(
                        ant_balance(&wallet, limit),
                        standing_allowance(&wallet, vault, limit)
                    )
                })
                .await
                .expect("evmlib's retries end well inside the limit");
                let reason = network_reason("ant_balance", ant);
                assert!(reason.starts_with("ANT balance query failed: "), "{reason}");
                assert_no_url("ant_balance", &reason);
                let reason = network_reason("standing_allowance", allowance);
                assert!(reason.starts_with("allowance query failed: "), "{reason}");
                assert_no_url("standing_allowance", &reason);
            }

            /// The approve's failure is pinned at its mapping, `approve_failure`,
            /// fed the text evmlib's approve fails with — a transport error,
            /// produced here against the canary stub, inside evmlib's own
            /// wrapping ("Transaction failed to send: gas estimation failed: …",
            /// `evmlib-0.9.0/src/retry.rs`). A live approve cannot pin it in a
            /// unit test: evmlib retries a failed send three times, 4, 16 and
            /// 36 s apart, and its error types are not reachable from here.
            #[tokio::test(flavor = "multi_thread")]
            async fn s57_a_failed_approve_names_no_url() {
                let stub = quiet("*", Quiet::Drop);
                let provider = wallet_at(stub.url_at(CANARY)).to_provider().erased();
                let transport = provider.get_gas_price().await.expect_err("dropped");
                let raw = format!("Transaction failed to send: gas estimation failed: {transport}");
                assert!(
                    raw.contains(CANARY),
                    "fixture: the raw text names the URL: {raw}"
                );
                let StorageError::Payment { reason } = approve_failure(&raw) else {
                    panic!("an approve that failed moved no ANT: Payment");
                };
                assert!(
                    reason.starts_with(
                        "token approve failed: Transaction failed to send: gas estimation failed: "
                    ),
                    "{reason}"
                );
                assert_no_url("approve_failure", &reason);
            }

            #[tokio::test(flavor = "multi_thread")]
            async fn s57_the_backfill_read_names_no_url() {
                let stub = quiet("eth_getTransactionReceipt", Quiet::Drop);
                let provider = wallet_at(stub.url_at(CANARY)).to_provider().erased();
                let mut receipt = unfilled();
                let reason = network_reason(
                    "fill_block_numbers",
                    fill_block_numbers(&provider, &mut receipt, LIMIT).await,
                );
                assert!(
                    reason.starts_with("eth_getTransactionReceipt failed: "),
                    "{reason}"
                );
                assert_no_url("fill_block_numbers", &reason);
                assert_eq!(receipt.txs[0].block_number, None, "the record is untouched");
            }

            // ── S58: every read ends on its own deadline, in its class ────

            #[tokio::test(flavor = "multi_thread")]
            async fn s58_the_chain_id_guard_is_bounded() {
                let stub = quiet("*", Quiet::Hang);
                let provider = wallet(&stub).to_provider().erased();
                let config = super::super::devnet_base();
                let (result, _) =
                    bounded("chain_id_guard", chain_id_guard(&provider, &config, LIMIT)).await;
                assert_eq!(
                    network_reason("chain_id_guard", result),
                    "payment RPC unreachable (eth_chainId): no answer within 300 ms"
                );
            }

            #[tokio::test(flavor = "multi_thread")]
            async fn s58_the_gas_price_read_is_bounded() {
                let stub = quiet("*", Quiet::Hang);
                let provider = wallet(&stub).to_provider().erased();
                let (result, _) = bounded("gas_price_wei", gas_price_wei(&provider, LIMIT)).await;
                assert_eq!(
                    network_reason("gas_price_wei", result),
                    "eth_gasPrice failed: no answer within 300 ms"
                );
            }

            #[tokio::test(flavor = "multi_thread")]
            async fn s58_the_balance_reads_are_bounded() {
                let stub = quiet("*", Quiet::Hang);
                let wallet = wallet(&stub);
                let (ant, _) = bounded("ant_balance", ant_balance(&wallet, LIMIT)).await;
                assert_eq!(
                    network_reason("ant_balance", ant),
                    "ANT balance query failed: no answer within 300 ms"
                );
                let (gas, _) = bounded("gas_balance", gas_balance(&wallet, LIMIT)).await;
                assert_eq!(
                    network_reason("gas_balance", gas),
                    "ETH balance query failed: no answer within 300 ms"
                );
            }

            #[tokio::test(flavor = "multi_thread")]
            async fn s58_the_allowance_read_is_bounded() {
                let stub = quiet("*", Quiet::Hang);
                let wallet = wallet(&stub);
                let vault = vault_address(&wallet);
                let (result, _) = bounded(
                    "standing_allowance",
                    standing_allowance(&wallet, vault, LIMIT),
                )
                .await;
                assert_eq!(
                    network_reason("standing_allowance", result),
                    "allowance query failed: no answer within 300 ms"
                );
            }

            /// The approve's gas read keeps its existing behaviour: unreadable
            /// in time counts 0.
            #[tokio::test(flavor = "multi_thread")]
            async fn s58_the_approve_gas_read_is_bounded() {
                let stub = quiet("*", Quiet::Hang);
                let provider = wallet(&stub).to_provider().erased();
                let (gas, _) = bounded(
                    "approve_gas_wei",
                    approve_gas_wei(&provider, alloy::primitives::B256::repeat_byte(0xA9), LIMIT),
                )
                .await;
                assert_eq!(gas, 0);
            }

            /// The backfill's read fails in its documented class — `status`'s
            /// host (U67) skips that silently — and leaves the record as it was.
            #[tokio::test(flavor = "multi_thread")]
            async fn s58_the_backfill_read_is_bounded() {
                let stub = quiet("*", Quiet::Hang);
                let provider = wallet(&stub).to_provider().erased();
                let mut receipt = unfilled();
                let (result, _) = bounded(
                    "fill_block_numbers",
                    fill_block_numbers(&provider, &mut receipt, LIMIT),
                )
                .await;
                assert_eq!(
                    network_reason("fill_block_numbers", result),
                    "eth_getTransactionReceipt failed: no answer within 300 ms"
                );
                assert_eq!(receipt.txs[0].block_number, None, "the record is untouched");
            }

            /// Finalize's proof-age read: a time that cannot be read in time is
            /// `None` — not expired (D179 R3) — on both of its reads.
            #[tokio::test(flavor = "multi_thread")]
            async fn s58_the_proof_age_reads_are_bounded() {
                let stub = quiet("*", Quiet::Hang);
                let provider = wallet(&stub).to_provider().erased();
                for (block_number, read) in
                    [(None, "the receipt read"), (Some(0x10), "the block read")]
                {
                    let paying = PayingTx {
                        tx_hash: TxHash::from_bytes([0x7E; 32]),
                        block_number,
                    };
                    let (time, _) = bounded(
                        &format!("paying_block_time_within, {read}"),
                        paying_block_time_within(&provider, paying, LIMIT),
                    )
                    .await;
                    assert_eq!(time, None, "{read}: unreadable in time is not expired");
                }
            }
        }
    }
}
