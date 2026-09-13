//! Real-devnet integration suite for the ant-core adapter (S6/S7/S8).
//!
//! # Gating (deliberate, two layers)
//!
//! 1. **Feature**: the whole file compiles only under the non-default
//!    `ant-backend` feature — default CI never builds it.
//! 2. **Environment**: every test SKIPS WITH A MESSAGE unless
//!    `ANTSEAL_DEVNET_ENV` points at a live devnet's run-scoped env
//!    export (and the exported launcher pid is alive). D52's scheduled
//!    lane and the S17 harness drive it; locally:
//!
//!    ```text
//!    scripts/devnet/local-up --nodes 14      # in the launcher checkout
//!    ANTSEAL_DEVNET_ENV=/path/to/.devnet/env \
//!        cargo test -p antseal-net --features ant-backend --test devnet_backend
//!    scripts/devnet/local-down
//!    ```
//!
//! The invocation is documented in docs/devnet/local-devnet.md
//! ("Consumers"). Every `local-up` mints fresh contracts/ports — the env
//! path is read per run, never cached.
//!
//! # Serialization
//!
//! Tests share one devnet but each stands up its own `Client` (an
//! in-process P2P node with ML-KEM/ML-DSA handshakes — heavy on the
//! 2-core reference host), so the whole file is serialized through a
//! process-global lock and kept to few, larger tests.

#![cfg(feature = "ant-backend")]

use std::sync::{Mutex, MutexGuard, OnceLock};

use antseal_core::crypto::secrets::SecretBuf;
use antseal_net::ant_backend::{AntCoreBackend, AntCoreReader};
use antseal_net::wallet::WalletKey;
use antseal_net::{
    Blob, BlobCost, DevnetEnv, NetworkConfig, PaymentReceipt, StorageBackend, StorageError,
};

/// Process-global serialization of devnet tests (module docs).
///
/// Deliberately a **std** mutex held across the test body's awaits
/// (`clippy::await_holding_lock` allowed per test): each `#[tokio::test]`
/// owns its own runtime, so a second test thread parking on this lock
/// blocks only itself — exactly the intended one-test-at-a-time behavior
/// — and no task inside a runtime ever waits on it twice (no deadlock
/// shape exists).
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The wallet key an arbitrum-sepolia devnet's export deliberately omits,
/// read from the process environment (U89; the recipe in
/// docs/devnet/sepolia-devnet.md).
///
/// Never printed, and never compared against — it goes straight into a
/// [`SecretBuf`] and from there into the export.
fn wallet_key_from_process_env() -> Option<SecretBuf> {
    let raw = std::env::var(antseal_net::network::devnet_keys::WALLET_PRIVATE_KEY).ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    Some(SecretBuf::new(raw.into_bytes()))
}

/// The env gate: `Some((config, env))` when a live devnet is exported,
/// `None` (after printing the skip message) otherwise.
fn devnet() -> Option<(NetworkConfig, DevnetEnv)> {
    let Some(path) = std::env::var_os("ANTSEAL_DEVNET_ENV") else {
        eprintln!(
            "SKIP: ANTSEAL_DEVNET_ENV is not set — point it at a live devnet's .devnet/env \
             (scripts/devnet/local-up) to run the real-backend suite"
        );
        return None;
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!(
                "SKIP: ANTSEAL_DEVNET_ENV={} is not readable ({error}) — is the devnet up?",
                path.to_string_lossy()
            );
            return None;
        }
    };
    // U89: the OPTIONAL-wallet parse. `from_env_file` demands all ten keys,
    // so P22's nine-key arbitrum-sepolia export used to land in the arm
    // below and be reported as "stale or partial" — a false statement about
    // a complete and correct export.
    let env = match DevnetEnv::<Option<SecretBuf>>::from_env_file_optional_wallet(&text) {
        Ok(env) => env,
        Err(error) => {
            eprintln!("SKIP: devnet env export did not parse ({error}) — stale or partial export?");
            return None;
        }
    };
    // This suite PAYS, so it needs a funded key whatever the mode. Ten keys
    // is the local devnet and nothing changes; nine is arbitrum-sepolia,
    // whose key is real key material and is never written to a file, so the
    // documented recipe supplies it through the process environment
    // (docs/devnet/sepolia-devnet.md). If neither, the skip names the key
    // and the mode instead of calling the devnet absent.
    let env: DevnetEnv = if env.wallet_private_key().is_some() {
        match env.require_wallet() {
            Ok(env) => env,
            // Structurally unreachable (the slot is `Some` on this arm).
            // Reported rather than unwrapped: no panic path in a gate.
            Err(error) => {
                eprintln!("SKIP: the export's wallet slot disagreed with itself ({error})");
                return None;
            }
        }
    } else if let Some(key) = wallet_key_from_process_env() {
        env.with_wallet(key)
    } else {
        eprintln!(
            "SKIP: the devnet export at {} carries no {} — the designed shape of an \
             arbitrum-sepolia devnet (this export names chain {}), whose key is real key \
             material and is never written to a file. This suite pays, so export {} with a \
             key funded on that chain (docs/devnet/sepolia-devnet.md) to run it.",
            path.to_string_lossy(),
            antseal_net::network::devnet_keys::WALLET_PRIVATE_KEY,
            env.chain_id(),
            antseal_net::network::devnet_keys::WALLET_PRIVATE_KEY,
        );
        return None;
    };
    // Stale-export guard: the launcher pid IS the devnet's lifetime
    // handle (runbook, "Lifecycle").
    let proc_path = format!("/proc/{}", env.pid());
    if !std::path::Path::new(&proc_path).exists() {
        eprintln!(
            "SKIP: the exported devnet launcher pid {} is not alive — re-run \
             scripts/devnet/local-up and re-point ANTSEAL_DEVNET_ENV",
            env.pid()
        );
        return None;
    }
    let config = NetworkConfig::devnet(&env);
    Some((config, env))
}

/// The funded dev wallet from the run-scoped export (Anvil account 0 —
/// a well-known public constant; still handled as key-shaped material).
fn funded_key(env: &DevnetEnv) -> WalletKey {
    WalletKey::import(env.wallet_private_key()).expect("devnet export carries a valid funded key")
}

/// Fresh test blobs per invocation: chunks persist for a devnet run's
/// lifetime, and one devnet may serve several suite invocations (a
/// re-run against the same `local-up` must not find its "fresh" blobs
/// already stored), so the seed mixes the devnet identity with this
/// process id and a nanosecond stamp. Tests that WANT an already-stored
/// blob re-use a `Blob` value, never this generator.
fn test_blobs(env: &DevnetEnv, label: &str, sizes: &[usize]) -> Vec<Blob> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    sizes
        .iter()
        .enumerate()
        .map(|(index, &size)| {
            let mut bytes = Vec::with_capacity(size.max(8));
            let seed = format!(
                "{}:{}:{}:{}:{}:{}",
                env.base_port(),
                env.pid(),
                std::process::id(),
                stamp,
                label,
                index
            );
            let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
            for b in seed.bytes() {
                acc = (acc ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
            }
            for i in 0..size.max(8) {
                acc = (acc ^ (i as u64)).wrapping_mul(0x0000_0100_0000_01b3);
                bytes.push((acc >> 32) as u8);
            }
            Blob::new(bytes).expect("test blob under cap")
        })
        .collect()
}

/// The wallet's confirmed tx count (nonce) — the "no new payment"
/// witness: any further payment or approve from this wallet bumps it.
async fn wallet_nonce(backend: &AntCoreBackend, env: &DevnetEnv) -> u64 {
    use alloy::providers::Provider;
    let key = funded_key(env);
    let address = alloy::primitives::Address::from(*key.address().as_bytes());
    // Reuse the backend's provider indirectly: any provider works; build
    // one against the same RPC via the wallet (read-only call).
    let wallet = key
        .evm_wallet(backend.network_config())
        .expect("wallet builds");
    wallet
        .to_provider()
        .get_transaction_count(address)
        .await
        .expect("nonce query")
}

// ===========================================================================
// S6 — quote → pay → finalize → get_data on the real devnet
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::await_holding_lock)] // deliberate whole-test serialization; see `serial`
async fn devnet_s6_round_trip_idempotency_and_zero_cost_lines() {
    let _serial = serial();
    let Some((config, env)) = devnet() else {
        return;
    };
    let key = funded_key(&env);
    let backend = AntCoreBackend::connect(&config, &key)
        .await
        .expect("backend connects to the live devnet");

    // ── Seal 1: a 3-blob batch round-trips ────────────────────────────
    let batch = test_blobs(&env, "s6-batch", &[272, 4_096, 40_000]);
    let quote = backend.quote_batch(&batch).await.expect("quote");
    assert_eq!(quote.blobs.len(), 3);
    for line in &quote.blobs {
        assert!(
            matches!(line.cost, BlobCost::Priced { .. }),
            "fresh blobs are priced"
        );
    }
    assert!(quote.total_ant_atto > 0, "devnet quotes are non-zero");
    assert!(quote.gas_estimate_wei > 0);

    // Addresses in the quote equal S4's WASM-safe recomputation.
    for (blob, line) in batch.iter().zip(&quote.blobs) {
        let s4 =
            antseal_core::storage::compute_storage_address(blob.as_bytes()).expect("under cap");
        assert_eq!(line.address, antseal_net::Address::from(s4));
    }

    let receipt = backend.pay(&quote).await.expect("pay");
    assert_eq!(receipt.txs.len(), 1, "3 transfers fit one sub-batch");
    assert_eq!(receipt.tx_map.len(), 3, "one non-zero quote per blob");
    assert!(receipt.covers_all_paid_quotes());
    assert_eq!(receipt.storage_cost_atto, quote.total_ant_atto);
    for tx in &receipt.txs {
        assert!(
            tx.block_number.is_some(),
            "block number captured from the awaited receipt (D33)"
        );
    }
    assert!(receipt.gas.gas_cost_wei > 0, "real gas was paid");

    let addresses = backend
        .finalize_batch(&receipt, &batch)
        .await
        .expect("finalize");
    assert_eq!(addresses.len(), 3);
    for (blob, address) in batch.iter().zip(&addresses) {
        let s4 =
            antseal_core::storage::compute_storage_address(blob.as_bytes()).expect("under cap");
        assert_eq!(
            *address,
            antseal_net::Address::from(s4),
            "S6 accept: finalize addresses == S4"
        );
        let fetched = backend
            .get_data(*address)
            .await
            .expect("stored chunk serves");
        assert_eq!(fetched, blob.as_bytes(), "byte-identical round trip");
    }

    // ── Idempotency: re-finalize issues ZERO new payment ──────────────
    let nonce_before = wallet_nonce(&backend, &env).await;
    let again = backend
        .finalize_batch(&receipt, &batch)
        .await
        .expect("re-finalize");
    assert_eq!(again, addresses, "same address vector");
    let nonce_after = wallet_nonce(&backend, &env).await;
    assert_eq!(
        nonce_before, nonce_after,
        "re-finalize moved no money (wallet tx count unchanged)"
    );

    // ── Already-stored: re-quoting a stored blob is a zero-cost line ──
    let mut second = test_blobs(&env, "s6-second", &[300]);
    second.insert(0, batch[0].clone());
    let requote = backend.quote_batch(&second).await.expect("re-quote");
    assert!(
        matches!(requote.blobs[0].cost, BlobCost::AlreadyStored),
        "stored blob quotes as the zero-cost already-stored line"
    );
    assert!(matches!(requote.blobs[1].cost, BlobCost::Priced { .. }));
    let receipt2 = backend.pay(&requote).await.expect("pay 2");
    assert_eq!(
        receipt2.blobs.len(),
        1,
        "no payment record for the already-stored blob"
    );
    let addresses2 = backend
        .finalize_batch(&receipt2, &second)
        .await
        .expect("finalize 2");
    assert_eq!(addresses2[0], addresses[0]);
    let fetched = backend.get_data(addresses2[1]).await.expect("serves");
    assert_eq!(fetched, second[1].as_bytes());

    // ── get_data: missing address is NotFound, not Network ────────────
    let missing = antseal_net::Address::from_bytes([0x5A; 32]);
    let err = backend.get_data(missing).await.expect_err("nothing there");
    assert_eq!(err, StorageError::NotFound { address: missing });

    // ── D36: a journaled/stale quote is never paid ────────────────────
    // `quote` was already consumed by `pay`; paying it again must be the
    // typed staleness rejection, with no transaction.
    let nonce_before = wallet_nonce(&backend, &env).await;
    let err = backend.pay(&quote).await.expect_err("stale quote refused");
    assert!(
        matches!(err, StorageError::Payment { .. }),
        "stale-quote rejection is Payment-class: {err:?}"
    );
    assert_eq!(
        wallet_nonce(&backend, &env).await,
        nonce_before,
        "no transaction for a refused quote"
    );
}

// ===========================================================================
// S7 — receipt completeness, capture consistency, multi-sub-batch, backfill
// ===========================================================================

/// The S7 completeness checklist (accept row 1): every element class the
/// spec's receipt requires (MVP-SPEC.md lines 69/110; D37 Decision 4) is
/// populated on a receipt from a REAL devnet pay.
fn assert_receipt_complete(receipt: &PaymentReceipt) {
    assert!(!receipt.blobs.is_empty(), "per-blob records exist");
    for record in &receipt.blobs {
        // Element class: per-blob triple {address, preimages, proof_bytes}.
        assert!(!record.payments.is_empty(), "payment ledger lines");
        assert!(
            record.payments.iter().any(|line| line.amount_atto > 0),
            "one non-zero (median-paid) line per blob"
        );
        assert!(
            !record.peer_quotes.is_empty(),
            "full signed quote preimages"
        );
        for peer_quote in &record.peer_quotes {
            assert!(!peer_quote.quote.node_pub_key.is_empty(), "node key");
            assert!(!peer_quote.quote.node_signature.is_empty(), "node sig");
            assert!(peer_quote.quote.timestamp_unix_secs > 0, "quote timestamp");
        }
        assert!(!record.proof_bytes.is_empty(), "store-ready proof bytes");
    }
    // Element class: the quote→tx map, complete over non-zero lines.
    assert!(
        receipt.covers_all_paid_quotes(),
        "map covers every paid quote"
    );
    // Element class: tx hashes + block-number slots, filled at capture.
    assert!(!receipt.txs.is_empty(), "per-tx records exist");
    for tx in &receipt.txs {
        assert_eq!(tx.status, antseal_net::TxStatus::Confirmed);
        assert!(
            tx.block_number.is_some(),
            "block number from the awaited receipt"
        );
        assert!(!tx.quote_hashes.is_empty(), "sub-batch membership recorded");
    }
    assert!(receipt.storage_cost_atto > 0);
    assert!(receipt.gas.gas_cost_wei > 0);
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::await_holding_lock)] // deliberate whole-test serialization; see `serial`
async fn devnet_s7_completeness_capture_consistency_and_backfill() {
    let _serial = serial();
    let Some((config, env)) = devnet() else {
        return;
    };
    let key = funded_key(&env);
    let backend = AntCoreBackend::connect(&config, &key)
        .await
        .expect("backend connects");

    let batch = test_blobs(&env, "s7-capture", &[512, 2_048]);
    let quote = backend.quote_batch(&batch).await.expect("quote");
    let receipt = backend.pay(&quote).await.expect("pay");

    // ── Completeness checklist after a real devnet pay ────────────────
    assert_receipt_complete(&receipt);

    // ── Capture consistency (S7 accept; D37 residual risk 2): the
    //    journaled proof_bytes parse via UPSTREAM's own deserializer and
    //    agree with the flat fields — captured bytes ARE the bytes
    //    finalize needs, not a lookalike. ──────────────────────────────
    for record in &receipt.blobs {
        assert_eq!(
            ant_protocol::detect_proof_type(&record.proof_bytes),
            Some(ant_protocol::ProofType::SingleNode),
            "single-node proof tag (0x01)"
        );
        let parsed =
            ant_protocol::payment::proof::deserialize_single_node_proof(&record.proof_bytes)
                .expect("upstream deserializer accepts the journaled bytes");

        // Flat tx hashes == parsed tx hashes (order: the blob's non-zero
        // lines in ledger order, exactly as upstream builds them).
        let expected_hashes: Vec<[u8; 32]> = record
            .payments
            .iter()
            .filter(|line| line.amount_atto > 0)
            .map(|line| {
                receipt
                    .tx_map
                    .get(&line.quote_hash)
                    .map(|tx| *tx.as_bytes())
                    .expect("covered by the map")
            })
            .collect();
        let parsed_hashes: Vec<[u8; 32]> = parsed.tx_hashes.iter().map(|hash| hash.0).collect();
        assert_eq!(
            parsed_hashes, expected_hashes,
            "flat tx hashes == proof tx hashes"
        );

        // Flat preimages == parsed preimages, field for field.
        assert_eq!(
            parsed.proof_of_payment.peer_quotes.len(),
            record.peer_quotes.len()
        );
        for (flat, (peer_id, quote)) in record
            .peer_quotes
            .iter()
            .zip(&parsed.proof_of_payment.peer_quotes)
        {
            assert_eq!(flat.peer_id.as_bytes(), peer_id.as_bytes());
            assert_eq!(flat.quote.content.as_bytes(), &quote.content.0);
            let parsed_secs = quote
                .timestamp
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            assert_eq!(flat.quote.timestamp_unix_secs, parsed_secs);
            assert_eq!(
                alloy::primitives::U256::from(flat.quote.price_atto),
                quote.price
            );
            assert_eq!(
                flat.quote.rewards_address.as_bytes(),
                &quote.rewards_address.0.0
            );
            assert_eq!(flat.quote.node_pub_key, quote.pub_key);
            assert_eq!(flat.quote.node_signature, quote.signature);
            assert_eq!(flat.quote.committed_key_count, quote.committed_key_count);
            assert_eq!(flat.quote.commitment_pin, quote.commitment_pin);
        }

        // Sidecars travel verbatim.
        assert_eq!(parsed.commitment_sidecars, record.commitment_sidecars);
    }

    // ── Enrichment-failure path (S7 accept): strip the block numbers —
    //    the journaled shape after a receipt-await interruption — then
    //    backfill idempotently with NO new payment. ────────────────────
    let mut stripped = receipt.clone();
    for tx in &mut stripped.txs {
        tx.block_number = None;
        tx.status = antseal_net::TxStatus::Submitted;
    }
    let nonce_before = wallet_nonce(&backend, &env).await;
    let filled = backend
        .backfill_block_numbers(&mut stripped)
        .await
        .expect("backfill");
    assert_eq!(filled, receipt.txs.len(), "every stripped slot refilled");
    assert_eq!(
        stripped, receipt,
        "backfill restored the captured values exactly"
    );
    // Idempotent: a second run fills nothing and changes nothing.
    let refilled = backend
        .backfill_block_numbers(&mut stripped)
        .await
        .expect("backfill again");
    assert_eq!(refilled, 0);
    assert_eq!(stripped, receipt);
    assert_eq!(
        wallet_nonce(&backend, &env).await,
        nonce_before,
        "backfill performed no payment"
    );

    // The paid batch still finalizes with the backfilled receipt.
    let addresses = backend
        .finalize_batch(&stripped, &batch)
        .await
        .expect("finalize with backfilled receipt");
    assert_eq!(addresses.len(), 2);
}

// ===========================================================================
// S8 — balances, preflight, distinct shortfalls, paid ≤ quoted
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::await_holding_lock)] // deliberate whole-test serialization; see `serial`
async fn devnet_s8_balances_preflight_distinct_shortfalls_and_paid_within_quote() {
    use alloy::primitives::U256;

    let _serial = serial();
    let Some((config, env)) = devnet() else {
        return;
    };
    let key = funded_key(&env);
    let backend = AntCoreBackend::connect(&config, &key)
        .await
        .expect("funded backend connects");
    let dev_wallet = key.evm_wallet(&config).expect("dev wallet builds");

    // ── Balances: the funded dev wallet reports both assets ──────────
    let balances = backend.balances().await.expect("balance query");
    assert_eq!(balances.wallet, key.address(), "reports THIS wallet");
    assert!(balances.ant_atto > 0, "premined ANT visible");
    assert!(balances.gas_wei > 0, "Anvil ETH visible");

    // ── True-complete quote + passing preflight ──────────────────────
    let batch = test_blobs(&env, "s8-seal", &[600, 1_200]);
    let quote = backend.quote_batch(&batch).await.expect("quote");
    assert_eq!(
        quote.blobs.len(),
        batch.len(),
        "the quote covers exactly the handed-in blob set (S8 completeness)"
    );
    let report = backend.preflight(&quote).await.expect("preflight passes");
    assert_eq!(report.required_ant_atto, quote.total_ant_atto);
    assert_eq!(report.required_gas_wei, quote.gas_estimate_wei);
    assert_eq!(report.available_ant_atto, balances.ant_atto);
    assert_eq!(report.available_gas_wei, balances.gas_wei);

    // ── Preflight-passed seal completes with paid ≤ quoted, asserted
    //    via Anvil balance deltas ───────────────────────────────────────
    let ant_before = dev_wallet.balance_of_tokens().await.expect("ANT before");
    let eth_before = dev_wallet
        .balance_of_gas_tokens()
        .await
        .expect("ETH before");
    let receipt = backend.pay(&quote).await.expect("pay");
    let addresses = backend
        .finalize_batch(&receipt, &batch)
        .await
        .expect("finalize");
    assert_eq!(addresses.len(), batch.len());
    let ant_after = dev_wallet.balance_of_tokens().await.expect("ANT after");
    let eth_after = dev_wallet.balance_of_gas_tokens().await.expect("ETH after");

    let ant_paid = ant_before - ant_after;
    assert_eq!(
        ant_paid,
        U256::from(receipt.storage_cost_atto),
        "on-chain ANT delta equals the receipt's storage cost"
    );
    assert!(
        ant_paid <= U256::from(quote.total_ant_atto),
        "paid ANT ≤ quoted ANT"
    );
    let eth_paid = eth_before - eth_after;
    assert_eq!(
        eth_paid,
        U256::from(receipt.gas.gas_cost_wei),
        "on-chain ETH delta equals the receipt's gas summary (approve + payment txs)"
    );
    assert!(
        eth_paid <= U256::from(quote.gas_estimate_wei),
        "actual gas ≤ the quote-time estimate (paid {eth_paid} vs estimate {})",
        quote.gas_estimate_wei
    );

    // ── InsufficientAnt: a fresh wallet holding ETH but NO ANT ───────
    // (funding-by-construction — the same below-requirement state the
    // entry's "drain" wording targets, without mutating the shared dev
    // wallet other tests depend on.)
    let ant_less = WalletKey::generate().expect("keygen");
    dev_wallet
        .transfer_gas_tokens(
            alloy::primitives::Address::from(*ant_less.address().as_bytes()),
            U256::from(10u128.pow(17)), // 0.1 ETH — plenty of gas, zero ANT
        )
        .await
        .expect("fund gas");
    let ant_less_backend = AntCoreBackend::connect(&config, &ant_less)
        .await
        .expect("ANT-less backend connects");
    let poor_quote = ant_less_backend
        .quote_batch(&test_blobs(&env, "s8-antless", &[500]))
        .await
        .expect("quoting needs no balance");
    let err = ant_less_backend
        .preflight(&poor_quote)
        .await
        .expect_err("ANT shortfall");
    match &err {
        StorageError::InsufficientAnt {
            required_atto,
            available_atto,
        } => {
            assert_eq!(*required_atto, poor_quote.total_ant_atto);
            assert_eq!(*available_atto, 0, "no ANT was ever sent to this wallet");
        }
        other => panic!("expected InsufficientAnt, got {other:?}"),
    }
    // Actionable, hash-free, key-free message.
    let message = err.to_string();
    assert!(message.contains("insufficient ANT"), "{message}");
    assert!(!message.contains("0x"), "no hex material: {message}");
    // pay() refuses identically, BEFORE any transaction (S8 guarantee:
    // no post-consent payment beyond the quote — even a skipped
    // preflight cannot move money it cannot cover).
    let nonce_before = wallet_nonce(&ant_less_backend, &env).await;
    let pay_err = ant_less_backend
        .pay(&poor_quote)
        .await
        .expect_err("pay refuses the same way");
    assert!(matches!(pay_err, StorageError::InsufficientAnt { .. }));
    assert_eq!(
        wallet_nonce(&ant_less_backend, &env).await,
        nonce_before,
        "no transaction was submitted"
    );

    // ── InsufficientGas: a fresh wallet holding ANT but NO ETH ───────
    let gas_less = WalletKey::generate().expect("keygen");
    dev_wallet
        .transfer_tokens(
            alloy::primitives::Address::from(*gas_less.address().as_bytes()),
            U256::from(10u128.pow(18)), // 1 ANT — plenty of storage budget
        )
        .await
        .expect("fund ANT");
    let gas_less_backend = AntCoreBackend::connect(&config, &gas_less)
        .await
        .expect("gas-less backend connects");
    let gasless_quote = gas_less_backend
        .quote_batch(&test_blobs(&env, "s8-gasless", &[500]))
        .await
        .expect("quoting needs no balance");
    let err = gas_less_backend
        .preflight(&gasless_quote)
        .await
        .expect_err("gas shortfall");
    match &err {
        StorageError::InsufficientGas {
            required_wei,
            available_wei,
        } => {
            assert_eq!(*required_wei, gasless_quote.gas_estimate_wei);
            assert_eq!(*available_wei, 0, "no ETH was ever sent to this wallet");
        }
        other => panic!("expected InsufficientGas, got {other:?}"),
    }
    let message = err.to_string();
    assert!(message.contains("insufficient gas"), "{message}");
    assert!(!message.contains("0x"), "no hex material: {message}");

    // The two shortfalls are distinct BY TYPE (S8 accept) — the ANT-less
    // wallet with gas reports ANT, the gas-less wallet with ANT reports
    // gas; neither is a string comparison.
    assert!(matches!(pay_err, StorageError::InsufficientAnt { .. }));
    assert!(matches!(err, StorageError::InsufficientGas { .. }));
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::await_holding_lock)] // deliberate whole-test serialization; see `serial`
async fn devnet_s7_multi_sub_batch_sequential_txs_with_capture_hook() {
    let _serial = serial();
    let Some((config, env)) = devnet() else {
        return;
    };
    let key = funded_key(&env);

    // The capture hook records every cumulative receipt it is handed —
    // the journal-write seam (the write itself is S10/S12's).
    let captured: std::sync::Arc<Mutex<Vec<PaymentReceipt>>> =
        std::sync::Arc::new(Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&captured);
    let backend = AntCoreBackend::connect(&config, &key)
        .await
        .expect("backend connects")
        // The sanctioned test seam (mirrors the mock's): cap 2 ⇒ 5 blobs
        // pay as 3 REAL sequential EVM txs.
        .with_max_transfers_per_tx(2)
        .with_capture_hook(std::sync::Arc::new(move |receipt: &PaymentReceipt| {
            sink.lock()
                .expect("capture sink lock")
                .push(receipt.clone());
        }));

    let batch = test_blobs(&env, "s7-multitx", &[64, 128, 256, 512, 1_024]);
    let quote = backend.quote_batch(&batch).await.expect("quote");
    let nonce_before = wallet_nonce(&backend, &env).await;
    let receipt = backend.pay(&quote).await.expect("pay");

    // ≥ 2 sub-batches, sequential, every quote mapped (S6/S7 accept).
    assert_eq!(receipt.txs.len(), 3, "ceil(5 transfers / cap 2)");
    let sizes: Vec<usize> = receipt.txs.iter().map(|tx| tx.quote_hashes.len()).collect();
    assert_eq!(sizes, vec![2, 2, 1], "sub-batches partition in order");
    assert_eq!(receipt.tx_map.len(), 5, "every quote mapped to a tx");
    assert!(receipt.covers_all_paid_quotes());
    let distinct: std::collections::BTreeSet<_> = receipt
        .txs
        .iter()
        .map(|tx| *tx.tx_hash.as_bytes())
        .collect();
    assert_eq!(distinct.len(), 3, "three distinct on-chain txs");
    // Sequential landings: block numbers monotonically non-decreasing,
    // and 3 payment txs + 1 approve really hit the chain.
    let blocks: Vec<u64> = receipt
        .txs
        .iter()
        .map(|tx| tx.block_number.expect("captured"))
        .collect();
    assert!(
        blocks.windows(2).all(|w| w[0] <= w[1]),
        "submission order: {blocks:?}"
    );
    assert_eq!(
        wallet_nonce(&backend, &env).await,
        nonce_before + 4,
        "exact-allowance approve + 3 sequential sub-batch txs"
    );

    // Hook timing (D37 Decision 2): one cumulative capture per landing,
    // strictly ordered — payload k carries exactly k tx records, each a
    // prefix of the final sequence — and the LAST payload equals the
    // returned receipt (instant-capture: the value is complete the
    // moment pay returns).
    let captures = captured.lock().expect("capture sink lock");
    assert_eq!(captures.len(), 3, "one capture per sub-batch landing");
    for (index, capture) in captures.iter().enumerate() {
        assert_eq!(capture.txs.len(), index + 1, "cumulative tx records");
        assert_eq!(
            capture.txs[..],
            receipt.txs[..=index],
            "capture {index} is a prefix of the final tx sequence"
        );
        assert!(
            capture.covers_all_paid_quotes(),
            "every capture is internally finalize-consistent"
        );
        // Blobs whose sub-batch has landed carry store-ready proofs:
        // sub-batches partition the 5 blobs as 2 + 2 + 1.
        assert_eq!(capture.blobs.len(), [2, 4, 5][index]);
    }
    assert_eq!(*captures.last().expect("nonempty"), receipt);
    drop(captures);

    // The multi-tx receipt finalizes and serves.
    let addresses = backend
        .finalize_batch(&receipt, &batch)
        .await
        .expect("finalize");
    for (blob, address) in batch.iter().zip(&addresses) {
        assert_eq!(
            backend.get_data(*address).await.expect("serves"),
            blob.as_bytes()
        );
    }
}

// ===========================================================================
// S15 — the `--live` persistence primitive against the real network
// ===========================================================================

/// S15 accept row 1, on a live devnet: freshly sealed blobs report
/// present-and-identical, a never-uploaded address reports not-found, and
/// a corrupted expectation reports present-but-different — through the
/// same `check_persistence` the mock tests drive (the primitive rides
/// `StorageBackend` only, so this file exercises the *other* impl of the
/// same trait, not other code).
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::await_holding_lock)] // deliberate whole-test serialization; see `serial`
async fn devnet_s15_live_persistence_identical_missing_and_different() {
    let _serial = serial();
    let Some((config, env)) = devnet() else {
        return;
    };
    let key = funded_key(&env);
    let backend = AntCoreBackend::connect(&config, &key)
        .await
        .expect("backend connects to the live devnet");

    // Seal three blobs for real (quote → pay → finalize).
    let batch = test_blobs(&env, "s15-live", &[272, 4_096, 40_000]);
    let quote = backend.quote_batch(&batch).await.expect("quote");
    let receipt = backend.pay(&quote).await.expect("pay");
    let addresses = backend
        .finalize_batch(&receipt, &batch)
        .await
        .expect("finalize");

    // ── present-and-identical, for every sealed blob ──────────────────
    let expected: Vec<(antseal_net::Address, &[u8])> = addresses
        .iter()
        .copied()
        .zip(batch.iter().map(antseal_net::Blob::as_bytes))
        .collect();
    let report = antseal_net::check_persistence(&backend, &expected).await;
    assert!(
        report.all_identical(),
        "freshly sealed blobs are present and identical: {report:?}"
    );
    assert_eq!(report.summary().identical, 3);
    assert_eq!(report.fetches, 3, "one get_data per distinct address");

    // ── not-found: an address nothing was ever uploaded to ────────────
    // Content-addressed, so an address no ciphertext hashes to cannot
    // hold anything: the network answers negatively.
    let never = antseal_net::Address::from_bytes([0xA5; 32]);
    let report =
        antseal_net::check_persistence(&backend, &[(never, b"never-sealed".as_slice())]).await;
    assert_eq!(
        report.blobs[0].outcome,
        antseal_net::PersistenceOutcome::NotFound,
        "a never-uploaded address is not-found, not a fetch error"
    );

    // ── present-but-different: a corrupted expectation ────────────────
    let mut corrupted = batch[0].as_bytes().to_vec();
    corrupted[0] ^= 0xFF;
    let report =
        antseal_net::check_persistence(&backend, &[(addresses[0], corrupted.as_slice())]).await;
    assert_eq!(
        report.blobs[0].outcome,
        antseal_net::PersistenceOutcome::Different {
            fetched_len: batch[0].len() as u64,
            first_diff_offset: 0,
        },
        "the network's real bytes vs a corrupted expectation"
    );
    assert!(!report.all_identical());

    // ── mixed report: rows survive each other ─────────────────────────
    let mixed: Vec<(antseal_net::Address, &[u8])> = vec![
        (addresses[0], batch[0].as_bytes()),
        (never, b"never-sealed".as_slice()),
        (addresses[1], batch[1].as_bytes()),
        (addresses[2], corrupted.as_slice()),
    ];
    let report = antseal_net::check_persistence(&backend, &mixed).await;
    let summary = report.summary();
    assert_eq!(summary.total, 4);
    assert_eq!(summary.identical, 2);
    assert_eq!(summary.not_found, 1);
    assert_eq!(summary.different, 1);
    assert_eq!(summary.fetch_error, 0);
    assert_eq!(
        summary.identical + summary.different + summary.not_found + summary.fetch_error,
        summary.total
    );
}

// ===========================================================================
// S9 — the size ladder on the real network
// ===========================================================================

/// The S9 size ladder, stored for real: 272 B (smallest padded-unit
/// ciphertext) / 65 552 B (mid) / 4 194 064 B (the largest ciphertext a
/// real unit plaintext can produce) / 4 194 304 B (the exact chunk cap).
///
/// The offline half of S9 — the cap's linkage to `ant_protocol`, the
/// max-plaintext derivation, the padding/tag constants, the two over-cap
/// refusals — is `tests/storage_constants.rs`. This is the half that needs
/// a network: **the addresses ant-core itself assigns must byte-match
/// S4's WASM-safe recomputation at every rung**, and every rung must come
/// back byte-identical.
const S9_LADDER: [(&str, usize); 4] = [
    ("min-unit-ciphertext", 272),
    ("mid", 65_552),
    ("max-plaintext-derived", 4_194_064),
    ("cap-edge", 4_194_304),
];

/// Address-equality with a failure that NAMES THE SIZE CLASS (S9 accept
/// row 4): a divergence between S4's rule and the real network must not
/// read as a generic assert_eq.
fn assert_address_matches(
    class: &str,
    size: usize,
    stage: &str,
    from_network: antseal_net::Address,
    blob_bytes: &[u8],
) {
    let s4 = antseal_core::storage::compute_storage_address(blob_bytes)
        .expect("ladder rungs are under the cap");
    let s4 = antseal_net::Address::from(s4);
    assert_eq!(
        from_network, s4,
        "ADDRESS DIVERGENCE in size class `{class}` ({size} B) at {stage}: the network assigned \
         {from_network} but S4's BLAKE3-256 recomputation says {s4}. The chunk-address rule \
         (D32/D11 — blake3 of the ciphertext, ant-protocol-2.3.0/src/chunk.rs:43) no longer \
         matches the pinned upstream; this is a deliberate-bump event (S20), never a drive-by."
    );
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::await_holding_lock)] // deliberate whole-test serialization; see `serial`
async fn devnet_s9_size_ladder_addresses_and_byte_identity() {
    let _serial = serial();
    let Some((config, env)) = devnet() else {
        return;
    };
    let key = funded_key(&env);
    let backend = AntCoreBackend::connect(&config, &key)
        .await
        .expect("backend connects to the live devnet");

    let sizes: Vec<usize> = S9_LADDER.iter().map(|(_, size)| *size).collect();
    let batch = test_blobs(&env, "s9-ladder", &sizes);
    for ((class, size), blob) in S9_LADDER.iter().zip(&batch) {
        assert_eq!(blob.len(), *size, "rung `{class}` is exactly {size} B");
    }

    // ── quote: the addresses upstream computes, at every rung ─────────
    let started = std::time::Instant::now();
    let quote = backend.quote_batch(&batch).await.expect("quote the ladder");
    let quote_elapsed = started.elapsed();
    assert_eq!(quote.blobs.len(), S9_LADDER.len());
    for (((class, size), line), blob) in S9_LADDER.iter().zip(&quote.blobs).zip(&batch) {
        assert_address_matches(class, *size, "quote", line.address, blob.as_bytes());
    }

    // ── pay: 4 transfers fit one sub-batch (upstream cap 256) ─────────
    let started = std::time::Instant::now();
    let receipt = backend.pay(&quote).await.expect("pay the ladder");
    let pay_elapsed = started.elapsed();
    assert_eq!(receipt.txs.len(), 1, "4 transfers ⇒ one EVM tx (D37)");

    // ── finalize: the addresses the network assigns on store ──────────
    let started = std::time::Instant::now();
    let addresses = backend
        .finalize_batch(&receipt, &batch)
        .await
        .expect("finalize the ladder");
    let finalize_elapsed = started.elapsed();
    assert_eq!(addresses.len(), S9_LADDER.len());
    for (((class, size), address), blob) in S9_LADDER.iter().zip(&addresses).zip(&batch) {
        assert_address_matches(class, *size, "finalize", *address, blob.as_bytes());
    }

    // ── get_data: byte-identity at every rung ─────────────────────────
    let started = std::time::Instant::now();
    for (((class, size), address), blob) in S9_LADDER.iter().zip(&addresses).zip(&batch) {
        let fetched = backend
            .get_data(*address)
            .await
            .unwrap_or_else(|error| panic!("rung `{class}` ({size} B) must serve: {error}"));
        assert_eq!(
            fetched.len(),
            blob.len(),
            "rung `{class}` ({size} B) came back the wrong length"
        );
        assert!(
            fetched == blob.as_bytes(),
            "rung `{class}` ({size} B) is not byte-identical on re-fetch"
        );
    }
    let fetch_elapsed = started.elapsed();

    // ── cap + 1 never reaches the network ─────────────────────────────
    // Structurally, not by observation: the value cannot be constructed,
    // so no backend call can be written that carries it. The wallet nonce
    // witnesses that the attempt moved nothing.
    let nonce_before = wallet_nonce(&backend, &env).await;
    let over_cap = vec![0u8; antseal_net::MAX_CHUNK_SIZE + 1];
    let refused = antseal_net::Blob::new(over_cap).expect_err("cap + 1 is not a blob");
    assert_eq!(refused.len, antseal_net::MAX_CHUNK_SIZE + 1);
    assert_eq!(
        wallet_nonce(&backend, &env).await,
        nonce_before,
        "a refused over-cap blob moves nothing"
    );

    // Live evidence for the S9 report.
    eprintln!(
        "S9 ladder: rungs {:?} | quote {:?} | pay {:?} ({} tx) | finalize {:?} | fetch {:?}",
        S9_LADDER.map(|(_, size)| size),
        quote_elapsed,
        pay_elapsed,
        receipt.txs.len(),
        finalize_elapsed,
        fetch_elapsed
    );
}

// ===========================================================================
// D170 §2 R1 — the wallet-less download-only reader
// ===========================================================================

/// A loopback port nothing listens on, for the UDP (QUIC) side.
///
/// Bound and immediately released, so the port is free and unanswered for
/// the lifetime of the measurement. Loopback only: nothing leaves the host.
fn dead_loopback_udp() -> std::net::SocketAddr {
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback probe socket");
    probe.local_addr().expect("the probe socket's address")
}

/// An HTTP URL on a loopback TCP port nothing listens on — a payment RPC
/// that refuses every connection.
fn dead_loopback_rpc_url() -> String {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback probe listener");
    let port = probe
        .local_addr()
        .expect("the probe listener's address")
        .port();
    format!("http://127.0.0.1:{port}")
}

/// The variant, as a stable word for evidence lines and failure messages.
fn storage_error_class(error: &StorageError) -> &'static str {
    match error {
        StorageError::Quote { .. } => "Quote",
        StorageError::Payment { .. } => "Payment",
        StorageError::InsufficientAnt { .. } => "InsufficientAnt",
        StorageError::InsufficientGas { .. } => "InsufficientGas",
        StorageError::Finalize { .. } => "Finalize",
        StorageError::StrandedPayment { .. } => "StrandedPayment",
        StorageError::ProofsExpired => "ProofsExpired",
        StorageError::NotFound { .. } => "NotFound",
        StorageError::Network { .. } => "Network",
    }
}

/// **D170 §2 R1, on a live devnet.** A reader built with no wallet and no EVM
/// network fetches, byte-identical, what a payer stored — and refuses every
/// call that could quote, pay, store or read a wallet, each in the variant
/// its trait contract names, with the funded wallet's nonce unmoved and the
/// refused blob still absent.
///
/// The reader is handed a configuration whose **payment half is unusable**:
/// an RPC nothing listens on, and a chain id no RPC here reports. The payer's
/// connect is shown to fail on that same configuration first, so the reader
/// connecting and fetching is evidence that it reads nothing from the payment
/// side — not a consequence of the payment side happening to work.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::await_holding_lock)] // deliberate whole-test serialization; see `serial`
async fn devnet_d170_reader_fetches_what_a_payer_stored_and_cannot_pay() {
    let _serial = serial();
    let Some((config, env)) = devnet() else {
        return;
    };
    let key = funded_key(&env);
    let payer = AntCoreBackend::connect(&config, &key)
        .await
        .expect("the payer connects to the live devnet");

    let batch = test_blobs(&env, "d170-reader", &[272, 4_096]);
    let quote = payer.quote_batch(&batch).await.expect("quote");
    let receipt = payer.pay(&quote).await.expect("pay");
    let addresses = payer
        .finalize_batch(&receipt, &batch)
        .await
        .expect("finalize");

    let payment_side_unusable = NetworkConfig {
        rpc_url: dead_loopback_rpc_url(),
        evm_chain_id: 1,
        ..config.clone()
    };
    // CONTROL: this configuration really is unusable for anything that pays.
    match AntCoreBackend::connect(&payment_side_unusable, &key).await {
        Err(StorageError::Network { .. }) => {}
        Err(other) => panic!(
            "CONTROL: the payer refused the unusable payment side in the wrong class ({}): {other}",
            storage_error_class(&other)
        ),
        Ok(_) => panic!(
            "CONTROL: the payer connected over a dead payment RPC with a wrong chain id — the \
             configuration is not unusable, so the reader connecting over it proves nothing"
        ),
    }

    let reader = AntCoreReader::connect(&payment_side_unusable)
        .await
        .expect("the reader connects with no wallet and no usable payment RPC");
    assert_eq!(
        reader.network_config(),
        &payment_side_unusable,
        "the reader is bound to the configuration it was given"
    );
    for (blob, address) in batch.iter().zip(&addresses) {
        let fetched = reader
            .get_data(*address)
            .await
            .expect("the reader fetches a chunk the payer stored");
        assert_eq!(
            fetched,
            blob.as_bytes(),
            "byte-identical through the reader"
        );
    }

    // ── every non-fetching call refuses, and nothing moves ────────────────
    let nonce_before = wallet_nonce(&payer, &env).await;
    let fresh = test_blobs(&env, "d170-reader-refused", &[300]);

    let refused = reader
        .quote_batch(&fresh)
        .await
        .expect_err("the download-only reader must refuse to quote");
    assert!(
        matches!(refused, StorageError::Quote { .. }),
        "quote_batch refuses in the Quote class: {refused:?}"
    );
    let refused = reader
        .pay(&quote)
        .await
        .expect_err("the download-only reader must refuse to pay");
    assert!(
        matches!(refused, StorageError::Payment { .. }),
        "pay refuses in the Payment class (nothing landed): {refused:?}"
    );
    let refused = reader
        .finalize_batch(&receipt, &fresh)
        .await
        .expect_err("the download-only reader must refuse to store");
    assert!(
        matches!(refused, StorageError::Finalize { .. }),
        "finalize_batch refuses in the Finalize class: {refused:?}"
    );
    let refused = reader
        .balances()
        .await
        .expect_err("the download-only reader holds no wallet to read");
    assert!(
        matches!(refused, StorageError::Network { .. }),
        "balances refuses in its documented Network class: {refused:?}"
    );
    let message = refused.to_string();
    assert!(
        message.contains("download-only") && !message.contains("0x"),
        "the refusal names the reason and carries no hex material: {message}"
    );

    assert_eq!(
        wallet_nonce(&payer, &env).await,
        nonce_before,
        "no transaction was submitted by any refused call"
    );
    let fresh_address = antseal_net::Address::from(
        antseal_core::storage::compute_storage_address(fresh[0].as_bytes()).expect("under cap"),
    );
    assert_eq!(
        payer.get_data(fresh_address).await,
        Err(StorageError::NotFound {
            address: fresh_address
        }),
        "the refused blob was not stored by anything"
    );
}

/// How long one unreachable-network connect or fetch may take before the
/// test fails it as a hang rather than waiting on.
const D170_UNREACHABLE_CAP: std::time::Duration = std::time::Duration::from_secs(120);

/// The negative control's verdict on one unreachable client's fetch of a
/// chunk the devnet holds: the network class, and nothing else.
fn assert_network_class_never_absence(who: &str, outcome: &Result<Vec<u8>, StorageError>) {
    match outcome {
        Err(StorageError::Network { .. }) => {}
        Err(StorageError::NotFound { address }) => panic!(
            "{who} reported {address} as NotFound — a chunk this devnet holds. An unreachable \
             network must be the network class, never absence: NotFound is rendered as a \
             negative fact about stored evidence (`fetch_failure_class`, the live check's \
             'no longer on the network')"
        ),
        Err(other) => panic!(
            "{who} failed in the {} class instead of the network class: {other}",
            storage_error_class(other)
        ),
        Ok(bytes) => panic!(
            "{who} served a chunk the devnet holds ({} bytes): it reached the devnet some other \
             way, so this configuration is not a negative control at all (D170 §2 R7)",
            bytes.len()
        ),
    }
}

/// Connect `who` over `connect` and fetch `stored`, timing both and printing
/// one evidence line; a connect that fails is itself the fetch's outcome.
async fn unreachable_fetch<B, C>(
    who: &str,
    connect: C,
    stored: antseal_net::Address,
) -> Result<Vec<u8>, StorageError>
where
    B: StorageBackend,
    C: std::future::Future<Output = Result<B, StorageError>>,
{
    let started = std::time::Instant::now();
    let connected = tokio::time::timeout(D170_UNREACHABLE_CAP, connect)
        .await
        .unwrap_or_else(|_elapsed| {
            panic!("{who}: connect did not return within {D170_UNREACHABLE_CAP:?}")
        });
    let connect_elapsed = started.elapsed();
    let client = match connected {
        Ok(client) => client,
        Err(error) => {
            eprintln!(
                "D170 MEASUREMENT [{who}]: connect -> Err({}) after {connect_elapsed:?}",
                storage_error_class(&error)
            );
            return Err(error);
        }
    };
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(D170_UNREACHABLE_CAP, client.get_data(stored))
        .await
        .unwrap_or_else(|_elapsed| {
            panic!("{who}: get_data did not return within {D170_UNREACHABLE_CAP:?}")
        });
    let fetch_elapsed = started.elapsed();
    let class = match &outcome {
        Ok(_) => "Ok (served)",
        Err(error) => storage_error_class(error),
    };
    eprintln!(
        "D170 MEASUREMENT [{who}]: connect -> Ok after {connect_elapsed:?}; get_data of a chunk \
         the devnet holds -> {class} after {fetch_elapsed:?}"
    );
    outcome
}

/// **The NotFound classification's negative control: an unreachable network is
/// never reported as absence** — the premise D170 §2 R2's *Inconclusive*
/// section and D43 §5's fallback both rest on.
///
/// Clients that cannot reach the devnet — a dead loopback bootstrap (D170 §2
/// R7's negative-control export) and an empty one (the shape
/// `arbitrum_one()`/`arbitrum_sepolia()` carry today, D170 §1.6) — are each
/// asked for a chunk **this devnet holds**, through the reader and through the
/// payer (one shared fetch path). The only honest answer is the network class:
/// `NotFound` would be a false negative fact, and bytes would mean the client
/// reached the devnet some other way.
///
/// **POSITIVE CONTROL, same test:** on the healthy devnet the reader reports a
/// never-uploaded address as `NotFound`, so the negatives are the
/// classification working rather than a classifier that no longer says
/// `NotFound` at all (S6 and S15 hold the same control for the payer).
///
/// Connect and fetch latencies are printed as `D170 MEASUREMENT` lines: they
/// are what replaced D170 §2 R2's connect-budget question.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::await_holding_lock)] // deliberate whole-test serialization; see `serial`
async fn devnet_d170_an_unreachable_network_is_never_reported_as_absence() {
    let _serial = serial();
    let Some((config, env)) = devnet() else {
        return;
    };
    let key = funded_key(&env);
    let payer = AntCoreBackend::connect(&config, &key)
        .await
        .expect("the payer connects to the live devnet");
    let batch = test_blobs(&env, "d170-unreachable", &[272]);
    let quote = payer.quote_batch(&batch).await.expect("quote");
    let receipt = payer.pay(&quote).await.expect("pay");
    let addresses = payer
        .finalize_batch(&receipt, &batch)
        .await
        .expect("finalize");
    let stored = addresses[0];
    assert_eq!(
        payer
            .get_data(stored)
            .await
            .expect("POSITIVE CONTROL: the devnet serves the chunk"),
        batch[0].as_bytes()
    );

    let healthy = AntCoreReader::connect(&config)
        .await
        .expect("the reader connects to the live devnet");
    let never = antseal_net::Address::from_bytes([0xA6; 32]);
    let started = std::time::Instant::now();
    assert_eq!(
        healthy.get_data(never).await,
        Err(StorageError::NotFound { address: never }),
        "POSITIVE CONTROL: on a healthy devnet a never-uploaded address is authoritative absence"
    );
    eprintln!(
        "D170 MEASUREMENT [healthy devnet, reader]: never-uploaded address -> NotFound after \
         {:?}",
        started.elapsed()
    );

    for (label, bootstrap) in [("dead", vec![dead_loopback_udp()]), ("empty", Vec::new())] {
        let unreachable = NetworkConfig {
            bootstrap,
            ..config.clone()
        };
        let who = format!("the reader with a {label} bootstrap");
        let outcome = unreachable_fetch(&who, AntCoreReader::connect(&unreachable), stored).await;
        assert_network_class_never_absence(&who, &outcome);

        let who = format!("the payer with a {label} bootstrap");
        let outcome =
            unreachable_fetch(&who, AntCoreBackend::connect(&unreachable, &key), stored).await;
        assert_network_class_never_absence(&who, &outcome);
    }
}
