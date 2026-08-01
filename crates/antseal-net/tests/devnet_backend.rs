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

use antseal_net::ant_backend::AntCoreBackend;
use antseal_net::evm::WalletKey;
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
    let env = match DevnetEnv::from_env_file(&text) {
        Ok(env) => env,
        Err(error) => {
            eprintln!("SKIP: devnet env export did not parse ({error}) — stale or partial export?");
            return None;
        }
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
