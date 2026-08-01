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

/// Deterministic, devnet-unique test blobs: every run must use fresh
/// bytes (chunks persist across tests within one devnet run), so blobs
/// are derived from the run's base port + a per-call label.
fn test_blobs(env: &DevnetEnv, label: &str, sizes: &[usize]) -> Vec<Blob> {
    sizes
        .iter()
        .enumerate()
        .map(|(index, &size)| {
            let mut bytes = Vec::with_capacity(size.max(8));
            let seed = format!("{}:{}:{}:{}", env.base_port(), env.pid(), label, index);
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

// A compile-time witness that the receipt type re-exports stay reachable
// for the suite (the S7 tests grow from here).
#[allow(dead_code)]
fn receipt_type_reachable(receipt: &PaymentReceipt) -> usize {
    receipt.txs.len()
}
