//! Shared devnet gating and instrumentation for the M1 E2E gate suites
//! (S17 happy path, S18 kill/resume, S19 clean-tree restore).
//!
//! Everything here is the part those three files would otherwise triplicate:
//! the environment gate, the process-global serialization, the D37 receipt
//! sink, and a dependency-free Anvil JSON-RPC probe.
//!
//! # Gating (two layers, same shape as `antseal-net`'s S6-S8 suite)
//!
//! 1. **Feature** — compiled only under the non-default `ant-backend`
//!    feature, so the default `--workspace` lane never builds it.
//! 2. **Environment** — every test SKIPS WITH A MESSAGE unless
//!    `ANTSEAL_DEVNET_ENV` points at a live devnet's run-scoped export and
//!    the exported launcher pid is alive. `scripts/e2e-devnet.sh` sets it;
//!    locally see `docs/devnet/local-devnet.md`.
//!
//! A skip is deliberately not a failure: the suite is meaningless without a
//! devnet, and `scripts/e2e-devnet.sh` is the thing that guarantees one is
//! there. What that script will not tolerate is the suite *file* going
//! missing — that is its registry's job.
//!
//! NON-SECRET: the funded devnet wallet is Anvil's well-known public
//! account 0. It is still routed through `SecretBuf`/`WalletKey` and never
//! printed, because project rule 6 binds the pattern, not just real value.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use antseal_cli::backend::ReceiptSink;
// `antseal_net::WalletKey`, not `antseal_net::evm::WalletKey`: S17 wrote the
// latter when `evm.rs` re-exported the type, and U37/D89 (`6bc8dbf`) moved
// the wallet light half into the default graph, demoting that re-export to a
// private `use`. Nothing noticed, because no lane type-checks this feature's
// TEST targets — `cargo check -p antseal-cli --features ant-backend` builds
// lib+bin only, and the devnet suites are environment-gated so they skip
// rather than fail. The whole M1 devnet gate has not compiled since.
// Second instance of U39's gap, and the reason its lane must be
// `--all-targets`.
use antseal_net::{DevnetEnv, NetworkConfig, PaymentReceipt, WalletKey};

// ─────────────────────────────────────────────────────────────────────
// Serialization and the environment gate
// ─────────────────────────────────────────────────────────────────────

/// Process-global serialization.
///
/// Each test stands up its own `Client` (an in-process P2P node doing
/// ML-KEM/ML-DSA handshakes) and, in S18's case, its own tokio runtime and
/// SIGKILLed child. On the 2-core reference host these do not overlap
/// usefully, and an overlapping pair would make the Anvil tx-count deltas
/// S18 asserts meaningless — another test's payment would land inside the
/// window. One test at a time, per binary.
///
/// A **std** mutex held across awaits is deliberate (the S6-S8 suite makes
/// the same call): every test owns its runtime, so a thread parked here
/// blocks only itself and no task inside a runtime ever waits on it twice.
pub fn serial() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The env gate: `Some((config, env))` when a live devnet is exported,
/// `None` (after printing why) otherwise.
#[must_use]
pub fn devnet() -> Option<(NetworkConfig, DevnetEnv)> {
    let Some(path) = std::env::var_os("ANTSEAL_DEVNET_ENV") else {
        eprintln!(
            "SKIP: ANTSEAL_DEVNET_ENV is not set — point it at a live devnet's .devnet/env \
             (scripts/devnet/local-up --nodes 14), or run the whole gate with \
             scripts/e2e-devnet.sh"
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
    // Stale-export guard: the launcher pid IS the devnet's lifetime handle.
    if !std::path::Path::new(&format!("/proc/{}", env.pid())).exists() {
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

/// The funded dev wallet from the run-scoped export.
///
/// # Panics
///
/// If the export carries a key the D44 gate rejects — which would mean the
/// launcher wrote something no payment path could have used either.
#[must_use]
pub fn funded_key(env: &DevnetEnv) -> WalletKey {
    WalletKey::import(env.wallet_private_key()).expect("devnet export carries a valid funded key")
}

/// A skip-or-run preamble every devnet test opens with.
///
/// Returns `None` after printing the reason, so the caller's body is a
/// plain `let Some(..) = .. else { return; }`.
#[must_use]
pub fn gate() -> Option<(NetworkConfig, DevnetEnv, WalletKey)> {
    let (config, env) = devnet()?;
    let key = funded_key(&env);
    Some((config, env, key))
}

// ─────────────────────────────────────────────────────────────────────
// Run-scoped freshness
// ─────────────────────────────────────────────────────────────────────
//
// The mock suites are seeded from constants and are bit-reproducible. A
// devnet suite **must not** be, for two independent reasons:
//
//  1. Autonomi storage is immutable and content-addressed, and one
//     `local-up` may serve several suite invocations. A fixed seed re-seals
//     byte-identical ciphertext, whose quote lines then come back
//     already-stored at zero cost — and "total ANT spent equals the
//     consented quote" degenerates to 0 == 0. The assertion would still
//     pass while proving nothing.
//  2. A fixed seed means a fixed `W`, hence fixed unit keys and fixed
//     nonces. Re-running over *edited* fixture bytes would then encrypt
//     different plaintext under the same `(k_u, nonce)` — the exact AEAD
//     misuse S18's guard exists to prevent. Baking that pattern into the
//     gate's own fixtures would be indefensible even against a throwaway
//     devnet.
//
// So the seeds are derived from a per-process run tag, and the tag is
// printed by every test that uses it: reproducing a failure means re-using
// the printed tag, not re-running and hoping.

/// The environment variable a parent uses to hand its run tag to a child
/// process (S18's SIGKILL scenarios).
pub const RUN_TAG_ENV: &str = "ANTSEAL_RUN_TAG";

/// A per-run identifier mixed into every seed and fixture body.
///
/// **Inherited when present.** S18 seals in a child process and resumes in
/// the parent, and the two must derive the same `W`, the same nonces and
/// the same fixture bytes or they are not working on the same seal at all.
/// The child therefore takes the parent's tag from [`RUN_TAG_ENV`] rather
/// than minting its own from its own pid.
#[must_use]
pub fn run_tag() -> &'static str {
    static TAG: OnceLock<String> = OnceLock::new();
    TAG.get_or_init(|| {
        if let Some(inherited) = std::env::var_os(RUN_TAG_ENV) {
            let inherited = inherited.to_string_lossy().into_owned();
            if !inherited.is_empty() {
                return inherited;
            }
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        format!("{}-{nanos}", std::process::id())
    })
}

/// A 32-byte seed for `label` within this run — BLAKE3 over the run tag and
/// the label, so distinct call sites never collide and no two runs share a
/// `W`.
///
/// # Panics
///
/// Never in practice: the input is far below the chunk cap the address
/// helper rejects on.
#[must_use]
pub fn run_seed(label: &str) -> [u8; 32] {
    let material = format!("antseal-m1-gate/{}/{label}", run_tag());
    *antseal_core::storage::compute_storage_address(material.as_bytes())
        .expect("a short seed label is far below the chunk cap")
        .as_bytes()
}

// ─────────────────────────────────────────────────────────────────────
// The D37 receipt sink
// ─────────────────────────────────────────────────────────────────────

/// Records every per-sub-batch receipt `SealBackend::connect` routes to it.
///
/// This is how S17 proves the hook is **installed on the real path**: the
/// type system proves a `SealBackend` cannot exist without one (that is
/// `backend.rs`'s private-field argument), but only a live payment proves
/// the installed hook actually fires against ant-core's `pay`. S16 showed
/// the without-hook direction costs a second payment, so this is the
/// direction worth instrumenting.
#[derive(Debug, Default)]
pub struct CapturedReceipts {
    fired: AtomicUsize,
    receipts: Mutex<Vec<PaymentReceipt>>,
}

impl CapturedReceipts {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// How many times the hook fired (≥ 1 after any non-zero payment; one
    /// per D37 sub-batch).
    #[must_use]
    pub fn fired(&self) -> usize {
        self.fired.load(Ordering::SeqCst)
    }

    /// The last receipt captured, if any.
    #[must_use]
    pub fn last(&self) -> Option<PaymentReceipt> {
        match self.receipts.lock() {
            Ok(guard) => guard.last().cloned(),
            Err(poisoned) => poisoned.into_inner().last().cloned(),
        }
    }

    /// Total atto-ANT across the captured receipts' cumulative totals —
    /// read from the **last** receipt, since D37's hook delivers the
    /// receipt-so-far rather than a per-tx delta.
    #[must_use]
    pub fn cumulative_atto(&self) -> u128 {
        self.last().map_or(0, |r| r.storage_cost_atto)
    }
}

impl ReceiptSink for CapturedReceipts {
    fn capture(&self, receipt: &PaymentReceipt) {
        self.fired.fetch_add(1, Ordering::SeqCst);
        match self.receipts.lock() {
            Ok(mut guard) => guard.push(receipt.clone()),
            Err(poisoned) => poisoned.into_inner().push(receipt.clone()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Anvil JSON-RPC probe
// ─────────────────────────────────────────────────────────────────────
//
// S18 has to answer "did money move, and how many times" from **outside**
// the code under test — a receipt the pipeline wrote is exactly the
// artifact a double-payment bug would also write, so the chain is the only
// impartial witness.
//
// Deliberately hand-rolled over `std::net::TcpStream` rather than pulling
// in an HTTP or EVM client: the `dep-graph` lane measures the default
// workspace graph, and a dev-dependency here would enter it for every
// package that builds these tests. The whole probe is ~60 lines against a
// localhost Anvil that speaks plain HTTP/1.1, and `serde_json` is already a
// normal dependency of this crate.

/// A JSON-RPC call against the devnet's Anvil endpoint.
///
/// Returns the `result` member. Every failure is a `String` rather than a
/// panic so a caller can distinguish "the chain says no" from "the probe
/// broke".
///
/// # Errors
///
/// Transport, HTTP-framing, JSON and JSON-RPC-level (`error` member)
/// failures, each named.
pub fn rpc(rpc_url: &str, method: &str, params: &serde_json::Value) -> Result<String, String> {
    let (host, port, path) = split_url(rpc_url)?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();

    let mut stream =
        TcpStream::connect((host.as_str(), port)).map_err(|e| format!("connect {rpc_url}: {e}"))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .map_err(|e| format!("set timeout: {e}"))?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read: {e}"))?;

    let payload = http_body(&raw)?;
    let value: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|e| format!("{method}: bad JSON ({e})"))?;
    if let Some(error) = value.get("error") {
        return Err(format!("{method}: JSON-RPC error {error}"));
    }
    value
        .get("result")
        .map(|r| match r {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .ok_or_else(|| format!("{method}: response carried no result member"))
}

/// Split `http://host:port/path` into its parts. Only the plain-HTTP shape
/// Anvil serves is supported; anything else is an error, not a guess.
fn split_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// devnet RPC URLs are supported, got {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| format!("devnet RPC URL has no port: {url}"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("devnet RPC URL port is not a number: {url}"))?;
    Ok((host.to_owned(), port, path.to_owned()))
}

/// Extract the entity body from a raw HTTP/1.1 response, handling both
/// `Content-Length` and `Transfer-Encoding: chunked` — a response framed
/// one way and parsed the other yields a JSON error that looks like a
/// chain problem, which is the confusing failure worth spending 20 lines
/// to avoid.
fn http_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "HTTP response had no header terminator".to_owned())?;
    let headers = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    let body = &raw[split + 4..];
    if !headers.contains("transfer-encoding: chunked") {
        return Ok(body.to_vec());
    }
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "chunked body: unterminated size line".to_owned())?;
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&rest[..line_end])
                .split(';')
                .next()
                .unwrap_or("")
                .trim(),
            16,
        )
        .map_err(|_| "chunked body: bad chunk size".to_owned())?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size {
            return Err("chunked body: truncated chunk".to_owned());
        }
        out.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or(&[]);
    }
}

/// Parse a `0x`-prefixed quantity into `u128`.
fn hex_quantity(text: &str) -> Result<u128, String> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if digits.is_empty() {
        return Err("empty hex quantity".to_owned());
    }
    u128::from_str_radix(digits, 16).map_err(|e| format!("hex quantity {text}: {e}"))
}

/// The wallet's transaction count (its EVM nonce) at the latest block.
///
/// This is the impartial "how many transactions has this account sent"
/// counter S18's no-double-payment row reads: it counts submissions,
/// including ones whose receipts never reached the journal.
///
/// # Errors
///
/// Any probe or chain-level failure, named.
pub fn tx_count(rpc_url: &str, address: &str) -> Result<u64, String> {
    let result = rpc(
        rpc_url,
        "eth_getTransactionCount",
        &serde_json::json!([address, "latest"]),
    )?;
    let count = hex_quantity(&result)?;
    u64::try_from(count).map_err(|_| "transaction count does not fit u64".to_owned())
}

/// The wallet's ANT balance, via `balanceOf(address)` on the run's
/// AutonomiNetworkToken.
///
/// # Errors
///
/// Any probe or chain-level failure, named.
pub fn ant_balance(rpc_url: &str, token: &str, address: &str) -> Result<u128, String> {
    // ERC-20 `balanceOf(address)` = 0x70a08231, then the address
    // left-padded to 32 bytes.
    let bare = address.strip_prefix("0x").unwrap_or(address);
    let data = format!("0x70a08231{}{bare}", "0".repeat(24));
    let result = rpc(
        rpc_url,
        "eth_call",
        &serde_json::json!([{ "to": token, "data": data }, "latest"]),
    )?;
    hex_quantity(&result)
}

/// Whether a transaction landed successfully (`status == 0x1`).
///
/// # Errors
///
/// Probe failures; a *missing* receipt is `Ok(false)`, not an error — "the
/// chain has never heard of this tx" is a legitimate answer to the
/// question S18 asks.
pub fn tx_succeeded(rpc_url: &str, tx_hash: &str) -> Result<bool, String> {
    let result = match rpc(
        rpc_url,
        "eth_getTransactionReceipt",
        &serde_json::json!([tx_hash]),
    ) {
        Ok(result) => result,
        Err(error) if error.contains("no result member") => return Ok(false),
        Err(error) => return Err(error),
    };
    if result == "null" {
        return Ok(false);
    }
    let value: serde_json::Value =
        serde_json::from_str(&result).map_err(|e| format!("receipt is not an object: {e}"))?;
    Ok(value.get("status").and_then(serde_json::Value::as_str) == Some("0x1"))
}

/// Hex-encode a 32-byte hash as an `0x`-prefixed string.
#[must_use]
pub fn hex32_0x(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(66);
    out.push_str("0x");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
