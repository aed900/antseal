//! The CLI's storage-backend construction seam.
//!
//! Every network-touching command (`seal`, `restore`, `status --upgrade`,
//! `verify --live`) needs the same three things assembled in the same
//! order: U4's resolved [`NetworkConfig`], U10's vault-held wallet key,
//! and an async runtime to drive S6's `AntCoreBackend` on. That assembly
//! is one job with one right answer, so it lives here rather than being
//! re-derived per command.
//!
//! # The D37 obligation, made structural (U36/S27)
//!
//! S6's `AntCoreBackend` is a builder: [`connect`] returns one with no
//! capture hook and `with_capture_hook` bolts it on afterwards. That
//! shape lets a caller *forget*, and forgetting is expensive — without
//! the per-sub-batch hook a crash in the post-pay window loses receipts
//! that have already cost money, so resume pays a second time (D37
//! Decision 2; S16 asserts both directions; **S27** recorded that
//! nothing forced it).
//!
//! Nothing here relies on remembering. [`SealBackend`] lives in a private
//! module with a private field, so the only expression in this crate that
//! can produce one is [`SealBackend::connect`] — and that function takes
//! the [`ReceiptSink`] as an ordinary required argument and installs the
//! hook itself. There is no builder, no `Default`, no second constructor
//! and no way to opt out: a `SealBackend` that exists is a `SealBackend`
//! whose hook is installed. Commands hold the wrapper, never the inner
//! backend, and reach the network through its [`StorageBackend`] impl.
//!
//! [`connect`]: antseal_net::AntCoreBackend::connect
//! [`StorageBackend`]: antseal_net::StorageBackend
//!
//! # Feature gating and the runtime
//!
//! All of it sits behind the non-default `ant-backend` feature (S22's
//! gate policy), which is also what brings the tokio edge: `ant-core`'s
//! client and the alloy transport park on reactor-driven I/O, so the
//! futures need a real runtime rather than `test_util::block_on`'s
//! noop-waker loop. The edge is `optional = true` and activated only by
//! that feature, so the default `--workspace` graph the `dep-graph` lane
//! measures is unchanged — the same shape `devnet-launcher` uses for its
//! `devnet` feature, and the edge S6's recorded tokio decision named in
//! advance ("its futures run on the caller's runtime — `antseal-cli`
//! brings tokio").
//!
//! A default build compiles none of this and every network-touching
//! command refuses at [`unavailable`] with a specific, actionable message
//! rather than pretending the network is merely down.
//!
//! What was never blocked on any of it: `restore`'s whole policy half
//! runs over any [`StorageBackend`](antseal_net::StorageBackend) —
//! [`crate::restore_out::run_restore`] is generic and is driven end to end
//! in the test suites, which is also how D34 says the M1 E2E drives the
//! pipeline (library APIs, never a spawned binary).
//!
//! [`NetworkConfig`]: antseal_net::NetworkConfig

use crate::error::CliError;

// The flat path consumers use: `backend::SealBackend`, not
// `backend::ant::sealed::SealBackend`.
//
// **`pub`, not `pub(crate)` (S17).** `mod ant` stays private and `sealed`
// stays private inside it — the construction guarantee below is a property
// of *field* visibility and is untouched by this. What re-exporting widens
// is only reachability, and it has to widen: D34 puts the M1 E2E in
// `tests/`, i.e. an external crate, and the seam is precisely what those
// suites must drive (S17 asserts the hook is installed on the real path;
// S18 depends on it for the no-double-pay row). A `pub(crate)` seam would
// have forced the harness to build its own backend — which is the one
// thing this module exists to make impossible. Widening is sanctioned by
// the crate-root stability note: this library's API serves the binary and
// the workspace's own harnesses.
#[cfg(feature = "ant-backend")]
pub use ant::{ReadOnly, ReceiptSink, SealBackend, runtime, wallet_key};

/// The refusal a command gets when it needs the network and this build
/// cannot reach it.
///
/// Deliberately **not** the not-implemented class: the command itself is
/// implemented, and saying otherwise would send a user looking for a
/// milestone that has already arrived. It is reported in the transient
/// network class (D48 §6's floor), because from the caller's side that is
/// what it is — no bytes can be fetched — and the message names the
/// actual cause instead of implying an outage.
///
/// The two arms say different true things, which is the point: a message
/// blaming the missing feature would be a lie in a build that has it.
///
/// Public so U3's registered `--json` fixture can render the **real**
/// refusal instead of a hand-copied one. It had a copy, and the copy went
/// stale the moment this message changed — a snapshot documenting text no
/// build produces is worse than no snapshot (U19 made the same call for
/// `list`: the fixture is rendered by the real renderer).
#[must_use]
pub fn unavailable(command: &str) -> CliError {
    #[cfg(not(feature = "ant-backend"))]
    let detail = format!(
        "`{command}` needs a live Autonomi connection, and this build has no storage backend \
         compiled in (the `ant-backend` feature is off by default). The command itself is \
         complete — rebuild with `--features ant-backend` to reach the network"
    );
    // S17 update: the seam is no longer merely built — `tests/e2e_devnet.rs`
    // drives it against a live devnet, so "resolving the endpoint lands with
    // the devnet harness" stopped being true the moment that suite went
    // green. What is actually missing for a *command* is its own wiring
    // (U13 for `seal`), and that is what the refusal must name; pointing a
    // user at a task that has already shipped sends them looking for a fix
    // that is already in their build.
    #[cfg(feature = "ant-backend")]
    let detail = format!(
        "`{command}` has a storage backend compiled in but this command is not yet wired to it: \
         U36 built the construction seam (`backend::SealBackend`) and the M1 devnet harness \
         drives it end to end, but connecting it to this command's argument handling lands with \
         U13"
    );
    CliError::NetworkFailure { detail }
}

// U36 built the seam and its tests; the devnet harness (S17/S18/S19) is
// the first consumer that actually calls `connect`/`runtime`/`ReadOnly`
// against a network, which is why the `dead_code` allow this module
// carried until now is gone: the items are publicly re-exported above and
// driven by `tests/e2e_devnet.rs`. `seal`'s command wiring (U13) is still
// to come and is tracked there, not here.
#[cfg(feature = "ant-backend")]
mod ant {
    use std::sync::Arc;

    use antseal_core::crypto::secrets::SecretBuf;
    use antseal_net::evm::WalletKey;
    use antseal_net::{
        Address, AntCoreBackend, Blob, CaptureHook, CostQuote, NetworkConfig, PaymentReceipt,
        StorageBackend, StorageError,
    };

    use crate::error::CliError;
    use crate::vault::wallet::{WALLET_KEY_LEN, WalletKeyHandle};

    /// Where D37's per-sub-batch receipts go.
    ///
    /// The hook upstream accepts is `Arc<dyn Fn(&PaymentReceipt) + Send +
    /// Sync>` — `'static`, `Send` and `Sync` — which the pipeline's own
    /// journal handle is none of (`VaultJournal` borrows the unlocked
    /// vault and holds a `RefCell` around the RNG). So the seam is this
    /// trait rather than `&VaultJournal` directly: the *write* is still
    /// the pipeline's (S10/S12), and this is only the timing seam D37
    /// specifies — invoked with the cumulative receipt-so-far after each
    /// sub-batch tx lands, strictly before the next is submitted.
    ///
    /// Implementations must not panic: they run inside `pay()`, between
    /// two transactions, on the far side of money having moved.
    pub trait ReceiptSink: Send + Sync + 'static {
        /// Durably record the receipt-so-far.
        fn capture(&self, receipt: &PaymentReceipt);
    }

    /// The sink for commands that never pay.
    ///
    /// `restore`, `verify --live` and `status --upgrade` call `get_data`
    /// and nothing else, so this can only fire if such a command grows a
    /// payment path without growing a journal — which is a bug, and is
    /// logged as one rather than silently dropped. It exists so those
    /// commands still go through the one constructor: "this path does not
    /// pay" is then a statement in the code, not an omission.
    pub struct ReadOnly;

    impl ReceiptSink for ReadOnly {
        fn capture(&self, _receipt: &PaymentReceipt) {
            tracing::error!(
                "a read-only command produced a payment receipt — it has not been journaled \
                 (D37: this path must construct the backend with a journal-backed sink)"
            );
        }
    }

    /// Build the tokio runtime the backend's futures need.
    ///
    /// Multi-thread: `ant-core`'s client drives concurrent peer I/O and
    /// alloy's transport its own reactor tasks, and the pipeline awaits
    /// them from one blocking call at the command layer.
    ///
    /// # Errors
    ///
    /// [`CliError::NetworkFailure`] if the runtime cannot be created —
    /// reported in the network class because that is what it costs the
    /// caller: no bytes can move.
    pub fn runtime() -> Result<tokio::runtime::Runtime, CliError> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|source| CliError::NetworkFailure {
                detail: format!("the async runtime could not be started: {source}"),
            })
    }

    /// Bridge U10's vault-held 32 bytes to S5's validated payment key.
    ///
    /// The vault stores raw bytes; `WalletKey` is defined extensionally
    /// as "what the pinned upstream parse accepts" (D44), so the bytes
    /// are hex-encoded and pushed through that same gate — the one
    /// acceptance path generation and import already share.
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] when the stored bytes are not a valid secp256k1
    /// scalar. The message names the condition and **never** any part of
    /// the key material (project rule 6).
    pub fn wallet_key(handle: &WalletKeyHandle) -> Result<WalletKey, CliError> {
        let mut hex = String::with_capacity(WALLET_KEY_LEN * 2);
        for byte in handle.secret_bytes() {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        let candidate = SecretBuf::new(hex.into_bytes());
        WalletKey::import(&candidate).map_err(|_| CliError::Usage {
            message: "the vault's wallet key is not a valid payment key — the record is corrupt, \
                     or it was written by a build with a different key format. Restore the vault \
                     from a `vault export` backup"
                .to_owned(),
        })
    }

    pub use sealed::SealBackend;

    /// The private module is the enforcement: `SealBackend`'s field is
    /// visible only in here, and the only function in here that builds
    /// one is `connect`. Nothing outside — not even the rest of this
    /// module — can write `SealBackend { .. }`.
    mod sealed {
        use super::{
            Address, AntCoreBackend, Arc, Blob, CaptureHook, CliError, CostQuote, NetworkConfig,
            PaymentReceipt, ReceiptSink, StorageBackend, StorageError, WalletKey,
        };

        /// A connected Autonomi backend that **has** its D37 capture hook.
        ///
        /// Not merely by convention: see the module docs. The type is the
        /// proof, so no test, review step or comment has to carry it.
        pub struct SealBackend {
            inner: AntCoreBackend,
        }

        impl SealBackend {
            /// Connect, installing the D37 per-sub-batch capture hook.
            ///
            /// `receipts` is required and has no default. That is the
            /// whole design: the obligation S27 recorded is discharged by
            /// the signature, not by remembering to call a builder.
            ///
            /// # Errors
            ///
            /// [`CliError::NetworkFailure`] for connect, transport and
            /// chain-id failures (S6 maps upstream's; the chain-id guard
            /// is what catches a wrong-network RPC before any payment).
            pub async fn connect(
                config: &NetworkConfig,
                wallet_key: &WalletKey,
                receipts: Arc<dyn ReceiptSink>,
            ) -> Result<Self, CliError> {
                let inner = AntCoreBackend::connect(config, wallet_key)
                    .await
                    .map_err(|source| CliError::NetworkFailure {
                        detail: source.to_string(),
                    })?
                    .with_capture_hook(hook(receipts));
                Ok(Self { inner })
            }

            /// The hook `connect` installs, exposed so a test can fire it
            /// without a network. Constructing one does **not** construct
            /// a backend — this is the adapter, not a second door.
            pub fn hook_for(receipts: Arc<dyn ReceiptSink>) -> CaptureHook {
                hook(receipts)
            }
        }

        /// Adapt a sink to upstream's `Fn(&PaymentReceipt)` hook type.
        fn hook(receipts: Arc<dyn ReceiptSink>) -> CaptureHook {
            Arc::new(move |receipt: &PaymentReceipt| receipts.capture(receipt))
        }

        /// Straight delegation — this wrapper adds no policy, only the
        /// construction guarantee. Every method is the inner backend's.
        impl StorageBackend for SealBackend {
            async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
                self.inner.quote_batch(blobs).await
            }

            async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
                self.inner.pay(quote).await
            }

            async fn finalize_batch(
                &self,
                receipt: &PaymentReceipt,
                blobs: &[Blob],
            ) -> Result<Vec<Address>, StorageError> {
                self.inner.finalize_batch(receipt, blobs).await
            }

            async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
                self.inner.get_data(address).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// **S27's obligation, checked rather than reviewed.** The type-level
    /// half of "the hook cannot be forgotten" is that `SealBackend`'s
    /// field is private to a private module, so `SealBackend::connect` —
    /// which always installs the hook — is the only expression that can
    /// produce one. That half the compiler enforces.
    ///
    /// The half the compiler cannot enforce is a *future* command
    /// bypassing the wrapper entirely: `AntCoreBackend::connect` is
    /// public, returns a hookless backend, and satisfies `StorageBackend`
    /// on its own, so a hurried `seal` or `status --upgrade` could name it
    /// directly and compile, pay, crash, and pay again. This scan closes
    /// that: the raw backend type is nameable in exactly one file, so a
    /// second mention is a failing test rather than a lost payment.
    ///
    /// Deliberately ungated — under a default build the name should not
    /// appear anywhere at all, and this is the lane where regressions land
    /// first.
    #[test]
    fn the_raw_backend_type_is_named_in_exactly_one_file() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut named = Vec::new();
        let mut visited = 0usize;
        let mut stack = vec![src.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read src dir").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    visited += 1;
                    let text = std::fs::read_to_string(&path).expect("read source");
                    if text.contains("AntCoreBackend") {
                        named.push(
                            path.strip_prefix(&src)
                                .unwrap_or(&path)
                                .to_string_lossy()
                                .into_owned(),
                        );
                    }
                }
            }
        }
        assert!(
            visited > 10,
            "the scan found only {visited} source files — it is not looking where it thinks"
        );
        named.sort();
        assert_eq!(
            named,
            vec!["backend.rs".to_owned()],
            "`AntCoreBackend` may be named only in the construction seam. A command that names \
             it directly gets a backend with no D37 capture hook, and a crash in the post-pay \
             window then costs a second payment (S27). Go through `backend::SealBackend::connect`"
        );
    }

    /// The behavioral half: the hook `connect` installs really does reach
    /// the sink it was constructed with. Needs no network — the hook is
    /// upstream's `Fn(&PaymentReceipt)` and is fired directly.
    #[cfg(feature = "ant-backend")]
    #[test]
    fn the_installed_hook_delivers_receipts_to_its_sink() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use antseal_net::{GasSummary, PaymentReceipt};

        use super::{ReceiptSink, SealBackend};

        struct Counting(AtomicUsize);
        impl ReceiptSink for Counting {
            fn capture(&self, receipt: &PaymentReceipt) {
                assert_eq!(receipt.storage_cost_atto, 7, "the receipt arrives intact");
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let sink = Arc::new(Counting(AtomicUsize::new(0)));
        let hook = SealBackend::hook_for(sink.clone());
        let receipt = PaymentReceipt {
            blobs: Vec::new(),
            tx_map: std::collections::BTreeMap::new(),
            txs: Vec::new(),
            storage_cost_atto: 7,
            gas: GasSummary { gas_cost_wei: 0 },
        };

        assert_eq!(sink.0.load(Ordering::SeqCst), 0);
        hook(&receipt);
        hook(&receipt);
        assert_eq!(
            sink.0.load(Ordering::SeqCst),
            2,
            "every sub-batch capture must reach the journal, not just the first (D37)"
        );

        // The read-only sink satisfies the same obligation without a
        // journal, so `restore`/`verify --live` go through one door too.
        super::ReadOnly.capture(&receipt);
    }

    /// The vault→payment-key bridge accepts what U10's record stores, and
    /// refuses what no scalar can be — both through the single D44
    /// acceptance gate, never a second hand-rolled parse.
    #[cfg(feature = "ant-backend")]
    #[test]
    fn the_wallet_bridge_pushes_vault_bytes_through_the_d44_gate() {
        use crate::vault::wallet::WalletKeyHandle;

        // NON-SECRET, and the same repeated-byte fixture U10/U12's suites
        // use: a valid secp256k1 scalar by construction (far below the
        // group order) and obviously not a real key.
        const FIXTURE_WALLET_KEY: [u8; 32] = [0x5Au8; 32];

        let key = super::wallet_key(&WalletKeyHandle::from_bytes(FIXTURE_WALLET_KEY))
            .expect("a valid scalar is accepted");
        // Round-trips to the same lowercase hex the gate parsed.
        assert_eq!(key.as_hex().as_bytes(), "5a".repeat(32).as_bytes());

        // Zero is not a scalar; the refusal names the condition and
        // carries no part of the input (project rule 6).
        let err = super::wallet_key(&WalletKeyHandle::from_bytes([0u8; 32]))
            .expect_err("the zero scalar is refused");
        let rendered = err.to_string();
        assert!(rendered.contains("wallet key"), "{rendered}");
        assert!(
            !rendered.contains(&"00".repeat(4)),
            "the refusal echoed the rejected material: {rendered}"
        );
    }

    /// The runtime the backend's futures need actually builds, and is a
    /// real reactor rather than the noop-waker loop upstream warns off.
    #[cfg(feature = "ant-backend")]
    #[test]
    fn the_runtime_builds_and_drives_a_timer() {
        let rt = super::runtime().expect("runtime builds");
        rt.block_on(async {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        });
    }
}
