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
//! A default build compiles none of this and every command that *must*
//! reach the network refuses at [`unavailable`] with a specific, actionable
//! message rather than pretending the network is merely down.
//!
//! # The command that does not have to (U72)
//!
//! `reveal` is not one of those commands, and used to be treated as one.
//! Its gathering is cache-first by D43's ruling, so a work whose retained
//! cache is intact discloses with **zero** network access. [`unavailable`]
//! at entry made the default build refuse on bytes already sitting on the
//! user's disk. U72's ruling and the whole of its reasoning live on
//! [`VaultLocalBackend`], which is what the handler holds instead: a
//! `StorageBackend` that serves nothing, counts what it was asked for, and
//! refuses at exactly the point a fetch is genuinely required — which R16's
//! `prepare → build` split already places before the consent gate.
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
/// blaming the missing feature would be a lie in a build that has it. They
/// are [`BackendArm`]'s, and R82 moved them there **without** deleting the
/// divergence — that would have been a retraction of this paragraph, which
/// R82 requires to be argued rather than slipped in as a snapshot repair.
/// This function is the arm selector and nothing else.
///
/// Public so U3's registered `--json` fixture can render the **real**
/// refusal instead of a hand-copied one. It had a copy, and the copy went
/// stale the moment this message changed — a snapshot documenting text no
/// build produces is worse than no snapshot (U19 made the same call for
/// `list`: the fixture is rendered by the real renderer).
#[must_use]
pub fn unavailable(command: &str) -> CliError {
    unavailable_arm(command, BackendArm::THIS_BUILD)
}

/// Which storage-backend arm a build is — **R82's ruling, arm (b)**.
///
/// # Why this enum exists at all
///
/// [`unavailable`] used to select its sentence with `#[cfg]` *inside* the
/// function, so only one of the two texts existed in any given compilation.
/// That made the committed `--json` fixture unable to document both builds:
/// `tests/snapshots/json-envelopes.txt` is one file compared byte-for-byte,
/// and under `--features ant-backend` the registered documents that route
/// through this function rendered different bytes, so the snapshot test
/// failed in that build and *whichever* build it documented, the other
/// build's machine surface was pinned by nothing (R82).
///
/// R82 offered three arms: a second committed snapshot, a
/// **feature-parameterised** fixture, or one feature-invariant sentence.
/// Arm (b) is taken. The two sentences say different true things and
/// deleting that is a retraction of a recorded design choice, so (c) is
/// out; and a second committed file (a) answers R82's own question badly —
/// Q153 keeps `heavy-features` local-only, so a snapshot only the
/// feature-ON build compares is a file no CI job ever reads.
///
/// Arm (b) turns that around. Both messages are compiled into **both**
/// builds and the fixture renders both arms explicitly, so:
///
/// 1. one committed file carries both texts,
/// 2. the two builds render byte-identical fixture documents, so
///    `envelope_fixtures_match_the_committed_snapshot` is green in both,
///    and
/// 3. the **default** build — the one every CI job runs — is what witnesses
///    the feature-ON sentence, which is the property R82 says nothing had.
///
/// [`unavailable`] is still the only production entry, and it is exactly
/// `unavailable_arm(command, THIS_BUILD)`, so the fixture renders through
/// the real producer (U3's rule) rather than a hand-copied string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendArm {
    /// No storage backend is compiled in (the default feature set).
    NotCompiled,
    /// A storage backend is compiled in, but the command has no wiring
    /// that constructs one.
    Compiled,
}

impl BackendArm {
    /// Every arm, so a scan or a fixture cannot silently document one.
    pub const ALL: [Self; 2] = [Self::NotCompiled, Self::Compiled];

    /// The arm **this** build is.
    #[cfg(not(feature = "ant-backend"))]
    pub const THIS_BUILD: Self = Self::NotCompiled;

    /// The arm **this** build is.
    #[cfg(feature = "ant-backend")]
    pub const THIS_BUILD: Self = Self::Compiled;

    /// A stable identifier for the arm — fixture headers and failure
    /// messages, never user copy.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotCompiled => "no-backend-compiled-in",
            Self::Compiled => "backend-compiled-in-command-unwired",
        }
    }

    /// This arm's refusal sentence for `command`.
    ///
    /// **Names no task row, by rule.** The feature-ON sentence used to end
    /// *"connecting it to this command's argument handling lands with U13"*
    /// — and U13 shipped, so the message sent a user to closed work. Three
    /// independent lanes reported it before it was fixed, which is what
    /// makes it a standing defect rather than a stale comment. A refusal a
    /// user reads cannot cite an identifier only this repository can
    /// resolve, and a citation that is true today rots the moment the row
    /// closes; so the pending work is named in prose and
    /// `the_refusal_messages_name_no_task_row` holds the rule in **both**
    /// builds.
    #[must_use]
    pub fn message(self, command: &str) -> String {
        match self {
            Self::NotCompiled => format!(
                "`{command}` needs a live Autonomi connection, and this build has no storage \
                 backend compiled in (the `ant-backend` feature is off by default). The command \
                 itself is complete — rebuild with `--features ant-backend` to reach the network"
            ),
            // S17 update: the seam is no longer merely built —
            // `tests/e2e_devnet.rs` drives it against a live devnet, so
            // "resolving the endpoint lands with the devnet harness" stopped
            // being true the moment that suite went green. What is actually
            // missing for a *command* is its own wiring, and that is what
            // the refusal names — in prose, because pointing a user at a
            // task identifier sends them looking for something they cannot
            // look up, and at a task that has already shipped if it closes.
            Self::Compiled => format!(
                "`{command}` has a storage backend compiled in, but this command does not \
                 construct one yet: the construction seam exists and the devnet harness drives \
                 it end to end — connecting this command to it is still to come. Nothing is \
                 wrong with the network"
            ),
        }
    }
}

/// [`unavailable`]'s refusal for a **named** arm rather than for this build.
///
/// The production path never calls this directly — it calls [`unavailable`],
/// which is `unavailable_arm(command, BackendArm::THIS_BUILD)`. It is `pub`
/// so the registered `--json` fixture can render **both** arms through the
/// real producer in either build (R82 arm (b); U3's rule).
#[must_use]
pub fn unavailable_arm(command: &str, arm: BackendArm) -> CliError {
    CliError::NetworkFailure {
        detail: arm.message(command),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The vault-local backend (U72's ruling)
// ─────────────────────────────────────────────────────────────────────────

/// A [`StorageBackend`] that serves **nothing** and says why.
///
/// # U72's ruling, and the question it answers
///
/// `reveal` used to return [`unavailable`] *unconditionally*, at entry,
/// before a work was resolved and before a selection was read. But R16's
/// gathering is **cache-first by ruling** (D43): every retained cache copy
/// is integrity-rechecked and used, and only a missing or corrupt copy is
/// refetched. So a work whose cache is intact needs **zero** network access,
/// and refusing at entry made the default build unable to disclose bytes
/// that were already on the user's own disk — for the command MVP-SPEC.md
/// line 36 puts at the centre of the product.
///
/// U72 asked four questions. They are answered here because this type is
/// the answer to all four.
///
/// **(i) Does a fully-cached reveal complete in a build with no backend at
/// all?** *Yes.* Not "in a build that has one and could not reach it" — the
/// default build compiles no `ant-core`, no runtime and no transport, and
/// this type is a zero-I/O local struct. The engine's dependency on a
/// backend is *conditional*, so satisfying the type obligation with a
/// backend that refuses every call is honest rather than a stub: a build
/// that cannot fetch is exactly a backend whose fetches fail.
///
/// **(ii) What about a partial cache?** *The whole reveal is refused at the
/// first genuinely-required fetch.* A cached subset is never disclosed
/// instead. The selection is the user's statement of what to disclose, and
/// silently narrowing it to whatever happens to be cached would make the
/// contents of a permanent, irrevocable artifact a function of cache state
/// rather than of intent — and under D70's promotion rule dropping a single
/// unit can flip a file from a full reveal to a partial one, changing what
/// the bundle *means*. Note the direction of D43's asymmetry: `restore` is
/// network-first because its job is to reconstruct what may be gone, while
/// `reveal`'s job is to disclose what the user already has. That is the
/// argument for the lazy refusal and the argument against a silent partial
/// subset, and it is one argument.
///
/// **(iii) Before or after the consent gate?** *Before* — and this needed no
/// code at all, which is worth recording rather than rediscovering. R16's
/// two-phase `prepare → build` split already puts all gathering inside
/// `prepare`, and [`crate::reveal_out::run_reveal`] calls the consent gate
/// on `prepare`'s *result*. So a required fetch fails while the bundle is
/// still un-previewed and the gate is never asked. That lands the refusal
/// exactly where D68 §3 R8 wants it — after the output path is resolved and
/// a collision refused, before the gate — and it is the analogue of D68's
/// own clause: nobody consents to a disclosure that cannot be written, and
/// nobody consents to a disclosure that cannot be gathered.
///
/// **(iv) Does the message or the class change?** The class does **not**:
/// `RevealError::Unfetchable` already maps to
/// [`CliError::NetworkFailure`](crate::error::CliError::NetworkFailure)
/// (D69 §5 group 2, exit 23), and from the caller's side that is precisely
/// what this is — bytes that cannot be obtained. Minting a second class for
/// it would split one user-visible situation across two codes. The
/// *message* does change, and it is [`BackendArm::message`]'s — the same
/// two sentences [`unavailable`] uses, so a build that has a backend and a
/// build that has none say different true things here too, and the reveal
/// engine's own wrapper names the unit that could not be served.
///
/// # The instrument (U72's Accept)
///
/// [`Self::refusals`] counts calls **at the seam**. U72 requires the
/// zero-backend-call claim to be measured rather than inferred from a green
/// result, and a reveal that completed *because* nothing was fetched and a
/// reveal that completed *although* something was fetched are
/// indistinguishable from the outside. The counter costs one relaxed atomic
/// increment on a path that is already refusing.
#[derive(Debug)]
pub struct VaultLocalBackend {
    /// The command named in the refusal.
    command: &'static str,
    /// How many times any seam method was reached.
    refusals: std::sync::atomic::AtomicUsize,
}

impl VaultLocalBackend {
    /// A backend for `command` that refuses every call.
    #[must_use]
    pub const fn new(command: &'static str) -> Self {
        Self {
            command,
            refusals: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// How many seam calls this backend has refused — zero for a run
    /// served entirely from the D43 cache.
    #[must_use]
    pub fn refusals(&self) -> usize {
        self.refusals.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Count the call and produce the refusal.
    fn refuse(&self) -> antseal_net::StorageError {
        self.refusals
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        antseal_net::StorageError::Network {
            reason: BackendArm::THIS_BUILD.message(self.command),
        }
    }
}

impl antseal_net::StorageBackend for VaultLocalBackend {
    async fn quote_batch(
        &self,
        _blobs: &[antseal_net::Blob],
    ) -> Result<antseal_net::CostQuote, antseal_net::StorageError> {
        Err(self.refuse())
    }

    async fn pay(
        &self,
        _quote: &antseal_net::CostQuote,
    ) -> Result<antseal_net::PaymentReceipt, antseal_net::StorageError> {
        Err(self.refuse())
    }

    async fn finalize_batch(
        &self,
        _receipt: &antseal_net::PaymentReceipt,
        _blobs: &[antseal_net::Blob],
    ) -> Result<Vec<antseal_net::Address>, antseal_net::StorageError> {
        Err(self.refuse())
    }

    async fn get_data(
        &self,
        _address: antseal_net::Address,
    ) -> Result<Vec<u8>, antseal_net::StorageError> {
        Err(self.refuse())
    }

    async fn balances(&self) -> Result<antseal_net::BalanceReport, antseal_net::StorageError> {
        Err(self.refuse())
    }
}

/// Drive a future that performs **no I/O** to completion, without a runtime.
///
/// U72's vault-local path is async only because the engine it calls is
/// generic over a [`StorageBackend`] and that trait is async. Over
/// [`VaultLocalBackend`] nothing in the whole future can block: every
/// gather either reads the vault synchronously or takes the refusing arm,
/// which is `Ready` on the spot. So the future is complete on its **first**
/// poll, and a single poll with a no-op waker is a total, honest driver for
/// it.
///
/// A `Pending` is therefore a bug rather than a wait, and it is reported as
/// one instead of being spun on: a loop with a no-op waker would busy-spin
/// forever on a future that genuinely parked, which is a hang wearing the
/// costume of a driver. This is the one place the crate can say "that
/// cannot happen" and still be safe if it does.
///
/// tokio stays where it is — `optional = true`, activated only by
/// `ant-backend` — so the default dependency graph the `dep-graph` lane
/// measures is byte-for-byte unchanged by U72. A `reveal` that needs no
/// network must not drag in a reactor to prove it.
///
/// # Errors
///
/// [`CliError::Internal`](crate::error::CliError::Internal) if the future
/// parks, which over a [`VaultLocalBackend`] it cannot.
pub fn block_on_vault_local<F: core::future::Future>(future: F) -> Result<F::Output, CliError> {
    let mut future = core::pin::pin!(future);
    let mut context = core::task::Context::from_waker(core::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        core::task::Poll::Ready(value) => Ok(value),
        core::task::Poll::Pending => Err(CliError::Internal {
            detail: "the vault-local path parked on a future that needs a runtime; it is \
                     specified to perform no I/O and to complete on its first poll"
                .to_owned(),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The payment-RPC block-number source (U67's gated half)
// ─────────────────────────────────────────────────────────────────────────

/// Open a payment-RPC session for D33's block-number backfill, or say why
/// not — **U67's whole feature-gated surface**.
///
/// # Why this function is three lines of policy and nothing else
///
/// `antseal_net::AntCoreBackend::backfill_block_numbers` is the only code
/// that can resolve an empty `block_number` slot, and the only door to it is
/// `AntCoreBackend::connect` — a full Autonomi `Client::connect` over the
/// bootstrap set plus the `eth_chainId` guard, all of it `ant-backend`-only.
/// If U67's host were written against that directly, then the read, the
/// empty-slot test, the idempotence, the compare-and-set write and the
/// silence would all live behind a feature Q153 keeps out of CI, and one
/// machine would be their only witness for as long as that stays true.
///
/// So the policy lives ungated in
/// [`crate::pipeline::receipt_backfill`] over the
/// [`BlockNumberSource`](crate::pipeline::receipt_backfill::BlockNumberSource)
/// trait, and this is the bridge. It is exactly the split
/// [`crate::pipeline::VaultReceiptSink`] already uses for D37's durability
/// guarantee, and for the reason recorded there: a body placed on this side
/// of the gate is a body only S22's tier-2 sweep ever compiles.
///
/// # It is called only when there is something to fill
///
/// The caller counts empty slots first and returns before reaching here if
/// there are none, so a healthy work never opens a network session. That
/// ordering is what lets `status` host the pass without becoming a command
/// that dials (see the caller's docs).
///
/// `network` is the **work's own** recorded network, not the invocation's
/// `--network`: the payment landed on one chain and its receipt is
/// resolvable only there.
///
/// Every failure arm returns `None` after a `debug` trace. There is no
/// `Result`, because there is no caller that may fail on this.
#[cfg(not(feature = "ant-backend"))]
pub fn payment_rpc(
    _vault: &crate::vault::session::UnlockedVault,
    network: &str,
) -> Option<Box<dyn crate::pipeline::receipt_backfill::BlockNumberSource>> {
    tracing::debug!(
        network,
        arm = BackendArm::THIS_BUILD.name(),
        "no payment RPC: this build compiles no storage backend, so D33's block-number \
         enrichment cannot run. Rebuild with `--features ant-backend`"
    );
    None
}

/// Open a payment-RPC session for D33's block-number backfill, or say why
/// not. See the default-build arm above for the whole argument; this is the
/// same function with a backend to open.
#[cfg(feature = "ant-backend")]
pub fn payment_rpc(
    vault: &crate::vault::session::UnlockedVault,
    network: &str,
) -> Option<Box<dyn crate::pipeline::receipt_backfill::BlockNumberSource>> {
    ant::payment_rpc(vault, network)
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
    use antseal_net::wallet::WalletKey;
    use antseal_net::{
        Address, AntCoreBackend, BalanceReport, Blob, CaptureHook, CostQuote, NetworkConfig,
        PaymentReceipt, StorageBackend, StorageError,
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

    /// **The production sink** (D37 Decision 7 / S31): each sub-batch
    /// receipt is written to the vault journal *inline*, so `pay`'s loop
    /// cannot submit the next transaction until the last one is on disk.
    ///
    /// The bridge is three lines on purpose. Everything the sink actually
    /// does — the `Arc<UnlockedVault>` sharing, the `Mutex`, U9's atomic
    /// write, the arming contract, the fault slot — lives **ungated** in
    /// [`crate::pipeline::receipt_sink`], where the default required lane
    /// compiles and tests it. Putting the body here would have made the
    /// one implementation of D37's durability guarantee visible only to
    /// S22's tier-2 sweep, which is exactly the gap S30 is open on and
    /// D89 overturned for the wallet primitives.
    impl ReceiptSink for crate::pipeline::VaultReceiptSink {
        fn capture(&self, receipt: &PaymentReceipt) {
            Self::capture(self, receipt);
        }
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
    /// # `new_multi_thread` is load-bearing, not a default (D90 §3.3, Q84)
    ///
    /// `antseal-anchor` is **blocking** — it owns no runtime and requires no
    /// async context, which is what lets A15/U24's upgrade hook run in a
    /// build with no tokio compiled in (see that crate's docs, which point
    /// back here). The price is one coupling: when an anchor call is made
    /// from inside this runtime's `block_on`, the calling thread sits in a
    /// socket syscall. That is safe **only** on a multi-thread runtime,
    /// where ant-core's spawned tasks keep progressing on worker threads.
    /// On `new_current_thread` they would starve, and the symptom — a seal
    /// that hangs or times out — would surface nowhere near this line.
    ///
    /// One word here is therefore a silent behavioural change, so the
    /// invariant is asserted rather than described:
    /// `anchor_blocking_calls_require_a_multi_thread_runtime` checks the
    /// flavour tag and
    /// `a_spawned_task_progresses_while_the_runtime_thread_blocks` checks
    /// the property the tag stands for. Both live in this file's `tests`
    /// module, and `scripts/gate-features.sh`'s `HEAVY_TRIGGER_PATHS` names
    /// this file so that editing it actually runs them.
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

    /// What one leg of U67's enrichment may spend before it is abandoned.
    ///
    /// **U24's first rule is *never delay the host command*, and this is what
    /// makes that a bound rather than a hope.** The enrichment runs *before*
    /// `status` renders — deliberately, so one invocation both closes the gap
    /// and shows it closed — which is a stricter position than U24's hook
    /// occupies: the hook runs after every byte of output is written, so its
    /// budget protects only the process exit, while this one protects the
    /// **answer**. Without a deadline an unreachable bootstrap set would sit
    /// in ant-quic's own timeout with a user watching a blank terminal.
    ///
    /// Deliberately larger than `UpgradeBudget::opportunistic`'s 3 s: this
    /// leg is an Autonomi `Client::connect` and a chain read, not a calendar
    /// GET, and the user asked for this work by name. Applied to each of the
    /// two legs, so the worst case a `status` can absorb is 20 s — and
    /// absorbing it costs nothing but a retry, because a timed-out
    /// enrichment is the same silent skip every other failure is.
    const PAYMENT_RPC_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

    /// A payment-RPC session, adapted to the ungated backfill seam (U67).
    ///
    /// Holds its own runtime because the trait method is **synchronous**:
    /// the host that calls it is ordinary `status` code in a crate whose
    /// tokio edge is `optional = true`, and making the seam async would
    /// have pushed a runtime requirement into the default build for a
    /// feature it does not compile.
    struct PaymentRpc {
        backend: SealBackend,
        runtime: tokio::runtime::Runtime,
    }

    impl crate::pipeline::receipt_backfill::BlockNumberSource for PaymentRpc {
        fn backfill(&self, receipt: &mut PaymentReceipt) -> Result<usize, String> {
            self.runtime.block_on(async {
                match tokio::time::timeout(
                    PAYMENT_RPC_BUDGET,
                    self.backend.backfill_block_numbers(receipt),
                )
                .await
                {
                    Ok(result) => result.map_err(|error| error.to_string()),
                    // Not "the RPC said no" — "the RPC did not answer in the
                    // time a `status` may spend". Same silent skip, retried.
                    Err(_elapsed) => Err(format!(
                        "the payment RPC did not answer within {}s",
                        PAYMENT_RPC_BUDGET.as_secs()
                    )),
                }
            })
        }
    }

    /// Build the session, or trace which arm refused and return `None`.
    ///
    /// The order is the one `seal_over_backend` already uses and for the
    /// same reason — the network definition before the key, the key before
    /// the connection — except that nothing here may prompt or fail: this
    /// runs inside a command that has already answered the user.
    pub fn payment_rpc(
        vault: &crate::vault::session::UnlockedVault,
        network: &str,
    ) -> Option<Box<dyn crate::pipeline::receipt_backfill::BlockNumberSource>> {
        use core::str::FromStr as _;

        let network_id = antseal_net::NetworkId::from_str(network)
            .inspect_err(|error| {
                tracing::debug!(
                    network,
                    %error,
                    "no payment RPC: this work records a network this build cannot resolve"
                );
            })
            .ok()?;
        let config = NetworkConfig::select(network_id, crate::commands::devnet_env().as_ref())
            .inspect_err(|error| {
                tracing::debug!(
                    network,
                    %error,
                    "no payment RPC: the work's network has no usable definition here"
                );
            })
            .ok()?;
        let handle = match crate::vault::wallet::load_wallet_key(vault) {
            Ok(Some(handle)) => handle,
            // A real and likely arm, not a leftover: a vault created by an
            // older build holds no wallet record, and it must be traced
            // distinctly from an unreadable one so a reader of `RUST_LOG`
            // can tell "nothing to sign with" from "the record is damaged".
            Ok(None) => {
                tracing::debug!(
                    "no payment RPC: this vault holds no wallet key, so no payment endpoint can \
                     be opened for it"
                );
                return None;
            }
            Err(error) => {
                tracing::debug!(%error, "no payment RPC: the vault's wallet record is unreadable");
                return None;
            }
        };
        let key = wallet_key(&handle)
            .inspect_err(|error| {
                tracing::debug!(%error, "no payment RPC: the vault's wallet key is unusable");
            })
            .ok()?;
        let runtime = runtime()
            .inspect_err(|error| {
                tracing::debug!(%error, "no payment RPC: no async runtime could be started");
            })
            .ok()?;
        // Bounded: see `PAYMENT_RPC_BUDGET`. An unreachable bootstrap set
        // must cost `status` a deadline, not ant-quic's own timeout.
        let backend = runtime
            .block_on(async {
                tokio::time::timeout(
                    PAYMENT_RPC_BUDGET,
                    SealBackend::connect(&config, &key, Arc::new(ReadOnly) as Arc<dyn ReceiptSink>),
                )
                .await
                .map_err(|_elapsed| CliError::NetworkFailure {
                    detail: format!(
                        "the payment endpoint did not answer within {}s",
                        PAYMENT_RPC_BUDGET.as_secs()
                    ),
                })?
            })
            .inspect_err(|error| {
                tracing::debug!(
                    network,
                    %error,
                    "no payment RPC: the payment endpoint could not be reached"
                );
            })
            .ok()?;
        Some(Box::new(PaymentRpc { backend, runtime }))
    }

    pub use sealed::SealBackend;

    /// The private module is the enforcement: `SealBackend`'s field is
    /// visible only in here, and the only function in here that builds
    /// one is `connect`. Nothing outside — not even the rest of this
    /// module — can write `SealBackend { .. }`.
    mod sealed {
        // `BalanceReport` joined this list with U13. D89/U37 added
        // `balances()` to the `StorageBackend` trait and the delegating
        // impl below, but not to this `use` — and because every item in
        // this module is behind the non-default `ant-backend` feature, a
        // default `cargo check --workspace` never compiled the mistake.
        // U13 is the first work to build the feature since, and found it
        // red at `b11be2f`. (Cross-lane touch: this file is the S31
        // lane's; the change is one identifier and no behaviour.)
        use super::{
            Address, AntCoreBackend, Arc, BalanceReport, Blob, CaptureHook, CliError, CostQuote,
            NetworkConfig, PaymentReceipt, ReceiptSink, StorageBackend, StorageError, WalletKey,
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

            /// Forward S7's forced sub-batch cap to the inner backend.
            ///
            /// **Not a second door.** This consumes an existing
            /// `SealBackend` and returns one, so it cannot bring a backend
            /// into being — [`SealBackend::connect`] is still the only
            /// expression that can, and it still installs the hook. The
            /// module's guarantee is about the *hook*, and this cannot
            /// touch it; the "no second constructor" sentence above stays
            /// literally true.
            ///
            /// It exists because D37's multi-tx payment protocol is
            /// otherwise unreachable on a devnet without a 257-blob work
            /// (`MAX_TRANSFERS_PER_TRANSACTION = 256`). Upstream clamps
            /// the value into `1..=256`, so this can only ever make
            /// batches *smaller* — no caller can widen the protocol cap
            /// through it. S18's case (1b) is the consumer.
            #[must_use]
            pub fn with_max_transfers_per_tx(mut self, cap: usize) -> Self {
                self.inner = self.inner.with_max_transfers_per_tx(cap);
                self
            }

            /// The hook `connect` installs, exposed so a test can fire it
            /// without a network. Constructing one does **not** construct
            /// a backend — this is the adapter, not a second door.
            pub fn hook_for(receipts: Arc<dyn ReceiptSink>) -> CaptureHook {
                hook(receipts)
            }

            /// D33's idempotent block-number backfill, delegated (U67).
            ///
            /// Not part of [`StorageBackend`] — upstream's adapter carries
            /// it as an inherent method, deliberately, because it is a
            /// read-only payment-RPC enrichment and not a storage
            /// operation. It is exposed here for the same reason every
            /// other method on this wrapper is: `AntCoreBackend` may be
            /// named in this file and nowhere else
            /// (`the_raw_backend_type_is_named_in_exactly_one_file`), so a
            /// caller that wanted it directly would have to reach past the
            /// D37 construction guarantee to get it.
            ///
            /// # Errors
            ///
            /// Whatever the payment RPC returns — network class only. The
            /// caller is required to treat it as a skip: D33 Decision 2
            /// makes enrichment non-gating.
            pub async fn backfill_block_numbers(
                &self,
                receipt: &mut PaymentReceipt,
            ) -> Result<usize, StorageError> {
                self.inner.backfill_block_numbers(receipt).await
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

            async fn balances(&self) -> Result<BalanceReport, StorageError> {
                self.inner.balances().await
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

    /// D90 §3.3's coupling, asserted from the side that owns it (Q84).
    ///
    /// `antseal-anchor` is blocking, so an anchor call made from inside
    /// this runtime parks the calling thread in a socket syscall. That is
    /// safe only because the runtime is `new_multi_thread`. The check runs
    /// from *inside* `block_on`, because the flavour that matters is the
    /// one an anchor call would actually be executing under, not whatever
    /// the builder was asked for.
    #[cfg(feature = "ant-backend")]
    #[test]
    fn anchor_blocking_calls_require_a_multi_thread_runtime() {
        use tokio::runtime::{Handle, RuntimeFlavor};

        let rt = super::runtime().expect("runtime builds");
        rt.block_on(async {
            assert_eq!(
                Handle::current().runtime_flavor(),
                RuntimeFlavor::MultiThread,
                "backend::ant::runtime() is no longer new_multi_thread. antseal-anchor is \
                 blocking (D90 §3.3): on a current-thread runtime, ant-core's spawned tasks \
                 starve while an anchor call sits on a socket, and the symptom is a seal that \
                 hangs far from this cause"
            );
        });
    }

    /// The property the flavour tag stands for, asserted directly (Q84).
    ///
    /// A tag comparison would still pass if some future tokio grew a third
    /// flavour that reports `MultiThread` without workers. What D90 §3.3
    /// actually relies on is *progress*: a spawned task must run while the
    /// thread inside `block_on` is blocked in a synchronous call — which is
    /// precisely the shape of a `ureq` request. `std::thread::sleep` and a
    /// std channel are used deliberately: an `.await` would yield to the
    /// scheduler and prove nothing.
    ///
    /// Bounded by `recv_timeout`, so the current-thread failure mode is a
    /// failed assertion rather than a hung suite.
    #[cfg(feature = "ant-backend")]
    #[test]
    fn a_spawned_task_progresses_while_the_runtime_thread_blocks() {
        use std::sync::mpsc;
        use std::time::Duration;

        let rt = super::runtime().expect("runtime builds");
        rt.block_on(async {
            let (tx, rx) = mpsc::channel::<()>();
            tokio::spawn(async move {
                let _ = tx.send(());
            });
            // Blocking, not awaiting: this models an anchor HTTP call.
            std::thread::sleep(Duration::from_millis(20));
            rx.recv_timeout(Duration::from_secs(5)).expect(
                "a spawned task made no progress while the block_on thread was blocked in a \
                 synchronous call — the runtime has no worker threads, so every blocking \
                 antseal-anchor call from inside it would deadlock ant-core's tasks (D90 §3.3)",
            );
        });
    }
}
