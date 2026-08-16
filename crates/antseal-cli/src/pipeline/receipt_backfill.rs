//! **U67 — the production host for D33's block-number backfill.**
//!
//! MVP-SPEC.md line 69 (the receipt's block number), line 110 (captured at
//! payment time), line 114 (the reveal bundle's opt-in receipt), line 137
//! (the supporting-evidence class). The ruling this serves is
//! `docs/decisions/D33-block-number-locus.md` — Decision 2 in particular,
//! whose *"every subsequent invocation of the pipeline retries enrichment
//! idempotently"* named an event nothing in the product performed.
//!
//! # The defect this closes
//!
//! [`TxRecord::block_number`](antseal_net::TxRecord) is D33's **enrichment
//! slot**: filled from the receipt `pay()` awaits, `None` when that read
//! failed. `antseal-net`'s ant-core adapter carries `backfill_block_numbers`,
//! which implements the repair and is documented as idempotent — and until
//! U67 its only callers in the whole tree were two lines in a devnet test.
//! No command re-enters the payment path once a work is `Complete`, and
//! A15/U24's opportunistic hook walks *anchors*, never receipts. So *"later
//! invocations"* named nothing.
//!
//! (The adapter's **type name** is deliberately not spelled anywhere in this
//! module. `backend.rs`'s `the_raw_backend_type_is_named_in_exactly_one_file`
//! matches text, so naming it in prose would register this file as a second
//! place able to build a backend with no D37 capture hook. That scan caught
//! an earlier draft of this very paragraph, which is the scan working.)
//!
//! The consequence is user-visible: bundle registry §7.10 key 1 is
//! **required** and is defined as the minimum block number across the
//! receipt's transactions, so R16 refuses `reveal --include-receipt` with
//! `RevealError::ReceiptBlockNumberUnknown` when every slot is empty —
//! correctly, because fabricating `0` would put an unverified number in a
//! display field. That refusal stays. What U67 removes is its
//! **permanence**: a work whose enrichment failed once could never embed
//! its receipt again, for the life of the vault.
//!
//! # Why the slot can be `None`, and what re-fills it
//!
//! `None` means the payment landed but the receipt read did not: an
//! interrupted await, an RPC blip, a crash in the post-pay window. The tx
//! *hash* is the load-bearing capture (D33 residual risk 1) and is always
//! journaled; the block number is re-derivable from it forever, which is
//! exactly why enrichment is allowed to be lazy. What re-fills it is
//! [`enrich_recorded_receipt`], hosted by `status <work-id>` — see that
//! function's own docs for the argument, and `crate::commands::status` for
//! the call site.
//!
//! # Non-gating, by construction (D33 Decision 2 / U24's rules)
//!
//! Nothing here returns a `Result`. There is no expression through which a
//! backfill outcome could reach the host command's exit status or its
//! output, which is the same structural guarantee
//! [`crate::upgrade_hook::run_after_output`] gives one command layer up.
//! Every failure — no RPC, an unreachable endpoint, a contended lock, a
//! failed write — is a silent [`BackfillSkip`] traced at `debug` on this
//! module's own target, and is retried by the next invocation. A user is
//! never prompted and never delayed for a receipt that is already complete:
//! the *source is not even constructed* unless an empty slot was found.
//!
//! # Hygiene (S7, normative on `PaymentReceipt`)
//!
//! No receipt field may enter a log or an error message — receipts are
//! wallet-linkable on a public chain. Everything traced here is a **count**.
//! The one string that passes through is the source's own failure text,
//! which `antseal-net`'s adapter has already classified: its
//! `eth_getTransactionReceipt` path returns only the network class, and that
//! module's header rule is that payment-class strings are redacted to their
//! class name while network-class ones pass through.

use antseal_core::crypto::secrets::SealId;
use antseal_net::PaymentReceipt;
use rand_core::TryCryptoRng;

use super::receipt_sink::{encode_receipt, recorded_receipt};
use crate::vault::layout::BesideFile;
use crate::vault::lock::VaultLock;
use crate::vault::session::UnlockedVault;
use crate::vault::store::WorkStore;

/// Something that can resolve empty block-number slots over the payment RPC.
///
/// # Why this trait exists rather than a direct call
///
/// The one implementation that reaches a chain is `backfill_block_numbers`
/// on `antseal-net`'s ant-core adapter, and the only door to that adapter is
/// its own `connect`, which is `ant-backend`-only. A host written
/// directly against it would put **all** of U67 — the read, the empty-slot
/// test, the idempotence, the compare-and-set write, the silence — inside a
/// feature Q153 keeps out of CI, where one machine would be its only
/// witness, ever.
///
/// So the seam is this trait, and the split is
/// [`crate::pipeline::receipt_sink::VaultReceiptSink`]'s verbatim: the
/// policy lives here, ungated, compiled and tested by the default required
/// lane; `crate::backend::payment_rpc` is the three-line gated bridge that
/// supplies the RPC. What the feature gate costs is then exactly one
/// constructor, not a design.
///
/// Implementations must not panic and must be idempotent: a slot they cannot
/// resolve is left `None` for a later invocation rather than guessed at.
pub trait BlockNumberSource {
    /// Fill what can be filled **in place**; return how many
    /// `block_number` slots went from `None` to `Some`.
    ///
    /// A transaction whose receipt is not yet visible is left untouched and
    /// is not an error — that is a retry, not a failure.
    ///
    /// # Errors
    ///
    /// A human-readable class for the RPC being unusable. The caller
    /// **never** turns this into a command failure; it traces it and
    /// returns.
    fn backfill(&self, receipt: &mut PaymentReceipt) -> Result<usize, String>;
}

/// The line a hosting invocation emits when it had empty slots and tried.
///
/// A `pub const` rather than a literal because it is an **assertion
/// surface** — `tests/receipt_backfill.rs` reads it off the real binary's
/// debug trace to decide whether the production caller ran at all, and a
/// test that spelled the sentence itself would go green on the day the pass
/// stopped running and the line stopped being emitted. Exactly the role
/// [`crate::upgrade_hook::HOOK_ARMED`] plays for U24.
pub const BACKFILL_ATTEMPTED: &str = "receipt backfill: block-number enrichment attempted";

/// The line a hosting invocation emits when there was nothing to enrich —
/// the common case, and the reason `status` does not become a command that
/// dials.
pub const BACKFILL_NOT_NEEDED: &str =
    "receipt backfill: skipped, every recorded transaction already carries a block number";

/// Why a pass did nothing. Every arm is silent and retried; none is an
/// error, and none reaches the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackfillSkip {
    /// The work has no journaled receipt, or the record could not be read.
    /// A work that never paid is the common case and is not a defect.
    NoRecord,
    /// Every transaction already carries a block number. **This is the
    /// idempotence arm**: a second pass over an enriched work stops here,
    /// before any source is constructed, so the repeat costs no RPC at all.
    NothingUnfilled,
    /// This build compiles no payment RPC, or one could not be opened
    /// (no wallet key, an unusable network definition, an unreachable
    /// endpoint). `crate::backend::payment_rpc` traces which.
    NoSource,
    /// The RPC refused. Silent by D33 Decision 2 — enrichment never gates.
    SourceFailed,
    /// The RPC was reached and resolved nothing: the transactions are not
    /// visible yet. Retried on the next invocation.
    NothingFetched,
    /// Another process holds the U5 single-writer lock. The fetched values
    /// are discarded and recomputed next time (D99 R3's discipline).
    LockContended,
    /// The re-read under the lock found the slots already filled — a
    /// concurrent writer got there first. Nothing to do, and not a loss.
    AlreadyFilled,
    /// The record could not be re-encoded or written back.
    WriteFailed,
}

impl BackfillSkip {
    /// Every arm, so a trace, a match or an assertion cannot silently
    /// document one — the same anti-vacuity
    /// [`crate::backend::BackendArm::ALL`] exists for.
    pub const ALL: [Self; 8] = [
        Self::NoRecord,
        Self::NothingUnfilled,
        Self::NoSource,
        Self::SourceFailed,
        Self::NothingFetched,
        Self::LockContended,
        Self::AlreadyFilled,
        Self::WriteFailed,
    ];

    /// A stable identifier for the arm — debug traces and failure messages,
    /// never user copy.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoRecord => "no-record",
            Self::NothingUnfilled => "nothing-unfilled",
            Self::NoSource => "no-source",
            Self::SourceFailed => "source-failed",
            Self::NothingFetched => "nothing-fetched",
            Self::LockContended => "lock-contended",
            Self::AlreadyFilled => "already-filled",
            Self::WriteFailed => "write-failed",
        }
    }
}

/// What one backfill pass did.
///
/// Returned as **data** so a suite can assert on a pass without reading
/// stderr — the shape [`crate::upgrade_hook::HookPass`] already uses. It is
/// not a `Result` and carries no error: there is deliberately nothing here
/// for a future edit to propagate into an exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackfillPass {
    /// Empty slots seen in the first (unlocked) read.
    pub unfilled: usize,
    /// Slots the source resolved.
    pub fetched: usize,
    /// Slots actually written onto the record re-read under the lock. May
    /// be fewer than [`Self::fetched`] if a concurrent writer filled some.
    pub applied: usize,
    /// Whether the enriched record reached the disk.
    pub written: bool,
    /// Why the pass stopped early, if it did. `None` means it wrote.
    pub skip: Option<BackfillSkip>,
}

impl BackfillPass {
    /// A pass that stopped at `skip` having done nothing.
    const fn skipped(skip: BackfillSkip) -> Self {
        Self {
            unfilled: 0,
            fetched: 0,
            applied: 0,
            written: false,
            skip: Some(skip),
        }
    }
}

/// How many of this receipt's transactions carry no block number.
///
/// The predicate the whole pass keys on, and the one R16 inverts: registry
/// §7.10 key 1 is the **minimum** over the recorded block numbers, so a
/// receipt is embeddable as soon as *one* transaction has one — but a
/// backfill is worth attempting while *any* is missing, because the minimum
/// can only fall as slots fill and an under-reported minimum would misstate
/// when the payment landed.
#[must_use]
pub fn unfilled_block_numbers(receipt: &PaymentReceipt) -> usize {
    receipt
        .txs
        .iter()
        .filter(|tx| tx.block_number.is_none())
        .count()
}

/// **The production entry** — one work's opportunistic block-number
/// enrichment, hosted by `status <work-id>`.
///
/// # Why `status`, argued rather than assumed (U67's `Do` names two)
///
/// U67 offers the A15/U24 every-invocation hook or `status`, and calls the
/// hook *"the natural one"*. Measured against the tree on 2026-08-16, it is
/// not, and the measurement is the argument:
///
/// 1. **`status` is already the receipt's reader, and its only renderer.**
///    `crate::status::WorkStatus::gather` decodes the journaled receipt and
///    renders `block_numbers` — the very field this repairs. Every other
///    command in the surface renders nothing of it. So the repair sits
///    where the value is displayed, one read apart, and a single
///    `status <id>` both closes the gap and shows it closed (the pass runs
///    before the gather, which is exactly why `--upgrade`'s own persist
///    does).
/// 2. **The hook cannot host it without changing what the hook is.** The
///    only door to the backfill is the ant-core adapter's `connect`, a
///    full Autonomi `Client::connect` over the bootstrap set plus an
///    `eth_chainId` guard. U24's pass is budgeted at 3 s across *every work
///    in the vault* for cheap calendar GETs, and D90 §3.3 makes
///    `antseal-anchor` blocking precisely so that pass runs in a build with
///    **no tokio compiled in**. Hosting a payment-RPC session there would
///    put an Autonomi connect at the end of every `list`, and U24's first
///    rule is *never delay the host command*.
/// 3. **`status <work-id>` is scoped to a work the user named.**
///    `crate::status`'s own module docs already draw this line for
///    loudness: the hook is silent about a damaged record because it was
///    not asked, and `status` says so out loud because *"that is a command
///    the user ran about that work"*. Enrichment follows the same line, and
///    it is where a user lands after R16's refusal.
/// 4. **`status --upgrade` was refused as the host.** It is the existing
///    network arm, but its frozen help reads *"Poll OTS calendars and
///    upgrade pending attestations now"* — hosting a payment-RPC read under
///    it would make the shipped help false, and re-freezing
///    `cli-surface.help.txt` is U1's surface event, not this row's.
///
/// # What it costs when there is nothing to do
///
/// Nothing. The order is: read the record, count empty slots, and **return
/// before constructing a source** if there are none. A default build adds
/// one already-cached record read to `status`; an `ant-backend` build adds
/// a network session only for a work that is actually missing a block
/// number — which is the work the user is running `status` about.
///
/// # The race, closed by re-reading rather than by hope
///
/// The RPC round trip happens **unlocked** (D99 R3: the single-writer lock
/// exists to serialize writers, and holding it across a network call would
/// block a concurrent `seal`). A `seal --resume` could journal a fuller
/// receipt in that window, so the fetched values are applied to a record
/// **re-read under the lock**, matched by transaction hash, and only onto
/// slots still empty. Writing the pre-fetch snapshot back would clobber it.
pub fn enrich_recorded_receipt(vault: &UnlockedVault, seal_id: &SealId) -> BackfillPass {
    let pass = attempt(vault, seal_id);
    // Exactly one line per hosting invocation, naming the arm — the handle
    // `tests/receipt_backfill.rs` reads off the real binary to prove this
    // ran at all. Counts only: no receipt field may enter a log (S7).
    match pass.skip {
        Some(BackfillSkip::NothingUnfilled) => tracing::debug!("{BACKFILL_NOT_NEEDED}"),
        skip => tracing::debug!(
            unfilled = pass.unfilled,
            fetched = pass.fetched,
            applied = pass.applied,
            written = pass.written,
            skip = skip.map_or("none", BackfillSkip::name),
            "{BACKFILL_ATTEMPTED}"
        ),
    }
    pass
}

/// [`enrich_recorded_receipt`] without the trace, so the summary line has
/// exactly one emitter and every early return still reaches it.
fn attempt(vault: &UnlockedVault, seal_id: &SealId) -> BackfillPass {
    let store = WorkStore::new(vault);

    // Cheapest possible bail-out first: no receipt, or nothing missing.
    let receipt = match recorded_receipt(&store, seal_id) {
        Ok(Some(receipt)) => receipt,
        Ok(None) => return BackfillPass::skipped(BackfillSkip::NoRecord),
        Err(error) => {
            tracing::debug!(%error, "receipt backfill skipped: the journaled receipt is unreadable");
            return BackfillPass::skipped(BackfillSkip::NoRecord);
        }
    };
    let unfilled = unfilled_block_numbers(&receipt);
    if unfilled == 0 {
        return BackfillPass::skipped(BackfillSkip::NothingUnfilled);
    }

    // The work's OWN network, never the invocation's `--network`: the
    // payment happened on one chain and its receipt is only resolvable
    // there. A flag-resolved endpoint would query the wrong chain and
    // silently resolve nothing (or, worse, a colliding hash).
    let network = match store.load_meta(seal_id) {
        Ok(record) => record.network,
        Err(error) => {
            tracing::debug!(
                %error,
                "receipt backfill skipped: the work record does not name a network"
            );
            return BackfillPass {
                unfilled,
                skip: Some(BackfillSkip::NoSource),
                ..BackfillPass::default()
            };
        }
    };
    let Some(source) = crate::backend::payment_rpc(vault, &network) else {
        // `payment_rpc` has already traced which arm it took.
        return BackfillPass {
            unfilled,
            skip: Some(BackfillSkip::NoSource),
            ..BackfillPass::default()
        };
    };

    backfill_recorded_receipt(vault, seal_id, source.as_ref(), &mut crate::rng::OsEntropy)
}

/// The pass itself, over a supplied [`BlockNumberSource`].
///
/// Split from [`enrich_recorded_receipt`] at exactly the feature boundary:
/// everything here is compiled and driven by the **default** build, so the
/// idempotence, the compare-and-set and the silence are witnessed by every
/// CI job rather than by whoever last ran `--features ant-backend`. The
/// gated half is one constructor.
pub fn backfill_recorded_receipt<R: TryCryptoRng + ?Sized>(
    vault: &UnlockedVault,
    seal_id: &SealId,
    source: &dyn BlockNumberSource,
    rng: &mut R,
) -> BackfillPass {
    let store = WorkStore::new(vault);

    let mut snapshot = match recorded_receipt(&store, seal_id) {
        Ok(Some(receipt)) => receipt,
        Ok(None) => return BackfillPass::skipped(BackfillSkip::NoRecord),
        Err(error) => {
            tracing::debug!(%error, "receipt backfill skipped: the journaled receipt is unreadable");
            return BackfillPass::skipped(BackfillSkip::NoRecord);
        }
    };
    let unfilled = unfilled_block_numbers(&snapshot);
    if unfilled == 0 {
        return BackfillPass::skipped(BackfillSkip::NothingUnfilled);
    }

    // Unlocked: the RPC round trip must not hold the single-writer lock.
    let fetched = match source.backfill(&mut snapshot) {
        Ok(fetched) => fetched,
        Err(reason) => {
            // Traced, never raised. D33 Decision 2: enrichment never gates.
            tracing::debug!(
                %reason,
                unfilled,
                "receipt backfill skipped: the payment RPC could not be read"
            );
            return BackfillPass {
                unfilled,
                skip: Some(BackfillSkip::SourceFailed),
                ..BackfillPass::default()
            };
        }
    };
    if fetched == 0 {
        tracing::debug!(
            unfilled,
            "receipt backfill: no transaction is visible yet; retrying on a later invocation"
        );
        return BackfillPass {
            unfilled,
            skip: Some(BackfillSkip::NothingFetched),
            ..BackfillPass::default()
        };
    }

    // What the source resolved, keyed by transaction hash so it can be
    // replayed onto a record that may have moved underneath us. No receipt
    // field is logged from here on (S7).
    let resolved: std::collections::BTreeMap<[u8; 32], (Option<u64>, antseal_net::TxStatus)> =
        snapshot
            .txs
            .iter()
            .filter(|tx| tx.block_number.is_some())
            .map(|tx| (*tx.tx_hash.as_bytes(), (tx.block_number, tx.status)))
            .collect();

    let lock = match VaultLock::acquire(&vault.layout().beside_path(BesideFile::Lockfile)) {
        Ok(lock) => lock,
        Err(error) => {
            tracing::debug!(
                %error,
                "receipt backfill declined: another process holds the vault lock; the resolved \
                 values are discarded and recomputed on the next invocation"
            );
            return BackfillPass {
                unfilled,
                fetched,
                skip: Some(BackfillSkip::LockContended),
                ..BackfillPass::default()
            };
        }
    };

    // Re-read under the lock: the snapshot above is pre-RPC and a
    // concurrent `seal --resume` may have journaled a fuller record.
    let mut current = match recorded_receipt(&store, seal_id) {
        Ok(Some(receipt)) => receipt,
        Ok(None) | Err(_) => {
            drop(lock);
            return BackfillPass {
                unfilled,
                fetched,
                skip: Some(BackfillSkip::WriteFailed),
                ..BackfillPass::default()
            };
        }
    };
    let mut applied = 0usize;
    for tx in &mut current.txs {
        if tx.block_number.is_some() {
            continue;
        }
        if let Some((block_number, status)) = resolved.get(tx.tx_hash.as_bytes()) {
            tx.block_number = *block_number;
            tx.status = *status;
            applied += 1;
        }
    }
    if applied == 0 {
        drop(lock);
        return BackfillPass {
            unfilled,
            fetched,
            skip: Some(BackfillSkip::AlreadyFilled),
            ..BackfillPass::default()
        };
    }

    // The one encoder every writer of this record shares (S31).
    let outcome = encode_receipt(&current)
        .and_then(|bytes| store.put_receipt(seal_id, &bytes, rng).map_err(Into::into));
    drop(lock);
    match outcome {
        Ok(()) => {
            tracing::debug!(
                unfilled,
                fetched,
                applied,
                "receipt backfill: block numbers enriched and journaled (D33 Decision 2)"
            );
            BackfillPass {
                unfilled,
                fetched,
                applied,
                written: true,
                skip: None,
            }
        }
        Err(error) => {
            tracing::debug!(%error, "receipt backfill skipped: the enriched record was not written");
            BackfillPass {
                unfilled,
                fetched,
                applied,
                written: false,
                skip: Some(BackfillSkip::WriteFailed),
            }
        }
    }
}

#[cfg(test)]
/// U67's pass, driven over scripted [`BlockNumberSource`]s.
///
/// Everything here runs in the **default** build. That is the point of the
/// trait seam: the idempotence, the non-gating silence, the compare-and-set
/// write and the lock discipline are witnessed by every CI job, and the
/// `ant-backend` feature owns exactly one constructor
/// (`crate::backend::payment_rpc`) and nothing else.
///
/// Every scripted source below **counts its calls**, because the strongest
/// form of "running it twice changes nothing" is not "the second run wrote
/// the same bytes" — it is "the second run never asked the RPC at all", and
/// only a counter can tell those apart.
///
/// NON-SECRET: every byte here is a documented fixture (project rule 6) —
/// repeated-byte transaction hashes and a throwaway passphrase.
mod tests {

    use std::cell::Cell;

    use antseal_core::crypto::secrets::{MasterSecret, SealId, SecretBuf};
    use antseal_net::{GasSummary, PaymentReceipt, TxHash, TxRecord, TxStatus};

    use super::{
        BackfillSkip, BlockNumberSource, backfill_recorded_receipt, unfilled_block_numbers,
    };
    use crate::pipeline::journal::{SealJournal, WorkIdentity};
    use crate::pipeline::receipt_sink::recorded_receipt;
    use crate::pipeline::vault_journal::VaultJournal;
    use crate::vault::kdf::KdfSelection;
    use crate::vault::layout::{BesideFile, VaultLayout};
    use crate::vault::lock::VaultLock;
    use crate::vault::session::{UnlockedVault, create_vault, unlock_vault};
    use crate::vault::store::{SealShapingFlags, WorkStore};

    // ─────────────────────────────────────────────────────────────────────
    // Fixture
    // ─────────────────────────────────────────────────────────────────────

    /// NON-SECRET test passphrase.
    fn passphrase() -> SecretBuf {
        SecretBuf::new(b"receipt-backfill-test-passphrase".to_vec())
    }

    /// One transaction record tagged by a repeated-byte hash. NON-SECRET.
    fn tx(tag: u8, block_number: Option<u64>) -> TxRecord {
        TxRecord {
            tx_hash: TxHash::from_bytes([tag; 32]),
            block_number,
            status: if block_number.is_some() {
                TxStatus::Confirmed
            } else {
                TxStatus::Submitted
            },
            quote_hashes: Vec::new(),
        }
    }

    fn receipt_with(txs: Vec<TxRecord>) -> PaymentReceipt {
        PaymentReceipt {
            blobs: Vec::new(),
            tx_map: std::collections::BTreeMap::new(),
            txs,
            storage_cost_atto: 11,
            gas: GasSummary { gas_cost_wei: 3 },
        }
    }

    struct Fixture {
        dir: std::path::PathBuf,
        vault: UnlockedVault,
        seal_id: SealId,
    }

    impl Fixture {
        /// A vault holding one begun work whose journaled receipt carries two
        /// transactions, both with an **empty** block-number slot — the exact
        /// state U67 exists for.
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "antseal-u67-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            std::fs::create_dir_all(&dir).expect("mk fixture dir");
            let layout = VaultLayout::at(dir.join("vault"));
            let mut rng = crate::rng::OsEntropy;
            create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng)
                .expect("create vault");
            let vault = unlock_vault(&layout, &passphrase()).expect("unlock");

            let seal_id = SealId::generate(&mut rng).expect("seal id");
            let w = MasterSecret::generate(&mut rng).expect("W");
            let journal = VaultJournal::new(WorkStore::new(&vault), &mut rng);
            journal
                .begin(&WorkIdentity {
                    seal_id,
                    w: w.secret_ref(),
                    network: "devnet".to_owned(),
                    degraded: false,
                    unanchored: true,
                    input_paths_as_given: vec!["a.txt".to_owned()],
                    input_paths_absolute: vec!["/w/a.txt".to_owned()],
                    shaping: SealShapingFlags::default(),
                })
                .expect("begin");

            let fixture = Self {
                dir,
                vault,
                seal_id,
            };
            fixture.write(&receipt_with(vec![tx(0x11, None), tx(0x22, None)]));
            fixture
        }

        fn store(&self) -> WorkStore<'_> {
            WorkStore::new(&self.vault)
        }

        fn write(&self, receipt: &PaymentReceipt) {
            let bytes = super::encode_receipt(receipt).expect("encode");
            self.store()
                .put_receipt(&self.seal_id, &bytes, &mut crate::rng::OsEntropy)
                .expect("write");
        }

        fn read(&self) -> PaymentReceipt {
            recorded_receipt(&self.store(), &self.seal_id)
                .expect("read")
                .expect("journaled")
        }

        /// U9's record path for this work's receipt slot.
        ///
        /// The store keeps its own naming private, so this reproduces it — and
        /// every caller `expect`s the read, so a naming change is a loud
        /// failure here rather than a silent comparison of two absences.
        fn receipt_path(&self) -> std::path::PathBuf {
            use std::fmt::Write as _;
            let mut hex = String::with_capacity(32);
            for byte in self.seal_id.as_bytes() {
                let _ = write!(hex, "{byte:02x}");
            }
            self.vault.layout().works_dir().join(hex).join("receipt")
        }

        /// The on-disk record bytes — a byte-identity handle for the
        /// "nothing changed" claims. The ciphertext is randomized per write,
        /// so this proves **no write happened**, which is strictly stronger
        /// than proving the plaintext is equal.
        fn record_bytes(&self) -> Vec<u8> {
            std::fs::read(self.receipt_path()).expect("the record file exists")
        }

        fn run(&self, source: &dyn BlockNumberSource) -> super::BackfillPass {
            backfill_recorded_receipt(
                &self.vault,
                &self.seal_id,
                source,
                &mut crate::rng::OsEntropy,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Scripted sources
    // ─────────────────────────────────────────────────────────────────────

    /// Fills every empty slot with `base + index`, and counts how many times
    /// it was asked.
    struct Resolving {
        base: u64,
        calls: Cell<usize>,
    }

    impl Resolving {
        fn new(base: u64) -> Self {
            Self {
                base,
                calls: Cell::new(0),
            }
        }
    }

    impl BlockNumberSource for Resolving {
        fn backfill(&self, receipt: &mut PaymentReceipt) -> Result<usize, String> {
            self.calls.set(self.calls.get() + 1);
            let mut filled = 0;
            for (index, tx) in receipt.txs.iter_mut().enumerate() {
                if tx.block_number.is_none() {
                    tx.block_number = Some(self.base + index as u64);
                    tx.status = TxStatus::Confirmed;
                    filled += 1;
                }
            }
            Ok(filled)
        }
    }

    /// The RPC is down. The negative control for every non-gating claim.
    struct Failing {
        calls: Cell<usize>,
    }

    impl BlockNumberSource for Failing {
        fn backfill(&self, _receipt: &mut PaymentReceipt) -> Result<usize, String> {
            self.calls.set(self.calls.get() + 1);
            Err("eth_getTransactionReceipt failed: connection refused".to_owned())
        }
    }

    /// Reached, but nothing is visible on chain yet — the retry arm, which is
    /// deliberately not the failure arm.
    struct Silent;

    impl BlockNumberSource for Silent {
        fn backfill(&self, _receipt: &mut PaymentReceipt) -> Result<usize, String> {
            Ok(0)
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // The pass
    // ─────────────────────────────────────────────────────────────────────

    /// **U67 Accept row 1, the vault half.** A completed work whose records all
    /// carry `block_number: None` reaches a filled slot. (The `--include-receipt`
    /// half is asserted with it, over the real reveal engine, in
    /// `tests/receipt_backfill.rs` — the two halves are worthless apart.)
    #[test]
    fn an_empty_slot_is_filled_and_journaled() {
        let fx = Fixture::new("fill");
        assert_eq!(unfilled_block_numbers(&fx.read()), 2);

        let source = Resolving::new(900);
        let pass = fx.run(&source);

        assert_eq!(pass.unfilled, 2);
        assert_eq!(pass.fetched, 2);
        assert_eq!(pass.applied, 2);
        assert!(pass.written);
        assert_eq!(pass.skip, None);
        assert_eq!(source.calls.get(), 1);

        let after = fx.read();
        assert_eq!(
            unfilled_block_numbers(&after),
            0,
            "the pass reported a write but the journaled record still has empty slots"
        );
        assert_eq!(
            after
                .txs
                .iter()
                .map(|tx| tx.block_number)
                .collect::<Vec<_>>(),
            vec![Some(900), Some(901)],
        );
        assert!(after.txs.iter().all(|tx| tx.status == TxStatus::Confirmed));
        // Nothing else about the record moved.
        assert_eq!(after.storage_cost_atto, 11);
        assert_eq!(after.gas.gas_cost_wei, 3);
    }

    /// **U67 Accept row 2, the idempotence half.** Running it twice changes
    /// nothing — and the second run does not even ask the RPC, because the
    /// empty-slot count is zero before a source is reached.
    ///
    /// The counter is what makes this fallible: an assertion that the record
    /// is equal after the second run would stay green against a pass that
    /// re-fetched and re-wrote identical bytes every single invocation, which
    /// is a different (and worse) program.
    ///
    /// Its negative control is [`a_source_that_resolves_nothing_writes_nothing`]
    /// below: same fixture, same call, a source that fills nothing — the record
    /// is untouched, so the "the record changed" assertion here is reachable in
    /// both directions.
    #[test]
    fn a_second_pass_changes_nothing_and_costs_no_rpc() {
        let fx = Fixture::new("idempotent");
        let source = Resolving::new(700);

        let first = fx.run(&source);
        assert!(first.written);
        let after_first = fx.record_bytes();
        assert_eq!(source.calls.get(), 1);

        let second = fx.run(&source);
        // The counter is asserted FIRST, deliberately: it is the load-bearing
        // claim, and a `skip` assertion placed ahead of it would fire on a
        // re-fetching pass before the counter ever got the chance.
        assert_eq!(
            source.calls.get(),
            1,
            "the second pass asked the payment RPC again — enrichment must stop at the empty-slot \
             count, or every invocation pays for a network round trip it cannot need"
        );
        assert_eq!(second.skip, Some(BackfillSkip::NothingUnfilled));
        assert!(!second.written);
        assert_eq!(second.applied, 0);
        assert_eq!(
            fx.record_bytes(),
            after_first,
            "the second pass rewrote the record; the write is not conditional on there being \
             something to write"
        );
    }

    /// **U67 Accept row 2, the non-gating half, at the record.** An RPC failure
    /// leaves the journaled record **byte-identical** — not merely equal in
    /// plaintext, which a rewrite would also satisfy since the record's
    /// ciphertext is randomized per write.
    ///
    /// Negative control: [`an_empty_slot_is_filled_and_journaled`] proves the
    /// same fixture and the same call *do* move those bytes when the source
    /// resolves, so a record that never changed under any input would fail
    /// there.
    ///
    /// (The exit-code and output half of non-gating is a property of the host
    /// command, and is asserted against the real binary in
    /// `tests/receipt_backfill.rs`: a function returning no `Result` cannot be
    /// shown to leave an exit code alone by a library test.)
    #[test]
    fn a_failing_source_is_silent_and_writes_nothing() {
        let fx = Fixture::new("rpcdown");
        let before = fx.record_bytes();

        let source = Failing {
            calls: Cell::new(0),
        };
        let pass = fx.run(&source);

        assert_eq!(pass.skip, Some(BackfillSkip::SourceFailed));
        assert_eq!(pass.unfilled, 2);
        assert_eq!(pass.fetched, 0);
        assert!(!pass.written);
        assert_eq!(source.calls.get(), 1, "the source really was asked");
        assert_eq!(
            fx.record_bytes(),
            before,
            "a pass whose RPC refused rewrote the journaled receipt anyway"
        );
        assert_eq!(
            unfilled_block_numbers(&fx.read()),
            2,
            "a pass whose RPC refused claimed to have filled something"
        );
    }

    /// Reached but nothing visible yet is a **retry**, not a failure: the
    /// transactions are simply not mined into a readable receipt. Distinct arm,
    /// distinct skip, no write.
    #[test]
    fn a_source_that_resolves_nothing_writes_nothing() {
        let fx = Fixture::new("notyet");
        let before = fx.record_bytes();

        let pass = fx.run(&Silent);

        assert_eq!(pass.skip, Some(BackfillSkip::NothingFetched));
        assert_eq!(pass.unfilled, 2);
        assert!(!pass.written);
        assert_eq!(
            fx.record_bytes(),
            before,
            "a pass that resolved nothing still wrote the record"
        );
    }

    /// A work that never paid has no record, and that is not a defect: the pass
    /// stops at the cheapest possible point and constructs nothing.
    #[test]
    fn a_work_with_no_receipt_is_not_a_failure() {
        let fx = Fixture::new("norecord");
        std::fs::remove_file(fx.receipt_path()).expect("drop the record");

        let source = Failing {
            calls: Cell::new(0),
        };
        let pass = fx.run(&source);

        assert_eq!(pass.skip, Some(BackfillSkip::NoRecord));
        assert_eq!(
            source.calls.get(),
            0,
            "no source is reached without a record"
        );
    }

    /// **The lock discipline (D99 R3).** The RPC happens unlocked, and the write
    /// takes the U5 single-writer lock. A lock held elsewhere is a silent
    /// decline that discards the fetched values — never a wait, never an error.
    ///
    /// `VaultLock::acquire` is a try-lock that refuses a second acquisition even
    /// inside one process, so holding one here reproduces the contended case
    /// exactly.
    #[test]
    fn a_contended_lock_declines_and_discards() {
        let fx = Fixture::new("contended");
        let before = fx.record_bytes();
        let held = VaultLock::acquire(&fx.vault.layout().beside_path(BesideFile::Lockfile))
            .expect("the fixture takes the lock first");

        let source = Resolving::new(500);
        let pass = fx.run(&source);

        assert_eq!(pass.skip, Some(BackfillSkip::LockContended));
        assert_eq!(pass.fetched, 2, "the RPC ran unlocked and did resolve");
        assert!(!pass.written);
        assert_eq!(
            fx.record_bytes(),
            before,
            "a pass that could not take the U5 lock wrote through it anyway"
        );

        // And once the lock is free the very next pass succeeds, so the decline
        // really was about the lock and not about the values.
        drop(held);
        let retry = fx.run(&source);
        assert!(
            retry.written,
            "the retry after the lock was released wrote nothing"
        );
        assert_eq!(
            unfilled_block_numbers(&fx.read()),
            0,
            "the retry after the lock was released left the slots empty"
        );
    }

    /// **The window between the read and the write, closed by re-reading.**
    ///
    /// The RPC round trip runs unlocked, so a concurrent `seal --resume` can
    /// journal a *fuller* receipt while it is in flight. Writing the pre-fetch
    /// snapshot back would silently erase that. The source here writes the
    /// fuller record as a side effect — which is precisely the interleaving —
    /// and the assertion is that the third transaction survives **and** the
    /// block numbers land.
    ///
    /// Without the re-read this test fails on `txs.len()`, which is the
    /// assertion that could not otherwise be reached: every other row here
    /// would stay green against a pass that clobbered.
    #[test]
    fn a_record_that_moved_under_the_rpc_is_not_clobbered() {
        struct Interleaving<'f> {
            fixture: &'f Fixture,
        }

        impl BlockNumberSource for Interleaving<'_> {
            fn backfill(&self, receipt: &mut PaymentReceipt) -> Result<usize, String> {
                // A concurrent writer lands a third transaction while we are
                // "on the network".
                let mut fuller = receipt.clone();
                fuller.txs.push(tx(0x33, None));
                self.fixture.write(&fuller);

                let mut filled = 0;
                for tx in &mut receipt.txs {
                    if tx.block_number.is_none() {
                        tx.block_number = Some(4_000);
                        tx.status = TxStatus::Confirmed;
                        filled += 1;
                    }
                }
                Ok(filled)
            }
        }

        let fx = Fixture::new("interleave");
        let pass = fx.run(&Interleaving { fixture: &fx });

        assert!(pass.written);
        assert_eq!(pass.fetched, 2);
        assert_eq!(pass.applied, 2, "only the two the source resolved");

        let after = fx.read();
        assert_eq!(
            after.txs.len(),
            3,
            "the concurrent writer's transaction was erased — the pass wrote its pre-RPC snapshot \
             back instead of re-reading under the lock"
        );
        assert_eq!(
            after
                .txs
                .iter()
                .map(|tx| tx.block_number)
                .collect::<Vec<_>>(),
            vec![Some(4_000), Some(4_000), None],
            "the resolved slots land on the re-read record, and the newcomer is left for the next \
             invocation"
        );
    }

    /// If someone else filled the slots during the RPC window there is nothing
    /// to apply, and that is a distinct, silent arm rather than a redundant
    /// write.
    #[test]
    fn slots_already_filled_under_the_lock_are_left_alone() {
        struct FillsBehindOurBack<'f> {
            fixture: &'f Fixture,
        }

        impl BlockNumberSource for FillsBehindOurBack<'_> {
            fn backfill(&self, receipt: &mut PaymentReceipt) -> Result<usize, String> {
                self.fixture
                    .write(&receipt_with(vec![tx(0x11, Some(1)), tx(0x22, Some(2))]));
                for tx in &mut receipt.txs {
                    tx.block_number = Some(9_999);
                }
                Ok(2)
            }
        }

        let fx = Fixture::new("raced");
        let pass = fx.run(&FillsBehindOurBack { fixture: &fx });

        assert_eq!(pass.skip, Some(BackfillSkip::AlreadyFilled));
        assert!(!pass.written);
        assert_eq!(
            fx.read()
                .txs
                .iter()
                .map(|tx| tx.block_number)
                .collect::<Vec<_>>(),
            vec![Some(1), Some(2)],
            "the winner's values stand; ours are discarded rather than overwriting them"
        );
    }

    /// A receipt whose slots are already complete never reaches a source at
    /// all — the property the whole "`status` does not become a command that
    /// dials" argument rests on.
    #[test]
    fn a_complete_receipt_reaches_no_source() {
        let fx = Fixture::new("complete");
        fx.write(&receipt_with(vec![tx(0x11, Some(5)), tx(0x22, Some(6))]));

        let source = Failing {
            calls: Cell::new(0),
        };
        let pass = fx.run(&source);

        assert_eq!(
            source.calls.get(),
            0,
            "a receipt with no empty slot still opened a payment-RPC session"
        );
        assert_eq!(pass.skip, Some(BackfillSkip::NothingUnfilled));
    }
}
