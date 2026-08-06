//! Shared harness for the pipeline suites (S11 resume, S12 seal, S13
//! no-anchor, S16 the invariant matrix).
//!
//! The doubles here implement the interfaces the pipeline is written over
//! and **record what they were handed**, because most of what these suites
//! assert is about *order and identity of arguments*, not return values:
//! that `pay` received the very quote the consent gate was shown, that the
//! anchor gate was never called in `--no-anchor` mode, that a resumed
//! invocation re-quoted before paying.
//!
//! Storage is the real `MockBackend` (S3) — its call log, fault set and
//! double-pay detector are the evidence base — wrapped by
//! [`RecordingBackend`] only to capture the argument *values* the call log
//! digests.
//!
//! NON-SECRET: every `W`, passphrase and byte string here is a documented
//! fixture (project rule 6).

#![allow(dead_code)] // each suite uses a different subset

/// The M1 devnet gate's shared half (S17/S18/S19): environment gating,
/// serialization, the D37 receipt sink and the Anvil JSON-RPC probe.
/// Feature-gated because it names the `ant-backend` construction seam.
#[cfg(feature = "ant-backend")]
pub mod devnet;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::OnceLock;

use antseal_anchor::{AnchorGate, AnchorGateError, AnchorSubmissionOutcome};
use antseal_cli::error::{CliError, ConsentOutcome};
use antseal_cli::pipeline::{
    Barrier, BarrierHook, ConsentDecision, ConsentHook, ConsentRequest, SealError, VaultJournal,
};
use antseal_cli::vault::kdf::KdfSelection;
use antseal_cli::vault::layout::VaultLayout;
use antseal_cli::vault::session::{UnlockedVault, create_vault, unlock_vault};
use antseal_cli::vault::store::{ConsentChannel, WorkStore};
use antseal_core::crypto::secrets::{SealId, SecretBuf};
use antseal_core::manifest::{encode_body, encode_envelope, fixtures};
use antseal_net::test_util::MockBackend;
use antseal_net::{Address, Blob, CostQuote, PaymentReceipt, StorageBackend, StorageError};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// ─────────────────────────────────────────────────────────────────────
// Vault harness (one Argon2id vault per test binary)
// ─────────────────────────────────────────────────────────────────────

pub const TEST_RNG_SEED: [u8; 32] = [0x77u8; 32];
pub const FIXTURE_PASSPHRASE: &[u8] = b"pipeline suite fixture passphrase";
/// NON-SECRET fixture master secret.
pub const FIXTURE_W: [u8; 32] = [0x3C; 32];

pub fn passphrase() -> SecretBuf {
    SecretBuf::new(FIXTURE_PASSPHRASE.to_vec())
}

/// The anchor stage every non-anchor suite runs with: **no endpoints at
/// all** (U22, Q16).
///
/// `SealContext` has no `Default` for exactly this reason — the built-in
/// list is `freetsa.org` and `timestamp.digicert.com`, so a defaulted field
/// would have every `run_seal` test in the tree POST to a live TSA the first
/// time someone wrote a case without `--no-anchor`. With empty lists that
/// mistake is a *loud offline abort* (`MinimumAnchor { attempted: 0 }`)
/// instead of a silent network call, and `tests/anchor_stage.rs` scans this
/// tree for any source that names a real endpoint.
///
/// A suite that genuinely needs a submission builds its own config over a
/// `127.0.0.1:0` stub — see `tests/anchor_stage.rs`.
pub fn offline_anchor_stage() -> antseal_cli::seal_run::AnchorStageConfig {
    antseal_cli::seal_run::AnchorStageConfig {
        endpoints: antseal_anchor::submit::AnchorEndpoints {
            tsa_urls: Vec::new(),
            ots_calendars: Vec::new(),
        },
        roots: *antseal_core::anchor::roots::TsaRootStore::pinned(),
        fetch_date: Some(1_800_000_000),
    }
}

pub fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed(TEST_RNG_SEED)
}

pub struct SharedVault {
    pub root: PathBuf,
    pub layout: VaultLayout,
}

impl SharedVault {
    pub fn unlock(&self) -> UnlockedVault {
        unlock_vault(&self.layout, &passphrase()).expect("unlock shared vault")
    }
}

pub fn shared_vault() -> &'static SharedVault {
    static VAULT: OnceLock<SharedVault> = OnceLock::new();
    VAULT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!(
            "antseal-cli-pipeline-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("mk root");
        let layout = VaultLayout::at(root.join("vault"));
        create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng())
            .expect("create shared vault");
        SharedVault { root, layout }
    })
}

/// Run `body` against a freshly-unlocked vault and a journal over it.
/// A new session each call, so every durability claim crosses a real
/// close/reopen rather than a live cache.
pub fn with_journal<T>(body: impl FnOnce(&VaultJournal<'_, ChaCha20Rng>) -> T) -> T {
    let vault = shared_vault().unlock();
    let mut rng = rng();
    let journal = VaultJournal::new(WorkStore::new(&vault), &mut rng);
    body(&journal)
}

/// Run `body` against an already-unlocked vault — for suites that would
/// otherwise pay an Argon2id derivation per pipeline invocation (the kill
/// matrices run dozens). Each call still builds a fresh journal.
pub fn journal_over<T>(
    vault: &UnlockedVault,
    body: impl FnOnce(&VaultJournal<'_, ChaCha20Rng>) -> T,
) -> T {
    let mut rng = rng();
    let journal = VaultJournal::new(WorkStore::new(vault), &mut rng);
    body(&journal)
}

/// A vault of its own, for the tests that assert **the vault did not
/// change**.
///
/// Those assertions read the whole directory tree, so they cannot share a
/// vault with tests running in parallel — a neighbour's legitimate write
/// would read as a violation. Isolation costs one Argon2id derivation per
/// such test, which is the honest price of a whole-tree claim.
pub struct IsolatedVault {
    pub root: PathBuf,
    pub layout: VaultLayout,
}

impl IsolatedVault {
    pub fn create(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "antseal-cli-iso-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("mk root");
        let layout = VaultLayout::at(root.join("vault"));
        create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng())
            .expect("create isolated vault");
        Self { root, layout }
    }

    pub fn unlock(&self) -> UnlockedVault {
        unlock_vault(&self.layout, &passphrase()).expect("unlock")
    }

    pub fn with_journal<T>(&self, body: impl FnOnce(&VaultJournal<'_, ChaCha20Rng>) -> T) -> T {
        let vault = self.unlock();
        let mut rng = rng();
        let journal = VaultJournal::new(WorkStore::new(&vault), &mut rng);
        body(&journal)
    }

    /// Every file under the vault root, with its length and content
    /// address — the literal form of "the vault is byte-identical".
    pub fn fingerprint(&self) -> Vec<(String, u64, [u8; 32])> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, u64, [u8; 32])>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if let Ok(bytes) = std::fs::read(&path) {
                    let digest = antseal_core::storage::compute_storage_address(&bytes)
                        .map_or([0u8; 32], |a| *a.as_bytes());
                    out.push((
                        path.to_string_lossy().into_owned(),
                        bytes.len() as u64,
                        digest,
                    ));
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.root, &mut out);
        out.sort();
        out
    }
}

/// A distinct fixture seal id per call site.
pub fn fixture_seal_id(tag: u8) -> SealId {
    let mut bytes = [tag; 16];
    bytes[0] = 0xB1;
    bytes[1] = tag;
    SealId::from_bytes(bytes)
}

/// A real, schema-valid manifest envelope built from core's committed
/// fixture bodies — the pipeline only ever reads it (for `work_id` and
/// `anchor_digest`), so fixture signatures are exactly right here.
pub fn fixture_manifest_envelope() -> Vec<u8> {
    let body_bytes =
        encode_body(fixtures::binary_single_unit_body()).expect("fixture body encodes");
    encode_envelope(&body_bytes, &fixtures::hybrid_signatures()).expect("fixture envelope encodes")
}

// ─────────────────────────────────────────────────────────────────────
// Anchor-gate doubles
// ─────────────────────────────────────────────────────────────────────

/// Records every digest it was asked to anchor. The count is what S13's
/// "no anchor-submission call occurs" row reads.
#[derive(Debug, Default)]
pub struct RecordingGate {
    pub digests: RefCell<Vec<[u8; 32]>>,
    pub refuse: bool,
}

impl RecordingGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn refusing() -> Self {
        Self {
            digests: RefCell::new(Vec::new()),
            refuse: true,
        }
    }

    pub fn calls(&self) -> usize {
        self.digests.borrow().len()
    }
}

impl AnchorGate for RecordingGate {
    async fn run(&self, digest: [u8; 32]) -> Result<AnchorSubmissionOutcome, AnchorGateError> {
        self.digests.borrow_mut().push(digest);
        if self.refuse {
            return Err(AnchorGateError::PolicyNotMet {
                detail: "0 TSA tokens verified".to_owned(),
            });
        }
        Ok(AnchorSubmissionOutcome::Empty)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Consent doubles
// ─────────────────────────────────────────────────────────────────────

/// What the gate was shown — captured so the suites can assert the
/// pay-argument identity rule and the D36 render inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenConsent {
    pub quote: CostQuote,
    pub blob_count: usize,
    pub resume: bool,
    pub proofs_expired: bool,
    pub had_prior: bool,
}

/// A consent gate that answers from a script and records every request.
#[derive(Debug)]
pub struct ScriptedConsent {
    answers: RefCell<VecDeque<ConsentDecision>>,
    default: ConsentDecision,
    pub seen: RefCell<Vec<SeenConsent>>,
}

impl ScriptedConsent {
    /// Always affirms, as `--yes` would.
    pub fn always_yes() -> Self {
        Self {
            answers: RefCell::new(VecDeque::new()),
            default: ConsentDecision::Granted {
                channel: ConsentChannel::YesFlag,
                at_unix_secs: 1_800_000_000,
            },
            seen: RefCell::new(Vec::new()),
        }
    }

    /// Always declines (interactive "no").
    pub fn always_declines() -> Self {
        Self {
            answers: RefCell::new(VecDeque::new()),
            default: ConsentDecision::Declined(ConsentOutcome::Declined),
            seen: RefCell::new(Vec::new()),
        }
    }

    /// Answers from `answers` in order, then falls back to the default.
    pub fn scripted(answers: Vec<ConsentDecision>, default: ConsentDecision) -> Self {
        Self {
            answers: RefCell::new(answers.into()),
            default,
            seen: RefCell::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> usize {
        self.seen.borrow().len()
    }

    pub fn last(&self) -> Option<SeenConsent> {
        self.seen.borrow().last().cloned()
    }
}

impl ConsentHook for ScriptedConsent {
    fn confirm(&self, request: &ConsentRequest<'_>) -> Result<ConsentDecision, CliError> {
        self.seen.borrow_mut().push(SeenConsent {
            quote: request.quote.clone(),
            blob_count: request.blob_count,
            resume: request.resume,
            proofs_expired: request.proofs_expired,
            had_prior: request.prior.is_some(),
        });
        Ok(self
            .answers
            .borrow_mut()
            .pop_front()
            .unwrap_or(self.default))
    }
}

// ─────────────────────────────────────────────────────────────────────
// Barrier hooks
// ─────────────────────────────────────────────────────────────────────

/// Kills the pipeline the first time it crosses `barrier`, then disarms —
/// so the *same* hook can be reused for the resuming invocation without
/// killing it again.
#[derive(Debug)]
pub struct KillAt {
    barrier: Barrier,
    armed: RefCell<bool>,
    pub crossed: RefCell<Vec<Barrier>>,
}

impl KillAt {
    pub fn new(barrier: Barrier) -> Self {
        Self {
            barrier,
            armed: RefCell::new(true),
            crossed: RefCell::new(Vec::new()),
        }
    }

    pub fn crossed(&self) -> Vec<Barrier> {
        self.crossed.borrow().clone()
    }
}

impl BarrierHook for KillAt {
    fn at(&self, barrier: Barrier) -> Result<(), SealError> {
        self.crossed.borrow_mut().push(barrier);
        let mut armed = self.armed.borrow_mut();
        if *armed && barrier == self.barrier {
            *armed = false;
            return Err(SealError::KilledAtBarrier(barrier));
        }
        Ok(())
    }
}

/// Records every barrier crossed and kills nothing — the "what did the
/// happy path actually execute" instrument.
#[derive(Debug, Default)]
pub struct TraceBarriers {
    pub crossed: RefCell<Vec<Barrier>>,
}

impl TraceBarriers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn crossed(&self) -> Vec<Barrier> {
        self.crossed.borrow().clone()
    }
}

impl BarrierHook for TraceBarriers {
    fn at(&self, barrier: Barrier) -> Result<(), SealError> {
        self.crossed.borrow_mut().push(barrier);
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────
// Backend decorator
// ─────────────────────────────────────────────────────────────────────

/// Delegates every call to a real [`MockBackend`] while capturing the
/// argument *values* the mock's call log only digests.
///
/// This exists for one assertion the digest cannot make directly: **the
/// `CostQuote` handed to `pay` is the very object the consent gate was
/// rendered against** (D36). Capturing both sides and comparing them is
/// the honest form of that check — and because the mock mints fresh quote
/// hashes per `quote_batch` round, a stale or re-fetched quote is
/// detectable rather than coincidentally equal.
pub struct RecordingBackend<'m> {
    pub inner: &'m MockBackend,
    pub quoted: RefCell<Vec<CostQuote>>,
    pub paid: RefCell<Vec<CostQuote>>,
    pub finalized_with: RefCell<Vec<PaymentReceipt>>,
    pub uploaded: RefCell<Vec<Vec<Vec<u8>>>>,
}

impl<'m> RecordingBackend<'m> {
    pub fn new(inner: &'m MockBackend) -> Self {
        Self {
            inner,
            quoted: RefCell::new(Vec::new()),
            paid: RefCell::new(Vec::new()),
            finalized_with: RefCell::new(Vec::new()),
            uploaded: RefCell::new(Vec::new()),
        }
    }

    pub fn last_quote(&self) -> Option<CostQuote> {
        self.quoted.borrow().last().cloned()
    }

    pub fn last_paid_quote(&self) -> Option<CostQuote> {
        self.paid.borrow().last().cloned()
    }

    pub fn pay_calls(&self) -> usize {
        self.paid.borrow().len()
    }

    pub fn quote_calls(&self) -> usize {
        self.quoted.borrow().len()
    }
}

impl StorageBackend for RecordingBackend<'_> {
    async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
        let quote = self.inner.quote_batch(blobs).await?;
        self.quoted.borrow_mut().push(quote.clone());
        Ok(quote)
    }

    async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
        self.paid.borrow_mut().push(quote.clone());
        self.inner.pay(quote).await
    }

    async fn finalize_batch(
        &self,
        receipt: &PaymentReceipt,
        blobs: &[Blob],
    ) -> Result<Vec<Address>, StorageError> {
        self.finalized_with.borrow_mut().push(receipt.clone());
        self.uploaded
            .borrow_mut()
            .push(blobs.iter().map(|b| b.as_bytes().to_vec()).collect());
        self.inner.finalize_batch(receipt, blobs).await
    }

    async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
        self.inner.get_data(address).await
    }

    async fn balances(&self) -> Result<antseal_net::BalanceReport, StorageError> {
        self.inner.balances().await
    }
}
