//! `seal`'s orchestration (U13): everything between a validated plan and
//! a printed work-id.
//!
//! # Where the normative order actually lives
//!
//! Not here. MVP-SPEC.md line 34's sequence — canonicalize → encrypt units
//! (journaled) → build + sign manifest → encrypt manifest → compute
//! addresses → `quote_batch` over the full blob set → permanence consent →
//! anchor gate → `pay` → journal the receipt → `finalize_batch` — is
//! [`Pipeline::seal`](crate::pipeline::Pipeline::seal)'s, and S12/S16
//! assert it from the outside. Re-implementing any of it here would create
//! a second order that could drift from the first.
//!
//! What this module owns is the boundary either side of that sequence:
//!
//! ```text
//! plan validation (seal_plan; D46 + the flag guards)   ← already done
//!   → open the vault                                   (as a SealSession)
//!   → D45 resume detection (seal_resume)
//!   → read the bytes                                   (fresh path only)
//!   → assemble the injected interfaces and run the pipeline
//!   → render the outcome
//! ```
//!
//! # The journal is the session's, never a fresh one (S36)
//!
//! [`run_seal`] takes a [`SealSession`] rather than an
//! [`UnlockedVault`](crate::vault::session::UnlockedVault), and every journal
//! it builds comes from [`SealSession::journal`] — which cannot omit D37's
//! durable receipt sink. That is what makes this a *paying* command's
//! orchestration rather than a generic one: `seal` is the only production
//! caller that can move money, and the sink it fires from inside `pay` is
//! the same object the pipeline arms with the drawn `seal_id`. Before S36
//! this module built its own bare journal and its own in-memory sink, so
//! D37 Decision 2's guarantee was implemented, tested, and not attached to
//! anything a user runs.
//!
//! # Generic over the backend, on purpose
//!
//! [`run_seal`] takes `B: StorageBackend`, exactly as U20's
//! [`run_restore`](crate::restore_out::run_restore) does. The binary hands
//! it [`SealBackend`](crate::backend::SealBackend) (behind the
//! `ant-backend` feature); the suites hand it `MockBackend` and drive the
//! entire command — resume detection, consent, payment ordering, the
//! journal — with no network at all. That is D34's rule that the M1 E2E
//! goes through library APIs rather than a spawned binary.
//!
//! # Resume is not a second code path
//!
//! An exact-match invocation calls
//! [`Pipeline::resume`](crate::pipeline::Pipeline::resume) and **never
//! reads a source file** — S11's rule, and the reason the read below sits
//! inside the fresh branch rather than above the fork. The consent gate is
//! the same object in both cases, which is what makes D45's "one merged
//! render, never two prompts" true by construction: there is only one
//! [`ConsentHook`](crate::pipeline::ConsentHook) in the process.

use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_net::StorageBackend;
use rand_core::TryCryptoRng;

use crate::error::CliError;
use crate::pipeline::{NoBarriers, Pipeline, SealFile, SealRequest, SealResult};
use crate::seal_consent::{ConsentPrompt, ConsentReport, SealConsent};
use crate::seal_plan::SealPlan;
use crate::seal_resume::{ResumeDecision, detect, resume_plan_lines};
use crate::seal_session::SealSession;
use crate::vault::store::WorkStore;
use antseal_anchor::NoAnchorGate;

/// What a completed `seal` produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealReport {
    /// `work_id = SHA-256(manifest body)` (MVP-SPEC.md line 75).
    pub work_id: [u8; 32],
    /// The work's seal id (the vault's store key).
    pub seal_id: SealId,
    /// Storage cost paid **by this invocation**, atto-ANT. Zero on a
    /// resume that only had to finish the upload.
    pub cost_atto: u128,
    /// Whether this invocation moved money.
    pub paid_here: bool,
    /// Blobs uploaded (units + raw mirrors + encrypted manifest).
    pub blob_count: usize,
    /// Whether this invocation finished an interrupted seal.
    pub resumed: bool,
    /// Sealed without anchors (dev-only `--no-anchor`).
    pub unanchored: bool,
    /// The effective network's canonical spelling.
    pub network: String,
    /// U18: this vault has never recorded a `vault export`, so the keys to
    /// everything just sealed exist in exactly one place. Read from the
    /// U34 bookkeeping record **after** the seal succeeded — a nag before
    /// anything was sealed would be advice about a risk not yet taken, and
    /// MVP-SPEC.md line 143 puts it after the first successful seal.
    pub export_nag: bool,
}

impl SealReport {
    /// The human report. The spec's own closing line for this flow is
    /// "print work-id + cost", and that is the first line here.
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let mut out = vec![format!(
            "Sealed. work-id {}  cost {} atto-ANT",
            crate::pipeline::hex32(&self.work_id),
            self.cost_atto
        )];
        if self.resumed && !self.paid_here {
            out.push(
                "  This invocation finished an interrupted seal that was already paid for — \
                 no further payment was made."
                    .to_owned(),
            );
        }
        out.push(format!(
            "  {} blob(s) uploaded to {}; the vault holds the keys.",
            self.blob_count, self.network
        ));
        if self.unanchored {
            out.push(
                "  UNANCHORED: this seal carries no timestamp attestations. It proves \
                 integrity and possession, not time. Development use only."
                    .to_owned(),
            );
        }
        if self.export_nag {
            out.extend(crate::vault::bookkeeping::export_nag());
        }
        out
    }

    /// The `--json` result document (U3's envelope wraps it).
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "work_id": crate::pipeline::hex32(&self.work_id),
            "seal_id": hex_seal(&self.seal_id),
            // Decimal string: atto-ANT is 18 decimals (U19's rule).
            "cost_atto": self.cost_atto.to_string(),
            "paid_here": self.paid_here,
            "blob_count": self.blob_count,
            "resumed": self.resumed,
            "unanchored": self.unanchored,
            "network": self.network,
            // U18 Accept row 1: the nag reaches machine consumers too — a
            // scripted seal that never sees stderr must still be able to
            // notice that this vault has no backup.
            "export_nag": self.export_nag,
        })
    }
}

/// What the command produced: a completed seal, or D49's truncated
/// rehearsal.
#[derive(Debug, Clone)]
pub enum SealCommandResult {
    /// The seal completed: paid, uploaded, marked complete.
    Sealed(SealReport),
    /// `--dry-run` (D49): a real quote over the real blob set, the full
    /// consent report, and zero vault mutation.
    DryRun(Box<ConsentReport>),
    /// `--dry-run` over an invocation that exact-matches a **resumable**
    /// work (D45 §5): the resume plan, and nothing else at all.
    ///
    /// Deliberately quote-free, which is the one place `--dry-run` is not
    /// D49's usual truncated prefix. Quoting a resume means loading its
    /// staged ciphertexts, and that load *is* S11's staged-bytes gate —
    /// which marks the work **abandoned** when the bytes are gone. A
    /// rehearsal that can abandon a paid-for seal is not a rehearsal, and
    /// D45 §5 asks only for the plan and zero side effects.
    ResumePlan(Vec<String>),
}

impl SealCommandResult {
    /// The human report, as lines.
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        match self {
            SealCommandResult::Sealed(report) => report.render(),
            SealCommandResult::DryRun(report) => {
                let mut out = report.render();
                out.push(
                    "  Dry run: nothing was consented to, anchored, paid or uploaded, and the \
                     vault was not touched. The cost above is indicative — a real seal draws \
                     fresh nonces, so it quotes different addresses at a later moment."
                        .to_owned(),
                );
                out
            }
            SealCommandResult::ResumePlan(lines) => {
                let mut out = lines.clone();
                out.push(
                    "  Dry run: this invocation matches an interrupted seal. Nothing was \
                     quoted, consented to, paid or uploaded, and the work was left exactly \
                     as it is — re-run without --dry-run to finish it."
                        .to_owned(),
                );
                out
            }
        }
    }

    /// The `--json` result document.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        match self {
            SealCommandResult::Sealed(report) => report.json(),
            SealCommandResult::DryRun(report) => {
                let mut doc = report.json();
                if let Some(map) = doc.as_object_mut() {
                    map.insert("dry_run".to_owned(), serde_json::Value::Bool(true));
                }
                doc
            }
            SealCommandResult::ResumePlan(lines) => serde_json::json!({
                "dry_run": true,
                "resume": true,
                "quoted": false,
                "resume_plan": lines,
            }),
        }
    }
}

/// Drive one `seal` invocation over an already-validated plan.
///
/// `session` carries the unlocked vault **and** D37's durable receipt sink
/// (S36): hand [`SealSession::receipts`] to the backend's constructor and
/// this function does the rest, so the sink the backend fires and the sink
/// the pipeline arms are one object by construction.
///
/// `journal_rng` encrypts vault records; `seal_rng` supplies `W`, the
/// `seal_id` and every AEAD nonce. Two separate sources, injected rather
/// than reached for, so a suite can replay either half deterministically —
/// the house pattern the pipeline suites already use.
///
/// # Errors
///
/// D45's two resume-safety classes, the consent classes (declined /
/// machine-mode-without-`--yes`), the two shortfall classes, and every
/// storage, journal and crypto class the pipeline surfaces.
#[allow(clippy::too_many_arguments)]
pub async fn run_seal<B, P, RJ, RS>(
    backend: &B,
    session: &SealSession,
    plan: &SealPlan,
    prompt: &mut P,
    ctx: &SealContext,
    journal_rng: &mut RJ,
    seal_rng: &mut RS,
) -> Result<SealCommandResult, CliError>
where
    B: StorageBackend,
    P: ConsentPrompt,
    RJ: TryCryptoRng + ?Sized,
    RS: TryCryptoRng + ?Sized,
{
    let store = WorkStore::new(session.vault());

    // ── D45, before consent and before a single byte is read ──
    let decision = detect(&store, plan.network, &plan.absolute_paths(), &plan.shaping)?;
    if let Some(notice) = decision.notice() {
        ctx.emit(&notice);
    }

    let resume_plan = match &decision {
        ResumeDecision::Resume(candidate) => resume_plan_lines(candidate),
        ResumeDecision::Fresh { .. } => Vec::new(),
    };

    // ── D45 §5, and it has to be here — before anything at all ──
    //
    // A `--dry-run` that exact-matches a resumable work must not enter
    // the resume path: `Pipeline::resume` pays and uploads, and it takes
    // no dry-run parameter (correctly — S11 has no truncation point; its
    // whole purpose is to finish a seal). Falling through would make
    // `seal --dry-run` spend money, which is the single worst thing this
    // flag could do. Returning here also means the rehearsal makes no
    // backend call whatsoever, not even the balance read.
    if plan.dry_run && matches!(decision, ResumeDecision::Resume(_)) {
        return Ok(SealCommandResult::ResumePlan(resume_plan));
    }

    // Balances are read ONCE here and handed to the gate as data (D89
    // Decision 3): the gate renders a pure function of values, so its
    // output is snapshot-cheap and it cannot reach the network on its own.
    let balances = backend
        .balances()
        .await
        .map_err(|e| CliError::from(crate::pipeline::SealError::Storage(e)))?;

    let consent = SealConsent::new(
        plan,
        balances,
        resume_plan,
        plan.yes,
        ctx.machine_mode,
        ctx.to_stderr,
        ctx.now_unix_secs,
        prompt,
    );

    // S36: the journal comes from the session, so it carries D37's durable
    // sink and there is no builder step here that could be omitted. The
    // `store` above is the read side (D45's scan); this is the write side.
    let journal = session.journal(journal_rng);
    let pipeline = Pipeline::new(backend, &NoAnchorGate, &journal, &consent, &NoBarriers);

    let (result, resumed) = match decision {
        ResumeDecision::Resume(candidate) => {
            // S11: resume re-uploads the byte-identical staged
            // ciphertexts. No source file is opened, here or below.
            let outcome = pipeline.resume(&candidate.seal_id).await?;
            (SealResult::Sealed(outcome), true)
        }
        ResumeDecision::Fresh { .. } => {
            // The one place source bytes enter the process. Read after
            // every refusal has had its chance (D46 validation, resume
            // detection, the balance read), so a rejected invocation
            // never loads a gigabyte first.
            let bytes = read_all(plan)?;
            let files: Vec<SealFile<'_>> = plan
                .files
                .iter()
                .zip(&bytes)
                .map(|(planned, bytes)| SealFile {
                    path_as_given: &planned.as_given,
                    path_absolute: &planned.absolute,
                    bytes,
                    flags: planned.flags,
                })
                .collect();
            let request = SealRequest {
                files: &files,
                title: plan.shaping.title.clone().unwrap_or_default(),
                claimed_time_unix_secs: ctx.now_unix_secs,
                app_version: ctx.app_version.clone(),
                network: plan.network,
                no_anchor: plan.shaping.no_anchor,
                degraded: plan.shaping.force_degraded,
                dry_run: plan.dry_run,
                sig_policy: SigPolicy::hybrid(),
                shaping: plan.shaping.clone(),
            };
            (pipeline.seal(&request, seal_rng).await?, false)
        }
    };

    match result {
        SealResult::Sealed(outcome) => Ok(SealCommandResult::Sealed(SealReport {
            work_id: outcome.work_id,
            seal_id: outcome.seal_id,
            cost_atto: outcome.paid_atto,
            paid_here: outcome.paid_here,
            blob_count: outcome.addresses.len(),
            resumed,
            unanchored: plan.shaping.no_anchor,
            network: plan.network.as_str().to_owned(),
            // U18: read after the seal, and read rather than assumed — a
            // vault restored from a backup carries its export record, so
            // the nag correctly stays quiet on a machine that has one.
            export_nag: !crate::vault::bookkeeping::load(session.vault())?.ever_exported(),
        })),
        // D49's truncation. The consent gate was never called (the
        // pipeline returns at the post-quote barrier), so the report is
        // built here from the same inputs it would have received —
        // through `report_for`, so the rehearsal screen and the real one
        // have one author.
        SealResult::DryRun(dry) => {
            let request = crate::pipeline::ConsentRequest {
                seal_id: SealId::from_bytes([0; 16]),
                quote: &dry.quote,
                blob_count: dry.blob_count,
                prior: None,
                resume: false,
                proofs_expired: false,
            };
            let mut report = consent.report_for(&request);
            report.dry_run = true;
            // The S8 preflight runs for real (D49): a dry run is a
            // scriptable funding gate, so a drained wallet exits with the
            // same distinct code the real seal would use.
            report.preflight()?;
            Ok(SealCommandResult::DryRun(Box::new(report)))
        }
    }
}

/// Per-invocation context the orchestration needs but does not decide.
#[derive(Debug, Clone)]
pub struct SealContext {
    /// D51's determination, from [`crate::machine::machine_mode_for`] —
    /// never a local isatty probe.
    pub machine_mode: bool,
    /// Human copy goes to stderr (true) or stdout (false) — D51
    /// invariant 2.
    pub to_stderr: bool,
    /// The one place a clock is trusted: the manifest's claimed time and
    /// the journaled consent time both come from here.
    pub now_unix_secs: u64,
    /// The `app_version` string the manifest records.
    pub app_version: String,
}

impl SealContext {
    fn emit(&self, line: &str) {
        if self.to_stderr {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
}

/// Read every planned file.
///
/// Re-`stat`ing is not repeated here: D46 already validated the list, and
/// a file that changed between validation and read surfaces as a read
/// error or as different bytes — neither of which this layer can
/// meaningfully adjudicate, and both of which land before anything is
/// paid.
fn read_all(plan: &SealPlan) -> Result<Vec<Vec<u8>>, CliError> {
    plan.files
        .iter()
        .map(|file| {
            std::fs::read(&file.absolute).map_err(|source| CliError::Io {
                context: format!("reading {}", file.as_given),
                source,
            })
        })
        .collect()
}

// `SealReceipts` used to live here: an in-memory sink handed to
// `SealBackend::connect` because the backend is built before the pipeline
// draws the `seal_id`, so nothing could be written to a work record whose
// key did not exist yet. S36 deleted it rather than kept it. The `seal_id`
// problem was never the backend's — S31's `VaultReceiptSink` is armed by
// the pipeline through `SealJournal::arm_receipts` at the one moment the
// id exists, immediately before every `pay`. So the type's whole reason to
// exist was a window that has been closed, and leaving it would have left
// a second, non-durable sink nameable on the paying path (the bypass
// `seal_session.rs`'s scan now refuses).
//
// Its doc comment also cited **U39** for the residual multi-tx window. That
// is the wrong id — U39 is the missing `--features ant-backend` CI lane;
// the sink obligation is U40 (recorded from the command side) and S36
// (from the sink's). Both are discharged by the session wiring above.

fn hex_seal(seal_id: &SealId) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(32);
    for byte in seal_id.as_bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
