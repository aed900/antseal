//! D45 resume detection: deciding, before consent and before anything is
//! read or paid, whether this `seal` invocation *is* an earlier one
//! finishing.
//!
//! # The whole mechanism is a comparison of recorded identities
//!
//! There is no `--resume` flag and no interactive picker
//! (`docs/decisions/D45-resume-detection-consent.md` §3 rejects both: the
//! crash-re-run path is where scripts and rattled humans live, and D51
//! forbids prompting under `--json` anyway). Re-running the same command
//! resumes; that is the entire user model.
//!
//! What makes it safe is that "the same command" is defined precisely and
//! recorded at seal start (U9's invocation-identity block): the effective
//! **network**, the **exact ordered list of lexically absolutized input
//! paths**, and the **seal-shaping flag set**. Session flags (`--yes`,
//! `--json`, `--dry-run`, `--passphrase-fd`) are deliberately excluded —
//! they say nothing about what is sealed, so they must never split one
//! resumable work into two.
//!
//! # The matching table (D45 §2), and why the near misses are errors
//!
//! | relation to a candidate | outcome |
//! | --- | --- |
//! | exact ordered paths ∧ equal shaping | [`ResumeDecision::Resume`] |
//! | exact ordered paths ∧ different shaping | [`CliError::ResumeFlagMismatch`] |
//! | same set, different order — or subset, superset, any overlap | [`CliError::ResumeOverlapNotExact`] |
//! | disjoint from every candidate | [`ResumeDecision::Fresh`] + a notice |
//!
//! Resume re-uploads the byte-identical staged ciphertexts and never
//! rebuilds the manifest (S11), and the manifest's file table is *ordered*
//! — argument order is `file_id` order, which feeds every per-file salt.
//! So only the exact ordered list is even resumable, and anything that
//! merely overlaps is a garbled re-run rather than new intent. Guessing
//! would mean either paying twice for bytes already staged or silently
//! sealing a different work than the one asked for.
//!
//! The candidate set excludes `complete` and `abandoned` works, so a
//! finished seal never blocks re-sealing the same files, and an abandoned
//! one never resurrects.
//!
//! # Uniqueness
//!
//! An exact match is auto-resumed rather than duplicated, so at most one
//! can exist per key. Two is not a user-facing situation — it is a
//! corrupted or hand-edited store — and is reported as the internal class
//! rather than as a question (D45 §2's closing note).

use antseal_core::crypto::secrets::SealId;
use antseal_net::NetworkId;

use crate::error::{CliError, ConsentOutcome};
use crate::pipeline::SealJournal;
use crate::pipeline::journal::{SealState, recorded_plan, recorded_state};
use crate::vault::store::{SealShapingFlags, WorkState, WorkStore};

/// One incomplete work, reduced to what the matching rule reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeCandidate {
    /// Store key of the incomplete work.
    pub seal_id: SealId,
    /// The recorded lexically absolutized input paths, in `file_id` order.
    pub absolute_paths: Vec<String>,
    /// The recorded as-given spellings — what the near-miss error prints,
    /// because it is the command the user would have to retype.
    pub as_given_paths: Vec<String>,
    /// The recorded seal-shaping flag set.
    pub shaping: SealShapingFlags,
    /// The recorded network (already filtered on, kept for the render).
    pub network: String,
    /// The coarse U9 state (pre-pay vs post-pay decides whether consent
    /// re-fires — D45 §4).
    pub state: WorkState,
    /// The fine S10 journal state, when the journal carries one. Absent
    /// is a state rather than a failure (U19's finding: an imported
    /// complete work has no journal entries at all).
    pub journal_state: Option<SealState>,
}

/// What plan validation decided about resume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeDecision {
    /// No candidate overlaps these inputs: a fresh seal.
    Fresh {
        /// How many incomplete works exist anyway — D45 §2's one-line
        /// stderr notice, so a user who mistyped a path is told that the
        /// interrupted seal is still there rather than silently starting
        /// a second one.
        incomplete_works: usize,
    },
    /// An exact match: this invocation finishes that work.
    Resume(Box<ResumeCandidate>),
}

impl ResumeDecision {
    /// The stderr notice, if this decision has one.
    #[must_use]
    pub fn notice(&self) -> Option<String> {
        match self {
            ResumeDecision::Fresh {
                incomplete_works: 0,
            } => None,
            ResumeDecision::Fresh { incomplete_works } => Some(format!(
                "note: {incomplete_works} incomplete seal(s) exist in this vault and none \
                 matches these inputs — run `antseal list` to see them"
            )),
            ResumeDecision::Resume(candidate) => Some(format!(
                "Resuming the interrupted seal {} — re-running the same command is how \
                 resume works (D45); nothing is re-encrypted.",
                hex_seal(&candidate.seal_id)
            )),
        }
    }
}

/// Scan the vault for incomplete works on this network and apply D45 §2.
///
/// Reads meta records only — no staged bytes, no source files, no network.
///
/// # Errors
///
/// The two D45 resume-safety usage errors
/// ([`CliError::ResumeOverlapNotExact`], [`CliError::ResumeFlagMismatch`]),
/// the defensive [`CliError::Internal`] for a store holding two exact
/// matches, and the store's own classes.
pub fn detect(
    store: &WorkStore<'_>,
    network: NetworkId,
    absolute_paths: &[String],
    shaping: &SealShapingFlags,
) -> Result<ResumeDecision, CliError> {
    let candidates = gather_candidates(store, network)?;
    match_candidates(&candidates, absolute_paths, shaping)
}

/// Build the candidate set: incomplete works on this network.
///
/// # Errors
///
/// The store's classes (a damaged vault is reported, never softened into
/// a shorter candidate list — a silently-dropped candidate is exactly the
/// failure that makes a user pay twice).
pub fn gather_candidates(
    store: &WorkStore<'_>,
    network: NetworkId,
) -> Result<Vec<ResumeCandidate>, CliError> {
    let mut out = Vec::new();
    for seal_id in store.list_works()? {
        let record = store.load_meta(&seal_id)?;
        // D45 §2's candidate set, exactly: incomplete (either barrier),
        // same network. `Complete` and `Abandoned` are excluded, so
        // re-sealing the same files after a finished seal is a fresh
        // seal, and an abandoned work never comes back.
        if !matches!(
            record.state,
            WorkState::IncompletePrePay | WorkState::IncompletePostPay
        ) || record.network != network.as_str()
        {
            continue;
        }
        out.push(ResumeCandidate {
            seal_id,
            absolute_paths: record.input_paths_absolute,
            as_given_paths: record.input_paths_as_given,
            shaping: record.shaping,
            network: record.network,
            state: record.state,
            journal_state: recorded_state(store, &seal_id).map_err(CliError::from)?,
        });
    }
    Ok(out)
}

/// D45 §2's table as a pure function over an already-gathered candidate
/// set — which is what makes the whole matrix testable without a vault.
///
/// # Errors
///
/// As [`detect`].
pub fn match_candidates(
    candidates: &[ResumeCandidate],
    absolute_paths: &[String],
    shaping: &SealShapingFlags,
) -> Result<ResumeDecision, CliError> {
    let mut exact: Vec<&ResumeCandidate> = Vec::new();
    for candidate in candidates {
        if candidate.absolute_paths == absolute_paths {
            exact.push(candidate);
        }
    }
    if exact.len() > 1 {
        return Err(CliError::Internal {
            detail: format!(
                "{} incomplete works record the same inputs; an exact match is auto-resumed \
                 rather than duplicated, so this cannot arise from normal use — the vault's \
                 work records disagree with each other",
                exact.len()
            ),
        });
    }
    if let Some(candidate) = exact.first() {
        if candidate.shaping == *shaping {
            return Ok(ResumeDecision::Resume(Box::new((*candidate).clone())));
        }
        return Err(CliError::ResumeFlagMismatch {
            seal_id: hex_seal(&candidate.seal_id),
            detail: format!(
                "work {}: recorded `{}`, this invocation `{}`",
                hex_seal(&candidate.seal_id),
                crate::listing::seal_invocation(
                    &candidate.as_given_paths,
                    &candidate.shaping,
                    &candidate.network
                ),
                crate::listing::seal_invocation(
                    &candidate.as_given_paths,
                    shaping,
                    &candidate.network
                ),
            ),
        });
    }

    // No exact match. Anything that merely *touches* a candidate is a
    // garbled re-run: refuse, naming the work and the command that would
    // resume it. Set equality with a different order lands here too — the
    // manifest file table is ordered, so a re-ordered list is a different
    // work, not the same one spelled differently.
    for candidate in candidates {
        let overlap = candidate
            .absolute_paths
            .iter()
            .filter(|p| absolute_paths.contains(p))
            .count();
        if overlap == 0 {
            continue;
        }
        let relation = if candidate.absolute_paths.len() == absolute_paths.len()
            && overlap == absolute_paths.len()
        {
            "the same files in a different order".to_owned()
        } else if overlap == absolute_paths.len() {
            format!(
                "these {} file(s) are a subset of that work's {}",
                absolute_paths.len(),
                candidate.absolute_paths.len()
            )
        } else if overlap == candidate.absolute_paths.len() {
            format!(
                "that work's {} file(s) are a subset of these {}",
                candidate.absolute_paths.len(),
                absolute_paths.len()
            )
        } else {
            format!(
                "{overlap} of these {} file(s) also belong to that work",
                absolute_paths.len()
            )
        };
        return Err(CliError::ResumeOverlapNotExact {
            seal_id: hex_seal(&candidate.seal_id),
            detail: format!(
                "work {} ({relation}); resume it with `{}`",
                hex_seal(&candidate.seal_id),
                crate::listing::seal_invocation(
                    &candidate.as_given_paths,
                    &candidate.shaping,
                    &candidate.network
                ),
            ),
        });
    }

    Ok(ResumeDecision::Fresh {
        incomplete_works: candidates.len(),
    })
}

// ─────────────────────────────────────────────────────────────────────
// U17: user-initiated abandonment of a pre-pay incomplete work
// ─────────────────────────────────────────────────────────────────────

/// What a user-initiated abandon did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbandonReport {
    /// The work that was abandoned.
    pub seal_id: SealId,
    /// The fine journal state it was in before (`None` when the journal
    /// carried no tag — an imported or half-written work).
    pub previous_state: Option<SealState>,
    /// The work was **already** abandoned and nothing was written. The
    /// postcondition holds either way, so this is an outcome rather than
    /// an error: a script re-running the same abandon must not fail.
    pub already: bool,
}

impl AbandonReport {
    /// The human report.
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        if self.already {
            return vec![format!(
                "Work {} was already abandoned; nothing changed.",
                hex_seal(&self.seal_id)
            )];
        }
        // U17 wrote "so nothing is lost but the local encryption work", true
        // for a work stopped before its anchor step and false for one that
        // got anchors: those timestamp *this* manifest, and a fresh seal has
        // a different one (D185 R4 names them as the destructive part of the
        // act). The report cannot tell the two apart — the anchor tag is
        // written even when `--no-anchor` skipped the step — so it states
        // what is true of both, and the anchors are counted where it matters,
        // in the preview shown before the question.
        vec![
            format!(
                "Abandoned the interrupted seal {}.",
                hex_seal(&self.seal_id)
            ),
            "  Nothing was paid for it and nothing was uploaded. Sealing these files again \
             starts a completely fresh work: a new seal_id, a new master secret, freshly drawn \
             nonces, and therefore a different work-id — none of this work's records, its \
             staged copy, its consent or any anchors, carries over to it."
                .to_owned(),
            // U17 wrote "until it is compacted": no command compacts a vault
            // (none exists, and no row or record proposes one), so the
            // sentence promised a mechanism the product does not have.
            "  The staged ciphertexts stay in the vault; they are no longer resumable and no \
             longer match any invocation."
                .to_owned(),
        ]
    }

    /// The `--json` result of `antseal abandon` (D185 R7; tier C, D65).
    ///
    /// `seal_id` is the 32-hex form every resume message prints, `already`
    /// is the idempotent outcome (the work was abandoned before this run and
    /// nothing was written), and `previous_state` is the fine journal state
    /// the work was in — `null` when its journal carried no tag. There is
    /// deliberately no `work_id` member: a work killed mid-staging has none,
    /// and `list --json` carries both ids for every work.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "seal_id": hex_seal(&self.seal_id),
            "already": self.already,
            "previous_state": self.previous_state.map(SealState::name),
        })
    }
}

/// Abandon a **pre-pay** incomplete work at the user's explicit request
/// (U17; the exit D45's flag-mismatch error records as missing).
///
/// # Why this exists, and what calls it
///
/// D45 §2 makes an inexact re-run a hard error: a user with a staged work
/// over paths `P` who now wants different flags cannot resume (the flags
/// differ) and cannot start fresh (the paths overlap). That is a trap, and
/// D45's own residual-risk section records it as one — *"a user-initiated
/// abandon is safe and needed for the §2 error text to offer a real way
/// forward … surface addition to be decided deliberately, not smuggled in
/// here"*.
///
/// This function is that mechanism, with its safety rules and its tests.
/// U17 built it without a surface token, on purpose: the canonical command
/// surface is frozen and shared, and adding to it was the deliberate
/// decision D45 asked for. **D185 made that decision**: a top-level
/// `antseal abandon <ID> [--yes]`, whose handler reaches this function
/// through [`run_abandon`] and calls it **unchanged** — the rules below are
/// the safety case, and the surface adds a confirmation in front of them,
/// never a second copy of them.
///
/// # The three rules, in the order they are checked
///
/// 1. **A finished work is never abandoned.** Its ciphertexts are on the
///    network permanently; "abandoning" the record would only throw away
///    the keys that make them readable.
/// 2. **A paid work is never abandoned on request.** The authority is the
///    *journaled receipt*, not the state tag — S16 found a real
///    double-payment defect that came from trusting the tag, because
///    D37's capture hook journals the receipt inside `pay()` and a crash
///    in that window leaves a durable receipt on a pre-pay tag. Reading
///    the receipt first means the money question is answered by the money
///    evidence. S11 *does* abandon paid works, but only as a safety
///    outcome when the staged bytes are gone and the alternative is
///    re-encrypting under a journaled nonce; forfeiting a payment because
///    someone typed a flag is a different thing entirely.
/// 3. Anything else — staged or anchored, no receipt — is abandonable,
///    and the transition is the S10 state machine's own
///    [`SealJournal::set_state`], never a hand-written tag write, so the
///    coarse [`WorkState`] mirror moves with it.
///
/// # Errors
///
/// [`CliError::Usage`] for rules 1 and 2 (no new exit class: this is the
/// user asking for something that is not a valid action for this work,
/// and the message says why); the journal's and store's own classes for
/// a damaged vault.
pub fn abandon_pre_pay<J: crate::pipeline::SealJournal>(
    store: &WorkStore<'_>,
    journal: &J,
    seal_id: &SealId,
) -> Result<AbandonReport, CliError> {
    let meta = store.load_meta(seal_id)?;

    // Rule 1: terminal states.
    match meta.state {
        WorkState::Complete => {
            return Err(CliError::Usage {
                message: format!(
                    "work {} is complete: its ciphertexts are on the network permanently and \
                     cannot be recalled, so there is nothing to abandon — discarding the \
                     record would only destroy the keys that make them readable",
                    hex_seal(seal_id)
                ),
            });
        }
        WorkState::Abandoned => {
            return Ok(AbandonReport {
                seal_id: *seal_id,
                previous_state: recorded_state(store, seal_id).map_err(CliError::from)?,
                already: true,
            });
        }
        WorkState::IncompletePrePay | WorkState::IncompletePostPay => {}
    }

    // Rule 2: the receipt is the authority on whether money moved.
    let paid = journal.receipt(seal_id).map_err(CliError::from)?.is_some()
        || meta.state == WorkState::IncompletePostPay;
    if paid {
        return Err(CliError::Usage {
            message: format!(
                "work {} has already been paid for — a payment receipt is journaled for it. \
                 Abandoning it would forfeit that payment permanently, and antseal will not \
                 do that on request. Finish it instead by re-running `{}`: no further \
                 payment is needed, and the network's payment proofs stay usable for \
                 uploading only about a day",
                hex_seal(seal_id),
                crate::listing::seal_invocation(
                    &meta.input_paths_as_given,
                    &meta.shaping,
                    &meta.network
                ),
            ),
        });
    }

    let previous_state = recorded_state(store, seal_id).map_err(CliError::from)?;
    journal
        .set_state(seal_id, SealState::Abandoned)
        .map_err(CliError::from)?;
    Ok(AbandonReport {
        seal_id: *seal_id,
        previous_state,
        already: false,
    })
}

// ─────────────────────────────────────────────────────────────────────
// D185: `antseal abandon <ID> [--yes]`, the surface over the engine above
// ─────────────────────────────────────────────────────────────────────

/// The two id forms `antseal abandon` takes, named by every refusal of its
/// argument (D185 R2).
const ABANDON_ID_FORMS: &str = "`antseal abandon` takes the seal id an interrupted seal's \
                                messages print (32 hexadecimal characters) or the work id \
                                `antseal list` prints (64 hexadecimal characters), in full";

/// Resolve `antseal abandon`'s one argument to the vault's store key
/// (D185 R2).
///
/// # Two forms, told apart by length alone
///
/// The works that need this command most are named by **seal-id**: both
/// D45 refusals print it, and a seal killed before its staging finished has
/// no work-id at all (`list` prints `(no work id yet; seal …)` for it). Once
/// a work is staged, `list` prints its 64-hex **work-id** instead. Each form
/// has exactly one length, so the length alone says which key the argument
/// is. This is not a prefix scheme: a prefix of either form is refused like
/// any other malformed id, for the reason
/// [`resolve_work_id`](crate::pipeline::restore::resolve_work_id) gives — a
/// prefix match is a second, silently ambiguous naming scheme. That
/// resolver answers the work-id form here too, so every command that takes
/// a work-id resolves it the same way; the seal-id form is this command's
/// own. Upper-case hex is accepted, since users paste what they are given.
///
/// A complete or an already-abandoned work resolves: what to do with it is
/// [`abandon_pre_pay`]'s question, and it answers in its own words.
///
/// # Errors
///
/// [`CliError::Usage`] naming the two forms — for an argument of any other
/// shape, and for a well-formed id that no work in this vault carries; the
/// store's own classes for a damaged vault.
pub fn resolve_abandon_id(store: &WorkStore<'_>, id: &str) -> Result<SealId, CliError> {
    let not_found = |kind: &str| CliError::Usage {
        message: format!("no work in this vault has the {kind} `{id}`: {ABANDON_ID_FORMS}"),
    };
    let hex = id.bytes().all(|b| b.is_ascii_hexdigit());
    if hex && id.len() == 32 {
        let mut bytes = [0u8; 16];
        for (slot, pair) in bytes.iter_mut().zip(id.as_bytes().chunks_exact(2)) {
            *slot = (hex_digit(pair[0]) << 4) | hex_digit(pair[1]);
        }
        let seal_id = SealId::from_bytes(bytes);
        return if store.list_works()?.contains(&seal_id) {
            Ok(seal_id)
        } else {
            Err(not_found("seal id"))
        };
    }
    if hex && id.len() == 64 {
        return crate::pipeline::restore::resolve_work_id(store, id).map_err(|err| match err {
            crate::pipeline::restore::RestoreError::WorkNotFound => not_found("work id"),
            other => other.into(),
        });
    }
    Err(CliError::Usage {
        message: format!("`{id}` is neither a seal id nor a work id: {ABANDON_ID_FORMS}"),
    })
}

/// One ASCII hex digit's value. Reached only after `is_ascii_hexdigit` has
/// accepted every byte, so the last arm is unreachable — and harmless.
const fn hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

/// What `antseal abandon` shows before it asks (D185 R3, R4).
///
/// # Read only for a work the engine would actually write
///
/// A preview exists only for an incomplete work whose coarse tag is pre-pay
/// and which has **no journaled receipt** — the two facts
/// [`abandon_pre_pay`] decides by, read the same way. Every other work goes
/// straight to the engine with nothing asked: it refuses a complete or a
/// paid work, and reports an abandoned one as already done, each in its own
/// sentence. Asking "abandon it?" first would put a question in front of a
/// refusal, and the question says *"Nothing was paid for it"*, which would be
/// false for a paid work.
///
/// The engine stays the authority. It reads both facts again after the
/// confirmation — under the vault lock the handler holds for the whole run,
/// so nothing can move between the two reads — and a preview decides only
/// whether a question is asked, never what happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbandonPreview {
    seal_id: SealId,
    title: Option<String>,
    paths: Vec<String>,
    network: String,
    /// The fine journal state, `None` when the journal carries no tag.
    tag: Option<SealState>,
    /// Whether the seal plan was journaled — the last write of staging.
    planned: bool,
    /// How many anchor artifacts the vault holds for the work. Counted from
    /// the slots, never inferred from the tag: the pipeline writes
    /// `Anchored` after the anchor step even when `--no-anchor` skipped it,
    /// so the tag alone would claim anchors an unanchored work never had.
    anchor_slots: usize,
}

impl AbandonPreview {
    /// The preview for `seal_id`, or `None` when the engine would not
    /// abandon the work (see the type's docs).
    ///
    /// # Errors
    ///
    /// The store's and the journal's classes.
    pub fn read<J: SealJournal>(
        store: &WorkStore<'_>,
        journal: &J,
        seal_id: &SealId,
    ) -> Result<Option<Self>, CliError> {
        let meta = store.load_meta(seal_id)?;
        if meta.state != WorkState::IncompletePrePay
            || journal.receipt(seal_id).map_err(CliError::from)?.is_some()
        {
            return Ok(None);
        }
        Ok(Some(Self {
            seal_id: *seal_id,
            title: meta.shaping.title.clone(),
            paths: meta.input_paths_as_given.clone(),
            network: meta.network.clone(),
            tag: recorded_state(store, seal_id).map_err(CliError::from)?,
            planned: recorded_plan(store, seal_id)
                .map_err(CliError::from)?
                .is_some(),
            anchor_slots: store.list_anchors(seal_id)?.len(),
        }))
    }

    /// Whether anchors were already obtained for the work — at least one
    /// anchor artifact is recorded. What abandoning gives up then includes
    /// those timestamps: they are over this work's manifest, and a fresh
    /// seal of the same files has a different one.
    #[must_use]
    pub const fn anchored(&self) -> bool {
        self.anchor_slots > 0
    }

    /// The screen shown before the question — and shown under `--yes` and in
    /// machine mode too, where nothing is asked (D51 invariant 1).
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let progress = match (self.tag, self.planned) {
            (Some(SealState::Staged), false) => {
                "staging was interrupted before it finished; not paid".to_owned()
            }
            (Some(SealState::Staged), true) => "staged; not paid".to_owned(),
            (Some(SealState::Anchored), _) => {
                "staged and past its anchor step; not paid".to_owned()
            }
            (Some(other), _) => format!("the journal records `{}`", other.name()),
            (None, _) => "the journal records no state for it".to_owned(),
        };
        let anchors = match self.anchor_slots {
            0 => "none recorded".to_owned(),
            n => format!("{n} recorded, and they cannot be carried over to a new seal"),
        };
        vec![
            format!("Interrupted seal {}", hex_seal(&self.seal_id)),
            format!(
                "  title:    {}",
                self.title.as_deref().unwrap_or("(untitled)")
            ),
            format!("  files:    {}", self.paths.join(", ")),
            format!("  network:  {}", self.network),
            format!("  progress: {progress}"),
            format!("  anchors:  {anchors}"),
        ]
    }

    /// The confirmation question, verbatim from D185 R4: default no, and the
    /// anchors clause only when anchors were obtained.
    #[must_use]
    pub fn question(&self) -> String {
        let anchors = if self.anchored() {
            ", and the anchors already obtained for it,"
        } else {
            ""
        };
        format!(
            "Abandon interrupted seal {}? Nothing was paid for it; the staged work{anchors} can \
             no longer be used. [y/N] ",
            hex_seal(&self.seal_id)
        )
    }
}

/// How `antseal abandon` is confirmed: D51's destructive-confirm class,
/// with `--yes` as its declared channel (D185 R4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbandonConfirm {
    /// `--yes`: confirmed in advance. It wins in every mode (D51).
    pub yes: bool,
    /// D51 machine mode, from [`crate::machine::machine_mode_for`] — the
    /// single detection point; nothing here probes a terminal.
    pub machine_mode: bool,
}

/// `antseal abandon <ID>` over an unlocked vault: resolve the id, show what
/// will be lost, confirm, then call [`abandon_pre_pay`] — **unchanged**
/// (D185 R3).
///
/// `emit` receives the preview's lines (the handler routes them to stdout,
/// or to stderr under `--json`). `ask` is asked the question on an
/// interactive terminal and answers whether the user said yes; in
/// production it is [`ask_on_tty`](crate::seal_consent::ask_on_tty), the one
/// implementation of "EOF, a blank line and anything unrecognised mean no"
/// every consent-class prompt shares.
///
/// Nothing is written before the confirmation: resolution and the preview
/// only read, so a declined or unobtainable confirmation leaves the vault
/// exactly as it was.
///
/// # Errors
///
/// - [`CliError::Usage`] — an argument that is not a seal id or a work id,
///   an id no work carries, and the engine's own refusals of a complete or a
///   paid work;
/// - [`CliError::AbandonNotConfirmed`] — machine mode without `--yes`, or a
///   declined prompt;
/// - the prompt's own channel failure, and the store's and journal's
///   classes.
pub fn run_abandon<J, E, A>(
    store: &WorkStore<'_>,
    journal: &J,
    id: &str,
    confirm: AbandonConfirm,
    mut emit: E,
    mut ask: A,
) -> Result<AbandonReport, CliError>
where
    J: SealJournal,
    E: FnMut(&str),
    A: FnMut(&str) -> Result<bool, CliError>,
{
    let seal_id = resolve_abandon_id(store, id)?;
    if let Some(preview) = AbandonPreview::read(store, journal, &seal_id)? {
        for line in preview.render() {
            emit(&line);
        }
        // `--yes` first: it is the declared channel, and D51's matrix has it
        // win in every row it appears in, TTY or not.
        if !confirm.yes {
            if confirm.machine_mode {
                return Err(CliError::AbandonNotConfirmed {
                    reason: ConsentOutcome::MachineModeWithoutYes,
                });
            }
            if !ask(&preview.question())? {
                return Err(CliError::AbandonNotConfirmed {
                    reason: ConsentOutcome::Declined,
                });
            }
        }
    }
    abandon_pre_pay(store, journal, &seal_id)
}

/// Whether `seal_id` is a seal interrupted before its staging finished
/// (D185 R6's T3), **measured** rather than assumed: no seal plan was
/// journaled (the plan is staging's last write), the state tag still reads
/// `Staged`, and no receipt exists.
///
/// `run_seal` asks this only after a resume failed with
/// `SealError::NothingStaged`, which has other producers whose works may be
/// further along; only this shape gets [`interrupted_before_staging`]'s
/// sentence, so each of its clauses is a fact about the work it names. A
/// read that fails counts as "not measured", and the original error stands.
#[must_use]
pub fn staging_never_finished(store: &WorkStore<'_>, seal_id: &SealId) -> bool {
    matches!(recorded_plan(store, seal_id), Ok(None))
        && matches!(recorded_state(store, seal_id), Ok(Some(SealState::Staged)))
        && matches!(store.get_receipt(seal_id), Ok(None))
}

/// T3's way forward (D185 R6): what re-running the command of a seal
/// interrupted before its staging finished meets, instead of a usage error
/// that repeated on every run with no exit.
///
/// `sink.begin` writes the work record and the `Staged` tag before the first
/// blob is staged, and the plan is written only once staging is done, so a
/// kill in between (Ctrl-C during encryption: the CLI installs no signal
/// handler) leaves an incomplete pre-pay work that resume cannot finish and
/// that every re-run matches again. The sentence says **"before its staging
/// finished"**, not "nothing was staged": unit blobs are journaled one by
/// one, so some may be in the vault. Nothing was anchored or paid — the tag
/// and the absent receipt say so ([`staging_never_finished`]) — and the
/// re-run after `antseal abandon` is a fresh seal, because an abandoned work
/// is never a resume candidate. The deeper fix is S45's.
#[must_use]
pub fn interrupted_before_staging(seal_id: &SealId) -> CliError {
    let id = hex_seal(seal_id);
    CliError::Usage {
        message: format!(
            "seal {id} was interrupted before its staging finished: nothing was anchored or paid \
             for it and there is nothing to resume — discard it with `antseal abandon {id}` and \
             re-run this command"
        ),
    }
}

/// The resume plan U17's merged render shows beside the fresh quote: what
/// is staged, whether money has already moved, and what is left to do.
///
/// Built from the recorded states alone — deliberately *not* from a
/// staged-bytes walk, which is the pipeline's own gate (S11 abandons
/// rather than re-encrypts if those bytes are gone, and duplicating that
/// judgement in a renderer would let the two disagree).
#[must_use]
pub fn resume_plan_lines(candidate: &ResumeCandidate) -> Vec<String> {
    let mut out = vec![format!(
        "  Resuming interrupted seal {}",
        hex_seal(&candidate.seal_id)
    )];
    let (staged, remaining) = match candidate.journal_state {
        Some(SealState::Staged) => (
            "encrypted units and manifest are staged in the vault",
            "anchor, pay, upload",
        ),
        Some(SealState::Anchored) => ("staged and anchored; nothing paid", "pay, upload"),
        Some(SealState::Paid) => (
            "PAID — the payment receipt is journaled",
            "upload only (no further payment)",
        ),
        Some(SealState::Finalizing) => (
            "PAID — upload was interrupted part-way",
            "resume the upload (no further payment)",
        ),
        // Terminal tags cannot be candidates, and a missing tag is a work
        // whose journal was never written. Say so rather than guess.
        Some(SealState::Complete) | Some(SealState::Abandoned) | None => (
            "state not recorded in the journal",
            "the pipeline will decide from the journal",
        ),
    };
    out.push(format!("    staged:    {staged}"));
    out.push(format!("    remaining: {remaining}"));
    if candidate.state == WorkState::IncompletePostPay {
        out.push(
            "    This seal is already paid for. Finishing it needs no further payment, \
             and its payment proofs stay usable for uploading only about a day."
                .to_owned(),
        );
    }
    out
}

fn hex_seal(seal_id: &SealId) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(32);
    for byte in seal_id.as_bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shaping(title: Option<&str>) -> SealShapingFlags {
        SealShapingFlags {
            title: title.map(str::to_owned),
            no_anchor: true,
            ..SealShapingFlags::default()
        }
    }

    fn candidate(tag: u8, paths: &[&str], shaping: SealShapingFlags) -> ResumeCandidate {
        ResumeCandidate {
            seal_id: SealId::from_bytes([tag; 16]),
            absolute_paths: paths.iter().map(|p| format!("/w/{p}")).collect(),
            as_given_paths: paths.iter().map(|p| (*p).to_owned()).collect(),
            shaping,
            network: "devnet".to_owned(),
            state: WorkState::IncompletePrePay,
            journal_state: Some(SealState::Staged),
        }
    }

    fn abs(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|p| format!("/w/{p}")).collect()
    }

    #[test]
    fn an_exact_ordered_match_with_equal_flags_auto_resumes() {
        let c = vec![candidate(0xA1, &["a.txt", "b.txt"], shaping(None))];
        let decision =
            match_candidates(&c, &abs(&["a.txt", "b.txt"]), &shaping(None)).expect("matched");
        let ResumeDecision::Resume(found) = decision else {
            panic!("expected auto-resume, got {decision:?}");
        };
        assert_eq!(found.seal_id, SealId::from_bytes([0xA1; 16]));
    }

    #[test]
    fn an_exact_match_with_different_flags_is_the_flag_mismatch_class() {
        let c = vec![candidate(0xA2, &["a.txt"], shaping(Some("first")))];
        let err =
            match_candidates(&c, &abs(&["a.txt"]), &shaping(Some("second"))).expect_err("refused");
        assert_eq!(err.class(), crate::error::ErrorClass::ResumeFlagMismatch);
        assert_eq!(err.exit_code(), 26);
        let rendered = err.to_string();
        // Both flag sets appear, as the recorded command lines that
        // produce them — which is what the user has to retype.
        assert!(rendered.contains("--title first"), "{rendered}");
        assert!(rendered.contains("--title second"), "{rendered}");
    }

    #[test]
    fn the_same_files_in_a_different_order_are_not_the_same_work() {
        let c = vec![candidate(0xA3, &["a.txt", "b.txt"], shaping(None))];
        let err =
            match_candidates(&c, &abs(&["b.txt", "a.txt"]), &shaping(None)).expect_err("refused");
        assert_eq!(err.class(), crate::error::ErrorClass::ResumeOverlapNotExact);
        assert_eq!(err.exit_code(), 25);
        assert!(err.to_string().contains("different order"), "{err}");
    }

    #[test]
    fn subset_superset_and_partial_overlap_all_refuse_with_the_resume_recipe() {
        let c = vec![candidate(0xA4, &["a.txt", "b.txt"], shaping(None))];

        for (inputs, expect) in [
            (vec!["a.txt"], "subset of that work's 2"),
            (vec!["a.txt", "b.txt", "c.txt"], "subset of these 3"),
            (vec!["b.txt", "z.txt"], "1 of these 2"),
        ] {
            let err = match_candidates(&c, &abs(&inputs), &shaping(None)).expect_err("refused");
            assert_eq!(err.class(), crate::error::ErrorClass::ResumeOverlapNotExact);
            let rendered = err.to_string();
            assert!(rendered.contains(expect), "{inputs:?}: {rendered}");
            // The error is actionable: it prints the command that resumes.
            assert!(
                rendered.contains("antseal seal a.txt b.txt --no-anchor --network devnet"),
                "{rendered}"
            );
        }
    }

    #[test]
    fn disjoint_inputs_run_fresh_and_the_notice_counts_the_incomplete_works() {
        let c = vec![
            candidate(0xA5, &["a.txt"], shaping(None)),
            candidate(0xA6, &["b.txt"], shaping(None)),
        ];
        let decision = match_candidates(&c, &abs(&["z.txt"]), &shaping(None)).expect("fresh seal");
        assert_eq!(
            decision,
            ResumeDecision::Fresh {
                incomplete_works: 2
            }
        );
        let notice = decision.notice().expect("a notice is printed");
        assert!(notice.contains("2 incomplete seal(s)"), "{notice}");
        assert!(notice.contains("antseal list"), "{notice}");

        // An empty vault says nothing at all.
        assert_eq!(
            match_candidates(&[], &abs(&["z.txt"]), &shaping(None))
                .expect("fresh")
                .notice(),
            None
        );
    }

    #[test]
    fn two_exact_matches_are_an_internal_error_not_a_question() {
        let c = vec![
            candidate(0xA7, &["a.txt"], shaping(None)),
            candidate(0xA8, &["a.txt"], shaping(None)),
        ];
        let err = match_candidates(&c, &abs(&["a.txt"]), &shaping(None)).expect_err("refused");
        assert_eq!(err.class(), crate::error::ErrorClass::Internal);
    }

    #[test]
    fn the_resume_plan_names_what_is_staged_and_whether_money_moved() {
        let mut pre_pay = candidate(0xB1, &["a.txt"], shaping(None));
        pre_pay.journal_state = Some(SealState::Anchored);
        let lines = resume_plan_lines(&pre_pay).join("\n");
        assert!(lines.contains("nothing paid"), "{lines}");
        assert!(lines.contains("remaining: pay, upload"), "{lines}");
        assert!(!lines.contains("already paid for"), "{lines}");

        let mut post_pay = candidate(0xB2, &["a.txt"], shaping(None));
        post_pay.state = WorkState::IncompletePostPay;
        post_pay.journal_state = Some(SealState::Paid);
        let lines = resume_plan_lines(&post_pay).join("\n");
        assert!(lines.contains("PAID"), "{lines}");
        assert!(lines.contains("no further payment"), "{lines}");
        assert!(lines.contains("about a day"), "{lines}");

        // A work with no journal tag renders honestly rather than guessing.
        let mut untagged = candidate(0xB3, &["a.txt"], shaping(None));
        untagged.journal_state = None;
        assert!(
            resume_plan_lines(&untagged)
                .join("\n")
                .contains("not recorded")
        );
    }
}
