//! The opportunistic upgrade engine and the `status`/`list` data backend
//! (task **A15**; U23, U24, U25 consume it).
//!
//! # Where the hook goes, and why it cannot go anywhere else
//!
//! U24 wires [`upgrade_pending`] into **every** CLI invocation, and A15's
//! contract is that it never delays or fails the host command. D90 handed on
//! the constraint unresolved and this is its answer:
//!
//! > **The hook runs after the host command's output is flushed.**
//!
//! That is forced, not preferred. The opportunistic profile's global timeout
//! is 3 s, and it cannot usefully go lower: the slowest calendar D90 measured
//! answers at a time-to-first-byte of 1.772 s, so a 1 s budget would report
//! every poll against a *healthy* calendar as a failure. At 3 s per calendar a
//! pre-output hook is plainly user-visible — `antseal list` would sit silent
//! for seconds before printing anything it already had in hand. No timeout
//! this substrate can offer fixes that, because the delay is not caused by the
//! timeout being wrong; it is caused by the work being ordered before the
//! output.
//!
//! After the flush, the same 3 s is invisible in the only way that matters:
//! the user has their answer, the process is exiting, and the shell prompt is
//! the only thing waiting. The budget then bounds *lateness of exit* rather
//! than *latency of answer*, and those are different quantities even though a
//! wall clock cannot tell them apart.
//!
//! Two consequences the caller must honour, both stated because a later reader
//! will otherwise "tidy" them:
//!
//! - **nothing here prints.** The report is data. Diagnostics are U's, on
//!   stderr, at debug level, and never on stdout — where they would corrupt
//!   `--json`;
//! - **nothing here fails the command.** [`upgrade_pending`] returns a report
//!   and no `Result`. Every per-anchor failure is a note. There is no error
//!   path to accidentally propagate, which is a stronger guarantee than
//!   remembering to ignore one.
//!
//! # The budget bounds what is *started*
//!
//! The substrate exposes no per-call deadline, so a budget check can only sit
//! between polls. The achievable bound is therefore
//! `budget.total + one in-flight call` — with
//! [`HttpPolicy::opportunistic`](crate::http::HttpPolicy::opportunistic) that
//! is `budget.total + 3 s`, and it is a bound rather than a typical case
//! because a poll that answers costs milliseconds. Stated here because the
//! obvious reading of "a 5-second budget" is wrong by up to 3 s.
//!
//! # This module persists nothing
//!
//! The vault is U's, and `antseal-anchor` has no business opening it. The
//! engine takes the works as data and returns the transitions to apply, so the
//! crate that owns the AEAD is the crate that writes to it. D42's rule that
//! the hook runs **iff** the host command already holds an unlocked vault
//! handle is enforced on that side, and cannot be violated from here: no
//! vault handle, no [`PendingWork`] values, no work.

use std::time::{Duration, Instant};

use antseal_core::anchor::ots::{OtsAttestation, OtsError, parse_ots};
use antseal_core::bundle::schema::OtsUpgrade;

use super::upgrade::{
    HeaderError, MergeError, PendingRef, UpgradePoll, UpgradeTarget, already_merged,
    confirm_header, merge_upgrade, pending_refs, poll_upgrade,
};
use super::upgrade_uri::UpgradeUriRefusal;
use crate::agree::EndpointPair;
use crate::http::{HTTP_OPPORTUNISTIC_GLOBAL, HttpClient};

/// One work's anchor state, as the vault hands it over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWork {
    /// The work this belongs to.
    pub work_id: [u8; 32],
    /// The digest every anchor of this work commits.
    pub anchor_digest: [u8; 32],
    /// The stored OTS artifacts, in vault order.
    pub ots: Vec<StoredOtsAnchor>,
    /// The stored TSA captures, in vault order.
    pub tsa: Vec<StoredTsaAnchor>,
    /// How many anchor slots this work holds whose **record** could not be
    /// interpreted at all — so neither their bytes nor even their kind
    /// reached this type (D100 R7.3).
    ///
    /// Zero for every healthy work, and the reason it lives here rather
    /// than being decided by the renderer: A15 owns the per-work nag
    /// (D98), and a work whose *only* slots are damaged would otherwise
    /// classify [`NagState::Unanchored`] — *"no anchors at all"* — which is
    /// a lie about a work that has anchors it cannot read. Deciding that in
    /// `list` instead would be a second nag rule in the CLI.
    pub unreadable_records: usize,
}

/// One stored OTS artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOtsAnchor {
    /// The `.ots` bytes.
    pub artifact: Vec<u8>,
    /// The upgrade group, once one has been recorded.
    pub upgrade: Option<OtsUpgrade>,
}

/// One stored TSA capture, reduced to what `status` and the nag rule need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredTsaAnchor {
    /// Whether a token is present at all.
    pub token_present: bool,
    /// Whether that token passed full `antseal-core` verification at capture
    /// time — the only thing that makes an anchor headline-eligible offline.
    pub verified: bool,
    /// When it was fetched, POSIX seconds UTC.
    pub fetch_date: u64,
}

/// How much work one hook invocation may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeBudget {
    /// Wall clock available for starting polls. See the module docs for what
    /// this does and does not bound.
    pub total: Duration,
    /// Hard ceiling on polls, so a vault with thousands of pending anchors
    /// cannot turn one invocation into a scan of all of them.
    pub max_polls: usize,
}

impl UpgradeBudget {
    /// U24's every-invocation hook: one calendar's worth of time, and a small
    /// number of polls.
    ///
    /// Four is deliberate: it is D54's default calendar count, so one
    /// invocation can finish one work's anchors and the *next* invocation
    /// starts on the next work rather than re-treading the first.
    #[must_use]
    pub const fn opportunistic() -> Self {
        Self {
            total: HTTP_OPPORTUNISTIC_GLOBAL,
            max_polls: 4,
        }
    }

    /// U23's `status --upgrade`: the user asked, so drive it as far as it
    /// goes.
    #[must_use]
    pub const fn interactive() -> Self {
        Self {
            total: Duration::from_secs(120),
            max_polls: usize::MAX,
        }
    }

    /// Whether `started` has used up the wall clock.
    #[must_use]
    pub fn exhausted(&self, started: Instant, polls: usize) -> bool {
        polls >= self.max_polls || started.elapsed() >= self.total
    }
}

/// A transition for the vault to apply. Nothing is written from here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedUpgrade {
    /// Which work.
    pub work_id: [u8; 32],
    /// Which OTS artifact of that work, by index into [`PendingWork::ots`].
    pub anchor_index: usize,
    /// The new artifact bytes, replacing the stored ones.
    pub artifact: Vec<u8>,
    /// The upgrade group to record with them. Recorded **together** with the
    /// artifact or not at all.
    pub upgrade: Option<OtsUpgrade>,
}

/// Why one anchor produced no transition. Never fatal, never a `Result`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UpgradeNote {
    /// The calendar knows the commitment and has not buried it yet. The
    /// ordinary case, and not a problem.
    #[error("{uri}: not yet confirmed in a Bitcoin block")]
    NotYetConfirmed {
        /// The calendar polled.
        uri: String,
    },
    /// The calendar has never heard of this commitment.
    #[error("{uri}: the calendar does not know this commitment — it will never upgrade")]
    NotFound {
        /// The calendar polled.
        uri: String,
    },
    /// The poll failed at the transport layer, or returned an unrecognised
    /// 404. Re-pollable.
    #[error("{uri}: the poll failed ({detail})")]
    PollFailed {
        /// The calendar polled.
        uri: String,
        /// What went wrong.
        detail: String,
    },
    /// A42's allowlist refused the URI in the stored artifact.
    #[error("{uri}: refused by the upgrade-URI allowlist ({source})")]
    Refused {
        /// The URI the artifact named.
        uri: String,
        /// Which rule it broke.
        source: UpgradeUriRefusal,
    },
    /// The calendar answered with an attestation this artifact already
    /// carries, so merging it would grow the file without adding evidence.
    ///
    /// The ordinary case once an anchor has upgraded, and **not** a problem: a
    /// merge is a pure insertion, so the pending branch survives it and is
    /// polled again next time. See
    /// [`already_merged`](super::upgrade::already_merged) for why this guard
    /// exists and why it compares bytes rather than attestation sets.
    #[error("{uri}: this calendar's attestation is already merged into the stored artifact")]
    AlreadyMerged {
        /// The calendar polled.
        uri: String,
    },
    /// The stored artifact does not parse, so it has no pending attestations
    /// this engine can address.
    #[error("the stored artifact does not parse: {0}")]
    Unreadable(OtsError),
    /// The upgrade arrived but could not be merged.
    #[error("{uri}: the upgrade could not be merged ({source})")]
    MergeRefused {
        /// The calendar polled.
        uri: String,
        /// Why.
        source: MergeError,
    },
    /// The upgrade merged but its header could not be confirmed, so nothing
    /// was recorded. Re-pollable: the merge is recomputed next time.
    #[error("{uri}: the block header could not be confirmed ({source})")]
    HeaderUnconfirmed {
        /// The calendar polled.
        uri: String,
        /// Why.
        source: HeaderError,
    },
    /// The budget ran out before this anchor was reached.
    #[error("the upgrade budget was exhausted before every pending anchor was polled")]
    BudgetExhausted,
}

/// What one hook invocation did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UpgradeReport {
    /// Polls actually issued.
    pub polls: usize,
    /// Transitions for the vault to apply.
    pub upgraded: Vec<AppliedUpgrade>,
    /// Everything that did not produce one.
    pub notes: Vec<UpgradeNote>,
    /// Whether work was left undone because the budget ran out.
    pub budget_exhausted: bool,
}

impl UpgradeReport {
    /// Whether anything is worth persisting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.upgraded.is_empty()
    }
}

/// Attempt pending OTS upgrades within `budget`.
///
/// **Returns no `Result`.** Every failure is a note, so there is no error path
/// for a caller to accidentally propagate into the host command's exit status.
///
/// `configured` is the user's calendar list, which widens A42's allowlist to
/// those hosts. `fetch_date` is supplied rather than read from a clock, so the
/// whole engine is testable without one.
#[must_use]
pub fn upgrade_pending(
    client: &HttpClient,
    pair: &EndpointPair,
    works: &[PendingWork],
    configured: &[String],
    budget: UpgradeBudget,
    fetch_date: u64,
) -> UpgradeReport {
    upgrade_pending_with(client, pair, works, budget, fetch_date, &|uri| {
        UpgradeTarget::from_pending_uri(uri, configured)
    })
}

/// [`upgrade_pending`] with the allowlist step supplied by the caller.
///
/// **A test seam, and never anything else.** A42's allowlist requires
/// `https`, a bare host and no port, so a loopback stub can never be admitted
/// through the real constructor — which is correct, and which also means the
/// engine's poll → merge → header path cannot be driven end to end against
/// A24's stubs without this seam.
///
/// The alternative that was tried first was worse and is worth recording: the
/// tests drove the real path with the committed artifact, whose pending URIs
/// are the **real** calendar hostnames. The allowlist admits those, so the
/// suite quietly contacted live calendars on every run — a Q16 violation that
/// passed every assertion, because the outcome is the same whether the
/// endpoint answers or not. A test that reaches the internet to prove a
/// timeout is not a test of the timeout.
///
/// # Why this widened from `#[cfg(test)] pub(crate)` to `test-util` + `pub`
///
/// D99 R5. U23's `status --upgrade` and U24's opportunistic hook both have
/// Accept rows requiring a pending → attested transition driven end to end,
/// and both live in `antseal-cli`. Under `#[cfg(test)]` this function does not
/// exist outside this crate's own compilation, and — by the paragraph above —
/// there is no other route: `from_pending_uri` can never admit a stub. So
/// those rows were **unexecutable by any means** until this gate changed.
///
/// **Measured safe, not assumed safe** (D99 §1.4, re-measured on
/// 2026-08-06). `cargo build -p antseal-cli` compiles this crate with
/// `--cfg 'feature="default"'` and nothing else, so under a product build this
/// item is not dead-code-eliminated — it is never parsed into the crate at
/// all. `cargo test -p antseal-cli` compiles it with `--cfg
/// 'feature="default"' --cfg 'feature="test-util"'`, and the two resulting
/// `target/debug/antseal` binaries differ by md5sum because cargo hard-link-
/// swaps them. `cargo tree -p antseal-cli -e features` shows
/// `antseal-anchor feature "test-util"` only under `[dev-dependencies]`, which
/// `scripts/check-anchor-net.py` R5 now enforces for every workspace manifest.
///
/// **A42 is not weakened.** Its invariant is a property of the *resolver*, not
/// of the target type: no poll is issued against a URI read out of a stored
/// artifact without `classify_upgrade_uri` having run. The production resolver
/// is untouched — [`upgrade_pending`] still closes over
/// [`UpgradeTarget::from_pending_uri`]. What this seam admits is a resolver
/// the *caller* supplies, and the caller is a test.
///
/// The residual — that a `test-util` build contains a bypass, and that the
/// `antseal` binary produced *during* `cargo test` is such a build — is closed
/// by `the_test_seam_has_no_production_call_sites`, which is proven red
/// against a planted call.
#[cfg(any(test, feature = "test-util"))]
pub fn upgrade_pending_with(
    client: &HttpClient,
    pair: &EndpointPair,
    works: &[PendingWork],
    budget: UpgradeBudget,
    fetch_date: u64,
    resolve: &dyn Fn(&str) -> Result<UpgradeTarget, UpgradeUriRefusal>,
) -> UpgradeReport {
    run(client, pair, works, budget, fetch_date, resolve)
}

/// The product build's private twin. Identical body; the only difference is
/// that nothing outside this module can name it, so [`upgrade_pending`]'s
/// allowlist step is not a parameter anybody can supply.
#[cfg(not(any(test, feature = "test-util")))]
fn upgrade_pending_with(
    client: &HttpClient,
    pair: &EndpointPair,
    works: &[PendingWork],
    budget: UpgradeBudget,
    fetch_date: u64,
    resolve: &dyn Fn(&str) -> Result<UpgradeTarget, UpgradeUriRefusal>,
) -> UpgradeReport {
    run(client, pair, works, budget, fetch_date, resolve)
}

fn run(
    client: &HttpClient,
    pair: &EndpointPair,
    works: &[PendingWork],
    budget: UpgradeBudget,
    fetch_date: u64,
    resolve: &dyn Fn(&str) -> Result<UpgradeTarget, UpgradeUriRefusal>,
) -> UpgradeReport {
    let started = Instant::now();
    let mut report = UpgradeReport::default();

    for work in works {
        for (anchor_index, anchor) in work.ots.iter().enumerate() {
            let refs = match pending_refs(&anchor.artifact, &work.anchor_digest) {
                Ok(refs) => refs,
                Err(error) => {
                    report.notes.push(UpgradeNote::Unreadable(error));
                    continue;
                }
            };
            if refs.is_empty() {
                continue;
            }
            if budget.exhausted(started, report.polls) {
                report.budget_exhausted = true;
                report.notes.push(UpgradeNote::BudgetExhausted);
                return report;
            }
            upgrade_one_anchor(
                client,
                pair,
                work,
                anchor_index,
                anchor,
                &refs,
                resolve,
                budget,
                fetch_date,
                started,
                &mut report,
            );
        }
    }
    report
}

/// Poll every pending attestation of one artifact, accumulating merges.
///
/// Merges accumulate into one artifact so that two calendars upgrading in the
/// same invocation produce **one** transition rather than two that would
/// overwrite each other — the second merge starts from the first's output.
#[allow(clippy::too_many_arguments)] // every argument is data the loop needs; bundling them into a
// struct would move the same fields behind a name that explains nothing.
fn upgrade_one_anchor(
    client: &HttpClient,
    pair: &EndpointPair,
    work: &PendingWork,
    anchor_index: usize,
    anchor: &StoredOtsAnchor,
    refs: &[PendingRef],
    resolve: &dyn Fn(&str) -> Result<UpgradeTarget, UpgradeUriRefusal>,
    budget: UpgradeBudget,
    fetch_date: u64,
    started: Instant,
    report: &mut UpgradeReport,
) {
    let mut artifact = anchor.artifact.clone();
    let mut upgrade = anchor.upgrade.clone();
    let mut changed = false;

    for pending in refs {
        if budget.exhausted(started, report.polls) {
            report.budget_exhausted = true;
            report.notes.push(UpgradeNote::BudgetExhausted);
            break;
        }

        let target = match resolve(&pending.uri) {
            Ok(target) => target,
            Err(source) => {
                report.notes.push(UpgradeNote::Refused {
                    uri: pending.uri.clone(),
                    source,
                });
                continue;
            }
        };

        report.polls += 1;
        let body = match poll_upgrade(client, &target, &pending.commitment) {
            UpgradePoll::Upgraded(body) => body,
            UpgradePoll::NotYetConfirmed => {
                report.notes.push(UpgradeNote::NotYetConfirmed {
                    uri: pending.uri.clone(),
                });
                continue;
            }
            UpgradePoll::NotFound => {
                report.notes.push(UpgradeNote::NotFound {
                    uri: pending.uri.clone(),
                });
                continue;
            }
            UpgradePoll::Failed(error) => {
                report.notes.push(UpgradeNote::PollFailed {
                    uri: pending.uri.clone(),
                    detail: error.to_string(),
                });
                continue;
            }
            UpgradePoll::Empty => {
                report.notes.push(UpgradeNote::PollFailed {
                    uri: pending.uri.clone(),
                    detail: "the calendar returned 200 with an empty body".to_owned(),
                });
                continue;
            }
        };

        // Re-derive the reference against the artifact **as it now stands**:
        // an earlier merge in this same loop shifted every offset after its
        // splice point, and a stale `PendingRef` would place the next one
        // wrongly. Cheap, and the alternative is offset arithmetic that is
        // right until the day it is not.
        let Some(current) = current_ref(&artifact, &work.anchor_digest, pending) else {
            report.notes.push(UpgradeNote::MergeRefused {
                uri: pending.uri.clone(),
                source: MergeError::LostAttestation,
            });
            continue;
        };

        // Repetition, refused. The pending branch survives every merge by
        // design, so this attestation is polled again on the next pass and the
        // calendar answers with the same bytes; splicing them a second time
        // adds no evidence and grows the stored artifact by one attestation
        // per run. Before U24 that cost one `status --upgrade`; the hook makes
        // it per **invocation**, for every work, for the life of the vault.
        // Checked against `current` rather than `pending`, because an earlier
        // merge in this same loop has already moved the offsets.
        if already_merged(&artifact, &current, &body) {
            report.notes.push(UpgradeNote::AlreadyMerged {
                uri: pending.uri.clone(),
            });
            continue;
        }

        let merged = match merge_upgrade(&artifact, &work.anchor_digest, &current, &body) {
            Ok(merged) => merged,
            Err(source) => {
                report.notes.push(UpgradeNote::MergeRefused {
                    uri: pending.uri.clone(),
                    source,
                });
                continue;
            }
        };

        // The header is fetched once per artifact: A14's `Do` says "on the
        // first Bitcoin attestation". A later calendar's attestation at a
        // different height merges its ops without a second fetch, and A12 only
        // needs one attestation to commit the embedded header.
        if upgrade.is_none() {
            let Some(attestation) = merged.added.first() else {
                report.notes.push(UpgradeNote::MergeRefused {
                    uri: pending.uri.clone(),
                    source: MergeError::NoBitcoinAttestation,
                });
                continue;
            };
            match confirm_header(client, pair, attestation, fetch_date) {
                Ok(confirmed) => upgrade = Some(confirmed),
                Err(source) => {
                    // Atomic: the merge is dropped with the header. Nothing
                    // half-done is ever handed to the vault.
                    report.notes.push(UpgradeNote::HeaderUnconfirmed {
                        uri: pending.uri.clone(),
                        source,
                    });
                    continue;
                }
            }
        }

        artifact = merged.artifact;
        changed = true;
    }

    if changed {
        report.upgraded.push(AppliedUpgrade {
            work_id: work.work_id,
            anchor_index,
            artifact,
            upgrade,
        });
    }
}

/// Re-locate `pending` in the current artifact bytes.
fn current_ref(
    artifact: &[u8],
    anchor_digest: &[u8; 32],
    pending: &PendingRef,
) -> Option<PendingRef> {
    pending_refs(artifact, anchor_digest)
        .ok()?
        .into_iter()
        .find(|candidate| {
            candidate.uri == pending.uri && candidate.commitment == pending.commitment
        })
}

// ── the status backend (A15's second half) ───────────────────────────────

/// What one stored OTS artifact currently is, offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OtsAnchorState {
    /// Pending attestations only: no Bitcoin attestation yet.
    Pending,
    /// At least one Bitcoin attestation, with the header group recorded.
    Attested,
    /// A Bitcoin attestation but no recorded header group — the state a
    /// header fetch that failed after a merge would leave behind.
    ///
    /// D97 made this unreachable from the whole **write path**, not merely
    /// from this engine: the artifact and its header group are keys of one
    /// record written by one `put_anchor`, so the filesystem's atomicity —
    /// not a convention anyone must remember — is what excludes the pair
    /// coming apart. It was a two-slot design that would have made this
    /// state ordinary, which is one of the four grounds D97 rejected it on.
    /// Still reported rather than assumed away, because a vault is editable
    /// by its owner.
    AttestedHeaderMissing,
    /// The artifact does not parse against this work's `anchor_digest`.
    Unreadable,
}

/// Per-anchor status data for U's `status` rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtsAnchorStatus {
    /// The offline state.
    pub state: OtsAnchorState,
    /// The calendars still pending, in document order.
    pub pending_uris: Vec<String>,
    /// The attested block heights, in document order.
    pub heights: Vec<u64>,
    /// When the header was fetched, when there is one.
    pub fetch_date: Option<u64>,
}

/// Whether a work should be nagged about, and why not when it should not be.
///
/// The five states are U25's fixture matrix, and they are five rather than a
/// boolean because "no nag" has four different meanings and rendering them
/// identically is how an UNANCHORED work comes to look merely pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NagState {
    /// A verified TSA token exists: there is a headline-eligible offline
    /// anchor and nothing to chase.
    Anchored,
    /// No headline-eligible anchor, and ≥1 OTS anchor still pending. **Nag**:
    /// `antseal status <id> --upgrade` can change this.
    OnlyPendingOts,
    /// No headline-eligible anchor, nothing pending, and everything this work
    /// holds is unreadable — either an `.ots` that does not parse against its
    /// `anchor_digest` or a record the vault codec refuses outright
    /// ([`PendingWork::unreadable_records`]).
    ///
    /// **Does not nag** ([`Self::nags`] is `false`), and that is the whole
    /// point of the state rather than an oversight: `nags()` drives the
    /// two-line PENDING block, whose count would read `0` and whose
    /// instruction (`--upgrade`) cannot help an artifact nothing can parse.
    /// The state exists so the row stops borrowing the name of a good
    /// outcome — A102 needed the **name**, not the boolean (D100 R7.1).
    Unreadable,
    /// No headline-eligible anchor, nothing pending, and nothing unreadable:
    /// this work holds anchors that no clock will improve offline.
    /// `--upgrade` cannot help.
    ///
    /// *"Every OTS anchor is already attested"* is the common case and not
    /// the definition — this is the last fall-through before "no anchors at
    /// all", so it also catches an `.ots` that parses but whose only
    /// attestation is of a **type this verifier does not implement**, and a
    /// work whose only anchors are TSA tokens that do not verify. `--online`
    /// verification helps the attested case and not the other two.
    AttestedOnly,
    /// **No anchor records at all**, whatever the seal's shaping flags said.
    /// The `--no-anchor` seal reaches it; so does a `--force-degraded` seal
    /// whose every anchor attempt failed, which was never given
    /// `--no-anchor`. Rendered UNANCHORED, never "pending".
    ///
    /// **Not** `WorkRecord::unanchored` and **not** MVP-SPEC.md line 137's
    /// UNANCHORED, and D98 rider 3c forbids collapsing any two of the four:
    /// the first is the `--no-anchor` input recorded at seal time, the
    /// second is *zero headline-eligible anchors* — which a work holding one
    /// pending OTS satisfies while this variant does not apply to it at all.
    /// `antseal-cli`'s `status_command.rs` pins a table of works on which
    /// those three answer differently (Q120).
    ///
    /// And **not** registry §7.6 key 3's *"both anchor arrays empty"*
    /// (sense (d), D108 R2), which is a layer-1 fact about the CBOR shape of
    /// a **`.sealproof`** and can never be the answer here: this variant is
    /// about a **work in a vault**, which has no bundle to have arrays in.
    /// That is also why the Q120 table cannot grow a fourth column. The
    /// registry's cell is frozen — `docs/format/frozen-registry-errata.md`
    /// records its scope.
    Unanchored,
}

impl NagState {
    /// Every state, in classifier order.
    ///
    /// The `ErrorClass::ALL` pattern: an enumeration test written over a
    /// hand-copied array passes while covering one state fewer than exists,
    /// which is exactly what `each_nag_class_has_its_own_name` did before
    /// D100 R8. A test written over this cannot (its length is the enum's).
    pub const ALL: [Self; 5] = [
        Self::Anchored,
        Self::OnlyPendingOts,
        Self::Unreadable,
        Self::AttestedOnly,
        Self::Unanchored,
    ];

    /// Whether `list` shows the nag marker.
    ///
    /// Deliberately **not** `matches!(self, Self::OnlyPendingOts)` any more:
    /// that shape defaults a new variant to "does not nag" silently, and
    /// D100 §1.7 measured it as the hole that let a fifth state be named and
    /// never have its rendering decided. Written wildcard-free so the choice
    /// is forced at this line.
    #[must_use]
    pub const fn nags(self) -> bool {
        match self {
            Self::OnlyPendingOts => true,
            Self::Anchored | Self::Unreadable | Self::AttestedOnly | Self::Unanchored => false,
        }
    }

    /// The stable kebab identifier for `--json` (**A103**).
    ///
    /// One table for one taxonomy: `list` used to carry a second copy of
    /// this on `WorkRow::nag_name`, which is two places for one set of
    /// names. Written wildcard-free so a sixth state fails compilation here
    /// instead of acquiring a wrong name in a `_` arm — the forcing that
    /// used to live in the CLI, moved to the enum it is about.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Anchored => "anchored",
            Self::OnlyPendingOts => "only-pending-ots",
            // Matches `OtsAnchorState::Unreadable`, which is the state it is
            // derived from — one word for one condition across both layers.
            Self::Unreadable => "unreadable",
            Self::AttestedOnly => "attested-only",
            Self::Unanchored => "unanchored",
        }
    }
}

/// One work's anchor status, for `status` and `list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkAnchorStatus {
    /// Which work.
    pub work_id: [u8; 32],
    /// Per-OTS-anchor data.
    pub ots: Vec<OtsAnchorStatus>,
    /// The TSA captures, unchanged.
    pub tsa: Vec<StoredTsaAnchor>,
    /// The nag decision.
    pub nag: NagState,
}

/// Derive the status data for one work. Pure: no clock, no network, no vault.
#[must_use]
pub fn work_status(work: &PendingWork) -> WorkAnchorStatus {
    let ots: Vec<OtsAnchorStatus> = work
        .ots
        .iter()
        .map(|anchor| anchor_status(anchor, &work.anchor_digest))
        .collect();

    let has_verified_tsa = work.tsa.iter().any(|tsa| tsa.token_present && tsa.verified);
    let has_pending = ots.iter().any(|status| {
        !status.pending_uris.is_empty() && status.state != OtsAnchorState::Unreadable
    });
    // Two sources for one condition: an `.ots` whose bytes do not parse
    // against this work's digest, and a vault record the codec would not open
    // at all (D100 R7.3). The second never reaches `work.ots`, which is why
    // it has to be counted separately rather than inferred from it.
    let has_unreadable = ots
        .iter()
        .any(|status| status.state == OtsAnchorState::Unreadable)
        || work.unreadable_records > 0;
    let has_any_anchor =
        !work.ots.is_empty() || !work.tsa.is_empty() || work.unreadable_records > 0;

    // The order is an argument, not a preference (D100 R7.2). Below
    // `has_verified_tsa`, because a work with a verified token genuinely
    // holds a headline-eligible anchor and calling it unreadable would
    // over-claim damage. Below `has_pending`, because `--upgrade` can still
    // help the pending half of a mixed work and satisfiable advice wins.
    // Above `has_any_anchor`, because that fall-through — "attested, or
    // unparseable" — is A102's entire complaint.
    let nag = if has_verified_tsa {
        NagState::Anchored
    } else if has_pending {
        NagState::OnlyPendingOts
    } else if has_unreadable {
        NagState::Unreadable
    } else if has_any_anchor {
        NagState::AttestedOnly
    } else {
        NagState::Unanchored
    };

    WorkAnchorStatus {
        work_id: work.work_id,
        ots,
        tsa: work.tsa.clone(),
        nag,
    }
}

fn anchor_status(anchor: &StoredOtsAnchor, anchor_digest: &[u8; 32]) -> OtsAnchorStatus {
    let Ok(artifact) = parse_ots(&anchor.artifact, anchor_digest) else {
        return OtsAnchorStatus {
            state: OtsAnchorState::Unreadable,
            pending_uris: Vec::new(),
            heights: Vec::new(),
            fetch_date: anchor.upgrade.as_ref().map(OtsUpgrade::fetch_date),
        };
    };

    let mut pending_uris = Vec::new();
    let mut heights = Vec::new();
    for attestation in &artifact.attestations {
        match attestation {
            OtsAttestation::Pending { uri, .. } => pending_uris.push(uri.clone()),
            OtsAttestation::Bitcoin { height, .. } => heights.push(*height),
            OtsAttestation::UnknownType { .. } => {}
        }
    }

    let state = match (heights.is_empty(), anchor.upgrade.is_some()) {
        (true, _) => OtsAnchorState::Pending,
        (false, true) => OtsAnchorState::Attested,
        (false, false) => OtsAnchorState::AttestedHeaderMissing,
    };

    OtsAnchorStatus {
        state,
        pending_uris,
        heights,
        fetch_date: anchor.upgrade.as_ref().map(OtsUpgrade::fetch_date),
    }
}

#[cfg(test)]
mod tests;
