//! `list` (U19): every work in the vault, what state it is in, what it
//! cost, and — for an unfinished seal — the exact command that finishes it.
//!
//! MVP-SPEC.md line 149 (`list`) and line 145 ("`list` shows `incomplete`
//! works").
//!
//! # Two state tags, and why `list` reads both
//!
//! S10 keeps the fine [`SealState`] in journal entry 0 and U9's coarse
//! [`WorkState`] as a derived mirror in the meta record. `list` prefers the
//! fine tag — `staged` vs `anchored` is what tells a user how far their
//! interrupted seal got — but it must not *require* it: a `vault import`ed
//! **complete** work carries no journal entries at all (U12 applies D43
//! §3's cache exclusion to the whole journal area), so after a restore-from-
//! backup the coarse mirror is the only tag left. Reading the mirror as the
//! fallback is what keeps `list` working on exactly the machine where a
//! user most needs it. (That same gap stops `restore` working there; it is
//! recorded as S29 and is not `list`'s to fix.)
//!
//! # The two clocks (U19, from the D36/D37 planning round)
//!
//! An unfinished seal is on one of two clocks, and they pull in opposite
//! directions:
//!
//! - **pre-pay** — nothing was paid, and the journaled quote is stale *by
//!   design*: resume always re-quotes and re-asks for consent (D36). There
//!   is no hurry and no risk of a surprise charge.
//! - **post-receipt** — money already moved, and the payment proofs stay
//!   usable for uploading only about a day (D37's conservative client-side
//!   window). Past it, finishing the seal costs a **second** payment.
//!   Hence the nag: resume promptly.
//!
//! Saying "resume when convenient" to the second class would cost users
//! money, and saying "hurry" to the first would be a lie, so the row states
//! which clock it is on rather than printing one generic reminder.
//!
//! # Reserved slot
//!
//! `pending_anchors` is the M2 column (U25's pending-OTS nag). It is
//! carried as `None` here so the shape U25 fills is already in the `--json`
//! contract rather than being added to it later.

use antseal_core::crypto::secrets::SealId;

use crate::error::CliError;
use crate::pipeline::journal::{JournalError, SealState, recorded_state};
use crate::vault::store::{SealShapingFlags, WorkState, WorkStore};

/// Which clock an unfinished seal is on (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeClock {
    /// Pre-pay: the journaled quote is stale by design; resume re-quotes
    /// and re-consents (D36). No time pressure.
    ReQuote,
    /// Post-receipt: the payment proofs are PUT-usable for roughly a day
    /// (D37); past that, finishing costs a second payment.
    TimeBoxed,
}

impl ResumeClock {
    /// Stable kebab identifier for `--json`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReQuote => "re-quote",
            Self::TimeBoxed => "time-boxed",
        }
    }

    /// The human note the row carries.
    #[must_use]
    pub const fn note(self) -> &'static str {
        match self {
            Self::ReQuote => {
                "nothing was paid; the recorded quote is stale by design — resuming re-quotes \
                 at current prices and asks for consent again"
            }
            Self::TimeBoxed => {
                "RESUME PROMPTLY: this seal is paid for, and the payment proofs stay usable for \
                 uploading only about a day — after that, finishing it costs a second payment"
            }
        }
    }
}

/// How to finish an unfinished seal: the exact invocation, and the clock
/// it is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeHint {
    /// The recorded invocation, reproduced verbatim from D45's identity
    /// block — the `seal` re-run that will exact-match this work rather
    /// than starting a second one.
    pub invocation: String,
    /// Which clock this work is on.
    pub clock: ResumeClock,
}

/// One work's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkRow {
    /// `work_id = SHA-256(manifest body)` — absent until the manifest was
    /// built (a seal killed during staging has none yet).
    pub work_id: Option<[u8; 32]>,
    /// The vault's store key.
    pub seal_id: SealId,
    /// `--title`, as recorded (D45 identity block).
    pub title: Option<String>,
    /// When the user consented to this permanent seal, Unix seconds —
    /// see [`WorkListing`] docs for why this is the date `list` shows.
    pub sealed_at_unix_secs: Option<u64>,
    /// The work's network, canonical CLI spelling.
    pub network: String,
    /// The coarse state (always available, survives `vault import`).
    pub state: WorkState,
    /// The fine state (S10's journal tag), when the journal still carries
    /// it.
    pub fine_state: Option<SealState>,
    /// Sealed with `--no-anchor`: the UNANCHORED class.
    pub unanchored: bool,
    /// Sealed with `--force-degraded`.
    pub degraded: bool,
    /// Total storage cost, atto-ANT, as journaled at seal.
    pub cost_atto: Option<u128>,
    /// Present exactly for unfinished works.
    pub resume: Option<ResumeHint>,
    /// **Reserved for U25 (M2)**: pending OTS attestations. Always `None`
    /// at M1 — the slot exists so U25 fills a shape rather than adding
    /// one.
    pub pending_anchors: Option<u64>,
}

impl WorkRow {
    /// The coarse state identifier a user sees: `complete`, `incomplete`
    /// or `abandoned`.
    #[must_use]
    pub const fn state_name(&self) -> &'static str {
        match self.state {
            WorkState::IncompletePrePay | WorkState::IncompletePostPay => "incomplete",
            WorkState::Complete => "complete",
            WorkState::Abandoned => "abandoned",
        }
    }

    /// The finest state identifier available: S10's journal tag when the
    /// vault still carries it, otherwise the coarse mirror's own spelling.
    #[must_use]
    pub const fn detail_state_name(&self) -> &'static str {
        match self.fine_state {
            Some(state) => state.name(),
            None => match self.state {
                WorkState::IncompletePrePay => "incomplete-pre-pay",
                WorkState::IncompletePostPay => "incomplete-post-pay",
                WorkState::Complete => "complete",
                WorkState::Abandoned => "abandoned",
            },
        }
    }

    /// The state badge, UNANCHORED included — the one place the
    /// orthogonal anchor class is folded into the state column.
    #[must_use]
    pub fn badge(&self) -> String {
        let mut badge = self.state_name().to_owned();
        if self.unanchored {
            badge.push_str(" UNANCHORED");
        }
        if self.degraded {
            badge.push_str(" (degraded anchors)");
        }
        badge
    }
}

/// Everything `list` gathered, in display order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkListing {
    /// One row per work, newest first (see [`WorkListing::gather`]).
    pub works: Vec<WorkRow>,
}

impl WorkListing {
    /// Read every work in the vault.
    ///
    /// **Order**: newest first by seal date, works with no recorded date
    /// last, ties broken by seal id — total and deterministic, so a
    /// snapshot or a script sees a stable sequence.
    ///
    /// **The date**: the D36 consent timestamp. It is the moment the user
    /// agreed to make this seal permanent, it is within the same
    /// invocation as the manifest's `claimed_time`, and — unlike
    /// `claimed_time`, which lives in the journaled manifest — it rides in
    /// the meta record, so it survives a `vault import`. A work killed
    /// before consent has no date, which is honest: nothing was sealed.
    ///
    /// # Errors
    ///
    /// Store-level failures, as their CLI classes. A record that cannot be
    /// read is *not* softened into a row: an unreadable work record means
    /// a damaged or tampered vault, which `list` reports as such rather
    /// than rendering a partial picture that looks complete.
    pub fn gather(store: &WorkStore<'_>) -> Result<Self, CliError> {
        let mut works = Vec::new();
        for seal_id in store.list_works().map_err(CliError::from)? {
            let record = store.load_meta(&seal_id).map_err(CliError::from)?;
            // The fine tag is preferred; its absence is a state, not a
            // failure (module docs).
            let fine_state =
                recorded_state(store, &seal_id).map_err(|err: JournalError| CliError::from(err))?;
            let state = record.state;
            let resume = match state {
                WorkState::IncompletePrePay => Some(ResumeHint {
                    invocation: seal_invocation(
                        &record.input_paths_as_given,
                        &record.shaping,
                        &record.network,
                    ),
                    clock: ResumeClock::ReQuote,
                }),
                WorkState::IncompletePostPay => Some(ResumeHint {
                    invocation: seal_invocation(
                        &record.input_paths_as_given,
                        &record.shaping,
                        &record.network,
                    ),
                    clock: ResumeClock::TimeBoxed,
                }),
                WorkState::Complete | WorkState::Abandoned => None,
            };
            works.push(WorkRow {
                work_id: record.work_id,
                seal_id,
                title: record.shaping.title.clone(),
                sealed_at_unix_secs: record.consent.map(|c| c.consent_time_unix_secs),
                network: record.network.clone(),
                state,
                fine_state,
                unanchored: record.unanchored,
                degraded: record.degraded,
                cost_atto: record.cost_atto,
                resume,
                pending_anchors: None,
            });
        }
        works.sort_by(|a, b| {
            // Newest first; undated last; seal id as the total tie-break.
            b.sealed_at_unix_secs
                .cmp(&a.sealed_at_unix_secs)
                .then_with(|| a.seal_id.as_bytes().cmp(b.seal_id.as_bytes()))
        });
        Ok(Self { works })
    }

    /// How many works are in each class (the summary line, and the
    /// `--json` counts object).
    #[must_use]
    pub fn counts(&self) -> ListingCounts {
        let mut counts = ListingCounts {
            total: self.works.len(),
            ..ListingCounts::default()
        };
        for row in &self.works {
            match row.state {
                WorkState::Complete => counts.complete += 1,
                WorkState::IncompletePrePay | WorkState::IncompletePostPay => {
                    counts.incomplete += 1;
                }
                WorkState::Abandoned => counts.abandoned += 1,
            }
            if row.unanchored {
                counts.unanchored += 1;
            }
        }
        counts
    }

    /// The `--json` result document (U3's envelope wraps it).
    ///
    /// Amounts are decimal **strings**: atto-ANT is an 18-decimal unit, so
    /// real values sit far above the 2^53 a JSON number survives in most
    /// consumers. The house already takes this route for EVM addresses —
    /// exactness beats convenience in a machine contract.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        let counts = self.counts();
        serde_json::json!({
            "works": self.works.iter().map(row_json).collect::<Vec<_>>(),
            "counts": {
                "total": counts.total,
                "complete": counts.complete,
                "incomplete": counts.incomplete,
                "abandoned": counts.abandoned,
                "unanchored": counts.unanchored,
            },
        })
    }

    /// The human report, as lines (the caller routes them to stdout or —
    /// under `--json` — to stderr, D51).
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.works.is_empty() {
            out.push("No sealed works in this vault yet.".to_owned());
            return out;
        }
        for row in &self.works {
            let id = row.work_id.as_ref().map_or_else(
                || format!("(no work id yet; seal {})", hex_seal(&row.seal_id)),
                crate::pipeline::hex32,
            );
            out.push(format!("{id}  {}", row.badge()));
            let title = row.title.as_deref().unwrap_or("(untitled)");
            let when = row
                .sealed_at_unix_secs
                .map_or_else(|| "not yet sealed".to_owned(), format_utc);
            out.push(format!("  {title}   {when}   {}", row.network));
            match row.cost_atto {
                Some(cost) => out.push(format!("  cost: {cost} atto-ANT")),
                None => out.push("  cost: not recorded (nothing paid)".to_owned()),
            }
            if let Some(resume) = &row.resume {
                out.push(format!("  state: {}", row.detail_state_name()));
                out.push(format!("  {}", resume.clock.note()));
                out.push(format!("  resume with: {}", resume.invocation));
            }
        }
        let counts = self.counts();
        out.push(format!(
            "{} work(s): {} complete, {} incomplete, {} abandoned{}.",
            counts.total,
            counts.complete,
            counts.incomplete,
            counts.abandoned,
            if counts.unanchored > 0 {
                format!(" ({} UNANCHORED)", counts.unanchored)
            } else {
                String::new()
            }
        ));
        out
    }
}

/// Per-class counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ListingCounts {
    /// Every work.
    pub total: usize,
    /// `finalize_batch` succeeded.
    pub complete: usize,
    /// Still resumable.
    pub incomplete: usize,
    /// Abandoned (S11's safety outcome).
    pub abandoned: usize,
    /// Sealed with `--no-anchor` (orthogonal to the three above).
    pub unanchored: usize,
}

fn row_json(row: &WorkRow) -> serde_json::Value {
    serde_json::json!({
        "work_id": row.work_id.as_ref().map(crate::pipeline::hex32),
        "seal_id": hex_seal(&row.seal_id),
        "title": row.title,
        "sealed_at": row.sealed_at_unix_secs,
        "network": row.network,
        "state": row.state_name(),
        "detail_state": row.detail_state_name(),
        "unanchored": row.unanchored,
        "degraded": row.degraded,
        "cost_atto": row.cost_atto.map(|c| c.to_string()),
        "resume": row.resume.as_ref().map(|hint| serde_json::json!({
            "invocation": hint.invocation,
            "clock": hint.clock.name(),
            "note": hint.clock.note(),
        })),
        // Reserved for U25 (M2).
        "pending_anchors": row.pending_anchors,
    })
}

/// Rebuild the recorded `seal` invocation from D45's identity block.
///
/// Reproduced **verbatim**: the paths exactly as the user gave them, and
/// every seal-shaping flag that was recorded — because D45 matches a
/// resume on precisely this tuple, and a hint that dropped a flag would
/// print a command that starts a *second* seal instead of finishing this
/// one. Session flags (`--yes`, `--json`, `--passphrase-fd`, `--dry-run`)
/// are deliberately absent: they are not identity, and reprinting them
/// would be advice rather than a record.
///
/// `--network` is included whenever the work's network is not the built-in
/// default, since the effective network *is* part of D45's identity and
/// the config file could resolve it differently on the next run.
#[must_use]
pub fn seal_invocation(paths: &[String], shaping: &SealShapingFlags, network: &str) -> String {
    let mut parts = vec!["antseal".to_owned(), "seal".to_owned()];
    for path in paths {
        parts.push(shell_quote(path));
    }
    if let Some(title) = &shaping.title {
        parts.push("--title".to_owned());
        parts.push(shell_quote(title));
    }
    if shaping.split_blank_lines {
        parts.push("--split".to_owned());
        parts.push("blank-lines".to_owned());
    }
    if shaping.force_text {
        parts.push("--force-text".to_owned());
    }
    for glob in &shaping.no_fine_tree {
        parts.push("--no-fine-tree".to_owned());
        parts.push(shell_quote(glob));
    }
    if shaping.no_anchor {
        parts.push("--no-anchor".to_owned());
    }
    if shaping.force_degraded {
        parts.push("--force-degraded".to_owned());
    }
    if network != antseal_net::NetworkId::default().as_str() {
        parts.push("--network".to_owned());
        parts.push(network.to_owned());
    }
    parts.join(" ")
}

/// Single-quote a token that a shell would otherwise re-split or expand.
/// Anything outside a conservative safe set is quoted; embedded single
/// quotes take the POSIX `'\''` dance. A token that needs nothing is
/// printed exactly as recorded — which is what "verbatim" means for the
/// overwhelmingly common case.
fn shell_quote(token: &str) -> String {
    let safe = !token.is_empty()
        && token.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '+' | '=' | ':' | ',')
        });
    if safe {
        return token.to_owned();
    }
    format!("'{}'", token.replace('\'', r"'\''"))
}

fn hex_seal(seal_id: &SealId) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(32);
    for byte in seal_id.as_bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Unix seconds as `YYYY-MM-DD HH:MM:SS UTC` (the same std-only calendar
/// arithmetic `commands.rs` uses for export filenames; no chrono-class
/// dependency for two renderers).
fn format_utc(unix_secs: u64) -> String {
    let (y, mo, d, h, mi, s) = crate::commands::civil_utc(unix_secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shaping() -> SealShapingFlags {
        SealShapingFlags {
            title: Some("my thesis".to_owned()),
            split_blank_lines: true,
            force_text: false,
            no_fine_tree: vec!["*.png".to_owned()],
            no_anchor: true,
            force_degraded: false,
        }
    }

    #[test]
    fn the_resume_hint_reproduces_every_identity_flag() {
        let hint = seal_invocation(
            &["chapter one.txt".to_owned(), "notes.md".to_owned()],
            &shaping(),
            "devnet",
        );
        assert_eq!(
            hint,
            "antseal seal 'chapter one.txt' notes.md --title 'my thesis' --split blank-lines \
             --no-fine-tree '*.png' --no-anchor --network devnet"
        );
    }

    #[test]
    fn a_bare_invocation_stays_bare() {
        let hint = seal_invocation(
            &["a.txt".to_owned()],
            &SealShapingFlags::default(),
            "arbitrum-one",
        );
        assert_eq!(
            hint, "antseal seal a.txt",
            "no flags invented, no network noise"
        );
    }

    /// Session flags are not identity, so they never appear — and a path
    /// that could be re-split by a shell is quoted rather than mangled.
    #[test]
    fn quoting_is_conservative_and_reversible() {
        assert_eq!(shell_quote("plain-1.txt"), "plain-1.txt");
        assert_eq!(shell_quote("with space"), "'with space'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn the_two_clocks_say_opposite_things() {
        assert!(ResumeClock::ReQuote.note().contains("nothing was paid"));
        assert!(ResumeClock::TimeBoxed.note().contains("RESUME PROMPTLY"));
        assert_ne!(ResumeClock::ReQuote.note(), ResumeClock::TimeBoxed.note());
        assert_eq!(ResumeClock::ReQuote.name(), "re-quote");
        assert_eq!(ResumeClock::TimeBoxed.name(), "time-boxed");
    }
}
