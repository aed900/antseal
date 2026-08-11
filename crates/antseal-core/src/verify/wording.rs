//! The **single core wording source** for verdict aggregation and the online
//! overlay — R17 lands the mechanism, **R18 is the freezer**.
//!
//! D64 (`docs/decisions/D64-online-overlay-headline-presentation.md` §3.1/§8)
//! rules that the overlay carries **final display strings embedded** (the
//! R74/R22 pattern: renderers — CLI and page JS alike — do layout only), and
//! that *"every sentence spelling inside that structure is R18's to author"*.
//! This module is where those sentences live so that R18 can freeze them —
//! snapshot tests, the full 7-state table, the positioning-checklist review —
//! **without moving any R17 type**: every display string
//! [`super::overlay::build_online_overlay`] embeds is drawn from here, none is
//! composed inline, and no other module (core, CLI, or page) may spell a
//! verdict sentence of its own (R18's grep-style Accept row is the
//! enforcement; the known CLI literals it will retire are recorded in R17's
//! closure notes).
//!
//! # Every spelling below is PROVISIONAL until R18
//!
//! What is **not** provisional is the structure D64 §8 freezes, which these
//! functions implement as shape rather than as prose:
//!
//! - **one headline template** ([`headline_sentence`]) — the overlay never
//!   mints a second "existed no later than"-class shape; the online variant
//!   differs only by the mandatory attribution marker **inside the source
//!   slot** ([`online_source_slot`]), which is what lets two times in one
//!   output read as two facts (Q89 via D64 §3);
//! - the overlay framing names "online" and "advisory", refers to the offline
//!   verdict **above**, and discloses that online results can strengthen
//!   **or refute** ([`overlay_framing_line`], D64 §5);
//! - probe lines are slot-named and carry a state word **only on refutation**
//!   (D64 §8); the disagreement/failure lines state that the offline state
//!   stands;
//! - the receipt line stays in the supporting-evidence register with no time
//!   and no state word (D64 §5; D98 rider 4);
//! - the endpoints-disclosure line labels an override as departing from the
//!   pinned defaults (D64 §8 edit 5).
//!
//! # WASM-safe
//!
//! Pure string assembly over already-computed data. No clock, no I/O, no
//! locale: times render as decimal POSIX seconds (the same spelling
//! `claimed_time_informational_only` and `fetch_date` froze at Q14), so the
//! output is byte-identical on native and wasm32.

use super::overlay::{EndpointProbeFailure, ProbeFailureClass};
use super::report::AnchorKind;
use super::verdict::Headline;

/// The slot text rendered when a headline-eligible anchor carries no source
/// identity (provisional; R18 freezes — the CLI's `status` currently spells
/// the same fallback inline).
pub const SOURCE_NOT_RECORDED: &str = "source not recorded";

/// The mandatory online-attribution marker (D64 §3.1: the Supplies headline
/// reuses the one template *"with a mandatory online-attribution marker in or
/// beside the source slot"*). Provisional spelling; the **presence** of a
/// marker is D64-frozen structure.
pub const ONLINE_ATTRIBUTION_MARKER: &str = "online-confirmed";

/// The anchor-kind label used inside sentences (provisional; R18 freezes).
///
/// Byte-identical to [`AnchorKind::wire_name`] today — kept as its own
/// wildcard-free match so R18 can give the two surfaces different spellings
/// without touching the report's frozen wire names, and so a third kind fails
/// compilation here as well.
#[must_use]
pub const fn kind_label(kind: AnchorKind) -> &'static str {
    match kind {
        AnchorKind::Ots => "ots",
        AnchorKind::Tsa => "tsa",
    }
}

/// The slot name for one per-anchor row: the kind plus its 1-based ordinal
/// **within that kind**, in report order (OTS artifacts first, then TSA, each
/// in wire order — [`crate::anchor::verdicts::AnchorVerdicts::outcomes`]).
///
/// This is the U23 slot convention D64 §6.2 requires the overlay's rows to
/// align with; R18's offline per-anchor rows must draw their names from this
/// same function so the two blocks name one anchor one way.
#[must_use]
pub fn slot_name(kind: AnchorKind, ordinal_within_kind: usize) -> String {
    format!("{}-{}", kind_label(kind), ordinal_within_kind)
}

/// The undecorated source-slot text for the offline headline sentence.
#[must_use]
pub fn source_slot(source: Option<&str>) -> String {
    source.unwrap_or(SOURCE_NOT_RECORDED).to_owned()
}

/// The online-attributed source-slot text (D64 §3.1: the marker lives in or
/// beside the source slot, never as a second sentence shape).
#[must_use]
pub fn online_source_slot(source: Option<&str>) -> String {
    format!(
        "{} — {ONLINE_ATTRIBUTION_MARKER}",
        source.unwrap_or(SOURCE_NOT_RECORDED)
    )
}

/// **The one headline template** (MVP-SPEC.md line 137's *"Existed no later
/// than \<time\> (source)"*; D64 §3: *"Template unity is frozen"*).
///
/// Both headline-shaped sentences the product can print — the offline block's
/// (R18) and the overlay's Supplies line ([`supplies_line`]) — must come from
/// this function, differing only in the `source_slot` text they pass. A second
/// "existed no later than"-class shape anywhere is the defect Q89 names.
#[must_use]
pub fn headline_sentence(time_unix: i64, kind: AnchorKind, source_slot: &str) -> String {
    format!(
        "existed no later than {time_unix} ({}, {source_slot})",
        kind_label(kind)
    )
}

/// The overlay's framing sentence (D64 §3/§5/§8): names "online" and
/// "advisory", refers to the offline verdict **above**, does not replace it,
/// and discloses that online results can strengthen **or refute**.
#[must_use]
pub const fn overlay_framing_line() -> &'static str {
    "online advisory — must-agree endpoint pairs; does not replace the offline verdict above; \
     online results can strengthen or refute individual anchors"
}

/// The Supplies-form headline-impact line (D64 §3.1 case 1): the one template
/// with the online-attribution marker in the source slot.
#[must_use]
pub fn supplies_line(headline: &Headline) -> String {
    headline_sentence(
        headline.time_unix(),
        headline.kind(),
        &online_source_slot(headline.source()),
    )
}

/// The Stands-form headline-impact line (D64 §3.1 case 2): points at the
/// offline headline, deliberately **not** restating the sentence.
#[must_use]
pub const fn stands_line() -> &'static str {
    "online result agrees: the offline headline above stands (time and source unchanged)"
}

/// The still-unanchored headline-impact line (D64 §3.1 case 3).
#[must_use]
pub const fn still_unanchored_line() -> &'static str {
    "still no independently provable time after the online check — the offline verdict above \
     stands"
}

/// Per-anchor line: promotion (D64 §5). Carries the promoted verdict's own
/// verified datum — block height, agreed time, attributed source — and **no
/// state word** (D64 §8: state words appear only on refutation).
#[must_use]
pub fn promoted_line(slot: &str, height: u64, time_unix: i64, source: Option<&str>) -> String {
    format!(
        "{slot}: Bitcoin block {height} agreed by both endpoints — time {time_unix} \
         ({})",
        online_source_slot(source)
    )
}

/// Per-anchor line: agreed refutation (D64 §5). The one line class that
/// carries the **state word `invalid`** and the error code (the
/// `anchor-forged-header` tamper family).
#[must_use]
pub fn refuted_line(slot: &str, code: &str) -> String {
    format!("{slot}: invalid — agreed online evidence refutes this anchor ({code})")
}

/// Per-anchor line: agreed refutation out-voted by a pending branch
/// (D56 §4's best-evidence-wins, D93 §5: the refutation is recorded as a
/// suppressed anomaly and the anchor's state does not move to `invalid`).
#[must_use]
pub fn refutation_suppressed_line(slot: &str, code: &str) -> String {
    format!(
        "{slot}: agreed online evidence contradicts the embedded header ({code}), but a pending \
         attestation out-votes the refutation; recorded, not promoted"
    )
}

/// Per-anchor line: the endpoint pair disagreed (D64 §5: advisory register,
/// no state word — nothing changed state; the offline state stands and
/// promotion is suppressed for this anchor alone).
#[must_use]
pub fn disagreed_line(slot: &str, height: u64) -> String {
    format!(
        "{slot}: the two endpoints disagreed about block {height} — no promotion; the offline \
         state stands"
    )
}

/// Per-anchor line: per-endpoint probe failures (D64 §5/§6.3; R24's
/// "per-endpoint fetch-failure states").
#[must_use]
pub fn endpoint_failures_line(
    slot: &str,
    height: u64,
    failures: &[EndpointProbeFailure],
) -> String {
    let detail = if failures.is_empty() {
        "no endpoint detail recorded".to_owned()
    } else {
        let parts: Vec<String> = failures
            .iter()
            .map(|failure| {
                format!(
                    "{}: {}",
                    failure.endpoint,
                    probe_failure_class_label(failure.class)
                )
            })
            .collect();
        parts.join("; ")
    };
    format!(
        "{slot}: online check for block {height} failed ({detail}) — no promotion; the offline \
         state stands"
    )
}

/// Per-anchor line: no agreed online evidence reached the verdict path for
/// this anchor's height (not attempted, or nothing usable arrived).
#[must_use]
pub fn no_evidence_line(slot: &str, height: u64) -> String {
    format!(
        "{slot}: no agreed online evidence for block {height} — no promotion; the offline state \
         stands"
    )
}

/// The failure-class word for one endpoint's probe failure. Wildcard-free so
/// a new class cannot ship unspelled (the L2 discipline at the class level).
#[must_use]
pub const fn probe_failure_class_label(class: ProbeFailureClass) -> &'static str {
    match class {
        ProbeFailureClass::Transport => "transport failure",
        ProbeFailureClass::Payload => "unusable reply",
        ProbeFailureClass::WrongChain => "wrong chain",
    }
}

/// Receipt echo: both RPCs confirmed the recorded transaction (supporting-
/// evidence register — **no time, no state word**; D64 §5, D98 rider 4).
#[must_use]
pub fn receipt_confirmed_line(block_number: u64, status_success: bool) -> String {
    let status = if status_success {
        ""
    } else {
        "; the transaction reverted"
    };
    format!(
        "receipt: both RPC endpoints confirm the recorded transaction on Arbitrum \
         (block {block_number}{status}) — supporting evidence only"
    )
}

/// Receipt echo: both RPCs agreed the transaction is not on chain.
#[must_use]
pub const fn receipt_not_on_chain_line() -> &'static str {
    "receipt: both RPC endpoints agree the recorded transaction is not on chain — supporting \
     evidence only"
}

/// Receipt echo: the RPC pair disagreed — no confirmation either way.
#[must_use]
pub const fn receipt_disagreed_line() -> &'static str {
    "receipt: the two RPC endpoints disagreed — no confirmation; supporting evidence only"
}

/// Receipt echo: the confirmation probe failed per endpoint.
#[must_use]
pub fn receipt_failed_line(failures: &[EndpointProbeFailure]) -> String {
    let detail = if failures.is_empty() {
        "no endpoint detail recorded".to_owned()
    } else {
        let parts: Vec<String> = failures
            .iter()
            .map(|failure| {
                format!(
                    "{}: {}",
                    failure.endpoint,
                    probe_failure_class_label(failure.class)
                )
            })
            .collect();
        parts.join("; ")
    };
    format!("receipt: online confirmation failed ({detail}) — supporting evidence only")
}

/// The endpoints-disclosure line (D64 §3/§8 edit 5): pinned defaults, or a
/// clearly-labeled departure from them.
#[must_use]
pub fn endpoints_line(identities: &[String], overridden: bool) -> String {
    let label = if overridden {
        "override — departing from pinned defaults"
    } else {
        "pinned defaults"
    };
    if identities.is_empty() {
        format!("endpoints: none recorded ({label})")
    } else {
        format!("endpoints: {} ({label})", identities.join(", "))
    }
}

/// Change-only aggregate line: the online-augmented computation flags a
/// headline divergence of more than 48 h where the offline one did not
/// (D64 §3's example, and the only aggregate delta the machinery can
/// produce today — online evidence adds eligible times and removes none,
/// so a flag can appear and never disappear).
#[must_use]
pub fn divergence_newly_flagged_line(earliest_unix: i64, latest_unix: i64) -> String {
    format!(
        "newly flagged: headline-eligible anchors now disagree by more than 48 h \
         (earliest {earliest_unix}, latest {latest_unix})"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D64 §3's frozen template unity, checked mechanically: the Supplies
    /// line **is** the one headline template with a decorated source slot —
    /// not a second sentence shape. Fails if `supplies_line` ever composes
    /// its own "existed no later than"-class string.
    #[test]
    fn the_supplies_line_is_the_one_headline_template_with_the_marker_in_the_source_slot() {
        let headline = Headline::fixture(1_700_000_000, AnchorKind::Ots, Some("bitcoin-block-42"));
        let line = supplies_line(&headline);
        assert_eq!(
            line,
            headline_sentence(
                1_700_000_000,
                AnchorKind::Ots,
                &online_source_slot(Some("bitcoin-block-42")),
            )
        );
        assert!(
            line.contains(ONLINE_ATTRIBUTION_MARKER),
            "the attribution marker is D64 §3.1's mandatory element: {line}"
        );
        // The offline form of the same headline differs ONLY in the slot
        // decoration — same template, two provenance labels (Q89 via D64 §3).
        let offline = headline_sentence(
            1_700_000_000,
            AnchorKind::Ots,
            &source_slot(Some("bitcoin-block-42")),
        );
        assert_ne!(line, offline, "the marker must be visible");
        assert_eq!(
            line.replace(&online_source_slot(Some("bitcoin-block-42")), ""),
            offline.replace(&source_slot(Some("bitcoin-block-42")), ""),
            "outside the source slot the two sentences are byte-identical — one template"
        );
    }

    /// D64 §8's structural obligations on the framing sentence — these
    /// tokens are frozen structure, not provisional spelling: the heading
    /// contains "online" and "advisory", refers to the verdict **above**,
    /// and discloses refutation. R18 may respell everything else.
    #[test]
    fn the_framing_line_carries_every_d64_structural_token() {
        let framing = overlay_framing_line();
        for token in ["online", "advisory", "above", "refute"] {
            assert!(
                framing.contains(token),
                "D64 §8 freezes `{token}` into the framing structure: {framing}"
            );
        }
    }

    /// D64 §8: a state word appears **only** on the refutation line. The
    /// promotion, disagreement, failure and no-evidence lines must not spell
    /// one — `proven` on the promoted line is the natural wrong rendering
    /// this pins against.
    #[test]
    fn state_words_appear_on_the_refutation_line_and_nowhere_else() {
        let failures = [EndpointProbeFailure {
            endpoint: "https://esplora.example".to_owned(),
            class: ProbeFailureClass::Transport,
        }];
        let stateless = [
            promoted_line("ots-1", 42, 1_700_000_000, Some("bitcoin-block-42")),
            disagreed_line("ots-1", 42),
            endpoint_failures_line("ots-1", 42, &failures),
            no_evidence_line("ots-1", 42),
        ];
        for line in &stateless {
            for word in ["proven", "invalid", "attested"] {
                assert!(
                    !line.contains(word),
                    "`{word}` is a state word; D64 §8 allows one only on refutation: {line}"
                );
            }
        }
        assert!(
            refuted_line("ots-1", "anchor-ots-online-header-mismatch").contains("invalid"),
            "the refutation line is the one place the state word is mandatory"
        );
    }

    /// The receipt lines stay in the supporting-evidence register: no state
    /// word, no time-shaped claim (D64 §5's report-side model — the arm
    /// carries "no time field and no state field").
    #[test]
    fn receipt_lines_carry_no_state_word_and_no_headline_shape() {
        let lines = [
            receipt_confirmed_line(200_000_001, true),
            receipt_confirmed_line(200_000_001, false),
            receipt_not_on_chain_line().to_owned(),
            receipt_disagreed_line().to_owned(),
            receipt_failed_line(&[]),
        ];
        for line in &lines {
            for word in ["proven", "invalid", "attested", "existed no later than"] {
                assert!(
                    !line.contains(word),
                    "the receipt register admits no `{word}`: {line}"
                );
            }
        }
    }

    /// The endpoints disclosure flips its label with the override flag — the
    /// R24 "departing from pinned defaults" datum, sourced here and nowhere
    /// page-authored (D64 §8 edit 5). Differential: same identities, one
    /// flag, two different lines.
    #[test]
    fn the_endpoints_line_labels_an_override_as_departing_from_pinned_defaults() {
        let identities = vec![
            "https://a.example".to_owned(),
            "https://b.example".to_owned(),
        ];
        let pinned = endpoints_line(&identities, false);
        let overridden = endpoints_line(&identities, true);
        assert_ne!(pinned, overridden);
        assert!(pinned.contains("pinned defaults"), "{pinned}");
        assert!(
            overridden.contains("departing from pinned defaults"),
            "{overridden}"
        );
    }

    /// Slot names follow the U23 kind-plus-ordinal convention the overlay's
    /// rows must share with the offline block (D64 §6.2).
    #[test]
    fn slot_names_are_kind_dash_ordinal() {
        assert_eq!(slot_name(AnchorKind::Ots, 1), "ots-1");
        assert_eq!(slot_name(AnchorKind::Tsa, 2), "tsa-2");
    }
}
