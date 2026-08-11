//! R17's overlay rows, through the real machinery: every fixture below is
//! evaluated by `evaluate_anchors` — promotion, refutation and suppression
//! come out of D56's rules, never out of hand-built states. Unit tests on
//! purpose (the A18 arrangement): the `wasm32-core-tests` lane runs this
//! crate's `--lib` tests on `wasm32-unknown-unknown`, fixtures arrive via
//! `include_bytes!` and literals, and every row runs on both targets.
//!
//! The synthetic artifacts are zero-op containers, so each branch's
//! commitment **is** the stamped digest: one digest (`D60_STAMPED`, shared
//! with the real TSA captures) serves every artifact in a mixed bundle, and
//! `header_with(&D60_STAMPED, ntime)` mints an embedded header the ops
//! commit at any height and any time — which is what lets these rows steer
//! promoted times around the DigiCert token's real `genTime`.

use super::*;

use crate::anchor::model::{AnchorVerdict, OnlineBlockResult, OnlineEvidence, ReceiptFacts};
use crate::anchor::roots::TsaRootStore;
use crate::anchor::testing::ots_writer::{
    FETCH_DATE, HEADER_NTIME, bitcoin, container, fork, header_with, pending,
};
use crate::anchor::testing::tamper_rows::{AFTER_CAPTURE, D60_STAMPED};
use crate::anchor::verdicts::{
    OTS_ONLINE_BLOCK_ABSENT_CODE, OTS_ONLINE_HEADER_MISMATCH_CODE, evaluate_anchors,
};
use crate::bundle::AnchorStatus;
use crate::bundle::schema::{OpaqueBytes, OtsAnchor, OtsUpgrade, ReceiptRecord, TsaAnchor};

/// The DigiCert capture — proven under the real pinned store at
/// [`AFTER_CAPTURE`] (the A18 reachability row's own fixture).
const DIGICERT: &[u8] =
    include_bytes!("../../../../../testdata/anchors/A25-bootstrap/D60-tsa-digicert-resp.tsr");

/// Heights no real fixture uses, so synthetic artifacts never collide with
/// captured material in one evidence map.
const HEIGHT_A: u64 = 700_100;
const HEIGHT_B: u64 = 700_200;

fn opaque(bytes: &[u8]) -> OpaqueBytes {
    OpaqueBytes::from_vec(bytes.to_vec())
}

/// A committed single-branch `.ots` stamping `D60_STAMPED` at `height`, its
/// embedded header carrying `ntime`.
fn committed_ots(height: u64, ntime: u32) -> OtsAnchor {
    let bytes = container(&D60_STAMPED, &bitcoin(height));
    let upgrade = OtsUpgrade::new(height, header_with(&D60_STAMPED, ntime), FETCH_DATE);
    OtsAnchor::new(AnchorStatus::Attested, opaque(&bytes), Some(upgrade))
        .expect("a synthetic committed artifact is under the D10 caps")
}

/// The same shape with a pending sibling branch — offline `attested` (O4
/// precedes O5), and the artifact rule O5 out-votes an online refutation on.
fn committed_ots_with_pending_branch(height: u64, ntime: u32) -> OtsAnchor {
    let bytes = container(
        &D60_STAMPED,
        &fork(&[bitcoin(height), pending("https://calendar.example")]),
    );
    let upgrade = OtsUpgrade::new(height, header_with(&D60_STAMPED, ntime), FETCH_DATE);
    OtsAnchor::new(AnchorStatus::Attested, opaque(&bytes), Some(upgrade))
        .expect("a synthetic forked artifact is under the D10 caps")
}

fn digicert_anchor() -> TsaAnchor {
    TsaAnchor::new(
        AnchorStatus::Proven,
        opaque(DIGICERT),
        Vec::new(),
        FETCH_DATE,
    )
    .expect("a real capture is under the D10 caps")
}

fn receipt_record() -> ReceiptRecord {
    ReceiptRecord::new(
        vec![[0xab; 32]],
        200_000_001,
        opaque(b"opaque capture payload"),
    )
    .expect("a one-transaction receipt is well-formed")
}

/// Evaluate a bundle's anchor sections — the exact call R21 makes, twice.
fn verdicts_of(
    ots: &[OtsAnchor],
    tsa: &[TsaAnchor],
    receipt: Option<&ReceiptRecord>,
    evidence: &OnlineEvidence,
) -> AnchorVerdicts {
    let artifacts = AnchorArtifacts::from_parts(ots, tsa, receipt);
    evaluate_anchors(
        &artifacts,
        &D60_STAMPED,
        evidence,
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    )
}

/// The agreed evidence that promotes the artifact at (`height`, `ntime`):
/// byte-identical to its embedded header (D56 rule O3).
fn agreeing_evidence(height: u64, ntime: u32) -> OnlineEvidence {
    OnlineEvidence::new().with_block(
        height,
        OnlineBlockResult::Header(header_with(&D60_STAMPED, ntime)),
    )
}

/// Agreed evidence that refutes it: same merkle root, a different `nTime`
/// (D56 rule O6 — the `differs_in_ntime` shape A18's rows use).
fn refuting_evidence(height: u64, ntime: u32) -> OnlineEvidence {
    OnlineEvidence::new().with_block(
        height,
        OnlineBlockResult::Header(header_with(&D60_STAMPED, ntime + 3600)),
    )
}

fn pinned_endpoints() -> ProbeEndpoints {
    ProbeEndpoints::new(
        vec![
            "https://esplora-a.example".to_owned(),
            "https://esplora-b.example".to_owned(),
        ],
        false,
    )
}

fn probe_log() -> ProbeLog {
    ProbeLog::new(pinned_endpoints())
}

/// The DigiCert token's real `genTime`, read off the machinery rather than
/// hard-coded, so rows that need a promoted time before/after it stay
/// deterministic against the fixture instead of against a guess.
fn digicert_gen_time() -> i64 {
    let verdicts = verdicts_of(&[], &[digicert_anchor()], None, &OnlineEvidence::new());
    verdicts.outcomes()[0]
        .verdict()
        .verified_time_unix()
        .expect("DigiCert is proven under the pinned store at AFTER_CAPTURE")
}

// ── promotion feeds only the overlay ────────────────────────────────────

/// R17 Accept: the offline aggregate is identical before and after the probe
/// input exists — promotion feeds only the overlay computation. The offline
/// verdicts still say `attested`, their aggregate is still UNANCHORED, and
/// the overlay carries the promotion; nothing offline moved.
#[test]
fn promotion_feeds_only_the_overlay_and_the_offline_aggregate_cannot_see_it() {
    let ots = [committed_ots(HEIGHT_A, HEADER_NTIME)];
    let offline = verdicts_of(&ots, &[], None, &OnlineEvidence::new());
    let before = VerdictAggregate::from_verdicts(&offline);

    let online = verdicts_of(&ots, &[], None, &agreeing_evidence(HEIGHT_A, HEADER_NTIME));
    let artifacts = AnchorArtifacts::from_parts(&ots, &[], None);
    let probes = probe_log().with_block(HEIGHT_A, BlockProbe::Agreed);
    let overlay = build_online_overlay(&artifacts, &offline, &online, &probes);

    let after = VerdictAggregate::from_verdicts(&offline);
    assert_eq!(before, after, "the offline aggregate is one value, twice");
    assert!(before.is_unanchored(), "offline, `attested` proves no time");
    assert_eq!(before.headline(), None);
    assert_eq!(
        offline.outcomes()[0].verdict().state(),
        AnchorState::Attested,
        "the offline verdict never saw the evidence"
    );
    // The promotion exists — in the overlay and only there.
    assert!(
        matches!(overlay.headline_impact, HeadlineImpact::Supplies { .. }),
        "{:?}",
        overlay.headline_impact
    );
}

/// D64 §4's designed adjacency: UNANCHORED offline block, Supplies overlay —
/// with the full headline datum (agreed `nTime`, OTS, `bitcoin-block-<H>`)
/// and the mandatory online-attribution marker in the impact line.
#[test]
fn an_unanchored_offline_bundle_with_a_promoted_anchor_renders_the_supplies_impact() {
    let ots = [committed_ots(HEIGHT_A, HEADER_NTIME)];
    let offline = verdicts_of(&ots, &[], None, &OnlineEvidence::new());
    let online = verdicts_of(&ots, &[], None, &agreeing_evidence(HEIGHT_A, HEADER_NTIME));
    let artifacts = AnchorArtifacts::from_parts(&ots, &[], None);
    let probes = probe_log().with_block(HEIGHT_A, BlockProbe::Agreed);
    let overlay = build_online_overlay(&artifacts, &offline, &online, &probes);

    let HeadlineImpact::Supplies { headline } = &overlay.headline_impact else {
        panic!("expected Supplies, got {:?}", overlay.headline_impact);
    };
    assert_eq!(headline.time_unix(), i64::from(HEADER_NTIME));
    assert_eq!(headline.kind(), AnchorKind::Ots);
    assert_eq!(
        headline.source(),
        Some(format!("bitcoin-block-{HEIGHT_A}").as_str())
    );
    assert_eq!(
        overlay.headline_impact_line,
        wording::supplies_line(headline),
        "the impact line is the one template with the marker"
    );
    assert!(
        overlay
            .headline_impact_line
            .contains(wording::ONLINE_ATTRIBUTION_MARKER)
    );

    // The per-anchor row carries D64 §6.2's Promoted datum.
    assert_eq!(overlay.anchor_outcomes.len(), 1);
    let row = &overlay.anchor_outcomes[0];
    assert_eq!(row.slot, "ots-1");
    assert_eq!(row.height, HEIGHT_A);
    assert_eq!(
        row.class,
        OverlayOutcomeClass::Promoted {
            time_unix: i64::from(HEADER_NTIME),
            height: HEIGHT_A,
            source: Some(format!("bitcoin-block-{HEIGHT_A}")),
        }
    );
}

/// The routine case (D64 §3.1's Stands): a TSA `genTime` precedes the
/// promoted block's `nTime`, so the online computation's headline equals the
/// offline one — the impact line points at the verdict above and restates
/// nothing, the anchor row still records the promotion, and no aggregate
/// delta appears (the spread stays inside 48 h by construction).
#[test]
fn a_promotion_later_than_the_offline_headline_leaves_it_standing() {
    let gen_time = digicert_gen_time();
    let later = u32::try_from(gen_time + 3600).expect("2026 genTime + 1 h fits u32");
    let ots = [committed_ots(HEIGHT_A, later)];
    let tsa = [digicert_anchor()];

    let offline = verdicts_of(&ots, &tsa, None, &OnlineEvidence::new());
    let online = verdicts_of(&ots, &tsa, None, &agreeing_evidence(HEIGHT_A, later));
    let artifacts = AnchorArtifacts::from_parts(&ots, &tsa, None);
    let probes = probe_log().with_block(HEIGHT_A, BlockProbe::Agreed);
    let overlay = build_online_overlay(&artifacts, &offline, &online, &probes);

    assert_eq!(overlay.headline_impact, HeadlineImpact::Stands);
    assert_eq!(overlay.headline_impact_line, wording::stands_line());
    assert!(
        !overlay
            .headline_impact_line
            .contains("existed no later than"),
        "Stands does not restate the headline sentence (Q89 via D64 §3)"
    );
    // The promotion still happened and still renders — as a row, not as a
    // headline.
    assert_eq!(overlay.anchor_outcomes.len(), 1);
    assert_eq!(overlay.anchor_outcomes[0].class.token(), "promoted");
    assert_eq!(
        overlay.aggregate_deltas,
        Vec::new(),
        "1 h of spread flags nothing; change-only lines stay absent"
    );
    // And the offline block's headline is the TSA's genTime, untouched.
    let offline_aggregate = VerdictAggregate::from_verdicts(&offline);
    assert_eq!(
        offline_aggregate
            .headline()
            .expect("TSA proven")
            .time_unix(),
        gen_time
    );
}

/// D64 §9's recorded risk, at the classifier boundary: an online headline
/// equal on **time** but different in source/kind is Supplies, never Stands.
/// A time-only comparison passes every other row in this file and fails
/// here.
#[test]
fn a_time_tie_with_a_different_source_classifies_as_supplies_never_stands() {
    let offline = VerdictAggregate::from_parts(
        [&AnchorVerdict::proven(
            AnchorKind::Tsa,
            300,
            Some("freetsa".to_owned()),
            None,
        )],
        None,
    );
    // The online-augmented set gains a promoted OTS at the same second; it
    // sits first in report order, so the tie-break hands it the headline.
    let promoted = AnchorVerdict::proven(
        AnchorKind::Ots,
        300,
        Some("bitcoin-block-7".to_owned()),
        None,
    );
    let tsa = AnchorVerdict::proven(AnchorKind::Tsa, 300, Some("freetsa".to_owned()), None);
    let online = VerdictAggregate::from_parts([&promoted, &tsa], None);

    match HeadlineImpact::classify(&offline, &online) {
        HeadlineImpact::Supplies { headline } => {
            assert_eq!(headline.time_unix(), 300, "same second");
            assert_eq!(headline.source(), Some("bitcoin-block-7"), "new source");
        }
        other => panic!("a source change at an equal time must be Supplies, got {other:?}"),
    }

    // The other two classes, at the same boundary: identical datum → Stands;
    // no online headline → StillUnanchored.
    let same = VerdictAggregate::from_parts([&tsa], None);
    assert_eq!(
        HeadlineImpact::classify(&offline, &same),
        HeadlineImpact::Stands
    );
    let none = VerdictAggregate::from_parts([], None);
    assert_eq!(
        HeadlineImpact::classify(&offline, &none),
        HeadlineImpact::StillUnanchored
    );
}

// ── per-anchor outcomes ─────────────────────────────────────────────────

/// D64 §5's measurement: `BlockEvidence` is keyed by height, so one
/// disagreeing pair suppresses promotion for **its** anchor alone — the
/// other anchor, with agreed evidence at its own height, still promotes.
#[test]
fn endpoint_disagreement_suppresses_promotion_for_that_anchor_alone() {
    let ots = [
        committed_ots(HEIGHT_A, HEADER_NTIME),
        committed_ots(HEIGHT_B, HEADER_NTIME),
    ];
    let offline = verdicts_of(&ots, &[], None, &OnlineEvidence::new());
    // Agreed evidence exists for HEIGHT_A only — the pair at HEIGHT_B
    // disagreed, which is the absence of the entry (D56 §3).
    let online = verdicts_of(&ots, &[], None, &agreeing_evidence(HEIGHT_A, HEADER_NTIME));
    let artifacts = AnchorArtifacts::from_parts(&ots, &[], None);
    let probes = probe_log()
        .with_block(HEIGHT_A, BlockProbe::Agreed)
        .with_block(HEIGHT_B, BlockProbe::Disagreed);
    let overlay = build_online_overlay(&artifacts, &offline, &online, &probes);

    assert_eq!(overlay.anchor_outcomes.len(), 2);
    assert_eq!(overlay.anchor_outcomes[0].slot, "ots-1");
    assert_eq!(overlay.anchor_outcomes[0].class.token(), "promoted");
    assert_eq!(overlay.anchor_outcomes[1].slot, "ots-2");
    assert_eq!(
        overlay.anchor_outcomes[1].class,
        OverlayOutcomeClass::NotPromoted {
            reason: NotPromotedReason::Disagreed,
        }
    );
    assert!(
        overlay.anchor_outcomes[1]
            .line
            .contains("offline state stands"),
        "{}",
        overlay.anchor_outcomes[1].line
    );
}

/// R24's per-endpoint fetch-failure states, as data through the probe log:
/// the failures render endpoint by endpoint, from core wording — and with no
/// agreed evidence anywhere the impact is StillUnanchored.
#[test]
fn per_endpoint_failures_render_from_the_probe_log_and_the_impact_stays_unanchored() {
    let ots = [committed_ots(HEIGHT_A, HEADER_NTIME)];
    let offline = verdicts_of(&ots, &[], None, &OnlineEvidence::new());
    let online = verdicts_of(&ots, &[], None, &OnlineEvidence::new());
    let artifacts = AnchorArtifacts::from_parts(&ots, &[], None);
    let failures = vec![
        EndpointProbeFailure {
            endpoint: "https://esplora-a.example".to_owned(),
            class: ProbeFailureClass::Transport,
        },
        EndpointProbeFailure {
            endpoint: "https://esplora-b.example".to_owned(),
            class: ProbeFailureClass::Payload,
        },
    ];
    let probes = probe_log().with_block(HEIGHT_A, BlockProbe::Failed(failures.clone()));
    let overlay = build_online_overlay(&artifacts, &offline, &online, &probes);

    assert_eq!(overlay.headline_impact, HeadlineImpact::StillUnanchored);
    assert_eq!(
        overlay.headline_impact_line,
        wording::still_unanchored_line()
    );
    assert_eq!(overlay.anchor_outcomes.len(), 1);
    assert_eq!(
        overlay.anchor_outcomes[0].class,
        OverlayOutcomeClass::NotPromoted {
            reason: NotPromotedReason::EndpointFailures { failures },
        }
    );
    let line = &overlay.anchor_outcomes[0].line;
    assert!(line.contains("https://esplora-a.example"), "{line}");
    assert!(line.contains("transport failure"), "{line}");
    assert!(line.contains("unusable reply"), "{line}");
    // Nothing changed aggregate-level: both computations saw no evidence.
    assert_eq!(
        VerdictAggregate::from_verdicts(&offline),
        VerdictAggregate::from_verdicts(&online)
    );
    assert_eq!(overlay.aggregate_deltas, Vec::new());
}

/// The no-evidence reason, twice: an absent probe entry, and — the sharper
/// half — an `Agreed` entry whose evidence never reached the evaluation.
/// The online-augmented **state** is authoritative; a probe log cannot
/// out-claim it (D56 §3's absence rule read back).
#[test]
fn a_missing_probe_entry_and_an_effectless_agreed_claim_both_render_no_evidence() {
    let ots = [committed_ots(HEIGHT_A, HEADER_NTIME)];
    let offline = verdicts_of(&ots, &[], None, &OnlineEvidence::new());
    let online = verdicts_of(&ots, &[], None, &OnlineEvidence::new());
    let artifacts = AnchorArtifacts::from_parts(&ots, &[], None);

    for probes in [
        probe_log(),
        probe_log().with_block(HEIGHT_A, BlockProbe::Agreed),
        probe_log().with_block(HEIGHT_A, BlockProbe::NotAttempted),
    ] {
        let overlay = build_online_overlay(&artifacts, &offline, &online, &probes);
        assert_eq!(
            overlay.anchor_outcomes[0].class,
            OverlayOutcomeClass::NotPromoted {
                reason: NotPromotedReason::NoEvidence,
            },
            "probe log {probes:?}"
        );
    }
}

/// Agreed refutation (D64 §5): the online-augmented state is `invalid`, the
/// row is `Refuted` with the refutation's code, and the line is the one
/// place a state word appears. Both refutation shapes: header-differs (O6)
/// and agreed no-such-block (O7), with their two distinct codes.
#[test]
fn agreed_refutation_renders_refuted_with_the_state_word_and_the_distinct_code() {
    let ots = [committed_ots(HEIGHT_A, HEADER_NTIME)];
    let offline = verdicts_of(&ots, &[], None, &OnlineEvidence::new());
    let artifacts = AnchorArtifacts::from_parts(&ots, &[], None);
    let probes = probe_log().with_block(HEIGHT_A, BlockProbe::Agreed);

    // O6 — the agreed header differs from the embedded one.
    let online = verdicts_of(&ots, &[], None, &refuting_evidence(HEIGHT_A, HEADER_NTIME));
    let overlay = build_online_overlay(&artifacts, &offline, &online, &probes);
    assert_eq!(
        overlay.anchor_outcomes[0].class,
        OverlayOutcomeClass::Refuted {
            code: OTS_ONLINE_HEADER_MISMATCH_CODE.to_owned(),
        }
    );
    let line = &overlay.anchor_outcomes[0].line;
    assert!(line.contains("invalid"), "{line}");
    assert!(line.contains(OTS_ONLINE_HEADER_MISMATCH_CODE), "{line}");
    assert_eq!(overlay.headline_impact, HeadlineImpact::StillUnanchored);

    // O7 — both endpoints agreed the height holds no block.
    let absent_evidence =
        OnlineEvidence::new().with_block(HEIGHT_A, OnlineBlockResult::NoSuchBlock);
    let online = verdicts_of(&ots, &[], None, &absent_evidence);
    let overlay = build_online_overlay(&artifacts, &offline, &online, &probes);
    assert_eq!(
        overlay.anchor_outcomes[0].class,
        OverlayOutcomeClass::Refuted {
            code: OTS_ONLINE_BLOCK_ABSENT_CODE.to_owned(),
        }
    );
    // The offline block never moves: the same bundle still says `attested`
    // offline, which is line 108's deliberate online-gating (D64 §5).
    assert_eq!(
        offline.outcomes()[0].verdict().state(),
        AnchorState::Attested
    );
}

/// The measured fourth outcome (R17's recorded extension to D64 §6.2's
/// reason set): agreed evidence refutes the header, a pending branch
/// out-votes the refutation (O5 over O6, D93 §5), the online-augmented state
/// is `pending`, and the row carries the suppressed anomaly's code — neither
/// `Refuted` (the state did not move to `invalid`) nor a plain no-evidence.
#[test]
fn an_agreed_refutation_out_voted_by_a_pending_branch_renders_the_suppressed_class() {
    let ots = [committed_ots_with_pending_branch(HEIGHT_A, HEADER_NTIME)];
    let offline = verdicts_of(&ots, &[], None, &OnlineEvidence::new());
    assert_eq!(
        offline.outcomes()[0].verdict().state(),
        AnchorState::Attested,
        "offline, O4 precedes O5: the committed upgrade wins"
    );

    let online = verdicts_of(&ots, &[], None, &refuting_evidence(HEIGHT_A, HEADER_NTIME));
    assert_eq!(
        online.outcomes()[0].verdict().state(),
        AnchorState::Pending,
        "online, the refutation gates O4 and the pending branch takes O5"
    );

    let artifacts = AnchorArtifacts::from_parts(&ots, &[], None);
    let probes = probe_log().with_block(HEIGHT_A, BlockProbe::Agreed);
    let overlay = build_online_overlay(&artifacts, &offline, &online, &probes);
    assert_eq!(
        overlay.anchor_outcomes[0].class,
        OverlayOutcomeClass::NotPromoted {
            reason: NotPromotedReason::RefutationSuppressed {
                code: OTS_ONLINE_HEADER_MISMATCH_CODE.to_owned(),
            },
        }
    );
    assert!(
        overlay.anchor_outcomes[0]
            .line
            .contains(OTS_ONLINE_HEADER_MISMATCH_CODE),
        "{}",
        overlay.anchor_outcomes[0].line
    );
}

/// TSA anchors get no outcome row (no online step, R21; D64 §5) — the
/// framing sentence carries the scope. One TSA beside one probed OTS: one
/// row, and it is the OTS's.
#[test]
fn tsa_anchors_get_no_outcome_row() {
    let ots = [committed_ots(HEIGHT_A, HEADER_NTIME)];
    let tsa = [digicert_anchor()];
    let offline = verdicts_of(&ots, &tsa, None, &OnlineEvidence::new());
    let online = verdicts_of(&ots, &tsa, None, &OnlineEvidence::new());
    let artifacts = AnchorArtifacts::from_parts(&ots, &tsa, None);
    let overlay = build_online_overlay(&artifacts, &offline, &online, &probe_log());

    assert_eq!(overlay.anchor_outcomes.len(), 1);
    assert_eq!(overlay.anchor_outcomes[0].slot, "ots-1");
    assert!(
        overlay
            .anchor_outcomes
            .iter()
            .all(|row| !row.slot.starts_with("tsa")),
        "no TSA row may exist"
    );
}

// ── receipt echo and endpoints disclosure ───────────────────────────────

/// D64 §3's presence rule, all four quadrants: the echo renders only when a
/// receipt is present AND was probed — and the confirmed echo carries no
/// time and no state, in the supporting-evidence register.
#[test]
fn the_receipt_echo_renders_only_when_a_receipt_is_present_and_was_probed() {
    let record = receipt_record();
    let ots = [committed_ots(HEIGHT_A, HEADER_NTIME)];
    let with_receipt = |evidence: &OnlineEvidence| verdicts_of(&ots, &[], Some(&record), evidence);
    let artifacts_with = AnchorArtifacts::from_parts(&ots, &[], Some(&record));
    let empty = OnlineEvidence::new();

    // Present and probed, agreed success: the confirmed echo.
    let facts = ReceiptFacts {
        status: 1,
        block_number: 200_000_001,
        block_hash: [0xcd; 32],
    };
    let probes = probe_log().with_receipt(ReceiptProbe::Agreed(ReceiptConfirmation::Agreed(facts)));
    let overlay = build_online_overlay(
        &artifacts_with,
        &with_receipt(&empty),
        &with_receipt(&empty),
        &probes,
    );
    let echo = overlay.receipt.expect("present and probed renders");
    assert_eq!(
        echo.outcome,
        ReceiptEchoOutcome::Confirmed {
            block_number: 200_000_001,
            status_success: true,
        }
    );
    for word in ["proven", "attested", "existed no later than"] {
        assert!(!echo.line.contains(word), "{}: {word}", echo.line);
    }

    // A reverted transaction is confirmed-with-status-false, never success.
    let reverted = ReceiptFacts { status: 0, ..facts };
    let probes =
        probe_log().with_receipt(ReceiptProbe::Agreed(ReceiptConfirmation::Agreed(reverted)));
    let overlay = build_online_overlay(
        &artifacts_with,
        &with_receipt(&empty),
        &with_receipt(&empty),
        &probes,
    );
    assert!(matches!(
        overlay.receipt.expect("probed").outcome,
        ReceiptEchoOutcome::Confirmed {
            status_success: false,
            ..
        }
    ));

    // Present, not probed: no echo.
    let overlay = build_online_overlay(
        &artifacts_with,
        &with_receipt(&empty),
        &with_receipt(&empty),
        &probe_log(),
    );
    assert_eq!(overlay.receipt, None, "not probed, no line");

    // Probed, but no receipt in the bundle: no echo either.
    let without = verdicts_of(&ots, &[], None, &empty);
    let artifacts_without = AnchorArtifacts::from_parts(&ots, &[], None);
    let probes = probe_log().with_receipt(ReceiptProbe::Disagreed);
    let overlay = build_online_overlay(&artifacts_without, &without, &without, &probes);
    assert_eq!(overlay.receipt, None, "no receipt, nothing to echo");
}

/// The endpoints disclosure echoes the identities and flips its label with
/// the overridden flag — the same identities render two different lines.
#[test]
fn the_endpoints_disclosure_echoes_identities_and_labels_an_override() {
    let ots = [committed_ots(HEIGHT_A, HEADER_NTIME)];
    let verdicts = verdicts_of(&ots, &[], None, &OnlineEvidence::new());
    let artifacts = AnchorArtifacts::from_parts(&ots, &[], None);

    let pinned = build_online_overlay(&artifacts, &verdicts, &verdicts, &probe_log());
    assert_eq!(pinned.endpoints.identities.len(), 2);
    assert!(!pinned.endpoints.overridden);
    assert!(pinned.endpoints.line.contains("pinned defaults"));

    let overridden_probes = ProbeLog::new(ProbeEndpoints::new(
        vec!["https://my-esplora.example".to_owned()],
        true,
    ));
    let overridden = build_online_overlay(&artifacts, &verdicts, &verdicts, &overridden_probes);
    assert!(overridden.endpoints.overridden);
    assert!(
        overridden
            .endpoints
            .line
            .contains("departing from pinned defaults"),
        "{}",
        overridden.endpoints.line
    );
    assert!(
        overridden
            .endpoints
            .line
            .contains("https://my-esplora.example"),
        "{}",
        overridden.endpoints.line
    );
    assert_ne!(pinned.endpoints.line, overridden.endpoints.line);
}

// ── change-only aggregate deltas ────────────────────────────────────────

/// A promotion more than 48 h from the offline headline lands the
/// newly-flagged divergence delta — the change-only line D64 §3 names — and
/// the within-48 h twin above (`a_promotion_later_than_the_offline_headline…`)
/// pins the empty side, so this pair is the differential.
#[test]
fn a_promotion_more_than_48_hours_out_lands_the_newly_flagged_divergence_delta() {
    let gen_time = digicert_gen_time();
    let far =
        u32::try_from(gen_time + crate::verify::verdict::HEADLINE_DIVERGENCE_THRESHOLD_SECS + 3600)
            .expect("2026 genTime + 49 h fits u32");
    let ots = [committed_ots(HEIGHT_A, far)];
    let tsa = [digicert_anchor()];

    let offline = verdicts_of(&ots, &tsa, None, &OnlineEvidence::new());
    let online = verdicts_of(&ots, &tsa, None, &agreeing_evidence(HEIGHT_A, far));
    let artifacts = AnchorArtifacts::from_parts(&ots, &tsa, None);
    let probes = probe_log().with_block(HEIGHT_A, BlockProbe::Agreed);
    let overlay = build_online_overlay(&artifacts, &offline, &online, &probes);

    assert_eq!(
        VerdictAggregate::from_verdicts(&offline).divergence(),
        None,
        "one eligible anchor offline: nothing to disagree"
    );
    assert_eq!(overlay.aggregate_deltas.len(), 1);
    assert_eq!(
        overlay.aggregate_deltas[0].delta,
        AggregateDelta::DivergenceNewlyFlagged {
            earliest_unix: gen_time,
            latest_unix: i64::from(far),
        }
    );
    assert!(
        overlay.aggregate_deltas[0].line.contains("48 h"),
        "{}",
        overlay.aggregate_deltas[0].line
    );
    // The promoted time is later, so the headline stands while the flag is
    // new — two independent outcomes on one run.
    assert_eq!(overlay.headline_impact, HeadlineImpact::Stands);
}

// ── the sibling-document containment ────────────────────────────────────

/// D64 §6's equality at this module's level: the canonical report bytes are
/// byte-identical whether or not the overlay computation runs — this API
/// never touches the report, and the overlay document itself serializes
/// deterministically beside it.
#[test]
fn report_bytes_are_byte_identical_whether_or_not_the_overlay_computation_runs() {
    use crate::verify::report::{
        Digest32, EvidenceLayerResult, REPORT_VERSION, RevealSet, SignatureScheme,
        StorageLinkageResult, SupportingEvidenceResult, VerificationReport, WorkMetadata,
    };

    let report = VerificationReport {
        report_version: REPORT_VERSION,
        work: WorkMetadata {
            work_id: Digest32([0x22; 32]),
            // No sealer text may contain the word the last assertion greps
            // for, or the probe would trip on its own fixture.
            title: "sibling-document containment probe".to_owned(),
            format_version: 1,
            app_version: "test".to_owned(),
            claimed_time_informational_only: None,
            signature_scheme: SignatureScheme::NotEvaluated,
        },
        evidence: EvidenceLayerResult {
            passed: true,
            units_verified: 0,
        },
        storage_linkage: StorageLinkageResult::NotEvaluated,
        anchors: Vec::new(),
        supporting_evidence: SupportingEvidenceResult::None,
        reveal: RevealSet {
            files: Vec::new(),
            unrevealed_files: Vec::new(),
        },
    };
    let before = report.to_canonical_json().expect("report serializes");

    let ots = [committed_ots(HEIGHT_A, HEADER_NTIME)];
    let offline = verdicts_of(&ots, &[], None, &OnlineEvidence::new());
    let online = verdicts_of(&ots, &[], None, &agreeing_evidence(HEIGHT_A, HEADER_NTIME));
    let artifacts = AnchorArtifacts::from_parts(&ots, &[], None);
    let probes = probe_log().with_block(HEIGHT_A, BlockProbe::Agreed);
    let overlay_a = build_online_overlay(&artifacts, &offline, &online, &probes);
    let overlay_b = build_online_overlay(&artifacts, &offline, &online, &probes);

    let after = report.to_canonical_json().expect("report serializes");
    assert_eq!(before, after, "zero report bytes move on an overlay run");
    // The sibling document is deterministic in its own right…
    assert_eq!(
        overlay_a.to_canonical_json().expect("overlay serializes"),
        overlay_b.to_canonical_json().expect("overlay serializes"),
        "two builds over one input are one byte string"
    );
    // …and no report key gains an overlay: the report's serialization
    // cannot name one (D64 §9's revisit trigger, asserted from this side).
    let report_text = String::from_utf8(before).expect("compact JSON is UTF-8");
    assert!(!report_text.contains("overlay"), "{report_text}");
}

// ── the closed class sets stay closed and rendered (L2's mechanism) ─────

/// Every outcome class, reason, impact class, echo outcome and delta has a
/// spelled token and a distinct, non-empty display line. The token lists are
/// hand-written on purpose (the Q127 shape): a lane that grows a class set
/// fails this row until the new class's token and line are written down —
/// which is the smallest mechanism under D64's L2 until R18's snapshot rows
/// take over.
#[test]
fn every_overlay_class_has_a_spelled_token_and_a_distinct_rendered_line() {
    let failure = EndpointProbeFailure {
        endpoint: "https://esplora-a.example".to_owned(),
        class: ProbeFailureClass::Transport,
    };
    let class_exemplars = [
        OverlayOutcomeClass::Promoted {
            time_unix: 1_700_000_000,
            height: 42,
            source: Some("bitcoin-block-42".to_owned()),
        },
        OverlayOutcomeClass::Refuted {
            code: OTS_ONLINE_HEADER_MISMATCH_CODE.to_owned(),
        },
        OverlayOutcomeClass::NotPromoted {
            reason: NotPromotedReason::Disagreed,
        },
        OverlayOutcomeClass::NotPromoted {
            reason: NotPromotedReason::EndpointFailures {
                failures: vec![failure.clone()],
            },
        },
        OverlayOutcomeClass::NotPromoted {
            reason: NotPromotedReason::NoEvidence,
        },
        OverlayOutcomeClass::NotPromoted {
            reason: NotPromotedReason::RefutationSuppressed {
                code: OTS_ONLINE_HEADER_MISMATCH_CODE.to_owned(),
            },
        },
    ];
    let tokens: Vec<&str> = class_exemplars
        .iter()
        .map(OverlayOutcomeClass::token)
        .collect();
    assert_eq!(
        tokens,
        [
            "promoted",
            "refuted",
            "not-promoted",
            "not-promoted",
            "not-promoted",
            "not-promoted"
        ],
        "D64 §6.2's closed class tokens moved; write the new one down here \
         and give it a line"
    );
    let lines: Vec<String> = class_exemplars
        .iter()
        .map(|class| anchor_outcome_line("ots-1", 42, class))
        .collect();
    for (line, class) in lines.iter().zip(&class_exemplars) {
        assert!(!line.is_empty(), "{class:?} renders nothing");
    }
    for (i, a) in lines.iter().enumerate() {
        for b in &lines[i + 1..] {
            assert_ne!(
                a, b,
                "two classes share one line — indistinguishable outcomes"
            );
        }
    }

    // The three-way impact set (D64 §3.1's one-of-three obligation).
    let impact_exemplars = [
        HeadlineImpact::Supplies {
            headline: Headline::fixture(1_700_000_000, AnchorKind::Ots, Some("bitcoin-block-42")),
        },
        HeadlineImpact::Stands,
        HeadlineImpact::StillUnanchored,
    ];
    let impact_tokens: Vec<&str> = impact_exemplars.iter().map(HeadlineImpact::token).collect();
    assert_eq!(impact_tokens, ["supplies", "stands", "still-unanchored"]);
    let impact_lines: Vec<String> = impact_exemplars.iter().map(headline_impact_line).collect();
    for (i, a) in impact_lines.iter().enumerate() {
        assert!(!a.is_empty());
        for b in &impact_lines[i + 1..] {
            assert_ne!(a, b);
        }
    }

    // The receipt echo's four rendered outcomes.
    let echo_probes = [
        ReceiptProbe::Agreed(ReceiptConfirmation::Agreed(ReceiptFacts {
            status: 1,
            block_number: 200_000_001,
            block_hash: [0xcd; 32],
        })),
        ReceiptProbe::Agreed(ReceiptConfirmation::NotOnChain),
        ReceiptProbe::Disagreed,
        ReceiptProbe::Failed(vec![failure]),
    ];
    let echo_lines: Vec<String> = echo_probes
        .iter()
        .map(|probe| {
            receipt_echo(probe)
                .expect("every probed outcome renders")
                .line
        })
        .collect();
    for (i, a) in echo_lines.iter().enumerate() {
        assert!(!a.is_empty());
        for b in &echo_lines[i + 1..] {
            assert_ne!(a, b);
        }
    }
    assert_eq!(receipt_echo(&ReceiptProbe::NotAttempted), None);

    // The delta set (one member today, held closed).
    let delta = AggregateDelta::DivergenceNewlyFlagged {
        earliest_unix: 0,
        latest_unix: 200_000,
    };
    assert_eq!(delta.token(), "divergence-newly-flagged");

    // And the serialized tokens match the in-memory ones — kebab-case,
    // externally tagged (the sibling document's own spelling discipline).
    let json = serde_json::to_string(&impact_exemplars[1]).expect("impact serializes");
    assert_eq!(json, "\"stands\"");
    let json = serde_json::to_string(&class_exemplars[1]).expect("class serializes");
    assert!(json.starts_with("{\"refuted\":"), "{json}");
}
