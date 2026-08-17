//! R21's Accept rows, through the real machinery on both targets.
//!
//! Unit tests on purpose (R17/A18's arrangement): the `wasm32-core-tests`
//! lane runs this crate's `--lib` tests on `wasm32-unknown-unknown`, so every
//! row here runs natively **and** in wasm32 — which is the only way the
//! offline claim (*"works on bundles with no local Autonomi access
//! whatsoever"*) and R22's page story are measured rather than asserted.
//!
//! Every bundle below is a **real** `.sealproof`: R6 builds it, the anchor
//! section is substituted by typed construction and re-encoded through
//! `encode_bundle` (so tier-`[X]` layer-1 rules run again on the way back
//! in), and the `.ots` stamps the rebuilt bundle's **own** recomputed
//! `anchor_digest`. Nothing here hand-builds a state.

use super::*;

use core::cell::Cell;

use crate::anchor::model::OnlineBlockResult;
use crate::anchor::testing::ots_writer::{FETCH_DATE, bitcoin, container, header_with};
use crate::bundle::schema::{OpaqueBytes, OtsAnchor, OtsUpgrade};
use crate::bundle::{AnchorStatus, BundleV1, encode_bundle};
use crate::test_util::bundle_fixtures::{Selection, build, shapes};
use crate::verify::overlay::{
    BlockProbe, EndpointProbeFailure, HeadlineImpact, NotPromotedReason, OverlayOutcomeClass,
    ProbeFailureClass,
};
use crate::verify::rung::refuted_in_report_slots;

/// A height no fixture in the tree uses, so synthetic artifacts never collide
/// with captured material.
const HEIGHT: u64 = 700_311;
/// The embedded header's `nTime`.
const NTIME: u32 = 1_483_398_000;
/// Endpoint identities for the probe log — fixtures, never contacted.
fn endpoints() -> ProbeEndpoints {
    ProbeEndpoints::new(
        vec![
            "https://blockstream.example/api".to_owned(),
            "https://mempool.example/api".to_owned(),
        ],
        false,
    )
}

// ─────────────────────────────────────────────────────────────────────
// fixtures
// ─────────────────────────────────────────────────────────────────────

/// R6's three-file work with **no anchors at all** — the UNANCHORED bundle.
fn unanchored_bundle() -> Vec<u8> {
    build(&shapes::multi_file(), &Selection::all(3)).bytes
}

/// The same work carrying one genuinely `attested` `.ots`: a zero-op
/// container stamping this bundle's own `anchor_digest`, committed at
/// [`HEIGHT`], with the D79 upgrade group whose embedded header commits the
/// same digest at [`NTIME`].
///
/// Returns the bytes and the header the online evidence must agree with.
fn attested_bundle() -> (Vec<u8>, [u8; 80]) {
    let built = build(&shapes::multi_file(), &Selection::all(3));
    let proof = SealProof::decode(&built.bytes).expect("the R6 fixture decodes");
    let digest = *anchor_digest(proof.anchor_digest_preimage()).as_bytes();
    let header = header_with(&digest, NTIME);

    let anchor = OtsAnchor::new(
        AnchorStatus::Attested,
        OpaqueBytes::from_vec(container(&digest, &bitcoin(HEIGHT))),
        Some(OtsUpgrade::new(HEIGHT, header, FETCH_DATE)),
    )
    .expect("a synthetic committed artifact is under the D10 caps");

    let mut parts = BundleV1::decode(&built.bytes)
        .expect("the R6 fixture decodes to the model")
        .into_parts();
    parts.ots_anchors = vec![anchor];
    let bytes = encode_bundle(&BundleV1::new(parts).expect("a well-formed bundle"))
        .expect("the rebuilt bundle re-encodes");
    (bytes, header)
}

fn options() -> VerifyOptions {
    VerifyOptions::new()
}

// ─────────────────────────────────────────────────────────────────────
// the rendering policy (D130 §3 R5/R9)
// ─────────────────────────────────────────────────────────────────────

/// The identity neutralisation policy.
///
/// D130 §3 R5 keeps the escape **sets** in the surfaces — `antseal-cli`'s
/// terminal set (D67 §3 R3) and `antseal-wasm`'s DOM one — and this crate has
/// none. Every row below asserts composition, ordering, pairing or
/// mode-invariance, and no neutralisation can change any of those; each
/// surface asserts its own escape in its own suite, which is exactly what
/// D130 §7.3 says a parity gate cannot do for it.
fn plain(text: &str) -> String {
    text.to_owned()
}

/// [`super::verify_offline`] under [`plain`] — a local shim, so the rows
/// below read as the entry point's own call shape and the policy appears
/// once.
fn verify_offline(bundle: &[u8], options: &VerifyOptions) -> Result<VerifyOutcome, VerifyRunError> {
    super::verify_offline(bundle, options, &plain)
}

/// [`super::verify_with_host`] under [`plain`].
fn verify_with_host<H>(
    bundle: &[u8],
    options: &VerifyOptions,
    modes: VerifyModes,
    host: &H,
) -> Result<VerifyOutcome, VerifyRunError>
where
    H: VerifyHost + ?Sized,
{
    super::verify_with_host(bundle, options, modes, host, &plain)
}

// ─────────────────────────────────────────────────────────────────────
// hosts
// ─────────────────────────────────────────────────────────────────────

/// A host that **cannot** be consulted: every method is a panic naming what
/// went wrong.
///
/// This is the R21 Accept row's *"panicking mock backend/HTTP client"*,
/// adapted to a library that performs no I/O of its own: the host seam is the
/// only route to a network, so a host that panics on contact is the strongest
/// available statement that no call was made. The pairing test below
/// (`the_host_seam_is_live_when_a_mode_asks_for_it`) is what keeps this row
/// from passing because the seam is dead.
struct PanickingHost;

impl VerifyHost for PanickingHost {
    fn online_inputs(&self) -> OnlineInputs {
        panic!("offline mode consulted the network host for online inputs")
    }

    fn live_inputs(&self) -> LiveInputs {
        panic!("offline mode consulted the network host for live inputs")
    }
}

/// A host that records how many times each method was reached — the positive
/// control for the panicking one.
struct CountingHost {
    online_calls: Cell<u32>,
    live_calls: Cell<u32>,
    evidence: OnlineEvidence,
    probes: ProbeLog,
    live: LiveInputs,
}

impl CountingHost {
    fn new(evidence: OnlineEvidence, probes: ProbeLog, live: LiveInputs) -> Self {
        Self {
            online_calls: Cell::new(0),
            live_calls: Cell::new(0),
            evidence,
            probes,
            live,
        }
    }

    fn empty() -> Self {
        Self::new(
            OnlineEvidence::new(),
            ProbeLog::new(endpoints()),
            LiveInputs::none(),
        )
    }
}

impl VerifyHost for CountingHost {
    fn online_inputs(&self) -> OnlineInputs {
        self.online_calls.set(self.online_calls.get() + 1);
        OnlineInputs::new(self.evidence.clone(), self.probes.clone())
    }

    fn live_inputs(&self) -> LiveInputs {
        self.live_calls.set(self.live_calls.get() + 1);
        self.live.clone()
    }
}

/// Run `--online` over the attested bundle with the given agreed evidence and
/// probe log.
fn run_online(bundle: &[u8], evidence: OnlineEvidence, probes: ProbeLog) -> VerifyOutcome {
    let host = CountingHost::new(evidence, probes, LiveInputs::none());
    verify_with_host(bundle, &options(), VerifyModes::new().with_online(), &host)
        .expect("the fixture bundle verifies")
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 1 — offline mode performs zero network I/O
// ─────────────────────────────────────────────────────────────────────

/// The panicking host, handed to an offline run over a real bundle, is never
/// reached. If any offline code path ever consults the seam, this test fails
/// with the message the panic carries.
#[test]
fn offline_mode_never_consults_the_host() {
    let outcome = verify_with_host(
        &unanchored_bundle(),
        &options(),
        VerifyModes::OFFLINE,
        &PanickingHost,
    )
    .expect("the fixture bundle verifies");
    assert!(outcome.overlay().is_none());
    assert!(outcome.live().is_none());

    // …and over the bundle that *has* something to probe, so the row is not
    // passing because there was nothing to fetch about.
    let (attested, _) = attested_bundle();
    verify_with_host(&attested, &options(), VerifyModes::OFFLINE, &PanickingHost)
        .expect("the attested bundle verifies offline");
}

/// The seam the row above proves untouched is a **live** seam: the same host
/// object records exactly one consultation per requested layer, and none when
/// the mode is offline. Without this, the panicking row would pass equally
/// well against an orchestration that never consults a host at all.
#[test]
fn the_host_seam_is_live_when_a_mode_asks_for_it() {
    let bundle = unanchored_bundle();

    let offline = CountingHost::empty();
    verify_with_host(&bundle, &options(), VerifyModes::OFFLINE, &offline)
        .expect("the fixture bundle verifies");
    assert_eq!(
        (offline.online_calls.get(), offline.live_calls.get()),
        (0, 0),
        "an offline run consulted the host"
    );

    let both = CountingHost::empty();
    verify_with_host(
        &bundle,
        &options(),
        VerifyModes::new().with_online().with_live(),
        &both,
    )
    .expect("the fixture bundle verifies");
    assert_eq!(
        (both.online_calls.get(), both.live_calls.get()),
        (1, 1),
        "each requested layer consults its method exactly once"
    );
}

/// `verify_offline` is the offline mode of the host entry, asserted rather
/// than described — which is what makes the panicking row above a statement
/// about the function third parties actually call.
#[test]
fn verify_offline_is_the_offline_mode_of_the_host_entry() {
    let bundle = unanchored_bundle();
    let direct = verify_offline(&bundle, &options()).expect("verifies");
    let through_host = verify_with_host(&bundle, &options(), VerifyModes::OFFLINE, &PanickingHost)
        .expect("verifies");
    assert_eq!(direct, through_host);
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 2 — the mock-endpoint outcomes
// ─────────────────────────────────────────────────────────────────────

/// Agreement on the embedded header promotes the anchor (D56 rule O3): the
/// overlay's row is `Promoted`, its headline impact **supplies** a headline
/// the offline block does not have, and the rung moves 43 → 0 (D69 §3 R5).
#[test]
fn agreement_promotes_and_the_overlay_supplies_the_headline() {
    let (bundle, header) = attested_bundle();
    let outcome = run_online(
        &bundle,
        OnlineEvidence::new().with_block(HEIGHT, OnlineBlockResult::Header(header)),
        ProbeLog::new(endpoints()).with_block(HEIGHT, BlockProbe::Agreed),
    );

    let overlay = outcome.overlay().expect("--online produces an overlay");
    assert_eq!(overlay.anchor_outcomes.len(), 1);
    let row = &overlay.anchor_outcomes[0];
    assert_eq!(row.slot, "ots-1");
    assert_eq!(row.height, HEIGHT);
    assert!(
        matches!(
            row.class,
            OverlayOutcomeClass::Promoted {
                time_unix,
                height: HEIGHT,
                ..
            } if time_unix == i64::from(NTIME)
        ),
        "D56 rule O3: agreed evidence matching the embedded header must \
         PROMOTE this slot, and did not: {:?}",
        row.class
    );
    assert!(
        matches!(overlay.headline_impact, HeadlineImpact::Supplies { .. }),
        "{:?}",
        overlay.headline_impact
    );
    assert!(
        overlay
            .headline_impact_line
            .contains(wording::ONLINE_ATTRIBUTION_MARKER),
        "the Supplies line must carry the mandatory online-attribution \
         marker: {}",
        overlay.headline_impact_line
    );

    // The offline block is untouched, and the rung is the one thing that
    // moved (D69 §3 R5's first row).
    assert!(outcome.verdict().is_unanchored());
    assert!(outcome.rendered().unanchored);
    assert!(!outcome.exit_verdict().is_unanchored());
    assert_eq!(outcome.exit_rung(), None);
    assert_eq!(outcome.verdict_class().rung, None);
}

/// Endpoint disagreement is the **absence** of evidence in the verdict path
/// (D56 §3), so the offline verdict stands untouched and the overlay states
/// the reason. Asserted against the offline run byte for byte and rung for
/// rung — D69 §7 row 6's *"probe failure and endpoint disagreement → the code
/// is byte-for-byte the offline run's"*.
#[test]
fn disagreement_is_advisory_and_leaves_the_offline_verdict_untouched() {
    let (bundle, _) = attested_bundle();
    let offline = verify_offline(&bundle, &options()).expect("verifies");
    let outcome = run_online(
        &bundle,
        // Nothing agreed, so nothing reaches the evaluation.
        OnlineEvidence::new(),
        ProbeLog::new(endpoints()).with_block(HEIGHT, BlockProbe::Disagreed),
    );

    let overlay = outcome.overlay().expect("--online produces an overlay");
    let row = &overlay.anchor_outcomes[0];
    assert!(
        matches!(
            row.class,
            OverlayOutcomeClass::NotPromoted {
                reason: NotPromotedReason::Disagreed
            }
        ),
        "D64 §5: endpoint disagreement must render NotPromoted{{disagreed}}, \
         and rendered: {:?}",
        row.class
    );
    assert!(matches!(
        overlay.headline_impact,
        HeadlineImpact::StillUnanchored
    ));

    assert_eq!(
        text(outcome.report_bytes()),
        text(offline.report_bytes()),
        "endpoint disagreement moved a report byte"
    );
    assert_eq!(outcome.rendered(), offline.rendered());
    assert_eq!(outcome.verdict(), offline.verdict());
    assert_eq!(outcome.exit_verdict(), offline.exit_verdict());
    assert_eq!(outcome.exit_rung(), offline.exit_rung());
    assert_eq!(
        outcome.exit_rung(),
        Some(VerdictExitRung::Unanchored),
        "an attested-only bundle is UNANCHORED offline"
    );
}

/// Per-endpoint failure renders its own reason and its own classes, and is
/// likewise incapable of moving the verdict (D66: a thrown browser fetch is
/// `Transport` and can never become `NoSuchBlock`; one permanently
/// unreachable endpoint is `NotPromoted{endpoint-failures}` and never a
/// promotion on the survivor).
#[test]
fn endpoint_failures_never_promote_on_the_survivor() {
    let (bundle, header) = attested_bundle();
    let offline = verify_offline(&bundle, &options()).expect("verifies");
    let failures = vec![
        EndpointProbeFailure {
            endpoint: "https://blockstream.example/api".to_owned(),
            class: ProbeFailureClass::Transport,
        },
        EndpointProbeFailure {
            endpoint: "https://mempool.example/api".to_owned(),
            class: ProbeFailureClass::Payload,
        },
    ];
    let outcome = run_online(
        &bundle,
        // One endpoint answered — but a must-agree pair with a failed member
        // agrees on nothing, so the host supplies no evidence. Handing the
        // survivor's header through anyway is the defect D66 forbids, and it
        // is unrepresentable here: the evidence map is the host's, and this
        // host builds it from agreement alone.
        OnlineEvidence::new(),
        ProbeLog::new(endpoints()).with_block(HEIGHT, BlockProbe::Failed(failures.clone())),
    );

    let overlay = outcome.overlay().expect("--online produces an overlay");
    assert!(
        matches!(
            &overlay.anchor_outcomes[0].class,
            OverlayOutcomeClass::NotPromoted {
                reason: NotPromotedReason::EndpointFailures { failures: seen },
            } if seen == &failures
        ),
        "D66: a permanently unreachable endpoint pair must render \
         NotPromoted{{endpoint-failures}} carrying both classes, and \
         rendered: {:?}",
        overlay.anchor_outcomes[0].class
    );
    assert_eq!(outcome.exit_rung(), offline.exit_rung());
    assert_eq!(
        text(outcome.report_bytes()),
        text(offline.report_bytes()),
        "probe weather moved a report byte"
    );

    // The survivor's header is genuinely the promoting one, so the row above
    // is not passing because the header was wrong.
    let promoted = run_online(
        &bundle,
        OnlineEvidence::new().with_block(HEIGHT, OnlineBlockResult::Header(header)),
        ProbeLog::new(endpoints()).with_block(HEIGHT, BlockProbe::Agreed),
    );
    assert_eq!(promoted.exit_rung(), None);
}

/// A header mismatch is agreed evidence that **refutes** (D56 rule O6): the
/// online-augmented state is `invalid`, the overlay row is `Refuted` with the
/// refutation's code, and the rung climbs to `verify-anchor-refuted` — while
/// the offline report bytes do not move.
#[test]
fn a_header_mismatch_refutes_and_climbs_the_rung() {
    let (bundle, _) = attested_bundle();
    let offline = verify_offline(&bundle, &options()).expect("verifies");
    let wrong_header = header_with(&[0xEE; 32], NTIME);
    let outcome = run_online(
        &bundle,
        OnlineEvidence::new().with_block(HEIGHT, OnlineBlockResult::Header(wrong_header)),
        ProbeLog::new(endpoints()).with_block(HEIGHT, BlockProbe::Agreed),
    );

    let overlay = outcome.overlay().expect("--online produces an overlay");
    assert!(
        matches!(
            &overlay.anchor_outcomes[0].class,
            OverlayOutcomeClass::Refuted { code }
                if code == crate::anchor::verdicts::OTS_ONLINE_HEADER_MISMATCH_CODE
        ),
        "D56 rules O6/O7: an agreed header mismatch must render REFUTED \
         with its own code, and rendered: {:?}",
        overlay.anchor_outcomes[0].class
    );
    assert_eq!(outcome.refuted().get(), 1);
    assert_eq!(outcome.exit_rung(), Some(VerdictExitRung::AnchorRefuted));
    assert_eq!(outcome.verdict_class().rung, Some("verify-anchor-refuted"));

    // D64 §2/§6: the offline block did not move, in bytes or in rendering.
    assert_eq!(
        text(outcome.report_bytes()),
        text(offline.report_bytes()),
        "an agreed refutation moved a report byte"
    );
    assert_eq!(outcome.rendered(), offline.rendered());
    assert_eq!(offline.exit_rung(), Some(VerdictExitRung::Unanchored));
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 5 / D64 — report-byte equality, with its negative control
// ─────────────────────────────────────────────────────────────────────

/// The row D64 requires, and the control that gives it teeth.
///
/// The equality (*"an `--online` run and an offline run over the same bundle
/// expose byte-identical canonical report bytes"*) would pass vacuously on a
/// bundle whose online computation changes nothing. So the fixture is proved
/// **discriminating** first: the online-augmented verdicts project to
/// different report slots, and a report carrying those slots serializes to
/// different bytes. Any implementation that renders the online computation as
/// *the* verdict emits those bytes — and this test names them and requires
/// the exposed bytes not to be them.
#[test]
fn the_online_run_exposes_the_offline_report_bytes_and_the_control_differs() {
    let (bundle, header) = attested_bundle();
    let offline = verify_offline(&bundle, &options()).expect("verifies");
    let online = run_online(
        &bundle,
        OnlineEvidence::new().with_block(HEIGHT, OnlineBlockResult::Header(header)),
        ProbeLog::new(endpoints()).with_block(HEIGHT, BlockProbe::Agreed),
    );

    // ── the control: what "the online computation as the verdict" looks like
    let proof = SealProof::decode(&bundle).expect("decodes");
    let artifacts = AnchorArtifacts::from_bundle(proof.bundle());
    let digest = *anchor_digest(proof.anchor_digest_preimage()).as_bytes();
    let online_verdicts = evaluate_anchors(
        &artifacts,
        &digest,
        &OnlineEvidence::new().with_block(HEIGHT, OnlineBlockResult::Header(header)),
        0,
        options().tsa_roots(),
    );
    let online_slots = online_verdicts.project_anchor_results();
    assert_ne!(
        online_slots,
        offline.report().anchors,
        "the fixture must be one the online computation moves, or the \
         equality below is vacuous"
    );
    let mut rendered_online = offline.report().clone();
    rendered_online.anchors = online_slots;
    let control_bytes = rendered_online
        .to_canonical_json()
        .expect("the control report serializes");
    assert_ne!(
        control_bytes,
        offline.report_bytes(),
        "the control must differ, or it is not a control"
    );

    // ── the row itself. Compared as text, deliberately: a `Vec<u8>`
    // comparison prints two 1 kB decimal arrays and the wave rule *verify a
    // failure by its message* stops being satisfiable.
    assert_eq!(
        text(online.report_bytes()),
        text(offline.report_bytes()),
        "D64 §6: an `--online` run must expose the OFFLINE report bytes — \
         the overlay is a sibling document, never a report field"
    );
    assert_ne!(
        text(online.report_bytes()),
        text(&control_bytes),
        "the `--online` run exposed the ONLINE computation's report bytes"
    );
}

/// Canonical report bytes as text, so a failed comparison prints JSON rather
/// than a decimal byte array.
fn text(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).expect("canonical report bytes are UTF-8")
}

/// The two evaluations are the same evaluation: the verdicts this module
/// re-derives project to **the report's own `anchors` array**.
///
/// This is what keeps the second `evaluate_anchors` call honest — a wrong
/// `verify_at_unix`, a wrong root store, or a digest taken from the wrong
/// pre-image would all produce an aggregate that silently disagrees with the
/// slots rendered beneath its headline.
#[test]
fn the_re_evaluated_verdicts_project_to_the_reports_own_slots() {
    for bundle in [unanchored_bundle(), attested_bundle().0] {
        let outcome = verify_offline(&bundle, &options()).expect("verifies");
        let slots = &outcome.report().anchors;

        // (a) the exported helper's evaluation is the report's.
        let proof = SealProof::decode(&bundle).expect("decodes");
        let verdicts = offline_verdicts(&proof, &options());
        assert_eq!(
            verdicts.project_anchor_results(),
            *slots,
            "`offline_verdicts` re-derived slots the report does not carry"
        );
        assert_eq!(
            refuted_in_verdicts(&verdicts),
            refuted_in_report_slots(slots),
            "the two refutation adapters must agree on a real evaluation"
        );

        // (b) — the load-bearing half — the evaluation the *orchestration*
        // performed is the report's too. (a) alone proves nothing about it:
        // a wrong digest, `verify_at_unix` or root store inside
        // `verify_with_host` leaves (a) green and silently re-states every
        // anchor beneath a headline computed from different verdicts.
        assert_eq!(
            outcome.refuted(),
            refuted_in_report_slots(slots),
            "the orchestration's own anchor evaluation disagrees with the \
             report's slots — its digest, verification time or root store is \
             not the pipeline's"
        );
        let a1 = crate::verify::aggregate::aggregate_anchors(slots);
        assert_eq!(
            a1.headline_eligible_count(),
            outcome.verdict().eligible_count(),
            "A1's fold over the report's slots and R17's fold over the \
             orchestration's verdicts disagree on eligibility"
        );
        assert_eq!(
            a1.headline_time_unix(),
            outcome.verdict().headline().map(|h| h.time_unix()),
            "A1's fold over the report's slots and R17's fold over the \
             orchestration's verdicts disagree on the headline time"
        );
        assert_eq!(a1.is_unanchored(), outcome.verdict().is_unanchored());
    }
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 3 — the live section
// ─────────────────────────────────────────────────────────────────────

fn live_rows() -> LiveInputs {
    LiveInputs::from_rows(vec![
        LiveBlobRow {
            subject: "unit 0".to_owned(),
            outcome: LiveBlobOutcome::Identical,
        },
        LiveBlobRow {
            subject: "unit 1".to_owned(),
            outcome: LiveBlobOutcome::Different,
        },
        LiveBlobRow {
            subject: "unit 2".to_owned(),
            outcome: LiveBlobOutcome::NotFound,
        },
        LiveBlobRow {
            subject: "encrypted manifest".to_owned(),
            outcome: LiveBlobOutcome::FetchFailed {
                class: FetchFailureClass::Transport,
            },
        },
    ])
}

fn run_live(bundle: &[u8], live: LiveInputs) -> VerifyOutcome {
    let host = CountingHost::new(OnlineEvidence::new(), ProbeLog::new(endpoints()), live);
    verify_with_host(bundle, &options(), VerifyModes::new().with_live(), &host)
        .expect("the fixture bundle verifies")
}

/// Every per-blob outcome renders its own row, drawn from the frozen table,
/// and the section carries its own counts.
#[test]
fn live_mode_renders_a_row_per_blob_from_the_frozen_table() {
    let outcome = run_live(&unanchored_bundle(), live_rows());
    let live = outcome.live().expect("--live produces a section");

    assert_eq!(live.label, wording::LIVE_LAYER_LABEL);
    assert_eq!(
        live.rows
            .iter()
            .map(|row| row.line.clone())
            .collect::<Vec<_>>(),
        vec![
            wording::live_blob_identical_line("unit 0"),
            wording::live_blob_different_line("unit 1"),
            wording::live_blob_not_found_line("unit 2"),
            wording::live_blob_fetch_error_line(
                "encrypted manifest",
                wording::live_fetch_failure_class_label(FetchFailureClass::Transport),
            ),
        ]
    );
    assert_eq!(
        live.counts,
        LiveCounts {
            identical: 1,
            different: 1,
            not_found: 1,
            fetch_failed: 1,
            checked: 4,
        }
    );
    assert_eq!(
        live.counts.identical
            + live.counts.different
            + live.counts.not_found
            + live.counts.fetch_failed,
        live.counts.checked,
        "the four counts must partition the rows"
    );
}

/// R11's normative precedence, restated over the projected rows: the worst
/// **established fact** wins, and uncertainty rules only when nothing
/// negative was established. Every rung of the ladder, plus the vacuum R11
/// refuses outright.
#[test]
fn the_live_verdict_follows_r11s_precedence() {
    let cases: &[(&str, Vec<LiveBlobOutcome>, LiveLayerVerdict)] = &[
        ("no rows", vec![], LiveLayerVerdict::NothingChecked),
        (
            "all identical",
            vec![LiveBlobOutcome::Identical, LiveBlobOutcome::Identical],
            LiveLayerVerdict::AllPersisted,
        ),
        (
            "a failed fetch alone",
            vec![
                LiveBlobOutcome::Identical,
                LiveBlobOutcome::FetchFailed {
                    class: FetchFailureClass::Transport,
                },
            ],
            LiveLayerVerdict::Inconclusive,
        ),
        (
            "a missing blob out-ranks an unfetchable one",
            vec![
                LiveBlobOutcome::NotFound,
                LiveBlobOutcome::FetchFailed {
                    class: FetchFailureClass::Transport,
                },
            ],
            LiveLayerVerdict::SomeMissing,
        ),
        (
            "divergence out-ranks everything",
            vec![
                LiveBlobOutcome::Different,
                LiveBlobOutcome::NotFound,
                LiveBlobOutcome::FetchFailed {
                    class: FetchFailureClass::Transport,
                },
            ],
            LiveLayerVerdict::Divergent,
        ),
    ];

    for (label, outcomes, expected) in cases {
        let rows = LiveInputs::from_rows(
            outcomes
                .iter()
                .enumerate()
                .map(|(index, outcome)| LiveBlobRow {
                    subject: format!("unit {index}"),
                    outcome: outcome.clone(),
                })
                .collect(),
        );
        let outcome = run_live(&unanchored_bundle(), rows);
        let live = outcome.live().expect("--live produces a section");
        assert_eq!(live.verdict, *expected, "{label}");
        assert_eq!(
            live.verdict_line.is_none(),
            *expected == LiveLayerVerdict::NothingChecked,
            "{label}: only the vacuum has no verdict line to state"
        );
    }
}

/// The live layer is **distinct from the evidence layer** and moves nothing
/// in it — R20's Accept row and D69 §3 R6 (*"storage is the product's bonus,
/// not its proof"*), asserted across the worst live result the machinery can
/// produce.
#[test]
fn the_live_layer_moves_nothing_in_the_evidence_layer() {
    let bundle = unanchored_bundle();
    let without = verify_offline(&bundle, &options()).expect("verifies");
    let with = run_live(&bundle, live_rows());

    assert_eq!(
        text(with.report_bytes()),
        text(without.report_bytes()),
        "the live layer moved a report byte"
    );
    assert_eq!(with.report(), without.report());
    assert_eq!(
        with.rendered(),
        without.rendered(),
        "the live layer moved the rendered offline block"
    );
    assert_eq!(
        with.exit_rung(),
        without.exit_rung(),
        "D69 §3 R6: `--live` and the storage-linkage layer NEVER move the \
         exit code (MVP-SPEC.md line 118)"
    );
    assert_eq!(
        with.verdict_class(),
        without.verdict_class(),
        "D69 §3 R6: the live layer moved the verdict-class datum"
    );
    assert_eq!(
        with.live().expect("a section").verdict,
        LiveLayerVerdict::Divergent,
        "the comparison above must be made against a live result that failed"
    );
    assert!(without.live().is_none());
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 4 — what U30 is handed
// ─────────────────────────────────────────────────────────────────────

/// The exposed bytes are `to_canonical_json`'s, and the **`serde_json::Value`
/// round trip D65 measured is demonstrated on this very report** so the
/// hazard is a fact of the tree rather than a warning in a decision record.
///
/// `serde_json::Map` is a `BTreeMap` in this build, so the round trip
/// alphabetizes the report's keys and destroys D29 rule 1's declaration
/// order. The API makes the mistake unavailable — [`VerifyOutcome`] has no
/// accessor that returns a `Value` — and this row is what would redden if one
/// were added and used.
#[test]
fn the_exposed_bytes_are_canonical_and_a_value_round_trip_would_lose_the_order() {
    let outcome = verify_offline(&unanchored_bundle(), &options()).expect("verifies");
    let canonical = outcome
        .report()
        .to_canonical_json()
        .expect("the report serializes");
    assert_eq!(
        text(outcome.report_bytes()),
        text(&canonical),
        "D65 tier A: the exposed bytes must be `to_canonical_json()`'s"
    );

    let exposed = text(outcome.report_bytes());
    assert!(
        exposed.starts_with(r#"{"report_version":1,"work":"#),
        "D29 rule 1 makes declaration order the wire order, and the exposed \
         bytes have lost it — the report was routed through a \
         `serde_json::Value`: {}",
        &exposed[..exposed.len().min(80)]
    );

    let round_tripped: serde_json::Value =
        serde_json::from_slice(outcome.report_bytes()).expect("the report parses");
    let reserialized = serde_json::to_vec(&round_tripped).expect("re-serializes");
    assert_ne!(
        text(&reserialized),
        exposed,
        "if a `Value` round trip preserved order, D65 §5's carriage rule \
         would have no teeth and this row would be pinning nothing"
    );
    assert!(
        text(&reserialized).starts_with(r#"{"anchors":"#),
        "the round trip must be shown to ALPHABETIZE, not merely to differ: {}",
        &text(&reserialized)[..reserialized.len().min(80)]
    );
}

/// D65 §8.2's tier-A instrument, exercised from the library's side over the
/// two carriages U30 may choose between: a document built around
/// [`VerifyOutcome::report_bytes`] **contains those bytes contiguously**, and
/// one built around a `serde_json::Value` does not.
///
/// The row is a byte containment and not a structural comparison for the
/// reason D65 states in its own outcome: *"the structural comparison passes
/// the bug"*. Both documents below parse to the same object; only one carries
/// the report.
#[test]
fn only_the_verbatim_carriage_contains_the_report_bytes() {
    let outcome = verify_offline(&unanchored_bundle(), &options()).expect("verifies");

    let head = br#"{"v":1,"command":"verify","network":"arbitrum-one","ok":true,"result":{"live":null,"overlay":null,"report":"#;
    let tail = br#","verdict":null}}"#;

    let mut verbatim = Vec::new();
    verbatim.extend_from_slice(head);
    verbatim.extend_from_slice(outcome.report_bytes());
    verbatim.extend_from_slice(tail);

    let parsed: serde_json::Value =
        serde_json::from_slice(outcome.report_bytes()).expect("the report parses");
    let reserialized = serde_json::to_vec(&parsed).expect("re-serializes");
    let mut through_value = Vec::new();
    through_value.extend_from_slice(head);
    through_value.extend_from_slice(&reserialized);
    through_value.extend_from_slice(tail);

    assert!(
        contains(&verbatim, outcome.report_bytes()),
        "the verbatim carriage must contain the canonical report bytes as a \
         contiguous substring (D65 §8.2)"
    );
    assert!(
        !contains(&through_value, outcome.report_bytes()),
        "a `serde_json::Value` carriage must NOT contain them — if it did, \
         this instrument would be green against the bug it exists to catch"
    );

    // …and the structural comparison the row must not be: both documents
    // have the same length and the same key set, so a shape check passes
    // both. Length equality is not a coincidence — a re-serialization moves
    // keys and moves no bytes.
    assert_eq!(
        verbatim.len(),
        through_value.len(),
        "the two carriages differ only in key ORDER, which is exactly why a \
         structural comparison cannot tell them apart"
    );
}

/// Whether `haystack` contains `needle` contiguously.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// D65 §5.1's presence rule, from the library's side: the two siblings are
/// `Some` exactly when their mode was requested, in all four combinations —
/// which is what lets U30 write one presence-only key assertion that covers
/// every combination by rendering `null` instead of omitting a key.
#[test]
fn the_two_siblings_are_present_exactly_when_their_mode_was_requested() {
    let bundle = unanchored_bundle();
    for (online, live) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut modes = VerifyModes::new();
        if online {
            modes = modes.with_online();
        }
        if live {
            modes = modes.with_live();
        }
        let host = CountingHost::new(
            OnlineEvidence::new(),
            ProbeLog::new(endpoints()),
            live_rows(),
        );
        let outcome = verify_with_host(&bundle, &options(), modes, &host).expect("verifies");
        assert_eq!(outcome.overlay().is_some(), online, "online={online}");
        assert_eq!(outcome.live().is_some(), live, "live={live}");
    }
}

/// The verdict-class datum carries the rung's stable **name** and the facts
/// it coarsens — and carries **no integer**, because U2 owns the one code
/// table (D69 §3 R1/R7).
#[test]
fn the_verdict_class_carries_the_rung_name_and_no_exit_code() {
    let outcome = verify_offline(&unanchored_bundle(), &options()).expect("verifies");
    let class = outcome.verdict_class();
    assert_eq!(class.rung, Some("verify-unanchored"));
    assert!(class.unanchored);
    assert!(!class.headline_divergence);
    assert_eq!(class.anchors_refuted, 0);
    assert_eq!(class.headline_eligible, 0);
    assert_eq!(class.total_anchors, 0);

    let json = String::from_utf8(class.to_canonical_json().expect("serializes"))
        .expect("canonical JSON is UTF-8");
    assert_eq!(
        json,
        r#"{"rung":"verify-unanchored","unanchored":true,"headline_divergence":false,"anchors_refuted":0,"headline_eligible":0,"total_anchors":0}"#
    );
    assert!(
        !json.contains("exit_code"),
        "the integer is U2's table, added by U30: {json}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// the rendered offline block (R18/R19/R20)
// ─────────────────────────────────────────────────────────────────────

/// The rendered block draws every string from the frozen table and adds none
/// of its own, and R19's view comes off the same report.
#[test]
fn the_rendered_block_is_drawn_from_the_frozen_table() {
    let (bundle, _) = attested_bundle();
    let outcome = verify_offline(&bundle, &options()).expect("verifies");
    let rendered = outcome.rendered();

    assert!(rendered.unanchored);
    assert_eq!(rendered.headline_line, wording::UNANCHORED_BANNER);
    assert_eq!(rendered.divergence_line, None);
    assert_eq!(rendered.evidence_layer_label, wording::EVIDENCE_LAYER_LABEL);
    assert_eq!(
        rendered.storage_linkage_label,
        wording::STORAGE_LINKAGE_LAYER_LABEL
    );
    assert_eq!(
        rendered.storage_linkage_line,
        wording::storage_linkage_line(outcome.report().storage_linkage)
    );
    assert_eq!(rendered.seal_meaning_line, wording::SEAL_MEANING_NOTE);
    assert_eq!(
        rendered.signature_scheme_line,
        wording::signature_scheme_line(outcome.report().work.signature_scheme)
    );

    assert_eq!(rendered.anchors.len(), 1);
    let slot = &rendered.anchors[0];
    assert_eq!(slot.slot, "ots-1");
    assert_eq!(slot.state, AnchorState::Attested);
    assert_eq!(slot.headline_tag, "");
    assert_eq!(
        slot.state_line,
        wording::anchor_state_line(AnchorState::Attested)
    );
    assert_eq!(
        slot.fetch_date_line,
        Some(wording::fetch_date_line(&FETCH_DATE.to_string())),
        "D95 rider (a): the sealer-recorded date renders under every slot"
    );

    // R19's view is a lens over the same report, never a second copy.
    let view = outcome.redaction();
    assert_eq!(view.totals.files, 3);
    assert_eq!(view.files.len(), 3);
}

/// Slot names are the U23 convention and count **within a kind**, so the
/// offline block and the overlay name one anchor one way — the property D64
/// §6.2 asks the overlay's rows to align with.
#[test]
fn slot_names_align_with_the_overlays_own() {
    let (bundle, header) = attested_bundle();
    let outcome = run_online(
        &bundle,
        OnlineEvidence::new().with_block(HEIGHT, OnlineBlockResult::Header(header)),
        ProbeLog::new(endpoints()).with_block(HEIGHT, BlockProbe::Agreed),
    );
    let offline_slot = &outcome.rendered().anchors[0].slot;
    let overlay_slot = &outcome.overlay().expect("an overlay").anchor_outcomes[0].slot;
    assert_eq!(offline_slot, overlay_slot);
    assert_eq!(offline_slot, &wording::slot_name(AnchorKind::Ots, 1));
}

/// The whole run is deterministic: two independent runs over the same bytes
/// produce equal outcomes, including both siblings. Determinism is what the
/// native↔wasm32 bit-match contract rests on, and this row runs on both
/// targets.
#[test]
fn the_run_is_deterministic() {
    let (bundle, header) = attested_bundle();
    let build_one = || {
        run_online(
            &bundle,
            OnlineEvidence::new().with_block(HEIGHT, OnlineBlockResult::Header(header)),
            ProbeLog::new(endpoints()).with_block(HEIGHT, BlockProbe::Agreed),
        )
    };
    assert_eq!(build_one(), build_one());
}

/// A rejected bundle produces the rejection arm, carrying the code U30 puts
/// in its message — and produces **no outcome at all**, which is D27 §4 (*"a
/// report exists only for a bundle that passed"*) and the reason D65 §5.2
/// gives for `ok:false` having no `result`.
#[test]
fn a_rejected_bundle_returns_the_verify_arm_with_its_code() {
    let mut bundle = unanchored_bundle();
    let last = bundle.len() - 1;
    bundle[last] ^= 0x01;

    let error = verify_offline(&bundle, &options()).expect_err("a mutated bundle is rejected");
    let inner = error
        .verify_error()
        .expect("a bundle rejection is the Verify arm");
    assert!(
        !inner.code().is_empty(),
        "the rejection code is what rides in U30's message"
    );
}
