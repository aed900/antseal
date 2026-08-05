//! A20's Accept rows.
//!
//! Two layers, deliberately:
//!
//! 1. **The decision table**, over [`evaluate_seal_gate`] — pure, exhaustive,
//!    and fast enough to enumerate.
//! 2. **The wired gate**, over [`SubmitAnchorGate`] driven against loopback
//!    stubs replaying real committed tokens — because a decision table proves
//!    the *rule*, and only running the real gate proves the rule is what the
//!    seal pipeline will actually consult.
//!
//! The third layer — that the abort **precedes `pay`**, asserted on a pay-call
//! counter rather than on an error — lives in `antseal-cli`'s
//! `tests/anchor_gate_prepay.rs`, because this crate has no backend to count.
//!
//! Q16: every endpoint below is a `127.0.0.1:0` stub. Success paths assert the
//! stub recorded the request, so a test that silently reached a real TSA would
//! fail rather than pass.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use super::*;
use crate::http::HttpPolicy;
use crate::ots::submit::{CalendarAttempt, CalendarFailure, PendingRecord};
use crate::testing::replay::{CalendarBehaviour, calendar, tsa as tsa_stub};
use crate::testing::stub::{StubReply, StubScript, StubServer};
use crate::tsa::{TsaAttempt, TsaFailure};

/// The digest the committed `D60-*` captures were taken over.
const STAMPED: [u8; 32] = [
    0x08, 0x3f, 0x87, 0xdf, 0x00, 0xfd, 0x5c, 0x70, 0x3d, 0x35, 0xb8, 0x83, 0xd8, 0x35, 0x35, 0x64,
    0x4c, 0x68, 0x6f, 0x9e, 0x53, 0xf1, 0x58, 0x4d, 0x7d, 0xf1, 0x26, 0xab, 0xda, 0xbd, 0x69, 0xdf,
];
const NONCE_FREETSA: [u8; 8] = [0x4c, 0xc6, 0x41, 0x96, 0x5b, 0x77, 0xb3, 0xcb];
const FETCH_DATE: u64 = 1_700_000_000;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/anchors/A25-bootstrap"
);

fn response(tsa: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}/D60-tsa-{tsa}-resp.tsr");
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn client() -> HttpClient {
    HttpClient::new(HttpPolicy::seal())
}

/// The M1 std-only executor (the shape `gate.rs` already sanctions here).
fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

// ── Submission builders for the pure decision table ─────────────────────
//
// Assembled by hand rather than captured, so the table enumerates the rule
// instead of enumerating which stubs happen to be up. The wired tests below
// are what tie the rule to real bytes.

fn complete_ots() -> OtsSubmission {
    let record = |uri: &str| PendingRecord {
        calendar: format!("https://{uri}"),
        uri: format!("https://{uri}"),
        commitment: vec![0xAB; 32],
        body: vec![0x00],
    };
    OtsSubmission {
        anchor_digest: STAMPED,
        attempts: vec![
            CalendarAttempt {
                calendar: "https://a.example".to_owned(),
                elapsed: Duration::from_millis(1),
                outcome: Ok(record("a.example")),
            },
            CalendarAttempt {
                calendar: "https://b.example".to_owned(),
                elapsed: Duration::from_millis(1),
                outcome: Ok(record("b.example")),
            },
        ],
        // A non-empty artifact is what `outcome()` requires; its bytes are not
        // read by anything in this file.
        artifact: Some(vec![0x00]),
        merge_rejected: None,
    }
}

fn failed_ots() -> OtsSubmission {
    OtsSubmission {
        anchor_digest: STAMPED,
        attempts: vec![CalendarAttempt {
            calendar: "https://dead.example".to_owned(),
            elapsed: Duration::from_millis(7),
            outcome: Err(CalendarFailure::NoPending {
                calendar: "https://dead.example".to_owned(),
            }),
        }],
        artifact: None,
        merge_rejected: None,
    }
}

fn failed_tsa(endpoints: &[&str]) -> TsaCaptureStage {
    TsaCaptureStage {
        anchor_digest: STAMPED,
        attempts: endpoints
            .iter()
            .map(|endpoint| TsaAttempt {
                endpoint: (*endpoint).to_owned(),
                elapsed: Duration::from_millis(11),
                outcome: Err(TsaFailure::Untrusted {
                    endpoint: (*endpoint).to_owned(),
                    state: antseal_core::verify::report::AnchorState::InternallyConsistentOnly,
                    fault: None,
                }),
            })
            .collect(),
    }
}

/// A stage holding one genuinely verified capture — obtained by running the
/// real client against a stub replaying a real token, never fabricated.
fn one_verified_tsa() -> TsaCaptureStage {
    let server = StubServer::spawn(tsa_stub(&response("freetsa")));
    let capture = crate::tsa::capture_one(
        &client(),
        &STAMPED,
        &server.base_url(),
        &NONCE_FREETSA,
        TsaRootStore::pinned(),
        FETCH_DATE,
    )
    .expect("a real FreeTSA token captures");
    assert_eq!(server.requests().len(), 1, "the stub was not contacted");
    TsaCaptureStage {
        anchor_digest: STAMPED,
        attempts: vec![TsaAttempt {
            endpoint: capture.endpoint.clone(),
            elapsed: Duration::from_millis(3),
            outcome: Ok(capture),
        }],
    }
}

fn submission(ots: OtsSubmission, tsa: TsaCaptureStage) -> AnchorSubmission {
    AnchorSubmission {
        anchor_digest: STAMPED,
        ots,
        tsa,
    }
}

const NO_FLAGS: SealGateFlags = SealGateFlags {
    no_anchor: false,
    force_degraded: false,
};
const FORCE_DEGRADED: SealGateFlags = SealGateFlags {
    no_anchor: false,
    force_degraded: true,
};
const NO_ANCHOR: SealGateFlags = SealGateFlags {
    no_anchor: true,
    force_degraded: false,
};

// ── A20 Accept row 1: the decision table ────────────────────────────────

/// Zero verified TSA tokens and no flags → **abort**, with every per-endpoint
/// failure carried verbatim.
#[test]
fn zero_verified_tsa_and_no_flags_aborts() {
    let sub = submission(
        failed_ots(),
        failed_tsa(&["https://a.tsa", "https://b.tsa"]),
    );
    let err = evaluate_seal_gate(Some(&sub), NO_FLAGS, NetworkClass::Permanent)
        .expect_err("the seal must abort");

    let AnchorGateError::MinimumAnchor {
        attempted,
        failures,
    } = &err
    else {
        panic!("wrong arm: {err:?}");
    };
    assert_eq!(*attempted, 2);
    // Three endpoints failed: one calendar and two TSAs, in stage order.
    assert_eq!(failures.len(), 3);
    assert_eq!(failures[0].stage, AnchorStage::Ots);
    assert_eq!(failures[1].stage, AnchorStage::Tsa);
    assert_eq!(failures[2].stage, AnchorStage::Tsa);

    // A20 Accept row 4: verbatim in the typed error's rendering.
    let rendered = err.to_string();
    for endpoint in ["https://dead.example", "https://a.tsa", "https://b.tsa"] {
        assert!(
            rendered.contains(endpoint),
            "{endpoint} missing:\n{rendered}"
        );
    }
    assert!(rendered.contains("nothing was paid for"), "{rendered}");
    assert!(rendered.contains("--force-degraded"), "{rendered}");
}

/// Zero verified TSA tokens **plus `--force-degraded`** → proceed, degraded.
#[test]
fn zero_verified_tsa_with_force_degraded_proceeds_degraded() {
    let sub = submission(complete_ots(), failed_tsa(&["https://a.tsa"]));
    assert_eq!(
        evaluate_seal_gate(Some(&sub), FORCE_DEGRADED, NetworkClass::Permanent),
        Ok(SealGateDecision::ProceedDegraded)
    );
}

/// At least one verified TSA token **plus total OTS failure** → proceed, with
/// a degradation note. The OTS half never gates (D54 §3).
#[test]
fn one_verified_tsa_with_total_ots_failure_proceeds_with_a_degradation_note() {
    let sub = submission(failed_ots(), one_verified_tsa());
    assert_eq!(
        evaluate_seal_gate(Some(&sub), NO_FLAGS, NetworkClass::Permanent),
        Ok(SealGateDecision::Proceed { degraded: true })
    );
    let report = sub.degradation_report();
    assert!(
        report
            .iter()
            .any(|line| line.contains("https://dead.example")),
        "{report:?}"
    );
    assert!(
        report.iter().any(|line| line.contains("1 distinct TSA(s)")),
        "{report:?}"
    );
}

/// `--no-anchor` on a permanent network → **rejected**, and rejected first:
/// `--force-degraded` cannot buy it.
#[test]
fn no_anchor_on_a_permanent_network_is_rejected_whatever_else_is_set() {
    for flags in [
        NO_ANCHOR,
        SealGateFlags {
            no_anchor: true,
            force_degraded: true,
        },
    ] {
        assert_eq!(
            evaluate_seal_gate(None, flags, NetworkClass::Permanent),
            Err(AnchorGateError::NoAnchorOnPermanentNetwork)
        );
        // And not even a fully successful submission can turn it into a
        // proceed — the flag combination is refused on its own terms.
        let sub = submission(complete_ots(), one_verified_tsa());
        assert_eq!(
            evaluate_seal_gate(Some(&sub), flags, NetworkClass::Permanent),
            Err(AnchorGateError::NoAnchorOnPermanentNetwork)
        );
    }
}

/// `--no-anchor` on devnet/sepolia → the empty anchor set.
#[test]
fn no_anchor_on_a_development_network_yields_the_empty_anchor_set() {
    assert_eq!(
        evaluate_seal_gate(None, NO_ANCHOR, NetworkClass::Development),
        Ok(SealGateDecision::SkipUnanchored)
    );
}

/// A clean run: one verified token, two calendars, nothing to report.
#[test]
fn a_clean_run_proceeds_undegraded_and_reports_nothing() {
    let sub = submission(complete_ots(), one_verified_tsa());
    assert!(sub.degradation_report().is_empty());
    assert!(!sub.is_degraded());
    assert_eq!(
        evaluate_seal_gate(Some(&sub), NO_FLAGS, NetworkClass::Permanent),
        Ok(SealGateDecision::Proceed { degraded: false })
    );
}

/// An **absent** submission is never a reason to proceed. This is the arm a
/// refactor is most likely to get wrong, because `None` reads as "nothing
/// went wrong".
#[test]
fn an_absent_submission_aborts_rather_than_proceeding() {
    assert!(matches!(
        evaluate_seal_gate(None, NO_FLAGS, NetworkClass::Permanent),
        Err(AnchorGateError::MinimumAnchor {
            attempted: 0,
            ref failures
        }) if failures.is_empty()
    ));
}

// ── A20 Accept row 2: a gate-passing seal always holds a proven anchor ───

/// **MVP-SPEC.md line 137's property.** Every gate outcome that proceeds
/// *without* `--force-degraded` holds at least one anchor that is
/// headline-eligible offline.
///
/// The quantifier is what matters: the assertion sweeps every capture in the
/// stage, so a future state added to the eligible set without a matching
/// change here goes red.
#[test]
fn a_gate_passing_seal_always_holds_a_headline_eligible_tsa_anchor() {
    let sub = submission(complete_ots(), one_verified_tsa());
    let decision =
        evaluate_seal_gate(Some(&sub), NO_FLAGS, NetworkClass::Permanent).expect("the gate passes");
    assert!(matches!(decision, SealGateDecision::Proceed { .. }));

    let mut eligible = 0usize;
    for capture in sub.tsa.verified() {
        assert!(
            matches!(
                capture.state,
                antseal_core::verify::report::AnchorState::Proven
                    | antseal_core::verify::report::AnchorState::ValidAtStampingCertSinceExpired
            ),
            "a capture reached the gate in {:?}",
            capture.state
        );
        eligible += 1;
    }
    assert!(eligible >= MIN_VERIFIED_TSA_TOKENS);
}

/// **The red direction of the same property.** A TSA that answers `200` with a
/// granted, fully verifying token whose root this build does not pin produces
/// **zero** verified anchors and the gate aborts.
///
/// Without this, "≥1 verified token" could be implemented as "≥1 HTTP 200" and
/// every other test in this file would still pass.
/// GlobalSign's nonce, so the capture reaches T3 rather than stopping at the
/// nonce check. The gate cannot be driven end-to-end for this row — it draws a
/// fresh nonce, which no recorded token can answer — so the capture is taken
/// with `capture_one` and the stage assembled around it. The *decision* under
/// test is still `evaluate_seal_gate`'s, over a real failure produced by the
/// real client from real bytes.
const NONCE_GLOBALSIGN: [u8; 8] = [0x4c, 0x18, 0x74, 0x5d, 0x80, 0x63, 0xb3, 0x1b];

#[test]
fn a_verifying_token_from_an_unpinned_root_does_not_pass_the_gate() {
    let server = StubServer::spawn(tsa_stub(&response("globalsign")));
    let failure = crate::tsa::capture_one(
        &client(),
        &STAMPED,
        &server.base_url(),
        &NONCE_GLOBALSIGN,
        TsaRootStore::pinned(),
        FETCH_DATE,
    )
    .expect_err("an unpinned root cannot anchor a seal");
    assert_eq!(server.requests().len(), 1, "the stub was not contacted");
    assert_eq!(failure.class(), "untrusted-chain");

    let stage = TsaCaptureStage {
        anchor_digest: STAMPED,
        attempts: vec![TsaAttempt {
            endpoint: server.base_url(),
            elapsed: Duration::from_millis(4),
            outcome: Err(failure),
        }],
    };
    let sub = submission(complete_ots(), stage);
    assert_eq!(sub.verified_tsa_count(), 0, "an HTTP 200 is not evidence");

    let err = evaluate_seal_gate(Some(&sub), NO_FLAGS, NetworkClass::Permanent)
        .expect_err("the gate must abort");
    let AnchorGateError::MinimumAnchor {
        attempted,
        failures,
    } = &err
    else {
        panic!("wrong arm: {err:?}");
    };
    assert_eq!(*attempted, 1);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].class, "untrusted-chain");
    assert!(err.to_string().contains(&server.base_url()));
}

// ── The wired gate ──────────────────────────────────────────────────────

/// The real gate, end to end against stubs: OTS submits, TSA captures, and a
/// populated outcome.
///
/// The TSA half must fail here — a recorded token answers only its own
/// recorded nonce and this path draws a fresh one — so `--force-degraded`
/// carries it. That is not a workaround: it is the only shape in which the
/// *whole* wired path (fresh CSPRNG nonce, real request, real reply, real
/// core verification, real decision) runs, and it proves the fresh-nonce
/// comparison is genuinely enforced rather than skipped.
#[test]
fn the_wired_gate_runs_both_halves_and_returns_a_populated_outcome() {
    let alice = StubServer::spawn(calendar(&CalendarBehaviour::PendingSubmit(
        crate::testing::replay::fixtures::CALENDAR_ALICE_A.to_vec(),
    )));
    let tsa = StubServer::spawn(tsa_stub(&response("freetsa")));
    let endpoints = AnchorEndpoints {
        tsa_urls: vec![tsa.base_url()],
        ots_calendars: vec![alice.base_url()],
    };
    let client = client();
    let gate = SubmitAnchorGate::new(
        &client,
        &endpoints,
        TsaRootStore::pinned(),
        FORCE_DEGRADED,
        NetworkClass::Development,
    )
    .with_fetch_date(FETCH_DATE);

    let outcome = block_on(gate.run(crate::testing::replay::fixtures::DIGEST_A))
        .expect("--force-degraded proceeds");
    assert!(!outcome.is_empty());
    let sub = outcome.submission().expect("a populated outcome");

    // OTS ran and produced a real pending attestation.
    assert_eq!(sub.ots.distinct_calendars(), 1);
    assert!(sub.ots.artifact.is_some());
    // TSA ran and its token was refused on the nonce, as it must be.
    assert_eq!(sub.verified_tsa_count(), 0);
    assert_eq!(sub.tsa.attempts.len(), 1);
    let failure = sub.tsa.attempts[0]
        .outcome
        .as_ref()
        .expect_err("a fresh nonce cannot match a recorded one");
    assert_eq!(failure.class(), "unverifiable");

    assert_eq!(alice.requests().len(), 1);
    assert_eq!(tsa.requests().len(), 1);
    assert!(sub.is_degraded());
}

/// `--no-anchor` reaches the gate only if the pipeline's own skip was
/// bypassed, and even then it submits **nothing**: the stubs record zero
/// requests.
#[test]
fn no_anchor_reaching_the_gate_directly_still_submits_nothing() {
    let tsa = StubServer::spawn(tsa_stub(&response("freetsa")));
    let endpoints = AnchorEndpoints {
        tsa_urls: vec![tsa.base_url()],
        ots_calendars: Vec::new(),
    };

    let client = client();
    let dev = SubmitAnchorGate::new(
        &client,
        &endpoints,
        TsaRootStore::pinned(),
        NO_ANCHOR,
        NetworkClass::Development,
    );
    assert_eq!(
        block_on(dev.run(STAMPED)).expect("dev networks may skip"),
        AnchorSubmissionOutcome::Empty
    );

    let main = SubmitAnchorGate::new(
        &client,
        &endpoints,
        TsaRootStore::pinned(),
        NO_ANCHOR,
        NetworkClass::Permanent,
    );
    assert_eq!(
        block_on(main.run(STAMPED)),
        Err(AnchorGateError::NoAnchorOnPermanentNetwork)
    );

    assert_eq!(
        tsa.connections(),
        0,
        "--no-anchor sent a request; the skip is not a skip"
    );
}

/// A transport failure on every TSA aborts the gate with the endpoint's own
/// message inside the abort error.
#[test]
fn every_tsa_down_aborts_with_the_urls_verbatim() {
    let dead =
        StubServer::spawn(StubScript::new().always(StubReply::body(502, b"bad gateway".to_vec())));
    let endpoints = AnchorEndpoints {
        tsa_urls: vec![dead.base_url()],
        ots_calendars: Vec::new(),
    };
    let client = client();
    let gate = SubmitAnchorGate::new(
        &client,
        &endpoints,
        TsaRootStore::pinned(),
        NO_FLAGS,
        NetworkClass::Permanent,
    )
    .with_fetch_date(FETCH_DATE);

    let err = block_on(gate.run(STAMPED)).expect_err("no TSA answered");
    let rendered = err.to_string();
    assert!(rendered.contains(&dead.base_url()), "{rendered}");
    assert!(rendered.contains("502"), "{rendered}");
}

// ── A31: the gate threshold is unchanged ────────────────────────────────

/// **A31 Accept row 4**, asserted rather than assumed: collapsing two
/// endpoints to one TSA changes what the seal *says*, never whether it
/// proceeds. Two captures from one TSA clear the threshold exactly as two
/// captures from two TSAs do.
///
/// The two decisions are **not** identical values, and that is the correct
/// outcome rather than a tolerated one: the collapsed run is `degraded`,
/// because a user who configured two endpoints and holds one anchor must be
/// told so. What A31 forbids is a change to whether the gate *passes*.
#[test]
fn collapsing_two_endpoints_to_one_tsa_does_not_change_the_gate_outcome() {
    let one_tsa = {
        let entrust = capture_real("entrust", &[0x5e, 0x54, 0x4c, 0x23, 0x0e, 0xd2, 0x8d, 0x93]);
        let sectigo = capture_real("sectigo", &[0xe4, 0xa2, 0x35, 0xf4, 0x4c, 0xe8, 0xc7, 0x43]);
        stage_of(vec![entrust, sectigo])
    };
    let two_tsas = {
        let freetsa = capture_real("freetsa", &NONCE_FREETSA);
        let digicert = capture_real(
            "digicert",
            &[0x6f, 0x9c, 0x67, 0xce, 0xbd, 0x59, 0x7b, 0x3c],
        );
        stage_of(vec![freetsa, digicert])
    };

    assert_eq!(one_tsa.verified_count(), 2);
    assert_eq!(one_tsa.distinct_tsas(), 1);
    assert_eq!(two_tsas.verified_count(), 2);
    assert_eq!(two_tsas.distinct_tsas(), 2);

    let collapsed = submission(complete_ots(), one_tsa);
    let independent = submission(complete_ots(), two_tsas);
    for sub in [&collapsed, &independent] {
        assert!(
            matches!(
                evaluate_seal_gate(Some(sub), NO_FLAGS, NetworkClass::Permanent),
                Ok(SealGateDecision::Proceed { .. })
            ),
            "the threshold moved: {:?}",
            evaluate_seal_gate(Some(sub), NO_FLAGS, NetworkClass::Permanent)
        );
    }

    // The reports differ, which is the whole point of A31.
    assert_eq!(
        evaluate_seal_gate(Some(&collapsed), NO_FLAGS, NetworkClass::Permanent),
        Ok(SealGateDecision::Proceed { degraded: true })
    );
    assert_eq!(
        evaluate_seal_gate(Some(&independent), NO_FLAGS, NetworkClass::Permanent),
        Ok(SealGateDecision::Proceed { degraded: false })
    );
    assert!(
        collapsed
            .degradation_report()
            .iter()
            .any(|line| line.contains("1 distinct TSA(s)")),
        "{:?}",
        collapsed.degradation_report()
    );
    assert!(independent.degradation_report().is_empty());
}

/// The gate compares [`MIN_VERIFIED_TSA_TOKENS`] against the **verified-token**
/// count, not the distinct-TSA count — A31's explicit ruling.
///
/// At a threshold of one the two are equivalent (`verified >= 1` iff
/// `distinct >= 1`), so nothing observable turns on the choice today. This
/// test records that equivalence so that raising the threshold has to confront
/// the question deliberately instead of inheriting whichever count happened to
/// be written here.
#[test]
fn at_a_threshold_of_one_the_two_counts_cannot_disagree() {
    assert_eq!(MIN_VERIFIED_TSA_TOKENS, 1);
    let entrust = capture_real("entrust", &[0x5e, 0x54, 0x4c, 0x23, 0x0e, 0xd2, 0x8d, 0x93]);
    let sectigo = capture_real("sectigo", &[0xe4, 0xa2, 0x35, 0xf4, 0x4c, 0xe8, 0xc7, 0x43]);
    let sub = submission(complete_ots(), stage_of(vec![entrust, sectigo]));
    assert_eq!(sub.verified_tsa_count(), 2);
    assert_eq!(sub.distinct_tsas(), 1);
    assert_eq!(
        sub.verified_tsa_count() >= MIN_VERIFIED_TSA_TOKENS,
        sub.distinct_tsas() >= MIN_VERIFIED_TSA_TOKENS
    );
}

fn capture_real(tsa: &str, nonce: &[u8; 8]) -> crate::tsa::TsaCapture {
    let server = StubServer::spawn(tsa_stub(&response(tsa)));
    let capture = crate::tsa::capture_one(
        &client(),
        &STAMPED,
        &server.base_url(),
        nonce,
        TsaRootStore::pinned(),
        FETCH_DATE,
    )
    .unwrap_or_else(|e| panic!("{tsa}: {e}"));
    assert_eq!(server.requests().len(), 1, "{tsa}: the stub was not used");
    capture
}

fn stage_of(captures: Vec<crate::tsa::TsaCapture>) -> TsaCaptureStage {
    TsaCaptureStage {
        anchor_digest: STAMPED,
        attempts: captures
            .into_iter()
            .map(|capture| TsaAttempt {
                endpoint: capture.endpoint.clone(),
                elapsed: Duration::from_millis(1),
                outcome: Ok(capture),
            })
            .collect(),
    }
}

// ── Endpoint configuration ──────────────────────────────────────────────

#[test]
fn the_default_endpoint_set_is_both_families_defaults() {
    let defaults = AnchorEndpoints::defaults();
    assert_eq!(defaults.tsa_urls, effective_tsa_urls(None));
    assert_eq!(defaults.ots_calendars, effective_calendars(None));
    assert_eq!(defaults.tsa_urls.len(), 2);
    assert_eq!(defaults.ots_calendars.len(), 4);
}

#[test]
fn a_config_override_replaces_each_family_independently() {
    let tsa = ["https://only.example/tsr".to_owned()];
    let endpoints = AnchorEndpoints::from_config(Some(&tsa), None);
    assert_eq!(endpoints.tsa_urls, tsa);
    assert_eq!(endpoints.ots_calendars, effective_calendars(None));
}
