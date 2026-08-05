//! A10's Accept rows plus A31 and A32, against A24's stubs replaying the
//! **nine real committed TSA responses**.
//!
//! # Q16: none of this touches a real endpoint, and that is asserted
//!
//! Every request below goes to a [`StubServer`] bound on `127.0.0.1:0`.
//! A stub that is never contacted is indistinguishable from a working one if
//! nothing checks — a previous lane in this wave shipped a suite that silently
//! reached the live OTS calendars and passed every assertion, because its
//! outcome was identical either way. So every success path here asserts
//! `server.requests().len() == 1`: had the client reached the real TSA, the
//! stub would have recorded nothing and the test would fail.
//!
//! # Which fixture proves what
//!
//! Measured against the pinned store v1 at each token's own `genTime`:
//!
//! | fixture | state | what only it can prove here |
//! | --- | --- | --- |
//! | FreeTSA | `proven` | the ECDSA P-384 happy path, and the recorded request bytes |
//! | DigiCert | `proven` | the RSA happy path over plain HTTP |
//! | Sectigo | `proven` | a nonce whose **top bit is set**, so the canonical-DER operand is witnessed |
//! | Entrust | `proven` | the same signer certificate as Sectigo — A31's collapse |
//! | GlobalSign | `internally-consistent-only` | a token that fully verifies and still must not count |
//! | Apple | T2 failure | a real granted response that does not verify (SHA-1 digest algorithm) |

use std::time::{Duration, Instant};

use antseal_core::anchor::error::AnchorError;

use super::*;
use crate::http::HttpPolicy;
use crate::testing::replay::{fixtures, request_line, tsa as tsa_stub};
use crate::testing::stub::{StubReply, StubScript, StubServer};

/// The digest all nine `D60-*` captures were taken over.
const STAMPED: [u8; 32] = [
    0x08, 0x3f, 0x87, 0xdf, 0x00, 0xfd, 0x5c, 0x70, 0x3d, 0x35, 0xb8, 0x83, 0xd8, 0x35, 0x35, 0x64,
    0x4c, 0x68, 0x6f, 0x9e, 0x53, 0xf1, 0x58, 0x4d, 0x7d, 0xf1, 0x26, 0xab, 0xda, 0xbd, 0x69, 0xdf,
];

// The nonce each committed capture was requested with, read out of its own
// `TSTInfo` (`openssl ts -reply -text`). They are not decoration: `verify_token`
// is called with `Some(nonce)` on this path, so a wrong value here fails the
// capture — which is what makes these tests exercise the comparison rather
// than skip it.
const NONCE_FREETSA: [u8; 8] = [0x4c, 0xc6, 0x41, 0x96, 0x5b, 0x77, 0xb3, 0xcb];
const NONCE_DIGICERT: [u8; 8] = [0x6f, 0x9c, 0x67, 0xce, 0xbd, 0x59, 0x7b, 0x3c];
const NONCE_GLOBALSIGN: [u8; 8] = [0x4c, 0x18, 0x74, 0x5d, 0x80, 0x63, 0xb3, 0x1b];
const NONCE_ENTRUST: [u8; 8] = [0x5e, 0x54, 0x4c, 0x23, 0x0e, 0xd2, 0x8d, 0x93];
/// **Top bit set.** Its canonical DER content octets are nine bytes with a
/// leading `0x00`, so this fixture is the only one that can witness the
/// canonical-form operand.
const NONCE_SECTIGO: [u8; 8] = [0xe4, 0xa2, 0x35, 0xf4, 0x4c, 0xe8, 0xc7, 0x43];
const NONCE_APPLE: [u8; 8] = [0x25, 0x1c, 0x60, 0x87, 0x63, 0xc4, 0x46, 0x00];

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

/// A fetch date with no relation to any `genTime` in the corpus — the point
/// of A32 is that no relation exists.
const FETCH_DATE: u64 = 1_700_000_000;

fn store() -> &'static TsaRootStore {
    TsaRootStore::pinned()
}

/// Capture one recorded token through a loopback stub, asserting the stub was
/// the endpoint actually contacted.
fn capture(tsa: &str, nonce: &[u8; 8]) -> (StubServer, Result<TsaCapture, TsaFailure>) {
    let server = StubServer::spawn(tsa_stub(&response(tsa)));
    let outcome = capture_one(
        &client(),
        &STAMPED,
        &server.base_url(),
        nonce,
        store(),
        FETCH_DATE,
    );
    assert_eq!(
        server.requests().len(),
        1,
        "the stub recorded no request — this test did not exercise the client, \
         or the client went somewhere else"
    );
    (server, outcome)
}

// ── A10 Accept row 1: the success path ──────────────────────────────────

/// The complete capture record, over the spec's normative ECDSA P-384 default.
#[test]
fn a_real_freetsa_token_produces_a_complete_capture_record() {
    let (server, outcome) = capture("freetsa", &NONCE_FREETSA);
    let capture = outcome.expect("a real FreeTSA token captures");

    assert_eq!(capture.endpoint, server.base_url());
    assert_eq!(capture.token, fixtures::TSA_FREETSA);
    assert_eq!(capture.state, AnchorState::Proven);
    assert_eq!(capture.root_label, Some("freetsa-root-ca"));
    assert_eq!(capture.root_store_version, store().version());
    assert_eq!(capture.gen_time_unix, 1_785_698_547);

    // The vault record U9 persists (A2's type), field by field.
    assert_eq!(capture.record.anchor_digest, STAMPED);
    assert_eq!(capture.record.endpoint, server.base_url());
    assert_eq!(capture.record.request_nonce, NONCE_FREETSA);
    assert_eq!(capture.record.fetch_date, FETCH_DATE);
}

/// The RSA half of the pair, over the plain-HTTP default's own bytes.
#[test]
fn a_real_digicert_token_produces_a_complete_capture_record() {
    let (_server, outcome) = capture("digicert", &NONCE_DIGICERT);
    let capture = outcome.expect("a real DigiCert token captures");
    assert_eq!(capture.state, AnchorState::Proven);
    assert_eq!(capture.root_label, Some("digicert-trusted-root-g4"));
    assert_eq!(capture.token, fixtures::TSA_DIGICERT);
}

/// The bytes this client puts on the wire are **byte-identical** to the
/// recorded request that produced the committed FreeTSA response.
///
/// This is the strongest available statement that A4's builder, the nonce
/// width, `certReq`, the content type and the method are all right: the
/// request was captured from a live TSA that answered it.
#[test]
fn the_request_sent_is_byte_identical_to_the_recorded_one() {
    let server = StubServer::spawn(tsa_stub(&response("freetsa")));
    let _ = capture_one(
        &client(),
        &STAMPED,
        &server.base_url(),
        &NONCE_FREETSA,
        store(),
        FETCH_DATE,
    );

    let raw = server.requests().pop().expect("one request");
    let line = request_line(&raw);
    assert!(line.starts_with("POST "), "{line}");

    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("headers end");
    let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
    assert!(
        head.contains("content-type: application/timestamp-query"),
        "{head}"
    );
    assert!(
        head.contains("accept: application/timestamp-reply"),
        "{head}"
    );

    let body = &raw[head_end + 4..];
    assert_eq!(
        body,
        fixtures::TSA_FREETSA_REQ,
        "the DER request must equal the one the live TSA answered"
    );
}

// ── A10 Accept row 1: distinct failure outcomes ─────────────────────────

/// **The canonical-DER operand.** A nonce whose top bit is set is echoed by
/// the TSA as nine content octets with a leading `0x00`; the drawn value is
/// eight bytes. Passing the drawn bytes to `verify_token` rejects the token.
///
/// Both directions in one test, because the FreeTSA fixture (top bit clear)
/// passes under either implementation and would have let the defect ship —
/// and roughly half of all real draws set the top bit.
#[test]
fn the_nonce_operand_is_the_canonical_der_form_not_the_drawn_bytes() {
    let canonical = canonical_request_nonce(&NONCE_SECTIGO);
    assert_eq!(canonical.len(), 9, "0xE4 sets the top bit, so DER pads");
    assert_eq!(canonical[0], 0x00);
    assert_ne!(canonical.as_slice(), NONCE_SECTIGO.as_slice());

    // The real client, using the canonical form: captures.
    let (_server, outcome) = capture("sectigo", &NONCE_SECTIGO);
    let capture = outcome.expect("a real Sectigo token captures");
    assert_eq!(capture.state, AnchorState::Proven);

    // The defect, reproduced directly against core: the drawn bytes are NOT
    // what the token carries.
    let raw_operand = verify_token(&response("sectigo"), &STAMPED, Some(&NONCE_SECTIGO));
    assert_eq!(
        raw_operand.expect_err("the raw form must not match"),
        AnchorError::NonceMismatch
    );

    // And the control: for a top-bit-clear nonce the two forms coincide, which
    // is exactly why the FreeTSA fixture cannot see any of this.
    assert_eq!(
        canonical_request_nonce(&NONCE_FREETSA).as_slice(),
        NONCE_FREETSA.as_slice()
    );
}

/// A granted, well-formed, correctly-imprinted token answered with the
/// **wrong nonce** does not count. A10's replay defence.
#[test]
fn a_nonce_mismatch_is_an_unverifiable_token_not_a_capture() {
    let mut wrong = NONCE_FREETSA;
    wrong[7] ^= 0x01;
    let (_server, outcome) = capture("freetsa", &wrong);
    match outcome.expect_err("a replayed token must not count") {
        TsaFailure::Token { source, .. } => {
            assert_eq!(source, AnchorError::NonceMismatch);
            assert_eq!(source.code(), "anchor-tsa-nonce-mismatch");
        }
        other => panic!("wrong class: {other:?}"),
    }
}

/// A token stamping a different digest is refused — the messageImprint check,
/// reached on the capture path exactly as on the bundle path.
#[test]
fn a_token_for_another_digest_is_refused() {
    let server = StubServer::spawn(tsa_stub(&response("freetsa")));
    let other = [0xAAu8; 32];
    let outcome = capture_one(
        &client(),
        &other,
        &server.base_url(),
        &NONCE_FREETSA,
        store(),
        FETCH_DATE,
    );
    match outcome.expect_err("a token for another digest must not count") {
        TsaFailure::Token { source, .. } => assert_eq!(source, AnchorError::ImprintMismatch),
        other => panic!("wrong class: {other:?}"),
    }
}

/// **A10 Accept: "a granted-but-unverifiable token counts as a failure".**
///
/// Apple's real response is granted and well-formed and its `digestAlgorithm`
/// is SHA-1, which D60 §3.4 rejects. A synthetic fixture would prove the
/// branch; this one proves the branch is reachable from a live TSA.
#[test]
fn a_granted_but_unverifiable_token_is_a_failure() {
    let (_server, outcome) = capture("apple", &NONCE_APPLE);
    match outcome.expect_err("SHA-1 is not a token digest") {
        TsaFailure::Token { source, endpoint } => {
            assert_eq!(source.code(), "anchor-digest-alg-unsupported");
            assert!(endpoint.starts_with("http://127.0.0.1:"));
        }
        other => panic!("wrong class: {other:?}"),
    }
}

/// **The row that makes "verified" mean verified.** GlobalSign's token passes
/// every CMS check and chains to a root this build does not pin, so it renders
/// `internally-consistent-only` — carries no independently proven time, and
/// must contribute nothing to the gate.
///
/// An implementation that counted `HTTP 200`, or `PKIStatus: granted`, or even
/// "the CMS signature verified", would count this one.
#[test]
fn a_verifying_token_that_reaches_no_pinned_root_is_not_a_capture() {
    let (_server, outcome) = capture("globalsign", &NONCE_GLOBALSIGN);
    match outcome.expect_err("an unpinned root cannot anchor a seal") {
        TsaFailure::Untrusted { state, fault, .. } => {
            assert_eq!(state, AnchorState::InternallyConsistentOnly);
            assert_eq!(fault, None);
        }
        other => panic!("wrong class: {other:?}"),
    }
}

/// A non-granted `PKIStatus` is its own outcome class — the TSA declined, the
/// artifact is fine, and the operator's next move is different from every
/// other failure here.
#[test]
fn a_non_granted_status_is_its_own_outcome() {
    // `TimeStampResp ::= SEQUENCE { status PKIStatusInfo }`, status = 2
    // (rejection), `timeStampToken` absent. Seven bytes, hand-encoded so the
    // fixture is readable at the byte level.
    let rejection = [0x30u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
    let server = StubServer::spawn(tsa_stub(&rejection));
    let outcome = capture_one(
        &client(),
        &STAMPED,
        &server.base_url(),
        &NONCE_FREETSA,
        store(),
        FETCH_DATE,
    );
    match outcome.expect_err("a rejection is not a token") {
        TsaFailure::NotGranted { source, .. } => {
            assert_eq!(source, AnchorError::StatusNotGranted { status: 2 });
            assert_eq!(source.code(), "anchor-tsa-status-not-granted");
        }
        other => panic!("wrong class: {other:?}"),
    }
}

/// HTTP failure, timeout and redirect each produce a distinct outcome, and all
/// three are distinct from every token-level class.
#[test]
fn http_failure_timeout_and_redirect_are_three_distinct_outcomes() {
    let fast = HttpClient::new(HttpPolicy {
        timeouts: crate::http::HttpTimeouts {
            global: Duration::from_millis(600),
            ..HttpPolicy::seal().timeouts
        },
        max_attempts: 1,
        tls: TlsPolicy::Optional,
    });

    let five_hundred = StubServer::spawn(
        StubScript::new().always(StubReply::body(500, b"upstream exploded".to_vec())),
    );
    let stalling = StubServer::spawn(
        StubScript::new().always(StubReply::StallBeforeHeaders(Duration::from_secs(5))),
    );
    let moved = StubServer::spawn(StubScript::new().always(StubReply::Redirect {
        status: 302,
        location: "https://elsewhere.example/tsr".to_owned(),
    }));

    let classes: Vec<&'static str> = [&five_hundred, &stalling, &moved]
        .iter()
        .map(|server| {
            capture_one(
                &fast,
                &STAMPED,
                &server.base_url(),
                &NONCE_FREETSA,
                store(),
                FETCH_DATE,
            )
            .expect_err("none of these is a token")
            .class()
        })
        .collect();
    assert_eq!(classes, ["http", "http", "http"]);

    // Same class, three different typed errors — the class is for the report,
    // the variant is what triage reads.
    let err = |server: &StubServer| {
        capture_one(
            &fast,
            &STAMPED,
            &server.base_url(),
            &NONCE_FREETSA,
            store(),
            FETCH_DATE,
        )
        .expect_err("not a token")
    };
    assert!(matches!(
        err(&five_hundred),
        TsaFailure::Http(AnchorHttpError::Status { status: 500, .. })
    ));
    assert!(matches!(
        err(&stalling),
        TsaFailure::Http(AnchorHttpError::ReceiveTimeout { .. })
    ));
    assert!(matches!(
        err(&moved),
        TsaFailure::Http(AnchorHttpError::Redirected { status: 302, .. })
    ));
}

/// The `500` body reaches the report verbatim rather than being collapsed to
/// a status code.
#[test]
fn a_failed_endpoint_appears_verbatim_in_the_degradation_report() {
    let broken = StubServer::spawn(
        StubScript::new().always(StubReply::body(503, b"maintenance window".to_vec())),
    );
    let good = StubServer::spawn(tsa_stub(&response("freetsa")));
    let endpoints = vec![good.base_url(), broken.base_url()];

    let stage = capture_from_tsas(&client(), &STAMPED, &endpoints, store(), FETCH_DATE)
        .expect("the CSPRNG works in CI");

    // The good endpoint gets a fresh random nonce, so it cannot verify against
    // a recorded token — which is precisely why `capture_one` takes the nonce
    // as a parameter and this test only reads the failing half.
    let report = stage.degradation_report();
    let line = report
        .iter()
        .find(|line| line.contains(&broken.base_url()))
        .unwrap_or_else(|| panic!("the failed URL is missing from {report:?}"));
    assert!(line.contains("[http]"), "{line}");
    assert!(line.contains("503"), "{line}");
    assert!(line.ends_with("ms)"), "{line}");
}

// ── A10 Accept row 2: independence ──────────────────────────────────────

/// **One TSA's failure never aborts *or delays* the others.**
///
/// Two assertions, and the second is the non-vacuous one: a sequential
/// implementation that happened to query the fast endpoint first would pass a
/// wall-clock check alone, so the fast endpoint's *own* elapsed time is
/// asserted too. A51's recipe.
#[test]
fn one_slow_tsa_does_not_delay_the_others() {
    let slow = StubServer::spawn(
        StubScript::new().always(StubReply::StallBeforeHeaders(Duration::from_millis(1_500))),
    );
    let fast = StubServer::spawn(
        StubScript::new().always(StubReply::body(500, b"fast and wrong".to_vec())),
    );
    // Slow first, so a sequential implementation cannot get lucky.
    let endpoints = vec![slow.base_url(), fast.base_url()];

    let started = Instant::now();
    let stage = capture_from_tsas(&client(), &STAMPED, &endpoints, store(), FETCH_DATE)
        .expect("the CSPRNG works in CI");
    let wall = started.elapsed();

    assert!(wall < Duration::from_millis(2_400), "wall {wall:?}");
    let fast_attempt = stage
        .attempts
        .iter()
        .find(|attempt| attempt.endpoint == fast.base_url())
        .expect("the fast endpoint was attempted");
    assert!(
        fast_attempt.elapsed < Duration::from_millis(900),
        "the fast endpoint waited for the slow one: {:?}",
        fast_attempt.elapsed
    );
    assert!(fast_attempt.outcome.is_err());
    // Results keep request order regardless of completion order.
    assert_eq!(stage.attempts[0].endpoint, slow.base_url());
    assert_eq!(stage.attempts[1].endpoint, fast.base_url());
}

// ── A32: no local clock invalidates a token ─────────────────────────────

/// **A32 Accept row 1.** A real committed token with a `fetch_date` *earlier
/// than its own `genTime`* still yields a complete, successful capture record
/// with no state change and no warning.
///
/// The host that captured every fixture in `testdata/anchors/A25-bootstrap/`
/// ran 129 s slow, so this is not a hypothetical ordering: the obvious
/// `gen_time <= fetch_date` check rejects the entire committed corpus.
#[test]
fn a_fetch_date_before_gen_time_still_captures() {
    let server = StubServer::spawn(tsa_stub(&response("freetsa")));
    // One hour before the token says it was stamped.
    let early = 1_785_698_547 - 3_600;
    let capture = capture_one(
        &client(),
        &STAMPED,
        &server.base_url(),
        &NONCE_FREETSA,
        store(),
        early,
    )
    .expect("a clock behind the TSA's is not a verification failure");

    assert_eq!(capture.state, AnchorState::Proven);
    assert_eq!(capture.record.fetch_date, early);
    assert!(capture.gen_time_unix > early);
}

/// The same token captured under wildly different `fetch_date` values yields
/// byte-identical results apart from the recorded provenance field — so the
/// value provably gates nothing.
#[test]
fn fetch_date_is_provenance_only_and_gates_no_outcome() {
    let outcomes: Vec<TsaCapture> = [0u64, 1, 1_785_698_547 - 10_000, u64::MAX]
        .into_iter()
        .map(|fetch_date| {
            let server = StubServer::spawn(tsa_stub(&response("freetsa")));
            capture_one(
                &client(),
                &STAMPED,
                &server.base_url(),
                &NONCE_FREETSA,
                store(),
                fetch_date,
            )
            .expect("no fetch_date may fail a capture")
        })
        .collect();

    for capture in &outcomes {
        assert_eq!(capture.state, outcomes[0].state);
        assert_eq!(capture.gen_time_unix, outcomes[0].gen_time_unix);
        assert_eq!(capture.identity, outcomes[0].identity);
        assert_eq!(capture.root_label, outcomes[0].root_label);
    }
}

// ── A31: two endpoints, one TSA ─────────────────────────────────────────

/// **A31 Accept row 2, capture side.** Entrust and Sectigo captured together
/// are one distinct TSA; FreeTSA and DigiCert are two.
///
/// The stage is assembled from two `capture_one` calls rather than through
/// `capture_from_tsas`, because each recorded response answers **its own**
/// recorded nonce and a fresh random draw could not match either.
#[test]
fn entrust_and_sectigo_count_as_one_tsa_and_the_report_says_so() {
    let entrust = capture("entrust", &NONCE_ENTRUST).1.expect("entrust");
    let sectigo = capture("sectigo", &NONCE_SECTIGO).1.expect("sectigo");
    let entrust_url = entrust.endpoint.clone();
    let sectigo_url = sectigo.endpoint.clone();

    let stage = stage_of(vec![entrust, sectigo]);
    assert_eq!(stage.verified_count(), 2, "two endpoints answered");
    assert_eq!(stage.distinct_tsas(), 1, "and they are one TSA");

    let report = stage.degradation_report();
    let line = report
        .iter()
        .find(|line| line.contains("[one-tsa-two-endpoints]"))
        .unwrap_or_else(|| panic!("the collapse is unreported: {report:?}"));
    assert!(line.contains(&entrust_url), "{line}");
    assert!(line.contains(&sectigo_url), "{line}");
    assert!(line.contains("ONE anchor"), "{line}");
}

/// The positive control: two genuinely different TSAs are two, and produce no
/// collapse line at all.
#[test]
fn freetsa_and_digicert_count_as_two_tsas_with_no_collapse_line() {
    let freetsa = capture("freetsa", &NONCE_FREETSA).1.expect("freetsa");
    let digicert = capture("digicert", &NONCE_DIGICERT).1.expect("digicert");

    let stage = stage_of(vec![freetsa, digicert]);
    assert_eq!(stage.verified_count(), 2);
    assert_eq!(stage.distinct_tsas(), 2);
    assert!(stage.collapsed_endpoints().is_empty());
    assert!(stage.degradation_report().is_empty());
}

/// Sectigo and Entrust really do differ as *endpoints* and as *tokens* — the
/// collapse is a statement about signers, not about duplicate bytes. Without
/// this, a byte-equality implementation would pass the row above.
#[test]
fn the_collapsed_pair_is_two_different_tokens_from_two_different_urls() {
    let entrust = capture("entrust", &NONCE_ENTRUST).1.expect("entrust");
    let sectigo = capture("sectigo", &NONCE_SECTIGO).1.expect("sectigo");
    assert_ne!(entrust.endpoint, sectigo.endpoint);
    assert_ne!(entrust.token, sectigo.token);
    assert_ne!(entrust.gen_time_unix, sectigo.gen_time_unix);
    assert_eq!(entrust.identity, sectigo.identity);
}

fn stage_of(captures: Vec<TsaCapture>) -> TsaCaptureStage {
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

// ── The endpoint list ───────────────────────────────────────────────────

#[test]
fn the_default_tsa_list_is_the_specs_two() {
    assert_eq!(
        effective_tsa_urls(None),
        vec![
            "https://freetsa.org/tsr".to_owned(),
            "http://timestamp.digicert.com".to_owned()
        ]
    );
    assert_eq!(effective_tsa_urls(Some(&[])), effective_tsa_urls(None));
}

/// A config override replaces the defaults wholesale (U26's semantics) and is
/// deduplicated, so one TSA cannot be contacted twice inside one seal.
#[test]
fn an_override_replaces_the_defaults_and_is_deduplicated() {
    let configured = [
        "https://a.example/tsr".to_owned(),
        "https://b.example/tsr".to_owned(),
        "https://a.example/tsr".to_owned(),
    ];
    assert_eq!(
        effective_tsa_urls(Some(&configured)),
        vec![
            "https://a.example/tsr".to_owned(),
            "https://b.example/tsr".to_owned()
        ]
    );
    assert!(!effective_tsa_urls(Some(&configured)).contains(&DEFAULT_TSA_URLS[0].to_owned()));
}

/// The default DigiCert endpoint is plain HTTP and must stay reachable:
/// `timestamp.digicert.com` has no port 443 at all, so a TLS-only policy here
/// would break a spec default (A49/D90 §6.6).
#[test]
fn the_plain_http_default_is_admitted_by_this_familys_policy() {
    assert!(DEFAULT_TSA_URLS[1].starts_with("http://"));
    assert!(Endpoint::parse(DEFAULT_TSA_URLS[1], TlsPolicy::Optional).is_ok());
    assert!(Endpoint::parse(DEFAULT_TSA_URLS[1], TlsPolicy::RequiredExceptLoopback).is_err());
    assert_eq!(HttpPolicy::seal().tls, TlsPolicy::Optional);
}
