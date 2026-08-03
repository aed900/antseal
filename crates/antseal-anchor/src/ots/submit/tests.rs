//! A13's Accept rows, against A24's routed stubs replaying the real captures.

use std::time::{Duration, Instant};

use antseal_core::anchor::ots::parse_ots;

use super::*;
use crate::http::HttpPolicy;
use crate::testing::replay::{CalendarBehaviour, calendar, fixtures};
use crate::testing::stub::StubServer;

fn client() -> HttpClient {
    HttpClient::new(HttpPolicy::seal())
}

fn stub(behaviour: &CalendarBehaviour) -> StubServer {
    StubServer::spawn(calendar(behaviour))
}

fn pending(bytes: &[u8]) -> CalendarBehaviour {
    CalendarBehaviour::PendingSubmit(bytes.to_vec())
}

/// A13 Accept row 1: two calendars → one `.ots` with two pending
/// attestations, clean through A11.
#[test]
fn two_calendars_produce_one_artifact_with_both_pending_attestations() {
    let alice = stub(&pending(fixtures::CALENDAR_ALICE_A));
    let bob = stub(&pending(fixtures::CALENDAR_BOB_A));
    let calendars = vec![alice.base_url(), bob.base_url()];

    let submission = submit_to_calendars(&client(), &fixtures::DIGEST_A, &calendars);

    assert_eq!(submission.outcome(), OtsSubmitOutcome::Complete);
    assert_eq!(submission.distinct_calendars(), 2);
    assert!(submission.degradation_report().is_empty());
    assert_eq!(submission.merge_rejected, None);

    let artifact = submission.artifact.as_ref().expect("an artifact");
    let parsed = parse_ots(artifact, &fixtures::DIGEST_A).expect("A11-clean");
    assert_eq!(parsed.attestations.len(), 2);

    // Both calendars' own URIs are present — not the loopback URLs we posted
    // to. That difference is the whole of D54's counting rule.
    let uris: Vec<&str> = submission.pending().map(|r| r.uri.as_str()).collect();
    assert!(uris.contains(&"https://alice.btc.calendar.opentimestamps.org"));
    assert!(uris.contains(&"https://bob.btc.calendar.opentimestamps.org"));
    assert!(uris.iter().all(|uri| !uri.contains("127.0.0.1")));

    // Each request carried the 32 raw digest bytes, not hex.
    for server in [&alice, &bob] {
        let request = server.requests().pop().expect("one request");
        assert!(request.ends_with(&fixtures::DIGEST_A));
        assert!(
            crate::testing::replay::request_line(&request).contains("/digest"),
            "the submit path is D54's"
        );
    }
}

/// Three calendars reproduce the committed merge exactly — the strongest
/// available statement that this client stores what A11's fixture says a
/// merged artifact is.
#[test]
fn three_calendars_reproduce_the_committed_merged_artifact() {
    let alice = stub(&pending(fixtures::CALENDAR_ALICE_A));
    let bob = stub(&pending(fixtures::CALENDAR_BOB_A));
    let catallaxy = stub(&pending(fixtures::CALENDAR_CATALLAXY_A));
    let calendars = vec![alice.base_url(), bob.base_url(), catallaxy.base_url()];

    let submission = submit_to_calendars(&client(), &fixtures::DIGEST_A, &calendars);
    assert_eq!(
        submission.artifact.as_deref(),
        Some(fixtures::MERGED_A),
        "the stored artifact must be byte-identical to the committed merge"
    );
}

/// D58 §7.3's first rider: branch order is A13's to fix, or two seals of one
/// digest against one calendar set produce different files.
#[test]
fn branch_order_is_deterministic_regardless_of_the_configured_order() {
    let alice = stub(&pending(fixtures::CALENDAR_ALICE_A));
    let bob = stub(&pending(fixtures::CALENDAR_BOB_A));
    let catallaxy = stub(&pending(fixtures::CALENDAR_CATALLAXY_A));

    let forwards = vec![alice.base_url(), bob.base_url(), catallaxy.base_url()];
    let backwards = vec![catallaxy.base_url(), bob.base_url(), alice.base_url()];

    let first = submit_to_calendars(&client(), &fixtures::DIGEST_A, &forwards);
    let second = submit_to_calendars(&client(), &fixtures::DIGEST_A, &backwards);

    assert_eq!(first.artifact, second.artifact);
    assert!(first.artifact.is_some());
}

/// The instrument check for the row above: the assertion must be able to fail.
///
/// A client that appended branches in configured order would produce two
/// different files from these two lists, and this proves the two orders really
/// are different orders rather than the same one twice.
#[test]
fn configured_order_really_does_differ_so_the_determinism_test_is_not_vacuous() {
    let branches = [
        fixtures::CALENDAR_ALICE_A.to_vec(),
        fixtures::CALENDAR_BOB_A.to_vec(),
        fixtures::CALENDAR_CATALLAXY_A.to_vec(),
    ];
    let reversed: Vec<Vec<u8>> = branches.iter().rev().cloned().collect();
    assert_ne!(
        super::assemble(&fixtures::DIGEST_A, &branches),
        super::assemble(&fixtures::DIGEST_A, &reversed),
        "order-preserving assembly of two orders must differ, or the \
         determinism test above proves nothing"
    );
}

/// A13 Accept row 2, first half: one calendar down still records the other.
#[test]
fn one_calendar_down_still_records_the_others() {
    let alice = stub(&pending(fixtures::CALENDAR_ALICE_A));
    let down = stub(&CalendarBehaviour::Down);
    let calendars = vec![alice.base_url(), down.base_url()];

    let submission = submit_to_calendars(&client(), &fixtures::DIGEST_A, &calendars);

    assert_eq!(submission.outcome(), OtsSubmitOutcome::Thin);
    assert_eq!(submission.distinct_calendars(), 1);
    let artifact = submission
        .artifact
        .as_ref()
        .expect("the survivor is stored");
    assert_eq!(
        parse_ots(artifact, &fixtures::DIGEST_A)
            .expect("parses")
            .attestations
            .len(),
        1
    );

    // D54 §8: every failed endpoint appears VERBATIM, with its class and its
    // elapsed time. A summarising "1 calendar failed" fails this.
    let report = submission.degradation_report();
    assert_eq!(report.len(), 1);
    assert!(report[0].contains(&down.base_url()));
    assert!(report[0].contains("[http]"));
    assert!(report[0].contains("ms)"));
}

/// A13 Accept row 2, second half: zero success is a typed degradation, never
/// an abort and never a panic.
#[test]
fn zero_calendar_success_is_a_typed_degradation() {
    let down = stub(&CalendarBehaviour::Down);
    let broken = stub(&CalendarBehaviour::ServerError);
    let calendars = vec![down.base_url(), broken.base_url()];

    let submission = submit_to_calendars(&client(), &fixtures::DIGEST_A, &calendars);

    assert_eq!(submission.outcome(), OtsSubmitOutcome::Absent);
    assert_eq!(submission.artifact, None);
    assert_eq!(submission.merge_rejected, None);
    assert_eq!(submission.degradation_report().len(), 2);
    assert!(
        submission
            .attempts
            .iter()
            .all(|attempt| attempt.outcome.is_err())
    );
}

/// D54's named test: distinct-success counting dedupes by pending URI, not by
/// the URL we posted to.
///
/// Both halves, because a counter that always returned 1 would pass the first
/// and a counter over HTTP 200s would pass the second.
#[test]
fn distinct_success_count_dedupes_by_pending_uri() {
    // Two endpoints, one calendar behind them — D54's aggregator-alias case.
    let first = stub(&pending(fixtures::CALENDAR_ALICE_A));
    let second = stub(&pending(fixtures::CALENDAR_ALICE_A));
    let same = submit_to_calendars(
        &client(),
        &fixtures::DIGEST_A,
        &[first.base_url(), second.base_url()],
    );
    assert_eq!(same.pending().count(), 2, "two endpoints answered");
    assert_eq!(
        same.distinct_calendars(),
        1,
        "…but they are one calendar, so this is Thin"
    );
    assert_eq!(same.outcome(), OtsSubmitOutcome::Thin);

    // The positive twin: two different URIs count as two.
    let alice = stub(&pending(fixtures::CALENDAR_ALICE_A));
    let bob = stub(&pending(fixtures::CALENDAR_BOB_A));
    let different = submit_to_calendars(
        &client(),
        &fixtures::DIGEST_A,
        &[alice.base_url(), bob.base_url()],
    );
    assert_eq!(different.distinct_calendars(), 2);
    assert_eq!(different.outcome(), OtsSubmitOutcome::Complete);
}

/// Normalisation is over scheme and authority only — a whole-string lowercase
/// would corrupt a path, and DNS case-insensitivity is correctness here.
#[test]
fn uri_normalisation_folds_case_in_the_authority_and_nowhere_else() {
    assert_eq!(
        normalise_uri("HTTPS://Alice.BTC.Calendar.OpenTimestamps.ORG"),
        "https://alice.btc.calendar.opentimestamps.org"
    );
    assert_eq!(
        normalise_uri("https://cal.example.com/"),
        "https://cal.example.com"
    );
    assert_eq!(
        normalise_uri("https://cal.example.com/Submit"),
        "https://cal.example.com/Submit",
        "a path is case-sensitive and must survive normalisation unchanged"
    );
}

/// A calendar that answers 200 with something that is not a timestamp over our
/// digest is *that calendar's* failure, and its siblings are unaffected.
#[test]
fn a_garbage_response_is_attributed_to_its_own_calendar() {
    let good = stub(&pending(fixtures::CALENDAR_ALICE_A));
    let junk = stub(&CalendarBehaviour::Garbage(vec![0xde, 0xad, 0xbe, 0xef]));
    let submission = submit_to_calendars(
        &client(),
        &fixtures::DIGEST_A,
        &[good.base_url(), junk.base_url()],
    );

    assert_eq!(submission.distinct_calendars(), 1);
    let failure = submission.attempts[1]
        .outcome
        .as_ref()
        .expect_err("the junk endpoint failed");
    assert_eq!(failure.class(), "unparseable");
    assert!(matches!(failure, CalendarFailure::Artifact { .. }));
}

/// A calendar's response for **another digest** is accepted at submit time,
/// and that is a property of the protocol rather than a hole in this client.
///
/// **Written after the opposite assertion failed**, which is the useful part.
/// The intuition was that `parse_ots` takes `anchor_digest` as a parameter, so
/// a response for the wrong digest must fail. It cannot: the digest lives in
/// the **container header**, this client writes that header from its own
/// `anchor_digest`, and the calendar's contribution is a bare op stream.
/// `append`/`prepend`/`sha256` execute from *any* starting value, so a
/// response for digest B run from digest A yields a perfectly well-formed
/// timestamp — with a commitment the calendar has never heard of.
///
/// There is no local check that can see this, and one should not be invented:
/// the detection is D58 §7.4(a)'s, and it is stronger than anything local
/// could be. The upgrade poll asks the calendar about the commitment we
/// derived, and a calendar that never issued it answers `404 Not found` —
/// which is precisely why that hard-error arm has to exist and has to be
/// distinguishable from `not yet confirmed`.
#[test]
fn a_response_for_another_digest_is_only_detectable_at_upgrade_time() {
    let wrong = stub(&pending(fixtures::CALENDAR_ALICE_A));
    // The alice capture is the response to digest A; submit under digest B.
    let submission = submit_to_calendars(&client(), &fixtures::DIGEST_B, &[wrong.base_url()]);

    assert_eq!(
        submission.outcome(),
        OtsSubmitOutcome::Thin,
        "structurally valid, so it is accepted here"
    );
    let record = submission.pending().next().expect("accepted");

    // …but the commitment it derives is NOT the one the calendar issued for
    // this response, which is what the upgrade poll will discover.
    let real = pending_refs_for(fixtures::MERGED_A, &fixtures::DIGEST_A);
    assert!(
        !real.contains(&record.commitment),
        "the derived commitment must differ from the one the calendar issued"
    );
}

fn pending_refs_for(artifact: &[u8], digest: &[u8; 32]) -> Vec<Vec<u8>> {
    crate::ots::pending_refs(artifact, digest)
        .expect("parses")
        .into_iter()
        .map(|reference| reference.commitment)
        .collect()
}

/// D54's named test: an over-cap response is a typed error, never a
/// truncation that fails later as a parse error.
#[test]
fn calendar_response_over_cap_is_a_typed_error_not_a_truncation() {
    let huge = stub(&CalendarBehaviour::Oversize);
    let submission = submit_to_calendars(&client(), &fixtures::DIGEST_A, &[huge.base_url()]);

    let failure = submission.attempts[0]
        .outcome
        .as_ref()
        .expect_err("over-cap must fail");
    assert!(
        matches!(
            failure,
            CalendarFailure::Http(crate::http::AnchorHttpError::OversizeBody { .. })
        ),
        "expected OversizeBody, got {failure:?}"
    );
}

/// A13's "per-calendar failures are independent" is about **delay** as much as
/// about outcome, and only the second assertion is non-vacuous: a sequential
/// implementation that happened to query the fast endpoint first would pass a
/// wall-clock check alone.
#[test]
fn calendars_are_submitted_concurrently_not_sequentially() {
    let slow_delay = Duration::from_millis(1_200);
    let slow = stub(&CalendarBehaviour::Slow(
        slow_delay,
        fixtures::CALENDAR_ALICE_A.to_vec(),
    ));
    let fast = stub(&pending(fixtures::CALENDAR_BOB_A));

    let started = Instant::now();
    let submission = submit_to_calendars(
        &client(),
        &fixtures::DIGEST_A,
        &[slow.base_url(), fast.base_url()],
    );
    let wall = started.elapsed();

    assert_eq!(submission.distinct_calendars(), 2);
    assert!(
        wall < slow_delay * 2,
        "sequential submission would cost at least both delays; took {wall:?}"
    );
    assert!(
        submission.attempts[1].elapsed < slow_delay,
        "the fast calendar's own elapsed must not include the slow one's: {:?}",
        submission.attempts[1].elapsed
    );
}
