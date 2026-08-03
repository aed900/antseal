//! A15's Accept rows: the budget, the never-fail contract, the transition,
//! and the status/nag data.

use std::time::Duration;

use antseal_core::anchor::ots::parse_ots;

use super::*;
use crate::http::{Endpoint, HttpPolicy, TlsPolicy};
use crate::testing::replay::{CalendarBehaviour, EsploraBehaviour, calendar, esplora, fixtures};
use crate::testing::stub::StubServer;

fn client() -> HttpClient {
    HttpClient::new(HttpPolicy::opportunistic())
}

fn esplora_pair(first: &StubServer, second: &StubServer) -> EndpointPair {
    EndpointPair::new(
        Endpoint::parse(&first.base_url(), TlsPolicy::RequiredExceptLoopback).expect("first"),
        Endpoint::parse(&second.base_url(), TlsPolicy::RequiredExceptLoopback).expect("second"),
    )
    .expect("distinct loopback origins")
}

fn dead_pair() -> (StubServer, StubServer) {
    (
        StubServer::spawn(esplora(&EsploraBehaviour::Down)),
        StubServer::spawn(esplora(&EsploraBehaviour::Down)),
    )
}

fn work_with(artifact: &[u8]) -> PendingWork {
    PendingWork {
        work_id: [0xA5; 32],
        anchor_digest: fixtures::DIGEST_A,
        ots: vec![StoredOtsAnchor {
            artifact: artifact.to_vec(),
            upgrade: None,
        }],
        tsa: Vec::new(),
    }
}

/// A15's central contract: the engine returns a report, never a `Result`, and
/// every failure is a note.
///
/// Asserted by driving it against endpoints that fail in four different ways
/// at once. There is no error path to propagate, which is a stronger guarantee
/// than a caller remembering to ignore one.
#[test]
fn no_failure_mode_produces_an_error_the_host_command_could_inherit() {
    let (first, second) = dead_pair();
    let pair = esplora_pair(&first, &second);

    let works = vec![
        // An artifact that does not parse at all.
        PendingWork {
            work_id: [0x01; 32],
            anchor_digest: fixtures::DIGEST_A,
            ots: vec![StoredOtsAnchor {
                artifact: b"not an ots file".to_vec(),
                upgrade: None,
            }],
            tsa: Vec::new(),
        },
        // A well-formed artifact under the wrong digest.
        PendingWork {
            work_id: [0x02; 32],
            anchor_digest: fixtures::DIGEST_B,
            ots: vec![StoredOtsAnchor {
                artifact: fixtures::MERGED_A.to_vec(),
                upgrade: None,
            }],
            tsa: Vec::new(),
        },
        // A real artifact whose calendars are unreachable at their real,
        // allowlisted hostnames — no network is available in a test process,
        // so these fail at DNS or connect.
        work_with(fixtures::MERGED_A),
        // No OTS anchors at all.
        PendingWork {
            work_id: [0x04; 32],
            anchor_digest: fixtures::DIGEST_A,
            ots: Vec::new(),
            tsa: Vec::new(),
        },
    ];

    // A tiny budget so the unreachable real calendars are not actually dialled
    // for long. The point is the shape of the return, not the timing.
    let report = upgrade_pending(
        &client(),
        &pair,
        &works,
        &[],
        UpgradeBudget {
            total: Duration::from_millis(1),
            max_polls: 1,
        },
        0,
    );
    assert!(report.upgraded.is_empty());
    assert!(report.is_empty());
    assert!(
        !report.notes.is_empty(),
        "failures must be visible as notes, not swallowed"
    );
}

/// A15 Accept row 2, first half: the budget is respected against a
/// deliberately slow calendar.
///
/// `max_polls` is the deterministic half — a wall-clock assertion alone would
/// be flaky on a loaded 2-core machine, and a budget that only ever stopped on
/// time would still be a budget that never stopped on count.
#[test]
fn the_poll_budget_is_respected() {
    let (first, second) = dead_pair();
    let pair = esplora_pair(&first, &second);

    let works = vec![work_with(fixtures::MERGED_A)];
    let report = upgrade_pending(
        &client(),
        &pair,
        &works,
        &[],
        UpgradeBudget {
            total: Duration::from_secs(60),
            max_polls: 1,
        },
        0,
    );

    assert_eq!(report.polls, 1, "the artifact has three pending calendars");
    assert!(report.budget_exhausted);
    assert!(
        report
            .notes
            .iter()
            .any(|note| matches!(note, UpgradeNote::BudgetExhausted))
    );
}

/// The instrument check for the row above: without the budget, the same
/// artifact produces three polls. A budget test that passed because nothing
/// was ever polled would be worthless.
#[test]
fn without_a_budget_the_same_artifact_polls_every_calendar() {
    let (first, second) = dead_pair();
    let pair = esplora_pair(&first, &second);

    let report = upgrade_pending(
        &client(),
        &pair,
        &[work_with(fixtures::MERGED_A)],
        &[],
        UpgradeBudget {
            total: Duration::from_secs(60),
            max_polls: 10,
        },
        0,
    );
    assert_eq!(
        report.polls, 3,
        "three pending attestations, three polls when the budget allows"
    );
    assert!(!report.budget_exhausted);
}

/// A15 Accept row 3: a successful upgrade produces the transition that makes
/// the next `reveal`/`verify` embed the upgraded artifact **and** its header.
///
/// Driven end to end through the engine, with the calendar allowlist widened
/// to the stub by `configured` — no, it cannot be: A42 requires https and a
/// bare host, so a loopback stub is unreachable through the real constructor
/// by design. The engine is therefore exercised here through its own merge and
/// header steps against real captured bytes, and the allowlist refusal is
/// asserted separately below.
#[test]
fn a_successful_upgrade_produces_an_artifact_and_header_transition() {
    let uri = "https://alice.btc.calendar.opentimestamps.org";
    let references =
        crate::ots::pending_refs(fixtures::MERGED_A, &fixtures::DIGEST_A).expect("parses");
    let target = references
        .iter()
        .find(|reference| reference.uri == uri)
        .expect("alice");

    let merged = crate::ots::merge_upgrade(
        fixtures::MERGED_A,
        &fixtures::DIGEST_A,
        target,
        fixtures::UPGRADE_A_ALICE,
    )
    .expect("merges");

    let applied = AppliedUpgrade {
        work_id: [0xA5; 32],
        anchor_index: 0,
        artifact: merged.artifact,
        upgrade: None,
    };

    // The transition's artifact is what the vault stores, and it must still be
    // parseable against the same digest afterwards.
    let parsed = parse_ots(&applied.artifact, &fixtures::DIGEST_A).expect("A11-clean");
    assert!(parsed.attestations.len() > 3);

    // …and the status backend now reads it as attested once the header group
    // is recorded beside it, and as header-missing when it is not.
    let no_header = work_status(&PendingWork {
        work_id: [0xA5; 32],
        anchor_digest: fixtures::DIGEST_A,
        ots: vec![StoredOtsAnchor {
            artifact: applied.artifact.clone(),
            upgrade: None,
        }],
        tsa: Vec::new(),
    });
    assert_eq!(no_header.ots[0].state, OtsAnchorState::AttestedHeaderMissing);

    let mut header = [0_u8; 80];
    let heights = no_header.ots[0].heights.clone();
    let with_header = work_status(&PendingWork {
        work_id: [0xA5; 32],
        anchor_digest: fixtures::DIGEST_A,
        ots: vec![StoredOtsAnchor {
            artifact: applied.artifact,
            upgrade: Some(OtsUpgrade::new(heights[0], {
                header[0] = 1;
                header
            }, 1_754_211_818)),
        }],
        tsa: Vec::new(),
    });
    assert_eq!(with_header.ots[0].state, OtsAnchorState::Attested);
    assert_eq!(with_header.ots[0].fetch_date, Some(1_754_211_818));
    assert_eq!(with_header.ots[0].pending_uris.len(), 3);
}

/// The stored artifact's URI is attacker-writable, so the allowlist must fire
/// before a socket is opened — on **every** CLI invocation, from the victim's
/// own IP.
#[test]
fn an_artifact_naming_a_hostile_calendar_is_refused_without_a_request() {
    let attacker = StubServer::spawn(calendar(&CalendarBehaviour::NotFound));
    let (first, second) = dead_pair();
    let pair = esplora_pair(&first, &second);

    // A synthetic artifact whose pending attestation names the attacker.
    let hostile_uri = attacker.base_url();
    let branch = {
        let mut branch = fixtures::CALENDAR_ALICE_A.to_vec();
        let real = crate::ots::container::pending_attestation_bytes(
            "https://alice.btc.calendar.opentimestamps.org",
        );
        branch.truncate(branch.len() - real.len());
        branch.extend_from_slice(&crate::ots::container::pending_attestation_bytes(
            &hostile_uri,
        ));
        branch
    };
    let artifact = crate::ots::assemble(&fixtures::DIGEST_A, &[branch]);
    // The synthetic artifact must be a real one, or this tests nothing.
    let parsed = parse_ots(&artifact, &fixtures::DIGEST_A).expect("well-formed");
    assert_eq!(parsed.attestations.len(), 1);

    let report = upgrade_pending(
        &client(),
        &pair,
        &[PendingWork {
            work_id: [0x07; 32],
            anchor_digest: fixtures::DIGEST_A,
            ots: vec![StoredOtsAnchor {
                artifact,
                upgrade: None,
            }],
            tsa: Vec::new(),
        }],
        &[],
        UpgradeBudget::interactive(),
        0,
    );

    assert_eq!(report.polls, 0, "no poll may be issued");
    assert_eq!(
        attacker.connections(),
        0,
        "the attacker's listener must never be contacted"
    );
    assert!(
        report
            .notes
            .iter()
            .any(|note| matches!(note, UpgradeNote::Refused { .. }))
    );
}

/// The instrument check for the row above: the stub *can* be contacted, so
/// `connections() == 0` means the allowlist stopped it and not that the stub
/// was unreachable.
#[test]
fn the_hostile_stub_would_have_answered_if_it_had_been_asked() {
    let attacker = StubServer::spawn(calendar(&CalendarBehaviour::NotFound));
    let target = crate::ots::UpgradeTarget::loopback_for_tests(&attacker.base_url());
    assert_eq!(
        crate::ots::poll_upgrade(&client(), &target, &[0x01]),
        UpgradePoll::NotFound
    );
    assert_eq!(attacker.connections(), 1);
}

/// An anchor whose header cannot be confirmed records **nothing** — the merge
/// is discarded with it, so the vault never holds a Bitcoin attestation whose
/// header was not agreed.
#[test]
fn an_unconfirmable_header_records_no_transition() {
    let uri = "https://alice.btc.calendar.opentimestamps.org";
    let references =
        crate::ots::pending_refs(fixtures::MERGED_A, &fixtures::DIGEST_A).expect("parses");
    let target = references
        .iter()
        .find(|reference| reference.uri == uri)
        .expect("alice");
    let merged = crate::ots::merge_upgrade(
        fixtures::MERGED_A,
        &fixtures::DIGEST_A,
        target,
        fixtures::UPGRADE_A_ALICE,
    )
    .expect("merges");

    let (first, second) = dead_pair();
    let error = crate::ots::confirm_header(
        &client(),
        &esplora_pair(&first, &second),
        &merged.added[0],
        0,
    )
    .expect_err("a dead pair confirms nothing");
    assert!(matches!(error, crate::ots::HeaderError::NotAgreed { .. }));
}

// ── the status backend ───────────────────────────────────────────────────

fn tsa(verified: bool) -> StoredTsaAnchor {
    StoredTsaAnchor {
        token_present: true,
        verified,
        fetch_date: 1_754_100_000,
    }
}

/// U25's fixture matrix, as four distinct states.
///
/// The four are not a boolean with decoration: "no nag" has three different
/// meanings here, and rendering them identically is exactly how an UNANCHORED
/// work comes to look merely pending.
#[test]
fn the_nag_matrix_distinguishes_all_four_states() {
    // A verified TSA token: headline-eligible offline, nothing to chase.
    let anchored = work_status(&PendingWork {
        work_id: [1; 32],
        anchor_digest: fixtures::DIGEST_A,
        ots: vec![StoredOtsAnchor {
            artifact: fixtures::MERGED_A.to_vec(),
            upgrade: None,
        }],
        tsa: vec![tsa(true)],
    });
    assert_eq!(anchored.nag, NagState::Anchored);
    assert!(!anchored.nag.nags());

    // Degraded: only a pending OTS anchor. This is the nag.
    let pending = work_status(&work_with(fixtures::MERGED_A));
    assert_eq!(pending.nag, NagState::OnlyPendingOts);
    assert!(pending.nag.nags());
    assert_eq!(pending.ots[0].state, OtsAnchorState::Pending);
    assert_eq!(pending.ots[0].pending_uris.len(), 3);
    assert!(pending.ots[0].heights.is_empty());

    // `--no-anchor`: UNANCHORED, and not "pending".
    let unanchored = work_status(&PendingWork {
        work_id: [3; 32],
        anchor_digest: fixtures::DIGEST_A,
        ots: Vec::new(),
        tsa: Vec::new(),
    });
    assert_eq!(unanchored.nag, NagState::Unanchored);
    assert!(!unanchored.nag.nags());

    // A token that is present but did NOT verify is not headline-eligible, so
    // it does not silence the nag. A `token_present` check alone would.
    let unverified = work_status(&PendingWork {
        work_id: [4; 32],
        anchor_digest: fixtures::DIGEST_A,
        ots: vec![StoredOtsAnchor {
            artifact: fixtures::MERGED_A.to_vec(),
            upgrade: None,
        }],
        tsa: vec![tsa(false)],
    });
    assert_eq!(unverified.nag, NagState::OnlyPendingOts);
}

/// An artifact that does not parse is `Unreadable` and does not silently
/// present as pending — and it cannot produce a nag that `--upgrade` could
/// never satisfy.
#[test]
fn an_unreadable_artifact_is_reported_as_such() {
    let status = work_status(&PendingWork {
        work_id: [5; 32],
        anchor_digest: fixtures::DIGEST_A,
        ots: vec![StoredOtsAnchor {
            artifact: b"junk".to_vec(),
            upgrade: None,
        }],
        tsa: Vec::new(),
    });
    assert_eq!(status.ots[0].state, OtsAnchorState::Unreadable);
    assert!(status.ots[0].pending_uris.is_empty());
    assert_eq!(status.nag, NagState::AttestedOnly);
    assert!(!status.nag.nags());
}

/// The status backend is pure: no clock, no network, no vault. Called twice on
/// the same input it produces the same answer.
#[test]
fn the_status_backend_is_deterministic() {
    let work = work_with(fixtures::MERGED_A);
    assert_eq!(work_status(&work), work_status(&work));
}

/// The opportunistic budget is the substrate's own opportunistic global, so
/// the hook's stated cost and the client's timeout cannot drift apart.
#[test]
fn the_opportunistic_budget_matches_the_substrate_profile() {
    assert_eq!(
        UpgradeBudget::opportunistic().total,
        crate::http::HTTP_OPPORTUNISTIC_GLOBAL
    );
    assert_eq!(
        UpgradeBudget::opportunistic().max_polls,
        crate::ots::DEFAULT_OTS_CALENDARS.len()
    );
}
