//! A15's Accept rows: the budget, the never-fail contract, the transition,
//! and the status/nag data.

use std::time::Duration;

use antseal_core::anchor::ots::parse_ots;

use super::*;
use crate::http::{Endpoint, HttpPolicy, TlsPolicy};
use crate::testing::replay::{
    CalendarBehaviour, EsploraBehaviour, RecordedEndpoint, attested_block, calendar, esplora,
    esplora_block_at, esplora_recorded_block, fixtures, tamper_hex,
};
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

/// Resolve every pending URI onto one loopback stub.
///
/// This is the seam `upgrade_pending_with` exists for: A42's allowlist
/// requires https, a bare host and no port, so a stub can never be admitted
/// through the production constructor — and a test that used the production
/// constructor with the committed artifact would be dialling the **real**
/// calendars, which Q16 forbids and which no assertion here would notice.
fn to_stub(server: &StubServer) -> impl Fn(&str) -> Result<UpgradeTarget, UpgradeUriRefusal> {
    let base = server.base_url();
    move |_uri: &str| Ok(UpgradeTarget::loopback_for_tests(&base))
}

/// Refuse everything, as the allowlist does for a host it does not know.
fn refuse_all() -> impl Fn(&str) -> Result<UpgradeTarget, UpgradeUriRefusal> {
    |_uri: &str| Err(UpgradeUriRefusal::HostNotAllowed)
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
        unreadable_records: 0,
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
            unreadable_records: 0,
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
            unreadable_records: 0,
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
            unreadable_records: 0,
        },
    ];

    // A tiny budget so the unreachable real calendars are not actually dialled
    // for long. The point is the shape of the return, not the timing.
    let report = upgrade_pending_with(
        &client(),
        &pair,
        &works,
        UpgradeBudget {
            total: Duration::from_millis(1),
            max_polls: 1,
        },
        0,
        &refuse_all(),
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

    // A deliberately slow calendar: every poll costs 400 ms, so a budget that
    // did not stop would spend 1.2 s here.
    let slow = StubServer::spawn(calendar(&CalendarBehaviour::Slow(
        Duration::from_millis(400),
        Vec::new(),
    )));
    let works = vec![work_with(fixtures::MERGED_A)];
    let started = std::time::Instant::now();
    let report = upgrade_pending_with(
        &client(),
        &pair,
        &works,
        UpgradeBudget {
            total: Duration::from_secs(60),
            max_polls: 1,
        },
        0,
        &to_stub(&slow),
    );
    let wall = started.elapsed();

    assert_eq!(report.polls, 1, "the artifact has three pending calendars");
    assert_eq!(slow.connections(), 1, "exactly one calendar round trip");
    assert!(
        wall < Duration::from_millis(1_200),
        "the budget must stop before three 400 ms polls; took {wall:?}"
    );
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

    let calendar = StubServer::spawn(calendar(&CalendarBehaviour::PendingSubmit(Vec::new())));
    let report = upgrade_pending_with(
        &client(),
        &pair,
        &[work_with(fixtures::MERGED_A)],
        UpgradeBudget {
            total: Duration::from_secs(60),
            max_polls: 10,
        },
        0,
        &to_stub(&calendar),
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
        unreadable_records: 0,
    });
    assert_eq!(
        no_header.ots[0].state,
        OtsAnchorState::AttestedHeaderMissing
    );

    let mut header = [0_u8; 80];
    let heights = no_header.ots[0].heights.clone();
    let with_header = work_status(&PendingWork {
        work_id: [0xA5; 32],
        anchor_digest: fixtures::DIGEST_A,
        ots: vec![StoredOtsAnchor {
            artifact: applied.artifact,
            upgrade: Some(OtsUpgrade::new(
                heights[0],
                {
                    header[0] = 1;
                    header
                },
                1_754_211_818,
            )),
        }],
        tsa: Vec::new(),
        unreadable_records: 0,
    });
    assert_eq!(with_header.ots[0].state, OtsAnchorState::Attested);
    assert_eq!(with_header.ots[0].fetch_date, Some(1_754_211_818));
    assert_eq!(with_header.ots[0].pending_uris.len(), 3);
}

/// A15 Accept row 3, end to end through the engine: poll → merge → header →
/// transition, with every byte of the calendar exchange being a **real
/// recorded upgrade**.
///
/// Only the block header is synthesised. What the synthetic header
/// establishes is the wiring — that a committing header produces a transition
/// carrying both the merged artifact and the upgrade group — and the
/// *non*-committing direction is covered against the same machinery by
/// `a_wrong_header_is_rejected…`.
///
/// **The header is no longer synthetic of necessity** (A112). When this test
/// was written the tree held no mainnet header for block 960767, so it
/// spliced the derived root into 80 zero bytes and said so. A25's day-3
/// capture landed those headers on 2026-08-07 and
/// [`a_promotion_round_replays_at_a_real_attested_height`] runs the same
/// round against them. This one is kept, and kept synthetic, because it is
/// the arm that isolates the wiring from the arithmetic: it passes for any
/// root the ops derive, so it still fails if the transition stops carrying
/// both halves even in a world where the mainnet capture were mislaid.
#[test]
fn the_engine_records_artifact_and_header_together() {
    // The upgrade the real calendar returned, and the root it derives.
    let references =
        crate::ots::pending_refs(fixtures::MERGED_A, &fixtures::DIGEST_A).expect("parses");
    let alice = references
        .iter()
        .find(|reference| reference.uri.contains("alice"))
        .expect("alice");
    let merged = crate::ots::merge_upgrade(
        fixtures::MERGED_A,
        &fixtures::DIGEST_A,
        alice,
        fixtures::UPGRADE_A_ALICE,
    )
    .expect("merges");
    let antseal_core::anchor::ots::OtsAttestation::Bitcoin {
        height,
        merkle_root: Some(root),
    } = &merged.added[0]
    else {
        panic!("a Bitcoin attestation with a determinate root")
    };

    let mut header = [0_u8; 80];
    header[36..68].copy_from_slice(root);
    let header_hex: String = header.iter().map(|byte| format!("{byte:02x}")).collect();

    let calendar_stub = StubServer::spawn(calendar(&CalendarBehaviour::Upgraded {
        pending: Vec::new(),
        upgrade: fixtures::UPGRADE_A_ALICE.to_vec(),
    }));
    let first = StubServer::spawn(esplora_at(*height, &header_hex));
    let second = StubServer::spawn(esplora_at(*height, &header_hex));

    let report = upgrade_pending_with(
        &client(),
        &esplora_pair(&first, &second),
        &[work_with(fixtures::MERGED_A)],
        UpgradeBudget {
            total: Duration::from_secs(60),
            // One poll: the stub answers every URI with alice's upgrade, and
            // splicing it at bob's attestation would derive a different root
            // that the header no longer commits — which is a different test.
            max_polls: 1,
        },
        0,
        &to_stub(&calendar_stub),
    );

    assert_eq!(report.upgraded.len(), 1, "notes: {:?}", report.notes);
    let applied = &report.upgraded[0];
    assert_eq!(applied.work_id, [0xA5; 32]);
    assert_eq!(applied.anchor_index, 0);
    assert_eq!(applied.artifact, merged.artifact, "the merged bytes");

    // Both halves, recorded together — never one without the other.
    let upgrade = applied.upgrade.as_ref().expect("the header group");
    assert_eq!(upgrade.block_height(), *height);
    assert_eq!(upgrade.block_header(), &header);

    // And the recorded pair is exactly what A12 will check offline.
    let parsed = parse_ots(&applied.artifact, &fixtures::DIGEST_A).expect("A11-clean");
    assert!(
        parsed
            .attestations
            .iter()
            .any(|a| antseal_core::anchor::ots::header_commits(a, upgrade)),
        "the recorded artifact must commit the recorded header"
    );
}

/// A stub esplora pair answering for one height with one header hex.
fn esplora_at(height: u64, header_hex: &str) -> crate::testing::stub::StubScript {
    use crate::testing::stub::{StubMatch, StubReply, StubScript};
    // A block hash is only ever echoed back into the next path, so any
    // 64-character lowercase hex string serves; the pair must agree on it,
    // which they do because both stubs are built from this one function.
    let hash: String = "00000000000000000000".to_owned() + &"ab".repeat(22);
    StubScript::new()
        .route(
            StubMatch::target(format!("/block-height/{height}")),
            StubReply::Body {
                status: 200,
                content_type: "text/plain",
                bytes: hash.as_bytes()[..64].to_vec(),
            },
        )
        .route(
            StubMatch::target("/header"),
            StubReply::Body {
                status: 200,
                content_type: "text/plain",
                bytes: header_hex.as_bytes().to_vec(),
            },
        )
}

// ── A112: the promotion round at a height this project actually attests ──

/// The instant blockstream.info served block 960767's header, from
/// `A25-upgrade-headers/CAPTURE.log` (2026-08-07T10:36:49Z).
///
/// A real recorded instant rather than `0`, because `fetch_date` is what a
/// bundle carries for ever as "when this header was obtained", and a replay
/// that stamps it zero is a replay whose one time-bearing field is the one
/// field it made up.
const HEADER_FETCH_DATE: u64 = 1_786_099_009;

/// **A112.** The whole round — poll → merge → header → transition — replayed
/// offline at **960767**, with no network and no new capture.
///
/// Every byte of this exchange was recorded from a live service. The calendar
/// leg replays alice's real 2026-08-03 upgrade response; the esplora legs
/// replay the two mainnet captures A25 took on 2026-08-07, each stub serving
/// **its own endpoint's file** so the must-agree rule compares two
/// independently recorded bodies rather than one body served twice.
///
/// What that buys over the synthetic sibling is the assertion at the end.
/// There, the header exists because the test spliced the derived root into
/// it, so `header_commits` cannot fail and proves only the wiring. Here
/// neither side of the comparison was chosen by this crate: the left is
/// derived by executing a real calendar's op chain over the committed golden
/// digest, the right is 32 bytes of a block header two independent operators
/// served. The round therefore promotes only if the OpenTimestamps proof this
/// project holds really is in the Bitcoin block it names — which is the claim
/// promotion exists to check, and the one a synthetic header can never test.
#[test]
fn a_promotion_round_replays_at_a_real_attested_height() {
    // alice's pending branch of `MERGED_A` attests block 960767 (D92's
    // "three calendars, three blocks"); `attested_block` refuses any height
    // this project did not stamp, so a wrong constant here does not silently
    // become a replay of nothing.
    let block = attested_block(960_767).expect("alice's attesting block is committed");

    let calendar_stub = StubServer::spawn(calendar(&CalendarBehaviour::Upgraded {
        pending: Vec::new(),
        upgrade: fixtures::UPGRADE_A_ALICE.to_vec(),
    }));
    let blockstream =
        StubServer::spawn(esplora_recorded_block(block, RecordedEndpoint::Blockstream));
    let mempool = StubServer::spawn(esplora_recorded_block(block, RecordedEndpoint::Mempool));

    let report = upgrade_pending_with(
        &client(),
        &esplora_pair(&blockstream, &mempool),
        &[work_with(fixtures::MERGED_A)],
        UpgradeBudget {
            total: Duration::from_secs(60),
            // One poll, as in the synthetic sibling: the stub answers every
            // URI with alice's upgrade, and splicing it at bob's attestation
            // would derive a root 960767's header does not commit.
            max_polls: 1,
        },
        HEADER_FETCH_DATE,
        &to_stub(&calendar_stub),
    );

    assert_eq!(report.upgraded.len(), 1, "notes: {:?}", report.notes);
    let applied = &report.upgraded[0];
    let upgrade = applied.upgrade.as_ref().expect("the header group");

    assert_eq!(upgrade.block_height(), 960_767);
    assert_eq!(
        upgrade.block_header(),
        &block
            .header_bytes(RecordedEndpoint::Blockstream)
            .expect("a committed capture is 160 lowercase hex"),
        "the recorded header must be the captured bytes, not a re-encoding"
    );
    assert_eq!(upgrade.fetch_date(), HEADER_FETCH_DATE);

    // The load-bearing one. `confirm_header` already refused to record a
    // header the attestation does not commit, so reaching this line is itself
    // the result; asserting it here says which fact the round established,
    // and does it through the same predicate the offline verifier will run
    // against the embedded bytes.
    let parsed = parse_ots(&applied.artifact, &fixtures::DIGEST_A).expect("A11-clean");
    assert!(
        parsed
            .attestations
            .iter()
            .any(|a| antseal_core::anchor::ots::header_commits(a, upgrade)),
        "the ops-derived merkle root must be the one Bitcoin published at 960767"
    );
}

/// The same round, with **one endpoint's copy of the real header** altered by
/// a single hex digit: nothing is recorded, and the merge is dropped with it.
///
/// This is the arm that makes the test above falsifiable. Without it, a
/// `fetch_agreed_header` that ignored the second endpoint entirely would pass
/// every assertion there — and the whole reason two endpoints are queried is
/// that one unsigned reply is not evidence.
#[test]
fn a_promotion_round_at_a_real_height_records_nothing_when_one_endpoint_disagrees() {
    let block = attested_block(960_767).expect("alice's attesting block is committed");

    let calendar_stub = StubServer::spawn(calendar(&CalendarBehaviour::Upgraded {
        pending: Vec::new(),
        upgrade: fixtures::UPGRADE_A_ALICE.to_vec(),
    }));
    let honest = StubServer::spawn(esplora_recorded_block(block, RecordedEndpoint::Blockstream));
    // Still 160 lowercase hex, still resolving the same hash: only the
    // comparison can catch it.
    let liar = StubServer::spawn(esplora_block_at(
        block.height,
        block.mempool_hash_hex,
        &tamper_hex(block.mempool_header_hex),
    ));

    let report = upgrade_pending_with(
        &client(),
        &esplora_pair(&honest, &liar),
        &[work_with(fixtures::MERGED_A)],
        UpgradeBudget {
            total: Duration::from_secs(60),
            max_polls: 1,
        },
        HEADER_FETCH_DATE,
        &to_stub(&calendar_stub),
    );

    assert!(
        report.upgraded.is_empty(),
        "a disagreed header must drop the merge with it: {:?}",
        report.upgraded
    );
    assert!(
        report.notes.iter().any(|note| matches!(
            note,
            UpgradeNote::HeaderUnconfirmed {
                source: HeaderError::NotAgreed { height: 960_767 },
                ..
            }
        )),
        "notes: {:?}",
        report.notes
    );
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
            unreadable_records: 0,
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

/// U25's fixture matrix, as distinct states.
///
/// They are not a boolean with decoration: "no nag" has four different
/// meanings here, and rendering them identically is exactly how an UNANCHORED
/// work comes to look merely pending.
#[test]
fn the_nag_matrix_distinguishes_its_states() {
    // A verified TSA token: headline-eligible offline, nothing to chase.
    let anchored = work_status(&PendingWork {
        work_id: [1; 32],
        anchor_digest: fixtures::DIGEST_A,
        ots: vec![StoredOtsAnchor {
            artifact: fixtures::MERGED_A.to_vec(),
            upgrade: None,
        }],
        tsa: vec![tsa(true)],
        unreadable_records: 0,
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
        unreadable_records: 0,
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
        unreadable_records: 0,
    });
    assert_eq!(unverified.nag, NagState::OnlyPendingOts);
}

/// An artifact that does not parse is `Unreadable` and does not silently
/// present as pending — and it cannot produce a nag that `--upgrade` could
/// never satisfy.
///
/// The fifth state is what let the other three assertions keep their meaning:
/// `nags()` stays false, so the unsatisfiable nag this test refuses is still
/// refused — what changed is only that the state no longer borrows the name of
/// a good outcome (D100 R7.1). A102's Accept row asked for a work whose only
/// anchor is unreadable to *"nag"*, and that literal reading is what this test
/// was right to refuse: `nags()` drives the two-line `ANCHORS PENDING: 0` /
/// `--upgrade` block, whose count would be a lie and whose instruction cannot
/// help bytes nothing can parse. A102 needed the **name**.
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
        unreadable_records: 0,
    });
    assert_eq!(status.ots[0].state, OtsAnchorState::Unreadable);
    assert!(status.ots[0].pending_uris.is_empty());
    assert_eq!(status.nag, NagState::Unreadable);
    assert!(!status.nag.nags());
}

/// **D100 R7.3**: a record the *vault codec* refused never reaches
/// [`PendingWork::ots`], so a work whose only slots are damaged would classify
/// `Unanchored` — *"no anchors at all"* — without the count.
///
/// Both halves are asserted, because they are two different inputs to one
/// condition: the unparseable `.ots` above arrives as an artifact, and this one
/// arrives as a number.
#[test]
fn a_record_the_vault_codec_refused_is_not_an_unanchored_work() {
    let damaged_only = work_status(&PendingWork {
        work_id: [6; 32],
        anchor_digest: fixtures::DIGEST_A,
        ots: Vec::new(),
        tsa: Vec::new(),
        unreadable_records: 1,
    });
    assert_eq!(
        damaged_only.nag,
        NagState::Unreadable,
        "a work with one undecodable record has anchors; it does not have none"
    );
    assert!(!damaged_only.nag.nags());

    // …and it does not over-claim damage over a work that still holds a
    // headline-eligible anchor, nor steal a satisfiable `--upgrade` hint from
    // one that still has something pending (R7.2's placement argument).
    let with_token = work_status(&PendingWork {
        work_id: [7; 32],
        anchor_digest: fixtures::DIGEST_A,
        ots: Vec::new(),
        tsa: vec![tsa(true)],
        unreadable_records: 1,
    });
    assert_eq!(with_token.nag, NagState::Anchored);

    let with_pending = work_status(&PendingWork {
        work_id: [8; 32],
        anchor_digest: fixtures::DIGEST_A,
        ots: vec![StoredOtsAnchor {
            artifact: fixtures::MERGED_A.to_vec(),
            upgrade: None,
        }],
        tsa: Vec::new(),
        unreadable_records: 1,
    });
    assert_eq!(with_pending.nag, NagState::OnlyPendingOts);
    assert!(with_pending.nag.nags());
}

/// **D100 R8 / A103**: every state has its own kebab name, and the set is the
/// enum's own rather than a hand-copied array.
#[test]
fn every_nag_state_has_its_own_name() {
    let names: Vec<&'static str> = NagState::ALL.iter().map(|state| state.name()).collect();
    assert_eq!(
        names,
        vec![
            "anchored",
            "only-pending-ots",
            "unreadable",
            "attested-only",
            "unanchored",
        ]
    );
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), names.len(), "two states share a name");
    // `ALL` is the enum, not a copy of it: a variant added without a row here
    // would make this length disagree with the array literal's, and the array
    // literal is what the compiler checks against the declared length.
    assert_eq!(NagState::ALL.len(), 5);
}

/// **D100 R10.4 — the reachability row nothing else provides.**
///
/// `work_status`'s classifier is an `if`/`else` chain, not a `match`, so a
/// variant can exist, have a name, be enumerated in [`NagState::ALL`], compile
/// clean and **never be constructed**. Naming a state is not the same as
/// producing one, and only this asserts the second.
///
/// Proven red the way A104 says a new suite has to be: delete R7.2's
/// `has_unreadable` branch and `Unreadable` becomes unreachable while every
/// other row in this file — including `every_nag_state_has_its_own_name` — stays
/// green.
#[test]
fn every_nag_state_is_actually_produced_by_the_classifier() {
    let junk = || StoredOtsAnchor {
        artifact: b"junk".to_vec(),
        upgrade: None,
    };
    let merged = || StoredOtsAnchor {
        artifact: fixtures::MERGED_A.to_vec(),
        upgrade: None,
    };

    let rows: Vec<PendingWork> = vec![
        // Anchored: a verified token.
        PendingWork {
            work_id: [0x10; 32],
            anchor_digest: fixtures::DIGEST_A,
            ots: Vec::new(),
            tsa: vec![tsa(true)],
            unreadable_records: 0,
        },
        // OnlyPendingOts: one pending `.ots`, nothing stronger.
        PendingWork {
            work_id: [0x11; 32],
            anchor_digest: fixtures::DIGEST_A,
            ots: vec![merged()],
            tsa: Vec::new(),
            unreadable_records: 0,
        },
        // Unreadable: bytes that do not parse, and nothing else.
        PendingWork {
            work_id: [0x12; 32],
            anchor_digest: fixtures::DIGEST_A,
            ots: vec![junk()],
            tsa: Vec::new(),
            unreadable_records: 0,
        },
        // AttestedOnly: an anchor exists, nothing is pending, nothing is
        // unreadable — a stored token that did not verify against today's
        // root store, and no `.ots` beside it.
        PendingWork {
            work_id: [0x13; 32],
            anchor_digest: fixtures::DIGEST_A,
            ots: Vec::new(),
            tsa: vec![tsa(false)],
            unreadable_records: 0,
        },
        // Unanchored: nothing at all.
        PendingWork {
            work_id: [0x14; 32],
            anchor_digest: fixtures::DIGEST_A,
            ots: Vec::new(),
            tsa: Vec::new(),
            unreadable_records: 0,
        },
    ];

    let produced: Vec<NagState> = rows.iter().map(|work| work_status(work).nag).collect();
    for state in NagState::ALL {
        assert!(
            produced.contains(&state),
            "no fixture row produces {state:?} — the classifier's if/else chain gives no \
             compiler help, so a named-but-unreachable state is exactly what this row exists \
             to catch"
        );
    }
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

// ─────────────────────────────────────────────────────────────────────
// D99 R5: the test seam has no production call sites
// ─────────────────────────────────────────────────────────────────────

/// Production files under `dir` (recursively) that **call** `needle`.
///
/// The S36 shape (`seal_session.rs::production_files_naming`), sharpened in
/// two ways this crate needs and that one did not:
///
/// 1. **Calls, not mentions.** `engine.rs` legitimately *defines*
///    `upgrade_pending_with` twice and names it throughout its docs, so a
///    scan that matched the bare identifier would report the definition site
///    as its own violation and would have to be given an exemption — and an
///    exemption is how a rule stops being one. Lines that open a comment and
///    lines carrying `fn <needle>` are therefore skipped, and the needle must
///    be followed by `(`.
/// 2. **This crate puts its unit tests in `foo/tests.rs`**, not only in
///    inline `#[cfg(test)] mod tests { … }`. Both conventions are live
///    (`nonce.rs` is inline, `ots/engine.rs` is external), so the cut has to
///    handle both: whole files named `tests.rs` are excluded, and inside the
///    rest the scan stops at the first line that is exactly `#[cfg(test)]`.
///    `testing.rs` and `testing/` are excluded for the same reason — they are
///    `#[cfg(any(test, feature = "test-util"))]` at the `lib.rs` declaration
///    and so are not production either.
///
/// Returned paths are relative to `dir` and sorted, so a failure names the
/// file. Pure and directory-taking so the scan can be proven red.
fn production_call_sites(dir: &std::path::Path, needle: &str) -> (Vec<String>, usize) {
    let mut named = Vec::new();
    let mut visited = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if path.is_dir() {
                if name != "testing" {
                    stack.push(path);
                }
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs")
                || name == "tests.rs"
                || name == "testing.rs"
            {
                continue;
            }
            visited += 1;
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let call = format!("{needle}(");
            let definition = format!("fn {needle}");
            let hit = text
                .lines()
                // The gate for an external test module. Matched on the
                // trimmed WHOLE line, never with `str::find` over the file:
                // this crate's doc comments quote `#[cfg(test)]` as prose,
                // and a substring cut would truncate `upgrade.rs` at its own
                // documentation.
                .take_while(|line| line.trim() != "#[cfg(test)]")
                .filter(|line| !line.trim_start().starts_with("//"))
                .any(|line| line.contains(&call) && !line.contains(&definition));
            if hit {
                named.push(
                    path.strip_prefix(dir)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    named.sort();
    (named, visited)
}

fn anchor_src() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// `antseal-cli`'s production sources, reached across the workspace because
/// that is the crate the seam was widened *for* and therefore the crate most
/// likely to reach for it by accident.
fn cli_src() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../antseal-cli/src")
}

/// **D99 R5's guard rail.** Neither half of the test seam is reachable from a
/// normal build of either crate that can name it.
///
/// # What this catches that the compiler does not
///
/// It is tempting to think the compiler already covers this — a production
/// call to `loopback_for_tests` from `antseal-cli/src` does fail
/// `cargo build`, because that build links the `["default"]` rlib where the
/// item does not exist. But cargo unifies features per invocation, so the
/// same call **compiles green under `cargo test`**, where `antseal-cli`'s dev
/// edge has already switched `test-util` on for the whole build unit
/// (measured, D99 §1.4). The failure mode is therefore: green for the
/// developer, green for CI's `test` job, red only in the job that builds the
/// product. This scan moves that verdict into the lane where somebody is
/// looking.
///
/// `upgrade_pending_with` has exactly one permitted production caller —
/// [`upgrade_pending`], which supplies A42's real resolver and is the whole
/// reason the seam is shaped as a parameter rather than a `cfg`. A second
/// file naming it is a production path that chose its own allowlist.
#[test]
fn the_test_seam_has_no_production_call_sites() {
    let (named, visited) = production_call_sites(&anchor_src(), "upgrade_pending_with");
    assert!(
        visited > 15,
        "the scan visited only {visited} anchor sources — it is not looking where it thinks"
    );
    assert_eq!(
        named,
        vec!["ots/engine.rs".to_owned()],
        "`upgrade_pending_with` takes A42's allowlist step as a PARAMETER. Its one production \
         caller is `upgrade_pending`, which passes `UpgradeTarget::from_pending_uri`; any other \
         production caller is a path that polls a URI read out of an attacker-writable stored \
         artifact with an allowlist of its own choosing (D99 R5, A42)"
    );

    for (label, dir) in [("antseal-anchor", anchor_src()), ("antseal-cli", cli_src())] {
        let (named, visited) = production_call_sites(&dir, "loopback_for_tests");
        assert!(
            visited > 15,
            "{label}: the scan visited only {visited} sources"
        );
        assert!(
            named.is_empty(),
            "{label}: `UpgradeTarget::loopback_for_tests` mints a target over an ARBITRARY base, \
             bypassing A42's https/bare-host/no-port allowlist entirely. It exists so a test can \
             reach a 127.0.0.1 stub and for no other reason; these production files call it: \
             {named:?}"
        );
    }

    // The CLI side of the engine seam, asserted separately so a failure says
    // which crate reached for it.
    let (named, _) = production_call_sites(&cli_src(), "upgrade_pending_with");
    assert!(
        named.is_empty(),
        "antseal-cli production code calls `upgrade_pending_with`. The CLI needs NO feature and \
         no seam: `upgrade_pending` is the production entry point (D99 R5). This compiles under \
         `cargo test` and breaks `cargo build`: {named:?}"
    );
}

/// **The scan proven red**, in all three directions it has to work in: it
/// must catch a planted call, ignore the definition it would otherwise report
/// as its own violation, and ignore a call that lives in a test module under
/// either of this workspace's two conventions.
#[test]
fn the_seam_scan_reports_a_planted_call_and_ignores_definitions_and_tests() {
    let dir = std::env::temp_dir().join(format!(
        "antseal-d99r5-scan-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(dir.join("nested")).expect("mk nested");
    std::fs::create_dir_all(dir.join("testing")).expect("mk testing");

    // The violation: a production file driving the seam with its own resolver.
    std::fs::write(
        dir.join("nested/hurried_hook.rs"),
        "fn hook() { let r = upgrade_pending_with(c, p, w, b, d, &mine); }\n",
    )
    .expect("write");
    // Clean: the definition site, plus a doc comment naming the call shape.
    // This is the case that forced the `fn`/comment filters — without them
    // `engine.rs` reports itself and the rule needs an exemption.
    std::fs::write(
        dir.join("clean_definition.rs"),
        "/// See `upgrade_pending_with(client, …)` for the seam.\n\
         pub fn upgrade_pending_with(c: u8) -> u8 { c }\n",
    )
    .expect("write");
    // Clean: an INLINE test module (the `nonce.rs` convention).
    std::fs::write(
        dir.join("clean_inline_tests.rs"),
        "fn prod() {}\n#[cfg(test)]\nmod tests {\n let r = upgrade_pending_with(a, b);\n}\n",
    )
    .expect("write");
    // Clean: an EXTERNAL test module (the `ots/engine.rs` convention). The
    // gate is in the parent file, so the scan can only tell by the filename.
    std::fs::write(
        dir.join("nested/tests.rs"),
        "let r = upgrade_pending_with(a, b);\n",
    )
    .expect("write");
    // Clean: the `test-util` module, which is not production either.
    std::fs::write(
        dir.join("testing/replay.rs"),
        "let t = UpgradeTarget::loopback_for_tests(&url);\n",
    )
    .expect("write");
    // Not Rust: never read at all.
    std::fs::write(dir.join("notes.md"), "upgrade_pending_with(\n").expect("write");

    let (named, visited) = production_call_sites(&dir, "upgrade_pending_with");
    assert_eq!(
        visited, 3,
        "three production .rs files: the .md, the tests.rs and the testing/ file are not among \
         them"
    );
    assert_eq!(
        named,
        vec!["nested/hurried_hook.rs".to_owned()],
        "the scan must catch the planted call, must not report the definition site, and must \
         leave both test-module conventions alone"
    );

    let (named, _) = production_call_sites(&dir, "loopback_for_tests");
    assert!(
        named.is_empty(),
        "the only `loopback_for_tests` here is inside `testing/`, which is not production: \
         {named:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
