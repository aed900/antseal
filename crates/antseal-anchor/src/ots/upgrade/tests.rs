//! A14's Accept rows, and the three-way discriminator against the real bodies.

use antseal_core::anchor::ots::{OtsAttestation, parse_ots};

use super::*;
use crate::esplora::DEFAULT_ESPLORA_ENDPOINTS;
use crate::http::HttpPolicy;
use crate::testing::replay::{
    CalendarBehaviour, EsploraBehaviour, calendar, esplora, fixtures, tampered_header,
};
use crate::testing::stub::StubServer;

fn client() -> HttpClient {
    HttpClient::new(HttpPolicy::opportunistic())
}

fn target(server: &StubServer) -> UpgradeTarget {
    UpgradeTarget::loopback_for_tests(&server.base_url())
}

fn commitment_for(uri: &str) -> Vec<u8> {
    pending_refs(fixtures::MERGED_A, &fixtures::DIGEST_A)
        .expect("the committed merge parses")
        .into_iter()
        .find(|reference| reference.uri == uri)
        .expect("a pending attestation for this calendar")
        .commitment
}

fn esplora_pair(first: &StubServer, second: &StubServer) -> EndpointPair {
    EndpointPair::new(
        Endpoint::parse(&first.base_url(), TlsPolicy::RequiredExceptLoopback).expect("first"),
        Endpoint::parse(&second.base_url(), TlsPolicy::RequiredExceptLoopback).expect("second"),
    )
    .expect("two distinct loopback origins")
}

// ── the three-way discriminator ──────────────────────────────────────────

/// D58 §7.4's table, executed. All three rows share a status code in two
/// cases, so a status-code client cannot produce these three answers.
#[test]
fn the_upgrade_discriminator_is_three_way_and_body_separated() {
    let commitment = commitment_for("https://alice.btc.calendar.opentimestamps.org");

    let upgraded = StubServer::spawn(calendar(&CalendarBehaviour::Upgraded {
        pending: fixtures::CALENDAR_ALICE_A.to_vec(),
        upgrade: fixtures::UPGRADE_A_ALICE.to_vec(),
    }));
    assert_eq!(
        poll_upgrade(&client(), &target(&upgraded), &commitment),
        UpgradePoll::Upgraded(fixtures::UPGRADE_A_ALICE.to_vec())
    );

    let not_ready = StubServer::spawn(calendar(&CalendarBehaviour::PendingSubmit(Vec::new())));
    assert_eq!(
        poll_upgrade(&client(), &target(&not_ready), &commitment),
        UpgradePoll::NotYetConfirmed
    );

    let unknown = StubServer::spawn(calendar(&CalendarBehaviour::NotFound));
    assert_eq!(
        poll_upgrade(&client(), &target(&unknown), &commitment),
        UpgradePoll::NotFound
    );

    // The two 404s are indistinguishable by status: assert that directly, so
    // the point of the test survives a future reader.
    assert_eq!(
        classify_404(fixtures::CALENDAR_PENDING_BODY),
        Some(UpgradePoll::NotYetConfirmed)
    );
    assert_eq!(
        classify_404(fixtures::CALENDAR_NOT_FOUND),
        Some(UpgradePoll::NotFound)
    );
}

/// The classifier compares trimmed content, never length and never a
/// byte-exact literal — D90's caution, measured: the same body arrives at 9
/// and 10 bytes from different calendars, one with a trailing newline.
#[test]
fn the_classifier_is_immune_to_trailing_whitespace_and_case() {
    for body in [
        b"Not found".as_slice(),
        b"Not found\n",
        b"Not found\r\n",
        b"  not found  ",
        b"NOT FOUND",
    ] {
        assert_eq!(
            classify_404(body),
            Some(UpgradePoll::NotFound),
            "{:?} must classify as the hard error",
            String::from_utf8_lossy(body)
        );
    }
    for body in [
        fixtures::CALENDAR_PENDING_BODY,
        b"Pending confirmation in Bitcoin blockchain\n",
        b"pending confirmation in bitcoin blockchain",
    ] {
        assert_eq!(classify_404(body), Some(UpgradePoll::NotYetConfirmed));
    }
}

/// A 404 that says neither thing is neither thing.
///
/// This is A16's lesson in a second place: a 404 is only meaningful when its
/// body says so. Mapping an unrecognised 404 onto `NotFound` would let a
/// mistyped base URL — which 404s on every path — declare an honest anchor
/// permanently dead.
#[test]
fn an_unrecognised_404_is_a_failure_and_not_either_discriminator() {
    assert_eq!(classify_404(b"endpoint does not exist \"/timestamp/aa\""), None);
    assert_eq!(classify_404(b""), None);
    assert_eq!(classify_404(&[0xff, 0xfe]), None);

    let typo = StubServer::spawn(calendar(&CalendarBehaviour::UnknownFourOhFour(
        r#"endpoint does not exist "/timestamp/00""#,
    )));
    let poll = poll_upgrade(&client(), &target(&typo), &[0x01, 0x02]);
    assert!(
        matches!(poll, UpgradePoll::Failed(_)),
        "an unrecognised 404 must be a failure, got {poll:?}"
    );
    assert!(poll.is_repollable(), "and it must stay re-pollable");
}

/// The third behaviour the live capture found: catallaxy answered **nothing**
/// to a corrupted-commitment poll (`http=000`) where alice and bob answered
/// `404 Not found`.
///
/// A transport failure must never be promoted to the hard error, or one flaky
/// endpoint permanently condemns an honest anchor.
#[test]
fn no_answer_at_all_is_a_failure_and_never_the_hard_error() {
    let silent = StubServer::spawn(calendar(&CalendarBehaviour::Down));
    let poll = poll_upgrade(&client(), &target(&silent), &[0x01, 0x02]);

    assert_ne!(poll, UpgradePoll::NotFound);
    assert!(matches!(poll, UpgradePoll::Failed(_)), "got {poll:?}");
    assert!(poll.is_repollable());
}

/// A `200` with an empty body is not an upgrade. Merging it would splice zero
/// bytes, re-validate happily, and record a transition that did not happen.
#[test]
fn an_empty_two_hundred_is_not_an_upgrade() {
    let empty = StubServer::spawn(calendar(&CalendarBehaviour::Upgraded {
        pending: Vec::new(),
        upgrade: Vec::new(),
    }));
    assert_eq!(
        poll_upgrade(&client(), &target(&empty), &[0x01]),
        UpgradePoll::Empty
    );
}

/// The commitment is hex-encoded, lowercase, into D54's path.
#[test]
fn the_poll_url_is_the_ruled_path_with_a_lowercase_hex_commitment() {
    let server = StubServer::spawn(calendar(&CalendarBehaviour::NotFound));
    let commitment = [0x6a, 0x6f, 0x98, 0x0f, 0xab];
    let _ = poll_upgrade(&client(), &target(&server), &commitment);

    let request = server.requests().pop().expect("one request");
    let line = crate::testing::replay::request_line(&request);
    assert!(line.contains("/timestamp/6a6f980fab"), "{line}");
    assert!(line.starts_with("GET "), "{line}");
}

/// A42's allowlist is not bypassable through the production constructor, and
/// the refusal happens **before** any socket is opened.
#[test]
fn a_disallowed_upgrade_uri_is_refused_before_any_request() {
    assert_eq!(
        UpgradeTarget::from_pending_uri("https://attacker.example", &[]),
        Err(UpgradeUriRefusal::HostNotAllowed)
    );
    assert_eq!(
        UpgradeTarget::from_pending_uri("http://btc.calendar.catallaxy.com", &[]),
        Err(UpgradeUriRefusal::NotHttps)
    );
    // Every real pending URI in the committed artifact is admitted.
    for reference in pending_refs(fixtures::MERGED_A, &fixtures::DIGEST_A).expect("parses") {
        assert!(
            UpgradeTarget::from_pending_uri(&reference.uri, &[]).is_ok(),
            "{} must be admitted",
            reference.uri
        );
    }
}

// ── merging ──────────────────────────────────────────────────────────────

/// A14 Accept row 1: a recorded real upgrade merges, and the result evaluates
/// `attested` with an embedded header through A12's own predicate.
#[test]
fn a_real_upgrade_merges_and_the_result_commits_a_real_header() {
    let uri = "https://alice.btc.calendar.opentimestamps.org";
    let references = pending_refs(fixtures::MERGED_A, &fixtures::DIGEST_A).expect("parses");
    let target = references
        .iter()
        .find(|reference| reference.uri == uri)
        .expect("alice");

    let merged = merge_upgrade(
        fixtures::MERGED_A,
        &fixtures::DIGEST_A,
        target,
        fixtures::UPGRADE_A_ALICE,
    )
    .expect("a real upgrade merges");

    // 664 + 1 separator + 1000 upgrade bytes.
    assert_eq!(merged.artifact.len(), 664 + 1 + 1_000);
    assert_eq!(merged.added.len(), 1);

    let parsed = parse_ots(&merged.artifact, &fixtures::DIGEST_A).expect("A11-clean");
    // Every pending attestation survives — A14's "retain other calendars'
    // pending attestations until they upgrade".
    let pending_count = parsed
        .attestations
        .iter()
        .filter(|a| matches!(a, OtsAttestation::Pending { .. }))
        .count();
    assert_eq!(pending_count, 3);
    let bitcoin: Vec<&OtsAttestation> = parsed
        .attestations
        .iter()
        .filter(|a| matches!(a, OtsAttestation::Bitcoin { .. }))
        .collect();
    assert_eq!(bitcoin.len(), 1);

    // A12's own predicate, against the header the attestation derives — which
    // is the same function the offline verifier will run.
    let OtsAttestation::Bitcoin { height, merkle_root } = bitcoin[0] else {
        unreachable!("filtered above")
    };
    let root = merkle_root.as_ref().expect("a determinate merkle root");
    assert_eq!(root.len(), 32);
    let mut header = [0_u8; 80];
    header[36..68].copy_from_slice(root);
    let upgrade = antseal_core::bundle::schema::OtsUpgrade::new(*height, header, 1_754_211_818);
    assert!(antseal_core::anchor::ots::header_commits(
        bitcoin[0], &upgrade
    ));
}

/// All three real calendars merge into one artifact, and the pending
/// attestations that have not upgraded are still there at every step.
#[test]
fn three_upgrades_accumulate_into_one_artifact() {
    let mut artifact = fixtures::MERGED_A.to_vec();
    let bodies = [
        (
            "https://alice.btc.calendar.opentimestamps.org",
            fixtures::UPGRADE_A_ALICE,
        ),
        (
            "https://bob.btc.calendar.opentimestamps.org",
            fixtures::UPGRADE_A_BOB,
        ),
        (
            "https://btc.calendar.catallaxy.com",
            fixtures::UPGRADE_A_CATALLAXY,
        ),
    ];

    for (index, (uri, body)) in bodies.iter().enumerate() {
        let references = pending_refs(&artifact, &fixtures::DIGEST_A).expect("parses");
        let target = references
            .iter()
            .find(|reference| reference.uri == *uri)
            .expect("still pending");
        let merged =
            merge_upgrade(&artifact, &fixtures::DIGEST_A, target, body).expect("merges");
        artifact = merged.artifact;

        // A14 Accept row 3: partially upgraded is representable and
        // re-pollable at every intermediate step.
        let parsed = parse_ots(&artifact, &fixtures::DIGEST_A).expect("A11-clean");
        assert_eq!(
            parsed
                .attestations
                .iter()
                .filter(|a| matches!(a, OtsAttestation::Bitcoin { .. }))
                .count(),
            index + 1
        );
        assert_eq!(
            parsed
                .attestations
                .iter()
                .filter(|a| matches!(a, OtsAttestation::Pending { .. }))
                .count(),
            3,
            "pending attestations are retained, not replaced"
        );
    }
    assert_eq!(artifact.len(), 664 + 3 + 1_000 + 1_036 + 1_105);
}

/// An upgrade body spliced against the **wrong** pending attestation cannot
/// pass: the ops execute from a different commitment, so nothing derives.
#[test]
fn an_upgrade_merged_at_the_wrong_attestation_is_refused() {
    let references = pending_refs(fixtures::MERGED_A, &fixtures::DIGEST_A).expect("parses");
    let bob = references
        .iter()
        .find(|reference| reference.uri.contains("bob"))
        .expect("bob");

    // alice's upgrade body against bob's attestation.
    let error = merge_upgrade(
        fixtures::MERGED_A,
        &fixtures::DIGEST_A,
        bob,
        fixtures::UPGRADE_A_ALICE,
    )
    .expect_err("a mismatched upgrade must not merge");
    assert_eq!(error, MergeError::NoBitcoinAttestation);
}

/// A body that is not a timestamp at all is refused by the re-validation, and
/// the stored bytes are untouched.
#[test]
fn a_corrupt_upgrade_body_is_refused_and_nothing_is_mutated() {
    let stored = fixtures::MERGED_A.to_vec();
    let references = pending_refs(&stored, &fixtures::DIGEST_A).expect("parses");

    for junk in [
        vec![0xde, 0xad, 0xbe, 0xef],
        vec![0xff],
        vec![0x00],
        fixtures::UPGRADE_A_ALICE[..40].to_vec(),
    ] {
        let error = merge_upgrade(&stored, &fixtures::DIGEST_A, &references[0], &junk)
            .expect_err("junk must not merge");
        assert!(
            matches!(
                error,
                MergeError::MergedUnparseable(_) | MergeError::NoBitcoinAttestation
            ),
            "got {error:?}"
        );
    }
    assert_eq!(stored, fixtures::MERGED_A, "the input is never mutated");
}

/// A stored artifact that does not parse is refused before anything else
/// happens.
#[test]
fn an_unparseable_stored_artifact_is_refused() {
    let reference = PendingRef {
        uri: "https://alice.btc.calendar.opentimestamps.org".to_owned(),
        commitment: vec![0x01],
        occurrence: 0,
        siblings: 1,
    };
    assert!(matches!(
        merge_upgrade(b"not an ots file", &fixtures::DIGEST_A, &reference, &[0x08]),
        Err(MergeError::StoredUnparseable(_))
    ));
    // …and so is a well-formed artifact under the wrong digest.
    assert!(matches!(
        merge_upgrade(fixtures::MERGED_A, &fixtures::DIGEST_B, &reference, &[0x08]),
        Err(MergeError::StoredUnparseable(_))
    ));
}

// ── the header embed ─────────────────────────────────────────────────────

fn bitcoin_attestation_at(height: u64, root: [u8; 32]) -> OtsAttestation {
    OtsAttestation::Bitcoin {
        height,
        merkle_root: Some(root.to_vec()),
    }
}

/// The recorded 800000 header, and the attestation that commits it.
fn recorded_header() -> [u8; 80] {
    let hex = core::str::from_utf8(fixtures::BLOCKSTREAM_HEADER).expect("ascii");
    let mut header = [0_u8; 80];
    for (byte, pair) in header.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(core::str::from_utf8(pair).expect("ascii"), 16).expect("hex");
    }
    header
}

/// The header is fetched through the must-agree pair and checked against the
/// ops-derived root before anything is recorded.
#[test]
fn an_agreeing_pair_whose_header_commits_the_attestation_is_accepted() {
    let header = recorded_header();
    let mut root = [0_u8; 32];
    root.copy_from_slice(&header[36..68]);

    let first = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::BLOCKSTREAM_HEADER.to_vec(),
    )));
    let second = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::MEMPOOL_HEADER.to_vec(),
    )));

    let upgrade = confirm_header(
        &client(),
        &esplora_pair(&first, &second),
        &bitcoin_attestation_at(crate::testing::replay::RECORDED_HEIGHT, root),
        1_754_211_818,
    )
    .expect("an agreeing, committing pair");

    assert_eq!(upgrade.block_height(), crate::testing::replay::RECORDED_HEIGHT);
    assert_eq!(upgrade.block_header(), &header);
    assert_eq!(upgrade.fetch_date(), 1_754_211_818);
}

/// A14 Accept row 2: an injected wrong header is rejected **before**
/// recording, and never persisted.
///
/// The two directions are different failures and both must be refused: a
/// header that does not commit the attestation, and a pair that cannot agree
/// on a header at all.
#[test]
fn a_wrong_header_is_rejected_before_recording() {
    let first = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::BLOCKSTREAM_HEADER.to_vec(),
    )));
    let second = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::MEMPOOL_HEADER.to_vec(),
    )));
    let pair = esplora_pair(&first, &second);

    // The endpoints agree perfectly; the attestation commits something else.
    let error = confirm_header(
        &client(),
        &pair,
        &bitcoin_attestation_at(crate::testing::replay::RECORDED_HEIGHT, [0x5a; 32]),
        0,
    )
    .expect_err("a non-committing header must be refused");
    assert_eq!(
        error,
        HeaderError::HeaderDoesNotCommit {
            height: crate::testing::replay::RECORDED_HEIGHT
        }
    );
}

/// A disagreeing pair records nothing: one endpoint's answer is not evidence.
#[test]
fn a_disagreeing_pair_records_nothing() {
    let honest = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::BLOCKSTREAM_HEADER.to_vec(),
    )));
    let liar = StubServer::spawn(esplora(&EsploraBehaviour::Header(tampered_header())));

    let header = recorded_header();
    let mut root = [0_u8; 32];
    root.copy_from_slice(&header[36..68]);

    let error = confirm_header(
        &client(),
        &esplora_pair(&honest, &liar),
        &bitcoin_attestation_at(crate::testing::replay::RECORDED_HEIGHT, root),
        0,
    )
    .expect_err("a disagreeing pair must record nothing");
    assert_eq!(
        error,
        HeaderError::NotAgreed {
            height: crate::testing::replay::RECORDED_HEIGHT
        }
    );
}

/// An unreachable pair is advisory, not alarming — and still records nothing.
#[test]
fn an_unreachable_pair_records_nothing() {
    let down = StubServer::spawn(esplora(&EsploraBehaviour::Down));
    let other = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::BLOCKSTREAM_HEADER.to_vec(),
    )));
    assert!(matches!(
        confirm_header(
            &client(),
            &esplora_pair(&down, &other),
            &bitcoin_attestation_at(crate::testing::replay::RECORDED_HEIGHT, [0; 32]),
            0,
        ),
        Err(HeaderError::NotAgreed { .. })
    ));
}

/// An agreed *absence* is not a header. Both endpoints saying "no block at
/// this height" about an attestation that claims one is a refusal, not a
/// silent skip.
#[test]
fn an_agreed_absence_is_refused() {
    let first = StubServer::spawn(esplora(&EsploraBehaviour::NoSuchBlock));
    let second = StubServer::spawn(esplora(&EsploraBehaviour::NoSuchBlock));
    assert!(matches!(
        confirm_header(
            &client(),
            &esplora_pair(&first, &second),
            &bitcoin_attestation_at(crate::testing::replay::RECORDED_HEIGHT, [0; 32]),
            0,
        ),
        Err(HeaderError::NoSuchBlock { .. })
    ));
}

/// The default esplora pair is the ruled one, and it pairs.
#[test]
fn the_default_esplora_pair_is_usable_for_the_upgrade_time_fetch() {
    let pair = EndpointPair::new(
        Endpoint::parse(DEFAULT_ESPLORA_ENDPOINTS[0], TlsPolicy::RequiredExceptLoopback)
            .expect("first"),
        Endpoint::parse(DEFAULT_ESPLORA_ENDPOINTS[1], TlsPolicy::RequiredExceptLoopback)
            .expect("second"),
    );
    assert!(pair.is_ok(), "the two defaults are distinct origins");
}
