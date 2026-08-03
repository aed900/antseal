//! A16's esplora tests.
//!
//! Every endpoint here is a loopback stub replaying the **committed live
//! captures** (`testdata/anchors/A16-A17-live/`), so the parsing is tested
//! against bytes blockstream.info and mempool.space actually sent.
//!
//! The suite is written against the failure directions, not the happy path:
//! for every `Agreed` assertion there is a sibling that makes the same call
//! disagree, and the two 404 shapes are tested against **each other** rather
//! than each in isolation, because the hazard is that they are confused.

use super::*;
use crate::http::{HttpPolicy, HttpTimeouts, TlsPolicy};
use crate::testing::replay::{
    EsploraBehaviour, RECORDED_HEIGHT, esplora, fixtures, tampered_header,
};
use crate::testing::stub::StubServer;

fn client() -> HttpClient {
    let mut policy = HttpPolicy::verify();
    policy.timeouts = HttpTimeouts::within(2_000);
    HttpClient::new(policy)
}

fn endpoint(url: &str) -> Endpoint {
    Endpoint::parse(url, TlsPolicy::Optional).expect("loopback stub url")
}

fn pair(first: &StubServer, second: &StubServer) -> EndpointPair {
    EndpointPair::new(endpoint(&first.base_url()), endpoint(&second.base_url()))
        .expect("two loopback ports are two origins")
}

fn recorded_header_bytes() -> BlockHeader {
    let hex = core::str::from_utf8(fixtures::BLOCKSTREAM_HEADER).expect("ascii");
    let mut out = [0u8; BLOCK_HEADER_LEN as usize];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let high = (pair[0] as char).to_digit(16).expect("hex");
        let low = (pair[1] as char).to_digit(16).expect("hex");
        *byte = u8::try_from(high * 16 + low).expect("byte");
    }
    out
}

/// A16 Accept row: agreement passes, and the returned header is **exactly 80
/// bytes** and byte-identical to what both endpoints sent.
#[test]
fn two_endpoints_returning_the_recorded_header_agree() {
    let honest = EsploraBehaviour::Header(fixtures::BLOCKSTREAM_HEADER.to_vec());
    let first = StubServer::spawn(esplora(&honest));
    // Deliberately built from the *mempool* capture, which is a separately
    // recorded file: if the two live services had disagreed, this test would
    // be red rather than comparing one file to itself.
    let second = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::MEMPOOL_HEADER.to_vec(),
    )));

    match fetch_agreed_header(&client(), &pair(&first, &second), RECORDED_HEIGHT) {
        Agreement::Agreed(Some(header)) => {
            assert_eq!(header.len(), 80);
            assert_eq!(header, recorded_header_bytes());
        }
        other => panic!("two honest endpoints must agree: {other:?}"),
    }
}

/// A16 Accept row: **differing headers produce a distinct disagreement
/// outcome** — the one R's M3 endpoint-disagreement case consumes.
///
/// The tampered header is still 160 valid hex characters, so nothing but the
/// comparison can reject it. Both values are carried.
#[test]
fn a_differing_header_is_a_disagreement_carrying_both_values() {
    let first = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::BLOCKSTREAM_HEADER.to_vec(),
    )));
    let second = StubServer::spawn(esplora(&EsploraBehaviour::Header(tampered_header())));

    match fetch_agreed_header(&client(), &pair(&first, &second), RECORDED_HEIGHT) {
        Agreement::Disagreed { first, second } => {
            let (first, second) = (first.expect("present"), second.expect("present"));
            assert_ne!(first, second);
            assert_eq!(first, recorded_header_bytes());
            // A one-nibble edit: everything but the last byte matches, which
            // is what a tolerant comparison would let through.
            assert_eq!(first[..79], second[..79]);
        }
        other => panic!("a differing header must be Disagreed: {other:?}"),
    }
}

/// A16 Accept row: one endpoint down is the **unavailable** outcome, and the
/// surviving endpoint's header is not returned.
#[test]
fn one_endpoint_down_is_unavailable_and_the_survivor_is_not_the_answer() {
    let up = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::BLOCKSTREAM_HEADER.to_vec(),
    )));
    let down = StubServer::spawn(esplora(&EsploraBehaviour::Down));

    let outcome = fetch_agreed_header(&client(), &pair(&up, &down), RECORDED_HEIGHT);
    assert_eq!(outcome.failed(), 1, "{outcome:?}");
    assert_eq!(outcome.agreed(), None);
    assert_eq!(into_online_block_result(&outcome), None);
}

/// Agreed absence is evidence: both endpoints' `404 Block not found` becomes
/// `NoSuchBlock`, which D56 rule O7 uses to refute an `.ots` claiming a
/// height beyond the tip.
#[test]
fn an_agreed_404_block_not_found_is_no_such_block() {
    let first = StubServer::spawn(esplora(&EsploraBehaviour::NoSuchBlock));
    let second = StubServer::spawn(esplora(&EsploraBehaviour::NoSuchBlock));

    let outcome = fetch_agreed_header(&client(), &pair(&first, &second), RECORDED_HEIGHT);
    assert_eq!(outcome.agreed(), Some(&None));
    assert_eq!(
        into_online_block_result(&outcome),
        Some(OnlineBlockResult::NoSuchBlock)
    );
}

/// **The hole a bare status check leaves open.**
///
/// A mistyped base URL makes both real services answer `404 endpoint does not
/// exist "…"`. An implementation that mapped any 404 to `NoSuchBlock` would
/// therefore turn a typo into an *agreed absence*, which under D56 rule O7
/// refutes an honest `.ots` and renders the anchor `invalid` — a
/// downgrade-to-forgery-accusation primitive available to anyone who can edit
/// the endpoint list.
///
/// Both bodies are real captures, and the test asserts the two 404s produce
/// **different outcomes**, so it cannot pass by accident.
#[test]
fn a_wrong_path_404_is_a_failure_and_never_an_agreed_absence() {
    let first = StubServer::spawn(esplora(&EsploraBehaviour::WrongPath));
    let second = StubServer::spawn(esplora(&EsploraBehaviour::WrongPath));

    let outcome = fetch_agreed_header(&client(), &pair(&first, &second), RECORDED_HEIGHT);
    assert_eq!(outcome.failed(), 2, "{outcome:?}");
    assert_eq!(
        into_online_block_result(&outcome),
        None,
        "a mistyped endpoint must refute nothing"
    );

    // The anti-vacuity leg: the *other* 404 body, over the same code path,
    // does produce the agreed absence. Without this the test would pass
    // against an implementation that refused every 404.
    let ok_first = StubServer::spawn(esplora(&EsploraBehaviour::NoSuchBlock));
    let ok_second = StubServer::spawn(esplora(&EsploraBehaviour::NoSuchBlock));
    assert_eq!(
        into_online_block_result(&fetch_agreed_header(
            &client(),
            &pair(&ok_first, &ok_second),
            RECORDED_HEIGHT
        )),
        Some(OnlineBlockResult::NoSuchBlock)
    );
}

/// One endpoint sees a block the other does not. Reported as `Disagreed`, and
/// — the part that matters — it does **not** reach core, so neither the
/// header nor the absence becomes evidence.
#[test]
fn a_header_against_no_such_block_is_a_disagreement_that_reaches_nothing() {
    let seeing = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::BLOCKSTREAM_HEADER.to_vec(),
    )));
    let blind = StubServer::spawn(esplora(&EsploraBehaviour::NoSuchBlock));

    let outcome = fetch_agreed_header(&client(), &pair(&seeing, &blind), RECORDED_HEIGHT);
    assert!(
        matches!(outcome, Agreement::Disagreed { .. }),
        "{outcome:?}"
    );
    assert_eq!(into_online_block_result(&outcome), None);
}

/// The hash an endpoint returns is validated **before** it is interpolated
/// into the next request path.
///
/// The hostile stub answers the height query with a traversal string and then
/// serves a 200 on every path, so an implementation that used the string
/// unvalidated would fetch the endpoint's chosen path and report a payload
/// error about the *header* rather than about the hash. The assertion is on
/// the reason string, which names which check fired.
#[test]
fn an_endpoint_cannot_steer_the_second_request_with_its_hash_reply() {
    for hostile in [
        "../../../../etc/passwd",
        "0000000000000000000000000000000000000000000000000000000000000000/../../evil",
        // Uppercase: real esplora returns lowercase, and accepting mixed case
        // here would widen what can be spliced into a path.
        "00000000000000000002A7C4C1E48D76C5A37902165A270156B7A8D72728A054",
        // Right shape, wrong length.
        "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a05",
        "",
    ] {
        let first = StubServer::spawn(esplora(&EsploraBehaviour::HostileHash(hostile)));
        let second = StubServer::spawn(esplora(&EsploraBehaviour::Header(
            fixtures::BLOCKSTREAM_HEADER.to_vec(),
        )));

        match fetch_agreed_header(&client(), &pair(&first, &second), RECORDED_HEIGHT) {
            Agreement::Unavailable { failures } => {
                assert_eq!(failures.len(), 1, "{hostile:?}");
                assert!(
                    matches!(
                        &failures[0],
                        EndpointFailure::Payload { reason, .. }
                            if reason.contains("block hash")
                    ),
                    "{hostile:?}: {:?}",
                    failures[0]
                );
            }
            other => panic!("{hostile:?} must be refused at the hash step: {other:?}"),
        }
    }
}

/// A header reply of the wrong length is a payload failure, named as such.
#[test]
fn a_header_that_is_not_160_hex_characters_is_a_payload_failure() {
    let broken = StubServer::spawn(esplora(&EsploraBehaviour::ShortHeader));
    let honest = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::BLOCKSTREAM_HEADER.to_vec(),
    )));

    match fetch_agreed_header(&client(), &pair(&broken, &honest), RECORDED_HEIGHT) {
        Agreement::Unavailable { failures } => assert!(
            matches!(
                &failures[0],
                EndpointFailure::Payload { reason, .. } if reason.contains("160 hex")
            ),
            "{:?}",
            failures[0]
        ),
        other => panic!("a short header must be a payload failure: {other:?}"),
    }
}

/// Each endpoint resolves height → hash → header **on its own**: two round
/// trips per endpoint, four in total, and neither endpoint is ever sent the
/// other's hash.
///
/// Asserted on the recorded request bytes. An implementation that resolved
/// the hash once and asked both endpoints for that header would show three
/// requests, and its `Agreed` would be an echo rather than corroboration.
#[test]
fn each_endpoint_resolves_the_height_itself() {
    let first = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::BLOCKSTREAM_HEADER.to_vec(),
    )));
    let second = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::MEMPOOL_HEADER.to_vec(),
    )));

    let outcome = fetch_agreed_header(&client(), &pair(&first, &second), RECORDED_HEIGHT);
    assert!(matches!(outcome, Agreement::Agreed(Some(_))), "{outcome:?}");

    for server in [&first, &second] {
        let requests = server.requests();
        assert_eq!(requests.len(), 2, "each endpoint answers two questions");
        let targets: Vec<String> = requests
            .iter()
            .map(|bytes| {
                String::from_utf8_lossy(bytes)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_owned()
            })
            .collect();
        assert!(
            targets[0].contains(&format!("/block-height/{RECORDED_HEIGHT}")),
            "{targets:?}"
        );
        assert!(targets[1].contains("/header"), "{targets:?}");
    }
}

/// The defaults are the two the capture log confirmed, both https, and they
/// pair — i.e. they are two origins.
#[test]
fn the_default_pair_is_two_https_origins() {
    assert_eq!(
        DEFAULT_ESPLORA_ENDPOINTS,
        ["https://blockstream.info/api", "https://mempool.space/api"]
    );
    let first = Endpoint::parse(
        DEFAULT_ESPLORA_ENDPOINTS[0],
        TlsPolicy::RequiredExceptLoopback,
    )
    .expect("https");
    let second = Endpoint::parse(
        DEFAULT_ESPLORA_ENDPOINTS[1],
        TlsPolicy::RequiredExceptLoopback,
    )
    .expect("https");
    assert!(first.is_https() && second.is_https());
    EndpointPair::new(first, second).expect("two distinct origins");
}

/// A base URL written with a trailing slash produces one separator, not two.
///
/// `//block-height/800000` is a different path on a real esplora and would
/// 404 — an override that is *correct* would be rejected as a dead endpoint.
#[test]
fn a_trailing_slash_on_the_base_url_does_not_double_the_separator() {
    let server = StubServer::spawn(esplora(&EsploraBehaviour::Header(
        fixtures::BLOCKSTREAM_HEADER.to_vec(),
    )));
    let with_slash = endpoint(&format!("{}/", server.base_url()));
    let derived = join(&with_slash, "block-height/800000");
    assert!(!derived.contains("//block-height"), "{derived}");
    assert!(derived.ends_with("/block-height/800000"), "{derived}");
}
