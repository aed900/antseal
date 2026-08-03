//! A17's outcome tests.
//!
//! Two layers, deliberately:
//!
//! - **projection** tests drive [`project`] from constructed
//!   [`Agreement`]s, so all five outcomes — including the two a live pair
//!   almost never produces — are reachable without a socket;
//! - **stub** tests drive [`confirm_arbitrum_tx`] end to end against
//!   loopback servers replaying the **real committed receipts**, so the
//!   extraction is tested against bytes this project did not author.
//!
//! A must-agree primitive whose tests only ever feed it agreeing endpoints
//! has not been tested. Every test below that asserts `Agreed` has a sibling
//! that makes the same call disagree.

use super::*;
use crate::agree::EndpointPair;
use crate::arbitrum::endpoints::verify_rpcs;
use crate::http::{Endpoint, HttpClient, HttpPolicy, TlsPolicy};
use crate::testing::replay::{RpcBehaviour, fixtures, rpc};
use crate::testing::stub::{StubScript, StubServer};

const ARBONE_CHAIN_ID_HEX: &str = "0xa4b1";
const SEPOLIA_CHAIN_ID_HEX: &str = "0x66eee";

/// The transaction the committed arbitrum-one receipts are for.
const ARBONE_TX: [u8; 32] =
    hex32("06a5012dddc0365d81d93a9ceac5a0060f4a23650fb75ddd683fbc1fb805b0b3");
/// The transaction the committed Sepolia receipts are for.
const SEPOLIA_TX: [u8; 32] =
    hex32("deae7e5fc869ad1e3b27fe7f4a04ed3f12ac7f2b2e3302a43c38b9f84d96ab21");

const fn hex32(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    let mut out = [0u8; 32];
    let mut index = 0;
    while index < 32 {
        out[index] = nibble(bytes[index * 2]) * 16 + nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    out
}

const fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn facts(status: u8, block_number: u64, tail: u8) -> ReceiptFacts {
    let mut block_hash = [0x11; 32];
    block_hash[31] = tail;
    ReceiptFacts {
        status,
        block_number,
        block_hash,
    }
}

// ─── projection: all five outcomes ──────────────────────────────────────────

/// The five-outcome space, each arm reached and each distinct.
///
/// **This is the test the corrected Accept row exists for.** A17's `Do`
/// listed four; collapsing `Lagging` into `Disagreed` reports a healthy pair
/// as broken, and collapsing it into `Unavailable` hides a lying endpoint.
/// Asserted on the **variant**, so a shared "not corroborated" rendering
/// string would not rescue an implementation that merged them.
#[test]
fn all_five_outcomes_are_reachable_and_distinct() {
    let a = facts(1, 100, 0xaa);
    let b = facts(1, 101, 0xbb);

    assert_eq!(
        project(Agreement::Agreed(Some(a))),
        ArbitrumConfirmation::Agreed(a)
    );
    assert_eq!(
        project(Agreement::Agreed(None)),
        ArbitrumConfirmation::Absent
    );
    assert_eq!(
        project(Agreement::Disagreed {
            first: Some(a),
            second: Some(b)
        }),
        ArbitrumConfirmation::Disagreed {
            first: a,
            second: b
        }
    );
    assert_eq!(
        project(Agreement::Disagreed {
            first: Some(a),
            second: None
        }),
        ArbitrumConfirmation::Lagging {
            seen_by: 0,
            facts: a
        }
    );
    assert_eq!(
        project(Agreement::Disagreed {
            first: None,
            second: Some(b)
        }),
        ArbitrumConfirmation::Lagging {
            seen_by: 1,
            facts: b
        }
    );
    let failure = EndpointFailure::payload(&endpoint("http://127.0.0.1:9/"), "down");
    assert_eq!(
        project(Agreement::Unavailable {
            failures: vec![failure.clone()]
        })
        .failed(),
        1
    );
    assert_eq!(
        project(Agreement::Unavailable {
            failures: vec![failure.clone(), failure]
        })
        .failed(),
        2
    );
}

/// `Lagging` names **which** endpoint saw the transaction, and the two
/// directions are not the same value.
///
/// Without the index the overlay cannot say "corroborated by 1 of 2" and
/// name it, and a renderer would have to guess — which for a single endpoint
/// asserting a receipt nobody else can see is exactly the wrong place to
/// guess.
#[test]
fn lagging_names_the_endpoint_that_saw_it() {
    let a = facts(1, 100, 0xaa);
    let first = project(Agreement::Disagreed {
        first: Some(a),
        second: None,
    });
    let second = project(Agreement::Disagreed {
        first: None,
        second: Some(a),
    });
    assert_ne!(first, second);
    assert!(matches!(
        first,
        ArbitrumConfirmation::Lagging { seen_by: 0, .. }
    ));
    assert!(matches!(
        second,
        ArbitrumConfirmation::Lagging { seen_by: 1, .. }
    ));
}

/// Only agreement crosses into `antseal-core`, and agreed **absence** is
/// agreement.
///
/// A17's "type-level or test-enforced separation", from this side: the
/// projection is total and every non-agreed outcome maps to `None`, so a
/// disagreeing or unreachable pair cannot become receipt evidence at all —
/// let alone anchor evidence.
#[test]
fn only_agreement_reaches_core() {
    let a = facts(1, 100, 0xaa);
    let b = facts(0, 100, 0xaa);

    assert_eq!(
        ArbitrumConfirmation::Agreed(a).into_receipt_confirmation(),
        Some(ReceiptConfirmation::Agreed(a))
    );
    assert_eq!(
        ArbitrumConfirmation::Absent.into_receipt_confirmation(),
        Some(ReceiptConfirmation::NotOnChain)
    );
    for degraded in [
        ArbitrumConfirmation::Disagreed {
            first: a,
            second: b,
        },
        ArbitrumConfirmation::Lagging {
            seen_by: 0,
            facts: a,
        },
        ArbitrumConfirmation::Unavailable {
            failures: vec![EndpointFailure::payload(
                &endpoint("http://127.0.0.1:9/"),
                "down",
            )],
        },
    ] {
        assert_eq!(
            degraded.into_receipt_confirmation(),
            None,
            "{degraded:?} must not reach core"
        );
    }
}

/// Every field of the tuple is compared, with **zero** tolerance.
///
/// The `block_number`-equal / `block_hash`-differing row is the important
/// one: it is a reorg, and an implementation that compared only the block
/// number would render it as corroboration.
#[test]
fn a_difference_in_any_field_is_a_disagreement() {
    let base = facts(1, 100, 0xaa);
    for other in [
        // status differs
        facts(0, 100, 0xaa),
        // block number differs by one — no window, no tolerance
        facts(1, 101, 0xaa),
        // same height, different hash: a reorg
        facts(1, 100, 0xab),
    ] {
        assert_ne!(base, other);
        assert!(
            matches!(
                project(Agreement::Disagreed {
                    first: Some(base),
                    second: Some(other)
                }),
                ArbitrumConfirmation::Disagreed { .. }
            ),
            "{other:?}"
        );
    }
    // …and the anti-vacuity leg: identical facts agree.
    assert_eq!(
        project(Agreement::Agreed(Some(base))),
        ArbitrumConfirmation::Agreed(base)
    );
}

// ─── stubs: the real committed receipts ─────────────────────────────────────

fn endpoint(url: &str) -> Endpoint {
    Endpoint::parse(url, TlsPolicy::Optional).expect("test url")
}

fn client() -> HttpClient {
    let mut policy = HttpPolicy::verify();
    // Loopback stubs answer immediately; a short ladder keeps the down-endpoint
    // cases from costing seconds.
    policy.timeouts = crate::http::HttpTimeouts::within(2_000);
    HttpClient::new(policy)
}

fn pair(first: &StubServer, second: &StubServer) -> EndpointPair {
    EndpointPair::new(endpoint(&first.base_url()), endpoint(&second.base_url()))
        .expect("two loopback stubs are two ports, hence two origins")
}

/// D55 §7's `receipt_facts_ignore_unknown_and_extra_keys`, over the **two
/// real committed Sepolia responses** — one carrying `timeboosted`, the other
/// `blobGasUsed`, bodies differing by construction.
///
/// This is the test that catches an object-equality or byte-equality
/// implementation, and it cannot pass vacuously: the fixtures are known to
/// differ in bytes (`replay::tests::the_recorded_receipt_pairs_differ_in_bytes`).
#[test]
fn two_honest_endpoints_with_different_key_sets_agree() {
    let first = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: SEPOLIA_CHAIN_ID_HEX,
        receipt: fixtures::SEPOLIA_RECEIPT_ROLLUP.to_vec(),
    }));
    let second = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: SEPOLIA_CHAIN_ID_HEX,
        receipt: fixtures::SEPOLIA_RECEIPT_DRPC.to_vec(),
    }));

    let outcome = confirm_arbitrum_tx(
        &client(),
        &pair(&first, &second),
        NetworkId::ArbitrumSepolia,
        &SEPOLIA_TX,
    );
    match outcome {
        ArbitrumConfirmation::Agreed(facts) => {
            assert_eq!(facts.status, 1);
            assert_eq!(facts.block_number, 0x1189_85d8);
        }
        other => panic!("two honest endpoints must agree, got {other:?}"),
    }
}

/// The same, on arbitrum-one, where the key sets are identical and the
/// **envelope key order** differs — the second, independent reason a byte
/// comparator is wrong (2026-08-03 measurement).
#[test]
fn two_honest_endpoints_with_different_envelope_order_agree() {
    let first = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: fixtures::ARBONE_RECEIPT_ARB1.to_vec(),
    }));
    let second = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: fixtures::ARBONE_RECEIPT_DRPC.to_vec(),
    }));

    let outcome = confirm_arbitrum_tx(
        &client(),
        &pair(&first, &second),
        NetworkId::ArbitrumOne,
        &ARBONE_TX,
    );
    assert!(
        matches!(outcome, ArbitrumConfirmation::Agreed(_)),
        "{outcome:?}"
    );
}

/// D55 §7's `hex_case_and_leading_zero_variants_do_not_disagree`.
#[test]
fn hex_case_and_leading_zero_variants_do_not_disagree() {
    let canonical = receipt_json("0x1", "0x1d3de74b", &"86".repeat(32));
    let noisy = receipt_json("0x01", "0x1D3DE74B", &"86".repeat(32).to_uppercase());

    let first = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: canonical.into_bytes(),
    }));
    let second = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: noisy.into_bytes(),
    }));

    let outcome = confirm_arbitrum_tx(
        &client(),
        &pair(&first, &second),
        NetworkId::ArbitrumOne,
        &ARBONE_TX,
    );
    assert!(
        matches!(outcome, ArbitrumConfirmation::Agreed(_)),
        "textual variation must not disagree: {outcome:?}"
    );
}

/// D55 §7's `differing_block_hash_is_disagreed_with_both_values`.
///
/// Identical block **number**, differing block **hash** — a reorg. Both
/// values must be carried, or the overlay is choosing a winner.
#[test]
fn differing_block_hash_is_disagreed_with_both_values() {
    let a = receipt_json("0x1", "0x1d3de74b", &"86".repeat(32));
    let b = receipt_json("0x1", "0x1d3de74b", &"99".repeat(32));

    let first = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: a.into_bytes(),
    }));
    let second = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: b.into_bytes(),
    }));

    match confirm_arbitrum_tx(
        &client(),
        &pair(&first, &second),
        NetworkId::ArbitrumOne,
        &ARBONE_TX,
    ) {
        ArbitrumConfirmation::Disagreed { first, second } => {
            assert_eq!(first.block_number, second.block_number);
            assert_ne!(first.block_hash, second.block_hash);
            assert_eq!(first.block_hash[0], 0x86);
            assert_eq!(second.block_hash[0], 0x99);
        }
        other => panic!("a reorg must be Disagreed, got {other:?}"),
    }
}

/// D55 §7's `one_absent_is_lagging_not_disagreed`, end to end.
#[test]
fn one_absent_is_lagging_not_disagreed() {
    let seeing = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: fixtures::ARBONE_RECEIPT_ARB1.to_vec(),
    }));
    let lagging = StubServer::spawn(rpc(&RpcBehaviour::Absent {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
    }));

    match confirm_arbitrum_tx(
        &client(),
        &pair(&seeing, &lagging),
        NetworkId::ArbitrumOne,
        &ARBONE_TX,
    ) {
        ArbitrumConfirmation::Lagging { seen_by, .. } => assert_eq!(seen_by, 0),
        other => panic!("one null must be Lagging, got {other:?}"),
    }

    // The mirror image, so the index is real and not a constant.
    match confirm_arbitrum_tx(
        &client(),
        &pair(&lagging, &seeing),
        NetworkId::ArbitrumOne,
        &ARBONE_TX,
    ) {
        ArbitrumConfirmation::Lagging { seen_by, .. } => assert_eq!(seen_by, 1),
        other => panic!("one null must be Lagging, got {other:?}"),
    }
}

/// Both `null` is `Absent`, which is a *different* outcome from `Lagging`.
#[test]
fn both_absent_is_absent() {
    let first = StubServer::spawn(rpc(&RpcBehaviour::Absent {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
    }));
    let second = StubServer::spawn(rpc(&RpcBehaviour::Absent {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
    }));
    assert_eq!(
        confirm_arbitrum_tx(
            &client(),
            &pair(&first, &second),
            NetworkId::ArbitrumOne,
            &ARBONE_TX
        ),
        ArbitrumConfirmation::Absent
    );
}

/// D55 §7's `chain_id_mismatch_is_unavailable_not_agreed`.
///
/// The stub reporting the wrong chain id serves a **perfectly good receipt**
/// for the requested transaction, so the only thing that can produce
/// `Unavailable` is the guard. A stub that answered with an error there would
/// pass this test with the guard deleted.
#[test]
fn chain_id_mismatch_is_unavailable_not_agreed() {
    let honest = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: fixtures::ARBONE_RECEIPT_ARB1.to_vec(),
    }));
    let wrong = StubServer::spawn(rpc(&RpcBehaviour::WrongChain {
        chain_id_hex: SEPOLIA_CHAIN_ID_HEX,
    }));

    match confirm_arbitrum_tx(
        &client(),
        &pair(&honest, &wrong),
        NetworkId::ArbitrumOne,
        &ARBONE_TX,
    ) {
        ArbitrumConfirmation::Unavailable { failures } => {
            assert_eq!(failures.len(), 1);
            match &failures[0] {
                EndpointFailure::WrongChain {
                    expected, reported, ..
                } => {
                    assert_eq!(*expected, 42_161);
                    assert_eq!(*reported, 0x0006_6eee);
                }
                other => panic!("expected WrongChain, got {other:?}"),
            }
            assert!(
                failures[0].to_string().contains("expected 42161"),
                "the message must name both ids: {}",
                failures[0]
            );
        }
        other => panic!("a wrong-chain endpoint must not contribute: {other:?}"),
    }

    // Anti-vacuity: the same pair with both endpoints on the right chain
    // agrees, so the `Unavailable` above is the guard and not the stub.
    let honest_two = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: fixtures::ARBONE_RECEIPT_DRPC.to_vec(),
    }));
    assert!(matches!(
        confirm_arbitrum_tx(
            &client(),
            &pair(&honest, &honest_two),
            NetworkId::ArbitrumOne,
            &ARBONE_TX
        ),
        ArbitrumConfirmation::Agreed(_)
    ));
}

/// An endpoint that answers about a **different transaction** is refused, not
/// compared.
///
/// Not in A17's `Do`. Without it, an endpoint that substitutes a receipt for
/// another transaction produces `Disagreed` — which renders as "one of these
/// two might be lying" and puts the honest endpoint under equal suspicion —
/// or, if the other endpoint is down, could pair with a matching substitution
/// and agree.
#[test]
fn a_receipt_for_a_different_transaction_is_refused() {
    let honest = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: fixtures::ARBONE_RECEIPT_ARB1.to_vec(),
    }));
    // The Sepolia receipt is well-formed and internally consistent — it is
    // simply about another transaction.
    let substituting = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: fixtures::SEPOLIA_RECEIPT_ROLLUP.to_vec(),
    }));

    match confirm_arbitrum_tx(
        &client(),
        &pair(&honest, &substituting),
        NetworkId::ArbitrumOne,
        &ARBONE_TX,
    ) {
        ArbitrumConfirmation::Unavailable { failures } => {
            assert_eq!(failures.len(), 1);
            assert!(
                matches!(
                    &failures[0],
                    EndpointFailure::Payload { reason, .. }
                        if reason.contains("different transaction")
                ),
                "{:?}",
                failures[0]
            );
        }
        other => panic!("a substituted receipt must not be compared: {other:?}"),
    }
}

/// One endpoint down is `Unavailable`, and — the load-bearing half — the
/// surviving endpoint's receipt is **not** promoted to the result.
#[test]
fn one_endpoint_down_is_unavailable_and_never_promotes_the_survivor() {
    let up = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: fixtures::ARBONE_RECEIPT_ARB1.to_vec(),
    }));
    let down = StubServer::spawn(rpc(&RpcBehaviour::Down));

    let outcome = confirm_arbitrum_tx(
        &client(),
        &pair(&up, &down),
        NetworkId::ArbitrumOne,
        &ARBONE_TX,
    );
    assert_eq!(outcome.failed(), 1, "{outcome:?}");
    assert_eq!(outcome.into_receipt_confirmation(), None);
}

/// Both down is `Unavailable` with two failures, each naming its endpoint.
#[test]
fn both_endpoints_down_names_both() {
    let first = StubServer::spawn(rpc(&RpcBehaviour::Down));
    let second = StubServer::spawn(rpc(&RpcBehaviour::Down));
    let urls = [first.base_url(), second.base_url()];

    match confirm_arbitrum_tx(
        &client(),
        &pair(&first, &second),
        NetworkId::ArbitrumOne,
        &ARBONE_TX,
    ) {
        ArbitrumConfirmation::Unavailable { failures } => {
            assert_eq!(failures.len(), 2);
            for (failure, url) in failures.iter().zip(urls.iter()) {
                assert!(
                    failure.endpoint().starts_with(url.as_str()),
                    "{failure} must name {url}"
                );
            }
        }
        other => panic!("both down must be Unavailable, got {other:?}"),
    }
}

/// A JSON-RPC error member on a `200` is a failure, not a missing result.
///
/// The HTTP substrate cannot see it — the status is 2xx — so if it were not
/// classified here the `result` lookup would fail with "no result member",
/// which reads as a malformed endpoint rather than as one that declined.
#[test]
fn a_json_rpc_error_member_is_an_endpoint_failure() {
    let honest = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: fixtures::ARBONE_RECEIPT_ARB1.to_vec(),
    }));
    let erroring = StubServer::spawn(rpc(&RpcBehaviour::JsonRpcError {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
    }));

    match confirm_arbitrum_tx(
        &client(),
        &pair(&honest, &erroring),
        NetworkId::ArbitrumOne,
        &ARBONE_TX,
    ) {
        ArbitrumConfirmation::Unavailable { failures } => assert!(
            matches!(
                &failures[0],
                EndpointFailure::Payload { reason, .. } if reason.contains("JSON-RPC error")
            ),
            "{:?}",
            failures[0]
        ),
        other => panic!("a JSON-RPC error must be a failure, got {other:?}"),
    }
}

/// D55 §7's `response_over_cap_is_a_typed_error`: the size error, asserted on
/// the **variant**, so a truncating implementation fails rather than
/// producing a JSON parse error.
#[test]
fn a_response_over_the_cap_is_a_size_error_not_a_parse_error() {
    use crate::http::{AnchorHttpError, HttpMethod, HttpRequest, Idempotency};
    use crate::testing::stub::StubReply;

    let server =
        StubServer::spawn(StubScript::new().always(StubReply::body(200, vec![b'{'; 4096])));
    let target = endpoint(&server.base_url());
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#;
    let request = HttpRequest {
        endpoint: &target,
        method: HttpMethod::Post,
        content_type: Some("application/json"),
        accept: Some("application/json"),
        body,
        receive_cap_bytes: 1024,
        idempotency: Idempotency::SafeToRepeat,
    };
    let err = HttpClient::new(HttpPolicy::verify())
        .send(&request)
        .expect_err("4096 bytes exceeds a 1024-byte ceiling");
    assert!(
        matches!(err, AnchorHttpError::OversizeBody { .. }),
        "{err:?}"
    );
}

/// Devnet has no pair and no overlay, so `confirm_arbitrum_tx` is
/// unreachable there through the endpoint constants — and if a caller
/// constructs a pair anyway, the guard refuses rather than waving it through.
#[test]
fn devnet_has_no_overlay_and_the_guard_refuses_rather_than_defaults() {
    assert_eq!(verify_rpcs(NetworkId::Devnet), None);
    assert_eq!(expected_chain_id(NetworkId::Devnet), None);

    let first = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: fixtures::ARBONE_RECEIPT_ARB1.to_vec(),
    }));
    let second = StubServer::spawn(rpc(&RpcBehaviour::Receipt {
        chain_id_hex: ARBONE_CHAIN_ID_HEX,
        receipt: fixtures::ARBONE_RECEIPT_DRPC.to_vec(),
    }));
    let outcome = confirm_arbitrum_tx(
        &client(),
        &pair(&first, &second),
        NetworkId::Devnet,
        &ARBONE_TX,
    );
    assert_eq!(
        outcome.failed(),
        2,
        "no expected chain id must never mean any chain id: {outcome:?}"
    );
}

/// A synthetic receipt envelope with exactly the three compared fields plus
/// the echoed transaction hash.
fn receipt_json(status: &str, block_number: &str, block_hash_hex: &str) -> String {
    let tx = ARBONE_TX
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"status":"{status}","blockNumber":"{block_number}",
"blockHash":"0x{block_hash_hex}","transactionHash":"0x{tx}"}}}}"#
    )
}
