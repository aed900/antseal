//! `probe_online`'s probe set is `ProbePlan`'s — measured on the wire.
//!
//! D132 §3 R9.2 asks for a row that keeps a later edit from re-forking the two
//! probe sets, and §7.4 says why it has to be **this** row rather than a
//! parity gate: after D132 both surfaces derive their set from
//! [`ProbePlan::from_bundle`], so a defect in that function is a defect in
//! *both* and is invisible to a gate that compares their renderings.
//!
//! So these do not restate the derivation and compare it with itself. They run
//! the **production collector** against stub endpoints bound to `127.0.0.1:0`
//! — Q16's no-real-endpoints policy satisfied by construction — and read the
//! request targets and bodies those endpoints actually received. If
//! `ProbePlan::from_bundle` changed what it names, the requests would change,
//! and these rows would go red for that reason.
//!
//! # Why the fixture is red-capable rather than merely populated
//!
//! Every `.ots` artifact here is an opaque placeholder, so **every anchor
//! verifies offline-invalid**. The overlay's `attested` set is therefore
//! *empty* for these bundles while the ruled (wide) set has two heights in it
//! — which means these rows separate the wide set from the narrow one by two
//! requests versus none, not by a subtlety. D132 §1 (c) is the measurement
//! that says the wide set is the safe one; this is the row that would notice
//! if someone "fixed" it to the narrow one.

use antseal_anchor::TlsPolicy;
use antseal_anchor::agree::EndpointPair;
use antseal_anchor::arbitrum::expected_chain_id;
use antseal_anchor::http::{Endpoint, HttpClient, HttpPolicy};
use antseal_anchor::testing::stub::{StubMatch, StubReply, StubScript, StubServer};
use antseal_core::bundle::{
    AnchorStatus, BundleV1, OpaqueBytes, OtsAnchor, OtsUpgrade, encode_bundle,
};
use antseal_core::test_util::bundle_fixtures::{
    FIXTURE_BLOCK_HEADER, FIXTURE_BLOCK_HEIGHT, Selection, build, shapes,
};
use antseal_core::verify::plan::ProbePlan;
use antseal_net::NetworkId;

use super::{OnlineEndpoints, probe_online};

/// The heights the synthetic bundle's anchors record — **unsorted, with one
/// repeated**, so ordering and deduplication are inputs and not accidents.
const RECORDED: [u64; 3] = [900_002, 900_001, 900_001];
/// What the plan must make of them, and therefore what may reach the wire.
const EXPECTED: [u64; 2] = [900_001, 900_002];
/// A height no anchor records. Nothing may ask about it.
const UNPLANNED: u64 = 900_003;

/// The fetch date the synthetic upgrade groups record. Never read by the plan
/// — it is here because D79's group is all three fields or none.
const FETCH_DATE: u64 = 1_767_225_600;

/// A bundle whose OTS anchors carry exactly `heights`, in the order given.
fn bundle_with_ots_heights(heights: &[u64]) -> Vec<u8> {
    let built = build(&shapes::multi_file(), &Selection::all(3));
    let mut parts = BundleV1::decode(&built.bytes)
        .expect("the R6 fixture decodes to the model")
        .into_parts();
    parts.ots_anchors = heights
        .iter()
        .enumerate()
        .map(|(ordinal, height)| {
            OtsAnchor::new(
                AnchorStatus::Attested,
                OpaqueBytes::from_vec(format!("fixture .ots artifact {ordinal}").into_bytes()),
                Some(OtsUpgrade::new(*height, FIXTURE_BLOCK_HEADER, FETCH_DATE)),
            )
            .expect("a placeholder artifact is under the D10 caps")
        })
        .collect();
    encode_bundle(&BundleV1::new(parts).expect("a well-formed bundle"))
        .expect("the rebuilt bundle re-encodes")
}

/// A loopback endpoint. `RequiredExceptLoopback` is `verify`'s own policy, so
/// `http://127.0.0.1:…` is admissible here and nowhere else.
fn endpoint(base_url: &str) -> Endpoint {
    Endpoint::parse(base_url, TlsPolicy::RequiredExceptLoopback).expect("a loopback endpoint")
}

/// The pair the collector is pointed at.
fn pair(first: &StubServer, second: &StubServer) -> EndpointPair {
    EndpointPair::new(endpoint(&first.base_url()), endpoint(&second.base_url()))
        .expect("two distinct origins")
}

/// A stub that answers every esplora GET with A16's own not-found body, and
/// every JSON-RPC POST plausibly enough to reach the second call.
///
/// Answering rather than refusing matters: a transport failure and a
/// `no-such-block` are different classes (D66 §3 R2), and a row about *what
/// was asked* must not depend on which one it provoked.
fn stub() -> StubServer {
    let chain_id = format!(
        "0x{:x}",
        expected_chain_id(NetworkId::ArbitrumOne).expect("mainnet has an expected chain id")
    );
    StubServer::spawn(
        StubScript::new()
            .route(
                StubMatch::body("eth_chainId"),
                StubReply::body(
                    200,
                    format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{chain_id}"}}"#).into_bytes(),
                ),
            )
            .route(
                StubMatch::body("eth_getTransactionReceipt"),
                StubReply::body(200, br#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_vec()),
            )
            .unmatched(StubReply::body(404, b"Block not found".to_vec())),
    )
}

/// Every request as text, for the substring assertions below.
fn requests(server: &StubServer) -> Vec<String> {
    server
        .requests()
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .collect()
}

/// The distinct heights one endpoint was asked about, ascending.
///
/// A set rather than a list: the client may legitimately repeat a request it
/// declared safe to repeat, and the property under test is *which* heights
/// were asked about, not how many times.
fn asked_heights(server: &StubServer) -> Vec<u64> {
    let mut out: Vec<u64> = requests(server)
        .iter()
        .filter_map(|text| {
            let at = text.find("block-height/")? + "block-height/".len();
            let rest = &text[at..];
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            rest[..end].parse::<u64>().ok()
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The collector, over one bundle, against one endpoint pair.
fn run(
    bundle_bytes: &[u8],
    bitcoin: EndpointPair,
    arbitrum: Option<EndpointPair>,
) -> antseal_core::verify::orchestration::OnlineInputs {
    let bundle = BundleV1::decode(bundle_bytes).expect("the fixture decodes");
    let endpoints = OnlineEndpoints::new(bitcoin, arbitrum, false);
    let client = HttpClient::new(HttpPolicy::verify());
    probe_online(&client, &bundle, &endpoints, NetworkId::ArbitrumOne)
}

#[test]
fn the_collector_asks_about_exactly_the_plans_heights() {
    let bytes = bundle_with_ots_heights(&RECORDED);
    let plan = ProbePlan::from_bundle(&BundleV1::decode(&bytes).expect("the fixture decodes"));
    assert_eq!(
        plan.blocks,
        EXPECTED.to_vec(),
        "the plan is ascending and deduplicated before anything is fetched"
    );

    let first = stub();
    let second = stub();
    let inputs = run(&bytes, pair(&first, &second), None);

    // The wire. This is the row: if `from_bundle` named a different set, a
    // different set of requests would have gone out.
    for (label, server) in [("first", &first), ("second", &second)] {
        assert_eq!(
            asked_heights(server),
            plan.blocks,
            "the {label} endpoint was asked about a different set than the plan names; \
             requests were {:#?}",
            requests(server)
        );
    }

    // …and the probe log agrees, in both directions.
    for height in plan.blocks {
        assert!(
            inputs.probes().block(height).is_some(),
            "height {height} is in the plan and must be recorded"
        );
    }
    assert!(
        inputs.probes().block(UNPLANNED).is_none(),
        "a height no anchor records may not appear in the log"
    );
}

#[test]
fn a_bundle_with_no_upgraded_anchor_makes_no_esplora_request_at_all() {
    // The empty plan is not a special case anywhere: zero fetches, and the
    // run still produces inputs (D132 §5 R24 item 2 requires the overlay to
    // render over exactly this).
    let bytes = build(&shapes::multi_file_anchored(), &Selection::all(3)).bytes;
    let plan = ProbePlan::from_bundle(&BundleV1::decode(&bytes).expect("the fixture decodes"));
    assert!(plan.blocks.is_empty(), "a pending anchor has no upgrade");

    let first = stub();
    let second = stub();
    let _ = run(&bytes, pair(&first, &second), None);

    for server in [&first, &second] {
        assert!(
            requests(server).is_empty(),
            "an empty plan must invent no work: {:#?}",
            requests(server)
        );
    }
}

#[test]
fn the_collector_asks_about_the_plans_transaction_hash_and_only_when_there_is_one() {
    // The half D132 was actually about: the hash reaches the endpoint from the
    // plan, and the plan is what the page is handed. The F13 fixture and its
    // receipt-excluded twin are the two arms.
    let bytes = build(&shapes::multi_file_every_anchor_kind(), &Selection::all(3)).bytes;
    let plan = ProbePlan::from_bundle(&BundleV1::decode(&bytes).expect("the fixture decodes"));
    let target = plan
        .receipt
        .as_ref()
        .expect("the F13 shape carries a receipt");
    assert_eq!(
        plan.blocks,
        vec![FIXTURE_BLOCK_HEIGHT],
        "and its one upgraded anchor is planned too, invalid though it is"
    );

    let first = stub();
    let second = stub();
    let arbitrum = pair(&first, &second);
    let _ = run(&bytes, pair(&first, &second), Some(arbitrum));

    let asked_for = format!("0x{}", target.tx_hash);
    for (label, server) in [("first", &first), ("second", &second)] {
        assert!(
            requests(server)
                .iter()
                .any(|text| text.contains("eth_getTransactionReceipt") && text.contains(&asked_for)),
            "the {label} endpoint was not asked about the transaction the plan names \
             ({asked_for}); requests were {:#?}",
            requests(server)
        );
    }

    // The twin: same shape, receipt section absent, and nothing Arbitrum-ward
    // goes out beyond the chain-id guard the CLI performs regardless.
    let twin = build(
        &shapes::multi_file_every_anchor_kind_no_receipt(),
        &Selection::all(3),
    )
    .bytes;
    assert!(
        ProbePlan::from_bundle(&BundleV1::decode(&twin).expect("the twin decodes"))
            .receipt
            .is_none()
    );

    let third = stub();
    let fourth = stub();
    let arbitrum = pair(&third, &fourth);
    let _ = run(&twin, pair(&third, &fourth), Some(arbitrum));
    for server in [&third, &fourth] {
        assert!(
            !requests(server)
                .iter()
                .any(|text| text.contains("eth_getTransactionReceipt")),
            "a bundle with no receipt must produce no receipt probe: {:#?}",
            requests(server)
        );
    }
}

#[test]
fn a_planted_divergence_between_the_plan_and_the_wire_would_be_caught() {
    // Anti-vacuity for the rows above (this project's own discipline, and
    // D132 §7.4 asks for it by name): the comparator must be able to fail.
    // The two candidate derivations D132 weighed are exercised here as data —
    // the ruled (wide) set, and the overlay's narrow `attested` set, which for
    // this fixture is EMPTY because every placeholder artifact verifies
    // invalid. The wire matched the first; it must not match the second.
    let bytes = bundle_with_ots_heights(&RECORDED);
    let first = stub();
    let second = stub();
    let _ = run(&bytes, pair(&first, &second), None);

    let wire = asked_heights(&first);
    assert_eq!(wire, EXPECTED.to_vec(), "the ruled set reached the wire");

    let narrow: Vec<u64> = Vec::new();
    assert_ne!(
        wire, narrow,
        "if these compared equal the row above would pass for a collector that fetched nothing"
    );
    let undeduplicated = {
        let mut heights = RECORDED.to_vec();
        heights.sort_unstable();
        heights
    };
    assert_ne!(
        wire, undeduplicated,
        "and it would pass for one that asked the same height twice"
    );
}

// ─────────────────────────────────────────────────────────────────────
// U44 (D188 R6): the config's per-network Arbitrum pair
// ─────────────────────────────────────────────────────────────────────

/// The URLs of a resolved pair, in order.
fn urls(pair: &EndpointPair) -> Vec<String> {
    vec![
        pair.first().url().to_owned(),
        pair.second().url().to_owned(),
    ]
}

/// **D188 R6, at resolution.** `endpoints_from_config` reads only the run's
/// own network's pair: a sepolia-only override leaves an arbitrum-one run on
/// the pinned pair and undisclosed as overridden, gives a sepolia run the
/// override and the disclosure, and devnet no pair at all.
///
/// Nothing here is probed. In-process `antseal-cli` tests are not covered by
/// Q16's `cfg(test)` arm (that arm is compiled into `antseal-anchor`'s own
/// unit tests only), so probing the pinned pair would dial the real Arbitrum
/// endpoints; the assertion is on what was RESOLVED.
#[test]
fn endpoints_from_config_reads_only_the_effective_networks_pair() {
    let config = crate::config::parse(
        "[verify.arbitrum-sepolia]\n\
         rpc_endpoints = [\"https://sep-a.example\", \"https://sep-b.example\"]\n",
    )
    .expect("a sepolia-only override loads");
    let configured = vec![
        "https://sep-a.example".to_owned(),
        "https://sep-b.example".to_owned(),
    ];

    let one = super::endpoints_from_config(&config, NetworkId::ArbitrumOne)
        .expect("resolves")
        .expect("arbitrum-one has a Bitcoin pair");
    let pinned_one: Vec<String> =
        antseal_anchor::arbitrum::endpoints::verify_rpcs(NetworkId::ArbitrumOne)
            .expect("arbitrum-one has a pinned pair")
            .iter()
            .map(|url| (*url).to_owned())
            .collect();
    assert_eq!(
        urls(
            one.arbitrum
                .as_ref()
                .expect("arbitrum-one has an Arbitrum pair")
        ),
        pinned_one,
        "the other network's override leaked into an arbitrum-one run"
    );
    assert!(
        !one.overridden(),
        "an arbitrum-one run consulted no configured endpoint, so it is not overridden"
    );

    let sepolia = super::endpoints_from_config(&config, NetworkId::ArbitrumSepolia)
        .expect("resolves")
        .expect("arbitrum-sepolia has a Bitcoin pair");
    assert_eq!(
        urls(
            sepolia
                .arbitrum
                .as_ref()
                .expect("arbitrum-sepolia has an Arbitrum pair")
        ),
        configured,
        "the sepolia run did not get its configured pair"
    );
    assert!(sepolia.overridden(), "and it is disclosed as overridden");

    let devnet = super::endpoints_from_config(&config, NetworkId::Devnet)
        .expect("resolves")
        .expect("devnet has a Bitcoin pair");
    assert!(devnet.arbitrum.is_none(), "devnet has no Arbitrum pair");
    assert!(!devnet.overridden());

    // With no file at all, every network is on its pinned pair and nothing is
    // disclosed as overridden.
    let defaults = crate::config::Config::default();
    for network in [NetworkId::ArbitrumOne, NetworkId::ArbitrumSepolia] {
        let resolved = super::endpoints_from_config(&defaults, network)
            .expect("resolves")
            .expect("a Bitcoin pair");
        assert!(!resolved.overridden(), "{network}: nothing configured");
    }
}

/// **D188 R6, on the wire** (U52's defect class one surface over: a key that
/// parses and is ignored). A configured `[verify.arbitrum-one]` pair of
/// loopback stubs is what the receipt probe contacts: both stubs see the
/// chain-id guard and the receipt request.
///
/// The pre-flight runs BEFORE any request: every endpoint the run would
/// consult must be one of this test's stubs, so a broken resolution (one that
/// fell back to a pinned pair) fails here rather than dialing a real endpoint
/// — Q16's `cfg(test)` arm does not cover this crate's in-process tests.
#[test]
fn a_configured_pair_is_what_the_receipt_probe_contacts() {
    let btc_first = stub();
    let btc_second = stub();
    let rpc_first = stub();
    let rpc_second = stub();
    let config = crate::config::parse(&format!(
        "[verify]\nbitcoin_endpoints = [\"{}\", \"{}\"]\n\
         [verify.arbitrum-one]\nrpc_endpoints = [\"{}\", \"{}\"]\n",
        btc_first.base_url(),
        btc_second.base_url(),
        rpc_first.base_url(),
        rpc_second.base_url(),
    ))
    .expect("loopback stubs are admissible endpoints");

    let endpoints = super::endpoints_from_config(&config, NetworkId::ArbitrumOne)
        .expect("resolves")
        .expect("arbitrum-one has a Bitcoin pair");
    let stubs = [
        btc_first.base_url(),
        btc_second.base_url(),
        rpc_first.base_url(),
        rpc_second.base_url(),
    ];
    let consulted = endpoints.identities();
    assert_eq!(
        consulted.len(),
        4,
        "two Bitcoin and two Arbitrum endpoints: {consulted:?}"
    );
    assert_eq!(
        consulted,
        stubs.to_vec(),
        "the run would consult an endpoint that is not one of this test's stubs — refusing \
         to probe"
    );
    assert!(endpoints.overridden());

    let bytes = build(&shapes::multi_file_every_anchor_kind(), &Selection::all(3)).bytes;
    let bundle = BundleV1::decode(&bytes).expect("the fixture decodes");
    assert!(
        ProbePlan::from_bundle(&bundle).receipt.is_some(),
        "the F13 shape carries a receipt, so a receipt probe is planned"
    );
    let client = HttpClient::new(HttpPolicy::verify());
    let _ = probe_online(&client, &bundle, &endpoints, NetworkId::ArbitrumOne);

    for (label, server) in [("first", &rpc_first), ("second", &rpc_second)] {
        let seen = requests(server);
        assert!(
            seen.iter().any(|text| text.contains("eth_chainId")),
            "the {label} configured RPC endpoint was not asked for its chain id: {seen:#?}"
        );
        assert!(
            seen.iter()
                .any(|text| text.contains("eth_getTransactionReceipt")),
            "the {label} configured RPC endpoint was not asked for the receipt: {seen:#?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// U98 (D195 R1–R2): the overlay discloses each endpoint by its origin
// ─────────────────────────────────────────────────────────────────────

/// What no disclosure may carry: a path segment, where a provider commonly
/// puts its API key. NON-SECRET: a marker string, not a key.
const PATH_CANARY: &str = "NOT-A-KEY-path-canary";
/// …and a query parameter, the other place it goes. Configured on the RPC pair
/// only: an esplora base with a query is refused at load (D196 R3), because
/// esplora requests append their path to it.
const QUERY_CANARY: &str = "NOT-A-KEY-query-canary";

/// A stub that answers every request with `status`.
fn stub_answering(status: u16) -> StubServer {
    StubServer::spawn(StubScript::new().unmatched(StubReply::body(status, b"no".to_vec())))
}

/// The F13 shape — its receipt included — with one genuinely attested `.ots`
/// anchor at `height` in place of its placeholders: the overlay renders a
/// per-anchor outcome only for an anchor attested offline, and the failure
/// lines this module's U98 rows read hang off that outcome.
fn keyed_probe_bundle(height: u64) -> Vec<u8> {
    use antseal_core::anchor::testing::ots_writer::{
        FETCH_DATE as WRITER_FETCH_DATE, bitcoin, container, header_with,
    };
    let built = build(&shapes::multi_file_every_anchor_kind(), &Selection::all(3));
    let proof =
        antseal_core::bundle::SealProof::decode(&built.bytes).expect("the F13 fixture decodes");
    let digest = *antseal_core::manifest::anchor_digest(proof.anchor_digest_preimage()).as_bytes();
    let header = header_with(&digest, 1_483_398_000);
    let mut parts = BundleV1::decode(&built.bytes)
        .expect("the F13 fixture decodes to the model")
        .into_parts();
    parts.ots_anchors = vec![
        OtsAnchor::new(
            AnchorStatus::Attested,
            OpaqueBytes::from_vec(container(&digest, &bitcoin(height))),
            Some(OtsUpgrade::new(height, header, WRITER_FETCH_DATE)),
        )
        .expect("a synthetic committed artifact is under the D10 caps"),
    ];
    encode_bundle(&BundleV1::new(parts).expect("a well-formed bundle"))
        .expect("the rebuilt bundle re-encodes")
}

/// Every string under an `"endpoint"` key anywhere in `value`.
fn endpoint_fields(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                if key == "endpoint"
                    && let Some(text) = inner.as_str()
                {
                    out.push(text.to_owned());
                }
                endpoint_fields(inner, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                endpoint_fields(item, out);
            }
        }
        _ => {}
    }
}

/// One `--online` run against four stubs configured as a provider would
/// configure them — the esplora pair with a key-shaped path, the RPC pair with
/// a key-shaped path AND query — read back as the human report, the `--json`
/// result and the overlay's own identities. The pre-flight runs BEFORE any
/// request: every endpoint the run would consult must be one of the stubs,
/// so a broken resolution fails here rather than dialing a real endpoint (Q16's
/// `cfg(test)` arm does not cover this crate's in-process tests).
struct KeyedRun {
    human: String,
    json: String,
    identities: Vec<String>,
    origins: Vec<String>,
}

fn keyed_run(btc: [&StubServer; 2], rpc: [&StubServer; 2]) -> KeyedRun {
    let esplora = |s: &StubServer| format!("{}/{PATH_CANARY}/x", s.base_url());
    let keyed = |s: &StubServer| format!("{}/{PATH_CANARY}/x?apikey={QUERY_CANARY}", s.base_url());
    let configured = vec![
        esplora(btc[0]),
        esplora(btc[1]),
        keyed(rpc[0]),
        keyed(rpc[1]),
    ];
    let config = crate::config::parse(&format!(
        "[verify]\nbitcoin_endpoints = [\"{}\", \"{}\"]\n\
         [verify.arbitrum-one]\nrpc_endpoints = [\"{}\", \"{}\"]\n",
        configured[0], configured[1], configured[2], configured[3],
    ))
    .expect("keyed loopback stubs are admissible endpoints");
    let endpoints = super::endpoints_from_config(&config, NetworkId::ArbitrumOne)
        .expect("resolves")
        .expect("arbitrum-one has a Bitcoin pair");
    assert_eq!(
        endpoints.identities(),
        configured,
        "the run would consult an endpoint that is not one of this test's stubs — refusing \
         to probe"
    );

    let bytes = keyed_probe_bundle(700_511);
    let bundle = BundleV1::decode(&bytes).expect("the keyed bundle decodes");
    let client = HttpClient::new(HttpPolicy::verify());
    let online = probe_online(&client, &bundle, &endpoints, NetworkId::ArbitrumOne);
    let run = crate::verify_out::run_verify(
        &bytes,
        &antseal_core::verify::VerifyOptions::new(),
        antseal_core::verify::orchestration::VerifyModes::new().with_online(),
        &super::CollectedInputs::none().with_online(online),
    )
    .expect("the keyed bundle verifies");
    let identities = run
        .outcome()
        .overlay()
        .expect("an --online run renders the overlay")
        .endpoints
        .identities
        .clone();
    KeyedRun {
        human: run.render().join("\n"),
        json: run.json().expect("the --json result serializes"),
        identities,
        origins: btc.iter().chain(rpc.iter()).map(|s| s.base_url()).collect(),
    }
}

/// **U98 Accept (D195 R1–R2), the identities.** A configured endpoint whose
/// URL carries a key in its path or query is consulted — with that key, which
/// each stub's request log proves — and disclosed by its origin alone: the
/// `endpoints:` line and `--json` carry `scheme://host:port` and neither
/// canary, and the overlay's identities ARE the stubs' origins.
#[test]
fn the_overlay_discloses_origins_and_never_a_configured_path_or_query() {
    let (btc_first, btc_second, rpc_first, rpc_second) = (stub(), stub(), stub(), stub());
    let run = keyed_run([&btc_first, &btc_second], [&rpc_first, &rpc_second]);

    for (surface, text) in [("human", &run.human), ("--json", &run.json)] {
        assert!(
            !text.contains(PATH_CANARY) && !text.contains(QUERY_CANARY),
            "the overlay disclosed a configured path or query on its {surface} surface:\n{text}"
        );
    }
    assert_eq!(
        run.identities, run.origins,
        "each identity is a stub's origin"
    );
    for origin in &run.origins {
        assert!(
            run.human.contains(origin.as_str()),
            "{origin} on the endpoints line:\n{}",
            run.human
        );
    }

    // The consulted half: the keyed URL was USED, not merely printed less.
    for (label, server) in [
        ("esplora first", &btc_first),
        ("esplora second", &btc_second),
    ] {
        assert!(
            requests(server)
                .iter()
                .any(|text| text.contains(PATH_CANARY)),
            "the {label} endpoint was not asked through its configured path: {:#?}",
            requests(server)
        );
    }
    for (label, server) in [("RPC first", &rpc_first), ("RPC second", &rpc_second)] {
        assert!(
            requests(server)
                .iter()
                .any(|text| text.contains(PATH_CANARY) && text.contains(QUERY_CANARY)),
            "the {label} endpoint was not asked through its configured path and query: {:#?}",
            requests(server)
        );
    }
}

/// **U98 Accept (D195 R2), the failure lines.** The same run with every stub
/// answering 500, so the per-anchor failure line (esplora: the configured base
/// with the request's path appended) and the receipt failure line are
/// rendered: neither canary on either surface, and every failure's endpoint
/// in `--json` is one of the stubs' origins.
#[test]
fn a_failure_line_discloses_the_origin_and_never_a_configured_path_or_query() {
    let (btc_first, btc_second) = (stub_answering(500), stub_answering(500));
    let (rpc_first, rpc_second) = (stub_answering(500), stub_answering(500));
    let run = keyed_run([&btc_first, &btc_second], [&rpc_first, &rpc_second]);

    for (surface, text) in [("human", &run.human), ("--json", &run.json)] {
        assert!(
            !text.contains(PATH_CANARY) && !text.contains(QUERY_CANARY),
            "a failure line disclosed a configured path or query on its {surface} surface:\n{text}"
        );
    }
    let document: serde_json::Value =
        serde_json::from_str(&run.json).expect("the --json result is one JSON document");
    let mut failed = Vec::new();
    endpoint_fields(&document, &mut failed);
    let (esplora, rpc) = run.origins.split_at(2);
    assert!(
        esplora.iter().all(|origin| failed.contains(origin))
            && rpc.iter().any(|origin| failed.contains(origin)),
        "both esplora endpoints and the RPC pair must have failed by origin: {failed:#?}"
    );
    assert!(
        failed.iter().all(|endpoint| run.origins.contains(endpoint)),
        "every failure names a stub's origin and nothing more: {failed:#?}"
    );
}
