//! U4 acceptance suite: the config file — precedence (flag > config >
//! default), missing-file defaults, the malformed matrix (typed errors,
//! never silent), unknown-key warnings, network mapping distinctness via
//! S5's schema, and the D47 cross-test (exported config survives import
//! and still resolves).
//!
//! NON-SECRET: config text fixtures only.

#[path = "common/spawn.rs"]
mod spawn;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use antseal_cli::cli::Network;
use antseal_cli::config::{Config, effective_network, initial_config_text, load_from, parse};
use antseal_cli::error::{CliError, ErrorClass};
use antseal_cli::vault::layout::{BesideFile, VaultLayout};
use antseal_net::{NetworkConfig, NetworkId};

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "antseal-cli-config-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create test dir");
        TestDir(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn layout_with_config(dir: &TestDir, text: Option<&str>) -> VaultLayout {
    let root = dir.path().join("vault");
    std::fs::create_dir_all(&root).expect("mk vault dir");
    let layout = VaultLayout::at(root);
    if let Some(text) = text {
        std::fs::write(layout.beside_path(BesideFile::Config), text).expect("write config");
    }
    layout
}

// ─────────────────────────────────────────────────────────────────────
// Precedence: flag > config > default
// ─────────────────────────────────────────────────────────────────────

/// The full table, including the row a clap-level default could never
/// express: an EXPLICIT `--network arbitrum-one` beating a config that
/// says devnet.
#[test]
fn precedence_table_flag_beats_config_beats_default() {
    let with_devnet = Config {
        default_network: Some(NetworkId::Devnet),
        ..Config::default()
    };
    let empty = Config::default();

    let table: [(Option<Network>, &Config, NetworkId); 5] = [
        (None, &empty, NetworkId::ArbitrumOne),  // built-in default
        (None, &with_devnet, NetworkId::Devnet), // config wins over default
        (
            Some(Network::ArbitrumSepolia),
            &with_devnet,
            NetworkId::ArbitrumSepolia,
        ),
        (
            Some(Network::ArbitrumOne),
            &with_devnet,
            NetworkId::ArbitrumOne,
        ), // explicit flag beats config
        (Some(Network::Devnet), &empty, NetworkId::Devnet),
    ];
    for (flag, config, expected) in table {
        assert_eq!(effective_network(flag, config), expected, "{flag:?}");
    }
}

/// No config file present ⇒ defaults, silently (a fresh machine).
#[test]
fn missing_file_is_the_defaults() {
    let dir = TestDir::new("missing");
    let layout = layout_with_config(&dir, None);
    let config = load_from(&layout).expect("missing file loads as defaults");
    assert_eq!(config, Config::default());
    assert_eq!(
        effective_network(None, &config),
        NetworkId::ArbitrumOne,
        "arbitrum-one is the built-in default with no config present"
    );
}

/// The initial config `init` will write round-trips through the loader
/// and resolves to its network.
#[test]
fn initial_config_round_trips() {
    let text = initial_config_text(NetworkId::ArbitrumSepolia);
    let config = parse(&text).expect("initial config parses");
    assert_eq!(config.default_network, Some(NetworkId::ArbitrumSepolia));
    assert!(config.warnings.is_empty());
}

// ─────────────────────────────────────────────────────────────────────
// The full schema loads
// ─────────────────────────────────────────────────────────────────────

/// Every slot of the v1 schema, each once in its home table — the fixture
/// `every_full_schema_key_is_refused_outside_its_home` derives its keys from.
const FULL_SCHEMA: &str = r#"
# full fixture
default_network = "devnet"

[networks.arbitrum-one]
bootstrap = ["192.0.2.10:10000", "198.51.100.20:10000"]

[anchors]
tsa_urls = ["https://freetsa.org/tsr", "http://timestamp.digicert.com"]
ots_calendars = ["https://cal-a.example.org", "https://cal-b.example.org"]
opportunistic_upgrades = false

[verify]
bitcoin_endpoints = ["https://btc-a.example", "https://btc-b.example"]

[verify.arbitrum-one]
rpc_endpoints = ['https://arb-a.example', 'https://arb-b.example']

[verify.arbitrum-sepolia]
rpc_endpoints = ["https://sep-a.example", "https://sep-b.example"]
"#;

#[test]
fn full_schema_parses_with_every_slot() {
    let config = parse(FULL_SCHEMA).expect("full schema parses");
    assert_eq!(config.default_network, Some(NetworkId::Devnet));
    // D173 §2 R4: the peer override, carried as parsed socket addresses.
    assert_eq!(
        config.arbitrum_one_bootstrap.as_ref().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        config.tsa_urls.as_deref(),
        Some(
            &[
                "https://freetsa.org/tsr".to_owned(),
                "http://timestamp.digicert.com".to_owned()
            ][..]
        )
    );
    assert_eq!(config.ots_calendars.as_ref().map(Vec::len), Some(2));
    assert_eq!(config.opportunistic_upgrades, Some(false));
    assert_eq!(
        config.verify_bitcoin_endpoints.as_ref().map(Vec::len),
        Some(2)
    );
    // U44 (D188 R4): one pair per network, read back through the accessor.
    assert_eq!(
        config
            .verify_rpc_endpoints(NetworkId::ArbitrumOne)
            .map(<[String]>::len),
        Some(2)
    );
    assert_eq!(
        config
            .verify_rpc_endpoints(NetworkId::ArbitrumSepolia)
            .map(<[String]>::len),
        Some(2)
    );
    assert!(config.warnings.is_empty(), "{:?}", config.warnings);
}

// ─────────────────────────────────────────────────────────────────────
// A49 — the transport requirement on unsigned online evidence
// ─────────────────────────────────────────────────────────────────────

/// A49 (decision D90 §6.6). The `[verify]` endpoints are the two must-agree
/// pairs; their replies carry no signature of their own and are trusted only
/// because two *independent* endpoints agree, so an `http://` override hands
/// one on-path attacker both halves and the agreement becomes a tautology
/// that still reports success.
///
/// Refused at **load**, before any network call. Both pairs' refusals name the
/// entry by its POSITION and never the URL: an RPC URL that answers
/// `eth_getTransactionReceipt` commonly carries an API key (U44, D188 R5), and
/// any URL can carry a credential (U99, D195 R4).
#[test]
fn a_plain_http_verify_endpoint_is_refused_at_config_load() {
    let text = "[verify]\nbitcoin_endpoints = [\"https://good.example\", \"http://plain.example/api\"]\n\
                [verify.arbitrum-one]\nrpc_endpoints = [\"https://a.example\", \"https://b.example\"]\n";
    let err = parse(text).expect_err("a plain-http must-agree endpoint is refused");
    let rendered = err.detail.clone();
    assert!(
        rendered.contains("entry 1") && !rendered.contains("plain.example"),
        "the failure names the offending entry's position, never its URL (U99): {rendered}"
    );
    assert!(
        rendered.contains("must be https"),
        "…and the reason: {rendered}"
    );
    assert!(
        rendered.contains("bitcoin_endpoints"),
        "…and the key: {rendered}"
    );

    for network in ["arbitrum-one", "arbitrum-sepolia"] {
        let text = format!(
            "[verify]\nbitcoin_endpoints = [\"https://a.example\", \"https://b.example\"]\n\
             [verify.{network}]\nrpc_endpoints = [\"https://good.example\", \"http://plain.example/api\"]\n"
        );
        let err = parse(&text).expect_err("a plain-http RPC endpoint is refused");
        let rendered = err.detail.clone();
        assert!(
            rendered.contains("must be https"),
            "[verify.{network}]: the reason: {rendered}"
        );
        assert!(
            rendered.contains("`rpc_endpoints`")
                && rendered.contains(&format!("[verify.{network}]"))
                && rendered.contains("entry 1"),
            "[verify.{network}]: the key, the table and the entry index: {rendered}"
        );
        assert!(
            !rendered.contains("plain.example"),
            "[verify.{network}]: never the URL: {rendered}"
        );
        assert_eq!(err.line, 4, "[verify.{network}]: the key's line: {err:?}");
    }
}

/// The other direction, so the rule is proven to be a *rule* and not a
/// blanket refusal: `https` passes, a loopback IP literal passes (A16/A17's
/// stub suites bind `127.0.0.1`, and Q16 forbids real endpoints in CI), and
/// the RFC 3161 slot still accepts plain HTTP — `timestamp.digicert.com` has
/// no port 443 at all, and its tokens are signed and nonce-bound.
#[test]
fn https_and_loopback_verify_endpoints_are_admitted_and_tsa_http_is_untouched() {
    let text = r#"
[anchors]
tsa_urls = ["http://timestamp.digicert.com"]

[verify]
bitcoin_endpoints = ["https://btc-a.example", "http://127.0.0.1:8332/rest"]

[verify.arbitrum-one]
rpc_endpoints = ["https://arb-a.example", "http://[::1]:8545/"]
"#;
    let config = parse(text).expect("https, loopback literals and a plain-http TSA all load");
    assert_eq!(
        config.verify_bitcoin_endpoints.as_ref().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        config
            .verify_rpc_endpoints(NetworkId::ArbitrumOne)
            .map(<[String]>::len),
        Some(2)
    );
    assert_eq!(
        config.tsa_urls.as_deref(),
        Some(&["http://timestamp.digicert.com".to_owned()][..])
    );

    // The carve-out is IP literals only: a NAME that resolves to loopback,
    // and a hostname that merely contains one, are both refused — FOR THE
    // TRANSPORT, in a pair whose count and origins are otherwise valid. Since
    // U101 checks the count at load, a one-entry list is refused for its count
    // and would keep this row green whatever the carve-out admitted.
    for hostile in ["http://localhost:8332/", "http://127.0.0.1.evil.example/"] {
        let text =
            format!("[verify]\nbitcoin_endpoints = [\"https://btc-a.example\", \"{hostile}\"]\n");
        let err = parse(&text).expect_err(hostile);
        assert!(
            err.detail.contains("entry 1 must be https"),
            "{hostile}: refused for its transport, not its count: {}",
            err.detail
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// U44 (D188) — the calendar list, and the per-network verify RPC pair
// ─────────────────────────────────────────────────────────────────────

/// **U44 Accept row 1, at load (D188 R1).** `[anchors] ots_calendars` is a
/// string array checked by the substrate's own parser under the SUBMIT path's
/// TLS policy (`TlsPolicy::Optional`, the one `ots/submit.rs` applies), so
/// load and use apply one rule: plain http loads — a calendar cannot forge an
/// OpenTimestamps proof — while a hostless URL, a scheme the substrate cannot
/// speak and embedded credentials are refused, naming the key, the entry's
/// position and the line, never the entry (U99, D195 R4: D188 R1's echo of a
/// calendar URL is retired). Order is kept as written and `[]` loads; that both collapse to
/// D54's defaults downstream is asserted in `anchor_stage.rs`, the one suite
/// allowed to name the stage's constructor.
#[test]
fn ots_calendars_load_validated_and_replace_wholesale() {
    let parse_list = |list: &str| parse(&format!("[anchors]\nots_calendars = {list}\n"));

    let config = parse_list(r#"["https://cal-b.example.org", "https://cal-a.example.org"]"#)
        .expect("two https calendars load");
    assert_eq!(
        config.ots_calendars,
        Some(vec![
            "https://cal-b.example.org".to_owned(),
            "https://cal-a.example.org".to_owned()
        ]),
        "loaded as written, in order"
    );
    assert!(
        config.warnings.is_empty(),
        "a recognised key, not a warning: {:?}",
        config.warnings
    );

    let empty = parse_list("[]").expect("an empty list loads");
    assert_eq!(empty.ots_calendars, Some(Vec::new()));

    // The submit path's own policy: a plain-http calendar loads.
    let plain = parse_list(r#"["http://cal.example.org"]"#).expect("plain http loads");
    assert_eq!(
        plain.ots_calendars,
        Some(vec!["http://cal.example.org".to_owned()])
    );

    let refused = [
        ("http:///x", "not a usable endpoint URL"),
        ("gopher://cal.example.org", "http:// or https://"),
        ("https://user:pw@cal.example.org", "userinfo"),
    ];
    assert_eq!(refused.len(), 3);
    for (entry, why) in refused {
        let err = parse(&format!(
            "# calendars\n[anchors]\nots_calendars = [\"https://ok.example.org\", \"{entry}\"]\n"
        ))
        .expect_err(entry);
        assert_eq!(err.line, 3, "{entry}: the key's line is named: {err:?}");
        assert!(
            err.detail.contains("`ots_calendars`"),
            "{entry}: names the key: {}",
            err.detail
        );
        assert!(
            err.detail.contains("entry 1") && !err.detail.contains(entry),
            "{entry}: names the entry's position, never the entry — a URL can carry a \
             credential (U99): {}",
            err.detail
        );
        assert!(
            err.detail.contains(why),
            "{entry}: says why ({why}): {}",
            err.detail
        );
    }

    let err = parse_list(r#""https://cal.example.org""#).expect_err("a string is not a list");
    assert!(err.detail.contains("takes an array"), "{}", err.detail);
}

/// **U44 Accept row 2 (D188 R4).** The two networks' tables load into
/// DISTINCT pairs, read back through the accessor every consumer uses — which
/// has no devnet pair to return. One table alone sets one network and leaves
/// the other on its pinned pair; an unknown key under a known table warns.
#[test]
fn verify_rpc_pairs_are_per_network() {
    let text = r#"
[verify.arbitrum-one]
rpc_endpoints = ["https://one-a.example", "https://one-b.example"]

[verify.arbitrum-sepolia]
rpc_endpoints = ["https://sep-a.example", "https://sep-b.example"]
"#;
    let config = parse(text).expect("both per-network tables load");
    assert!(config.warnings.is_empty(), "{:?}", config.warnings);
    let one = config
        .verify_rpc_endpoints(NetworkId::ArbitrumOne)
        .expect("arbitrum-one's pair")
        .to_vec();
    let sepolia = config
        .verify_rpc_endpoints(NetworkId::ArbitrumSepolia)
        .expect("arbitrum-sepolia's pair")
        .to_vec();
    assert_eq!(
        one,
        vec![
            "https://one-a.example".to_owned(),
            "https://one-b.example".to_owned()
        ]
    );
    assert_eq!(
        sepolia,
        vec![
            "https://sep-a.example".to_owned(),
            "https://sep-b.example".to_owned()
        ]
    );
    assert_ne!(one, sepolia, "two networks, two pairs");
    assert_eq!(
        config.verify_rpc_endpoints(NetworkId::Devnet),
        None,
        "devnet has no pair"
    );

    let only_sepolia = parse(
        "[verify.arbitrum-sepolia]\nrpc_endpoints = [\"https://sep-a.example\", \"https://sep-b.example\"]\n",
    )
    .expect("one table loads");
    assert_eq!(
        only_sepolia.verify_rpc_endpoints(NetworkId::ArbitrumOne),
        None,
        "arbitrum-one keeps its pinned pair"
    );
    assert!(
        only_sepolia
            .verify_rpc_endpoints(NetworkId::ArbitrumSepolia)
            .is_some()
    );

    let extra =
        parse("[verify.arbitrum-one]\nfuture_knob = \"x\"\n").expect("an unknown key warns");
    assert_eq!(extra.warnings.len(), 1, "{:?}", extra.warnings);
    assert!(
        extra.warnings[0].contains("[verify.arbitrum-one]")
            && extra.warnings[0].contains("ignored"),
        "{:?}",
        extra.warnings
    );
}

/// **U44 Accept row 2's refusals (D188 R4).** `[verify.devnet]` is refused
/// whatever the key, with its reason; an unknown network keeps the
/// `[networks.<id>]` answer word for word.
#[test]
fn a_devnet_or_unknown_verify_table_is_refused() {
    for body in [
        "rpc_endpoints = [\"https://a.example\", \"https://b.example\"]",
        "future_knob = \"x\"",
    ] {
        let err = parse(&format!("[verify.devnet]\n{body}\n")).expect_err(body);
        assert_eq!(err.line, 2, "{body}: {err:?}");
        assert!(
            err.detail.contains("`[verify.devnet]`")
                && err.detail.contains("no RPC pair to override")
                && err.detail.contains("fresh Anvil per run"),
            "{body}: names the table and the reason: {}",
            err.detail
        );
    }

    let verify =
        parse("[verify.ropsten]\nrpc_endpoints = [\"https://a.example\", \"https://b.example\"]\n")
            .expect_err("an unknown network is refused");
    assert_eq!(
        verify.detail,
        "`[verify.ropsten]` is not a known network (valid: arbitrum-one, arbitrum-sepolia, devnet)"
    );
    let networks = parse("[networks.ropsten]\nbootstrap = [\"192.0.2.10:10000\"]\n")
        .expect_err("the same name under [networks.*]");
    assert_eq!(
        verify.detail.replace("[verify.", "[networks."),
        networks.detail,
        "the [networks.<id>] wording, word for word"
    );
}

/// **U44 Accept row 3 (D188 R4, R5).** A verify-RPC override is exactly two
/// endpoints at two origins, checked at LOAD — never a silent one-endpoint
/// overlay, never a pair that agrees with itself — and no refusal repeats a
/// URL or a host, whatever shape the value is written in: the canary sits in
/// the path, where a provider puts its API key. The control is the same
/// vehicle with a well-formed pair.
#[test]
fn a_verify_rpc_override_is_exactly_two_distinct_origins_at_load() {
    let c = RPC_URL_CANARY;
    let cases = [
        (
            "one entry",
            format!(r#"["https://a.example/v2/{c}"]"#),
            "exactly two endpoints (found 1)",
        ),
        (
            "three entries",
            format!(
                r#"["https://a.example/v2/{c}", "https://b.example/v2/{c}", "https://c.example/v2/{c}"]"#
            ),
            "exactly two endpoints (found 3)",
        ),
        (
            "no entries",
            "[]".to_owned(),
            "exactly two endpoints (found 0)",
        ),
        (
            "one origin, two spellings",
            format!(r#"["https://a.example/v2/{c}", "https://A.example:443/other/{c}"]"#),
            "entries 0 and 1 are one origin",
        ),
        (
            "plain http",
            format!(r#"["https://a.example/v2/{c}", "http://b.example/v2/{c}"]"#),
            "entry 1 must be https",
        ),
        (
            "no host",
            format!(r#"["http:///{c}", "https://b.example/v2/{c}"]"#),
            "entry 0 is not a usable endpoint URL",
        ),
        (
            "credentials",
            format!(r#"["https://a.example/v2/{c}", "https://{c}:pw@b.example/"]"#),
            "entry 1 is not a usable endpoint URL (userinfo",
        ),
        (
            "a string",
            format!(r#""https://a.example/v2/{c}""#),
            "takes a one-line array",
        ),
        (
            "an unquoted value",
            format!("https://a.example/v2/{c}"),
            "takes a one-line array",
        ),
        (
            "an escape sequence",
            format!(r#"["https://a.example/v2/{c}\t", "https://b.example/v2/{c}"]"#),
            "takes a one-line array",
        ),
    ];
    assert_eq!(cases.len(), 10);
    for network in ["arbitrum-one", "arbitrum-sepolia"] {
        for (shape, value, needle) in &cases {
            let text = format!("# the pair\n[verify.{network}]\nrpc_endpoints = {value}\n");
            let err = parse(&text).expect_err(shape);
            assert_eq!(
                err.line, 3,
                "[verify.{network}], {shape}: the key's line: {err:?}"
            );
            assert!(
                err.detail.contains(needle),
                "[verify.{network}], {shape}: expected {needle:?} in {}",
                err.detail
            );
            assert!(
                err.detail.contains("`rpc_endpoints`")
                    && err.detail.contains(&format!("[verify.{network}]")),
                "[verify.{network}], {shape}: names the key and the table: {}",
                err.detail
            );
            assert!(
                !err.detail.contains(c) && !err.detail.contains("example"),
                "[verify.{network}], {shape}: no URL and no host may be repeated — an RPC URL \
                 often carries an API key: {}",
                err.detail
            );
        }
    }

    let ok = parse(&format!(
        "[verify.arbitrum-one]\nrpc_endpoints = [\"https://a.example/v2/{c}\", \"https://b.example/v2/{c}\"]\n"
    ))
    .expect("two https endpoints at two origins load");
    assert_eq!(
        ok.verify_rpc_endpoints(NetworkId::ArbitrumOne)
            .map(<[String]>::len),
        Some(2)
    );
}

/// **U44 Accept row 4, reversed (D188 R5).** The flat `[verify]
/// arbitrum_endpoints` is REFUSED at load — not warned: U30 had wired it, so
/// a warning would leave `verify --online` probing the pinned pair the user
/// configured away from (D180's reason, one table over). The refusal names
/// the key, the table, the line and the two replacement tables, and never the
/// value, whatever its shape — including the unquoted one, which a refusal
/// that waited for the value would answer with the subset's own sentence, not
/// the replacement tables (a sentence that repeated the URL until U99, D195 R4).
#[test]
fn the_flat_arbitrum_endpoints_key_is_refused_by_name() {
    let c = RPC_URL_CANARY;
    let shapes = [
        (
            "a pair",
            format!(r#"["https://a.example/v2/{c}", "https://b.example/v2/{c}"]"#),
        ),
        ("one entry", format!(r#"["https://a.example/v2/{c}"]"#)),
        ("an unquoted value", format!("https://a.example/v2/{c}")),
        ("a literal string", format!("'https://a.example/v2/{c}'")),
    ];
    assert_eq!(shapes.len(), 4);
    for (shape, value) in &shapes {
        let text = format!(
            "[verify]\nbitcoin_endpoints = [\"https://btc-a.example\", \"https://btc-b.example\"]\n\
             arbitrum_endpoints = {value}\n"
        );
        let err = parse(&text).expect_err(shape);
        assert_eq!(err.line, 3, "{shape}: the key's line: {err:?}");
        assert!(
            err.detail.contains("`arbitrum_endpoints`") && err.detail.contains("[verify]"),
            "{shape}: names the key and the table: {}",
            err.detail
        );
        assert!(
            err.detail.contains("[verify.arbitrum-one]")
                && err.detail.contains("[verify.arbitrum-sepolia]")
                && err.detail.contains("`rpc_endpoints`"),
            "{shape}: names where the pair goes now: {}",
            err.detail
        );
        assert!(
            !err.detail.contains(c),
            "{shape}: never the value — an RPC URL often carries an API key: {}",
            err.detail
        );
    }

    // U100 (D196 R2): the retired name is refused in every table — under a
    // per-network table it is one key name away from the right line, and the
    // refusal says so.
    let err = parse(&format!(
        "[verify.arbitrum-one]\narbitrum_endpoints = [\"https://a.example/v2/{c}\"]\n"
    ))
    .expect_err("the retired key is refused under a per-network table too");
    assert_eq!(err.line, 2, "the key's line: {err:?}");
    assert!(
        err.detail
            .contains("`arbitrum_endpoints` under [verify.arbitrum-one]")
            && err
                .detail
                .contains("write `rpc_endpoints` in this table instead")
            && !err.detail.contains(c),
        "names the key, the table and the replacement, never the value: {}",
        err.detail
    );
}

// ─────────────────────────────────────────────────────────────────────
// U60 + the grammar (D189) — booleans, and unknown keys' values unread
// ─────────────────────────────────────────────────────────────────────

/// **U60 Accept (D189 R1, R2), at load.** `[anchors] opportunistic_upgrades`
/// takes a bare lowercase boolean and nothing else: absent is on, `false` is
/// off, and every near miss — a quoted `"false"`, `off`, `False`, an array —
/// is refused with the key's own sentence on the key's line. Booleans are
/// typed per key: every string or array key refuses one with its own
/// message, so growing the grammar widened no key that did not ask for it.
#[test]
fn booleans_are_in_the_subset_and_typed_per_key() {
    let with = |value: &str| parse(&format!("[anchors]\nopportunistic_upgrades = {value}\n"));

    let off = with("false").expect("false loads");
    assert_eq!(off.opportunistic_upgrades, Some(false));
    assert!(!off.opportunistic_upgrades_enabled());
    assert!(off.warnings.is_empty(), "{:?}", off.warnings);

    let on = with("true").expect("true loads");
    assert_eq!(on.opportunistic_upgrades, Some(true));
    assert!(on.opportunistic_upgrades_enabled());

    let absent = parse("[anchors]\ntsa_urls = []\n").expect("loads");
    assert_eq!(absent.opportunistic_upgrades, None);
    assert!(absent.opportunistic_upgrades_enabled(), "absent is on");
    assert!(
        Config::default().opportunistic_upgrades_enabled(),
        "the default is on"
    );

    let near_misses = [
        "\"false\"",
        "'false'",
        "\"off\"",
        "off",
        "False",
        "TRUE",
        "0",
        "[]",
        "[\"false\"]",
        "[false]",
    ];
    assert_eq!(near_misses.len(), 10);
    for value in near_misses {
        let err = with(value).expect_err(value);
        assert_eq!(err.line, 2, "{value}: the key's line: {err:?}");
        assert_eq!(
            err.detail, "`opportunistic_upgrades` takes true or false",
            "{value}"
        );
    }

    // Typed per key: a boolean where a string or an array belongs.
    let typed = [
        (
            "default_network = true\n",
            1,
            "`default_network` takes a string, not a boolean",
        ),
        (
            "[anchors]\ntsa_urls = true\n",
            2,
            "`tsa_urls` takes an array of strings, not a boolean",
        ),
        (
            "[anchors]\nots_calendars = false\n",
            2,
            "`ots_calendars` takes an array of strings, not a boolean",
        ),
        (
            "[verify]\nbitcoin_endpoints = true\n",
            2,
            "`bitcoin_endpoints` takes an array of strings, not a boolean",
        ),
        (
            "[networks.arbitrum-one]\nbootstrap = true\n",
            2,
            "`bootstrap` takes an array of \"ip:port\" strings",
        ),
        (
            "[verify.arbitrum-one]\nrpc_endpoints = true\n",
            2,
            "`rpc_endpoints` under [verify.arbitrum-one] takes a one-line array",
        ),
        (
            "[anchors]\ntsa_urls = [true]\n",
            2,
            "a boolean inside an array is outside the config subset",
        ),
    ];
    assert_eq!(typed.len(), 7);
    for (text, line, needle) in typed {
        let err = parse(text).expect_err(text);
        assert_eq!(err.line, line, "{text:?}: {err:?}");
        assert!(
            err.detail.contains(needle),
            "{text:?}: expected {needle:?} in {:?}",
            err.detail
        );
    }
}

/// **D189 R3.** An unknown key warns WHATEVER its value — an integer, a date,
/// an inline table, a float, an unterminated string — because its value is
/// never parsed, so a config written by a newer antseal, in grammar this
/// build lacks, still loads (`docs/config.md`'s forward-compatibility
/// promise, now true for every single-line value). The controls hold both
/// sides: a RECOGNISED key with such a value is still refused, and a table
/// whose network is unknown is still refused by its name, judged first.
#[test]
fn an_unknown_key_warns_whatever_its_value() {
    let text = r#"
answer = 42
[future]
when = 2026-01-01
table = { a = 1 }
ratio = 0.5
open = "unterminated
[anchors]
future_knob = 7
[networks.arbitrum-one]
future_knob = true
[verify.arbitrum-sepolia]
future_knob = [1, 2]
"#;
    let config = parse(text).expect("an unknown key never fails on its value");
    assert_eq!(config.warnings.len(), 8, "{:#?}", config.warnings);
    for warning in &config.warnings {
        assert!(
            warning.contains("unknown key") && warning.contains("ignored"),
            "{warning}"
        );
    }

    // Control 1: a recognised key's value is still held to the subset.
    for text in [
        "default_network = 42\n",
        "[anchors]\ntsa_urls = 42\n",
        "[verify]\nbitcoin_endpoints = 2026-01-01\n",
    ] {
        let err = parse(text).expect_err(text);
        assert!(
            err.detail.contains("not a quoted string"),
            "{text:?}: {:?}",
            err.detail
        );
    }
    // Control 2: a table's network name is judged before its unknown key is
    // warned on, whatever the value.
    for text in ["[networks.ropsten]\nx = 1\n", "[verify.ropsten]\nx = 1\n"] {
        let err = parse(text).expect_err(text);
        assert!(
            err.detail.contains("is not a known network"),
            "{text:?}: {:?}",
            err.detail
        );
    }
}

/// The networks the config selects map onto DISTINCT endpoint/contract
/// sets from S5's schema (the U4 Accept, via antseal-net's pure half).
#[test]
fn selected_networks_resolve_to_distinct_endpoint_sets() {
    let one = NetworkConfig::select(NetworkId::ArbitrumOne, None).expect("builtin");
    let sepolia = NetworkConfig::select(NetworkId::ArbitrumSepolia, None).expect("builtin");
    assert_ne!(one.evm_chain_id, sepolia.evm_chain_id);
    assert_ne!(one.payment_token, sepolia.payment_token);
    assert_ne!(one.payment_vault, sepolia.payment_vault);
    assert_ne!(one.rpc_url, sepolia.rpc_url);
    // Devnet is run-scoped by design: no environment, no config — a
    // distinct set by construction.
    assert!(NetworkConfig::select(NetworkId::Devnet, None).is_err());
}

// ─────────────────────────────────────────────────────────────────────
// Malformed matrix (typed errors, never silent) + warnings
// ─────────────────────────────────────────────────────────────────────

#[test]
fn malformed_configs_fail_with_line_and_problem() {
    let cases: [(&str, &str); 9] = [
        ("default_network = devnet\n", "not a quoted string"),
        ("default_network = \"ropsten\"\n", "must be one of"),
        ("default_network = \"a\\nb\"\n", "escape sequences"),
        ("just a line of prose\n", "expected `key = value`"),
        (
            "[networks.ropsten]\nrpc_url = \"https://x.example\"\n",
            "not a known network",
        ),
        // U94 (D180): the key is retired, so a well-formed value is refused
        // too — by name, never by its value.
        (
            "[networks.devnet]\nrpc_url = \"https://x.example\"\n",
            "`rpc_url`",
        ),
        (
            "[anchors]\ntsa_urls = [\"gopher://x\"]\n",
            "http:// or https://",
        ),
        ("[anchors]\ntsa_urls = \"https://x.example\"\n", "array"),
        (
            "default_network = \"devnet\"\ndefault_network = \"devnet\"\n",
            "already set",
        ),
    ];
    for (text, needle) in cases {
        let err = parse(text).expect_err(text);
        assert!(
            err.detail.contains(needle),
            "{text:?}: expected {needle:?} in {:?}",
            err.detail
        );
        assert!(err.line > 0, "{text:?}: line is named");
    }
}

/// The loader wraps parse failures in the typed class with the path and
/// the distinct exit code 17.
#[test]
fn malformed_file_is_the_typed_class() {
    let dir = TestDir::new("malformed");
    let layout = layout_with_config(&dir, Some("default_network = 42\n"));
    let err = load_from(&layout).expect_err("malformed must fail");
    assert!(matches!(err, CliError::MalformedConfig { .. }));
    assert_eq!(err.class(), ErrorClass::MalformedConfig);
    assert_eq!(err.exit_code(), 17);
    let rendered = err.to_string();
    assert!(rendered.contains("config.toml"), "{rendered}");
    assert!(rendered.contains(":1"), "line named: {rendered}");
}

/// Unknown keys and sections warn (forward compat) rather than crash,
/// and recognized content still loads.
#[test]
fn unknown_keys_warn_and_do_not_crash() {
    let text = r#"
default_network = "devnet"
color = "auto"

[future-section]
shiny = "yes"

[networks.devnet]
frobnicate = "maybe"
"#;
    let config = parse(text).expect("unknown keys are not fatal");
    assert_eq!(config.default_network, Some(NetworkId::Devnet));
    assert_eq!(config.warnings.len(), 3, "{:?}", config.warnings);
    for warning in &config.warnings {
        assert!(warning.contains("ignored"), "{warning}");
    }
}

// ─────────────────────────────────────────────────────────────────────
// Wiring: the binary honors precedence and warns on stderr
// ─────────────────────────────────────────────────────────────────────

fn spawn(vault_dir: &Path, args: &[&str]) -> std::process::Output {
    spawn::antseal()
        .args(args)
        .env("ANTSEAL_DIR", vault_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn antseal")
}

/// The envelope's `network` field proves the resolution end to end:
/// config default when no flag, flag when explicit — and a malformed
/// config is the distinct exit code with one error envelope.
#[test]
fn binary_resolves_network_through_the_config() {
    let dir = TestDir::new("wiring");
    let layout = layout_with_config(&dir, Some("default_network = \"devnet\"\n"));
    let root = layout.root().to_path_buf();

    // **The stub rotation ends at U30, and this row's premise expires with
    // it.** `list` played this vehicle until U19 gave it a real handler,
    // `status` until U23, `show` until U27 (at which point the row read
    // exit 2 rather than 3), and `verify` until U30 — the last stub of the
    // frozen surface. There is no stub left to borrow, so the row now
    // asserts **a real handler's own code**, and it keeps `verify` as the
    // vehicle for a better reason than availability: it needs no vault and
    // never prompts, so the code it reports is a fact about the *config
    // resolution* and not about whatever a vault-opening command met first.
    //
    // `b.sealproof` does not exist in this layout, so the code is
    // `io-error` (4) — a process outcome, before any verification. What the
    // row measures is unchanged: the envelope's `network` field, which is
    // resolved by `main_entry` before dispatch either way.
    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(out.status.code(), Some(4), "a real handler's own code");
    let doc: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'))
            .expect("one JSON document");
    assert_eq!(
        doc["network"],
        serde_json::json!("devnet"),
        "config wins over default"
    );

    // Explicit flag beats the config.
    let out = spawn(
        &root,
        &[
            "--json",
            "--network",
            "arbitrum-one",
            "verify",
            "b.sealproof",
        ],
    );
    let doc: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'))
            .expect("one JSON document");
    assert_eq!(
        doc["network"],
        serde_json::json!("arbitrum-one"),
        "flag wins over config"
    );

    // Unknown keys: warning on stderr, command otherwise unaffected.
    std::fs::write(
        layout.beside_path(BesideFile::Config),
        "default_network = \"devnet\"\nshiny = \"yes\"\n",
    )
    .expect("rewrite config");
    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "warnings never change the outcome"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown key `shiny`"), "{stderr}");

    // Malformed: the distinct exit code, one error envelope.
    std::fs::write(
        layout.beside_path(BesideFile::Config),
        "default_network = 42\n",
    )
    .expect("rewrite config");
    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(out.status.code(), Some(17), "malformed-config code");
    let doc: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'))
            .expect("one JSON document");
    assert_eq!(doc["error"]["class"], serde_json::json!("malformed-config"));
    // Plain mode: same code, no stdout. Deliberately a command with a REAL
    // handler, because a malformed config hard-fails before dispatch and this
    // is where that is worth showing.
    let out = spawn(&root, &["status", "w1"]);
    assert_eq!(out.status.code(), Some(17));
    assert!(out.stdout.is_empty());
}

// ─────────────────────────────────────────────────────────────────────
// D173 §2 R4 — `[networks.arbitrum-one] bootstrap`, validated at load
// ─────────────────────────────────────────────────────────────────────

/// **D173 §2 R4.** The override loads under `arbitrum-one` as exactly the
/// listed peers, in order, and the same key under either other network is a
/// malformed config naming `ANTSEAL_DEVNET_ENV` — those networks' peers come
/// from a devnet export and belong to one run of it (docs/config.md,
/// "Bootstrap peers").
#[test]
fn a_bootstrap_override_loads_under_arbitrum_one_and_nowhere_else() {
    let text = r#"
default_network = "arbitrum-one"

[networks.arbitrum-one]
bootstrap = ["192.0.2.10:10000", "198.51.100.20:10001", "[2001:db8::1]:10002"]
"#;
    let config = parse(text).expect("a valid override loads");
    let expected: Vec<std::net::SocketAddr> = [
        "192.0.2.10:10000",
        "198.51.100.20:10001",
        "[2001:db8::1]:10002",
    ]
    .iter()
    .map(|peer| peer.parse().expect("a documentation address"))
    .collect();
    assert_eq!(
        config.arbitrum_one_bootstrap.as_deref(),
        Some(expected.as_slice()),
        "the override is carried as the listed peers, in order"
    );
    assert!(config.warnings.is_empty(), "{:?}", config.warnings);
    assert_eq!(
        Config::default().arbitrum_one_bootstrap,
        None,
        "no key, no override — the built-in list is the resolver's business"
    );

    for network in ["arbitrum-sepolia", "devnet"] {
        let text = format!("[networks.{network}]\nbootstrap = [\"192.0.2.10:10000\"]\n");
        let err = match parse(&text) {
            Err(err) => err,
            Ok(config) => panic!(
                "`bootstrap` under [networks.{network}] is refused: got {:?}",
                config.arbitrum_one_bootstrap
            ),
        };
        assert_eq!(err.line, 2, "the key's line is named: {err:?}");
        assert!(
            err.detail.contains("ANTSEAL_DEVNET_ENV"),
            "names the export as that network's only peer source: {}",
            err.detail
        );
        assert!(
            err.detail.contains(&format!("[networks.{network}]")),
            "names the section: {}",
            err.detail
        );
        assert!(
            err.detail.contains("arbitrum-one"),
            "names the one section that takes the key: {}",
            err.detail
        );
    }
}

/// **D173 §2 R4's validation matrix.** Every rule docs/config.md states,
/// refused at load with the line named: at least one entry; IP literals only
/// (a hostname is refused — nothing on the storage path resolves names); no
/// repeat; no unspecified address; no port 0; no loopback, so neither an
/// all-loopback nor a mixed list loads — and `[::ffff:127.0.0.1]` is loopback
/// (the one classifier canonicalizes, D173 §2 R8). An empty list is a
/// malformed config, not "use the built-in list": this is where `bootstrap`
/// differs from `tsa_urls`.
#[test]
fn a_bootstrap_override_is_validated_at_load() {
    let cases: [(&str, &str); 10] = [
        ("[]", "at least one"),
        ("[\"example.org:10000\"]", "example.org:10000"),
        ("[\"192.0.2.10\"]", "192.0.2.10"),
        ("[\"192.0.2.10:10000\", \"192.0.2.10:10000\"]", "repeats"),
        ("[\"0.0.0.0:10000\"]", "unspecified"),
        ("[\"192.0.2.10:0\"]", "port 0"),
        ("[\"127.0.0.1:10000\"]", "loopback"),
        ("[\"[::ffff:127.0.0.1]:10000\"]", "loopback"),
        (
            "[\"127.0.0.1:10000\", \"192.0.2.10:10000\"]",
            "mixes loopback",
        ),
        ("\"192.0.2.10:10000\"", "array"),
    ];
    for (value, needle) in cases {
        let text = format!("[networks.arbitrum-one]\nbootstrap = {value}\n");
        let err = match parse(&text) {
            Err(err) => err,
            Ok(config) => panic!(
                "`bootstrap = {value}` must be refused: got {:?}",
                config.arbitrum_one_bootstrap
            ),
        };
        assert!(
            err.detail.contains(needle),
            "`bootstrap = {value}`: expected {needle:?} in {:?}",
            err.detail
        );
        assert!(
            err.detail.contains("bootstrap"),
            "`bootstrap = {value}`: names the key: {:?}",
            err.detail
        );
        assert_eq!(err.line, 2, "`bootstrap = {value}`: the line is named");
    }
    // The hostname refusal must not be a refusal of the whole array shape: the
    // same shape with an IP literal loads.
    let config = parse("[networks.arbitrum-one]\nbootstrap = [\"192.0.2.10:10000\"]\n")
        .expect("one IP literal loads");
    assert_eq!(
        config.arbitrum_one_bootstrap.as_ref().map(Vec::len),
        Some(1)
    );
}

/// **D173 §2 R4 — raised before dispatch, so before any passphrase.** Through
/// the binary: a misplaced or empty `bootstrap` is the malformed-config code
/// (17) with its envelope, on a command that needs no vault and never prompts
/// (`verify`'s own code would be 4 — the bundle does not exist — so the 17
/// is the config loader's, ahead of the handler).
#[test]
fn a_bad_bootstrap_override_is_exit_17_before_any_command_runs() {
    let dir = TestDir::new("bootstrap-wiring");
    let layout = layout_with_config(&dir, None);
    let root = layout.root().to_path_buf();
    for (text, needle) in [
        (
            "[networks.devnet]\nbootstrap = [\"127.0.0.1:20001\"]\n",
            "ANTSEAL_DEVNET_ENV",
        ),
        ("[networks.arbitrum-one]\nbootstrap = []\n", "at least one"),
    ] {
        std::fs::write(layout.beside_path(BesideFile::Config), text).expect("write config");
        let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
        assert_eq!(
            out.status.code(),
            Some(17),
            "{text:?}: malformed-config code; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let doc: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'))
                .expect("one JSON document");
        assert_eq!(doc["error"]["class"], serde_json::json!("malformed-config"));
        let message = doc["error"]["message"].as_str().expect("a message");
        assert!(message.contains(needle), "{text:?}: {message}");
    }
    // The control: a valid override on the same vehicle is not a config error.
    std::fs::write(
        layout.beside_path(BesideFile::Config),
        "[networks.arbitrum-one]\nbootstrap = [\"192.0.2.10:10000\"]\n",
    )
    .expect("write config");
    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "a valid override loads and the handler's own code follows"
    );
}

// ─────────────────────────────────────────────────────────────────────
// U94 (D180) — `[networks.<id>] rpc_url`, retired and refused at load
// ─────────────────────────────────────────────────────────────────────

/// What a refusal must never repeat. A provider's RPC URL carries its API key
/// in the path, so the canary sits exactly there. NON-SECRET: a marker string,
/// not a key.
const RPC_URL_CANARY: &str = "NOT-A-KEY-canary";

/// **U94 (D180 U94 R1, R2).** `rpc_url` under every network's table is a
/// malformed config that names the key, the table and the line — and never
/// the value, whatever shape it is written in. The unquoted shape is the one
/// that pins *where* the refusal is raised: a refusal raised after the value
/// is parsed would answer exactly the typo a user makes most with the
/// subset's own *not a quoted string* sentence, which names no table (and,
/// until U99 made it value-free, D195 R4, repeated the URL). The section name
/// is judged first: an unknown network keeps its own answer.
#[test]
fn rpc_url_is_refused_at_load_under_every_network() {
    let shapes = [
        (
            "a basic string",
            format!("\"https://rpc.example/v2/{RPC_URL_CANARY}\""),
        ),
        (
            "a literal string",
            format!("'https://rpc.example/v2/{RPC_URL_CANARY}'"),
        ),
        (
            "an unquoted value",
            format!("https://rpc.example/v2/{RPC_URL_CANARY}"),
        ),
        (
            "an array",
            format!("[\"https://rpc.example/v2/{RPC_URL_CANARY}\"]"),
        ),
        (
            "a non-http URL",
            format!("\"ftp://rpc.example/{RPC_URL_CANARY}\""),
        ),
    ];
    for network in ["arbitrum-one", "arbitrum-sepolia", "devnet"] {
        for (shape, value) in &shapes {
            let text = format!("[networks.{network}]\nrpc_url = {value}\n");
            let err = parse(&text).expect_err("`rpc_url` must be refused at load");
            assert!(
                !err.detail.contains(RPC_URL_CANARY),
                "[networks.{network}], {shape}: the refusal must not echo the value: an RPC \
                 URL often carries an API key: {}",
                err.detail
            );
            assert_eq!(
                err.line, 2,
                "[networks.{network}], {shape}: the key's line is named: {err:?}"
            );
            assert!(
                err.detail.contains("`rpc_url`"),
                "[networks.{network}], {shape}: names the key: {}",
                err.detail
            );
            assert!(
                err.detail.contains(&format!("[networks.{network}]")),
                "[networks.{network}], {shape}: names the table: {}",
                err.detail
            );
        }
    }

    // The line is the KEY's, not the header's plus one: below a comment and a
    // key that loads, the refusal still lands on the `rpc_url` line.
    let text = format!(
        "# operator notes\n[networks.arbitrum-one]\nbootstrap = [\"192.0.2.10:10000\"]\n\
         rpc_url = \"https://rpc.example/v2/{RPC_URL_CANARY}\"\n"
    );
    let err = parse(&text).expect_err("`rpc_url` beside a valid key is still refused");
    assert_eq!(err.line, 4, "the `rpc_url` line is named: {err:?}");

    // R2: the section name is validated before the key is refused.
    let text =
        format!("[networks.ropsten]\nrpc_url = \"https://rpc.example/v2/{RPC_URL_CANARY}\"\n");
    let err = parse(&text).expect_err("an unknown network is refused");
    assert!(
        err.detail.contains("not a known network") && err.detail.contains("ropsten"),
        "an unknown network keeps its own answer: {}",
        err.detail
    );
    assert!(
        !err.detail.contains(RPC_URL_CANARY),
        "…which does not echo the value either: {}",
        err.detail
    );
}

/// **U94 (D180) — raised before dispatch, so before any passphrase.** Through
/// the binary: an `rpc_url` key is the malformed-config code (17) with its
/// envelope, on a command that needs no vault and never prompts (`verify`'s
/// own code would be 4 — the bundle does not exist — so the 17 is the config
/// loader's). Neither the `--json` document nor plain mode's stderr carries
/// the value. The control is the same vehicle over a config without the key.
#[test]
fn an_rpc_url_key_is_exit_17_before_any_command_runs() {
    let dir = TestDir::new("rpc-url-wiring");
    let layout = layout_with_config(&dir, None);
    let root = layout.root().to_path_buf();
    std::fs::write(
        layout.beside_path(BesideFile::Config),
        format!(
            "default_network = \"arbitrum-one\"\n\n[networks.arbitrum-one]\n\
             rpc_url = \"https://rpc.example/v2/{RPC_URL_CANARY}\"\n"
        ),
    )
    .expect("write config");

    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(
        out.status.code(),
        Some(17),
        "malformed-config code; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'))
            .expect("one JSON document");
    assert_eq!(doc["error"]["class"], serde_json::json!("malformed-config"));
    let message = doc["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains("`rpc_url`") && message.contains("[networks.arbitrum-one]"),
        "names the key and the table: {message}"
    );
    assert!(
        message.contains("config.toml:4"),
        "names the line: {message}"
    );
    for (stream, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains(RPC_URL_CANARY),
            "--json {stream} must not carry the value: {text}"
        );
    }

    // Plain mode: the same code, the refusal on stderr, still without the value.
    let out = spawn(&root, &["verify", "b.sealproof"]);
    assert_eq!(out.status.code(), Some(17), "plain mode: the same code");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("`rpc_url`"),
        "plain stderr names the key: {stderr}"
    );
    assert!(
        !stderr.contains(RPC_URL_CANARY),
        "plain stderr must not carry the value: {stderr}"
    );
    assert!(out.stdout.is_empty(), "plain mode prints nothing on stdout");

    // The control: the same vehicle over the same file without the key.
    std::fs::write(
        layout.beside_path(BesideFile::Config),
        "default_network = \"arbitrum-one\"\n",
    )
    .expect("write config");
    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "without the key the config loads and the handler's own code follows"
    );
}

/// **U44 (D188 R5) — the flat `[verify] arbitrum_endpoints`, through the
/// binary.** Exit 17 with its envelope before any command runs (on `verify`,
/// whose own code for a missing bundle would be 4), naming the key, the table
/// and the line, and the value on neither stream. The control is the same
/// vehicle once the pair has moved to its per-network table.
#[test]
fn a_flat_arbitrum_endpoints_key_is_exit_17_before_any_command_runs() {
    let dir = TestDir::new("flat-arbitrum-wiring");
    let layout = layout_with_config(&dir, None);
    let root = layout.root().to_path_buf();
    std::fs::write(
        layout.beside_path(BesideFile::Config),
        format!(
            "[verify]\narbitrum_endpoints = [\"https://a.example/v2/{RPC_URL_CANARY}\", \
             \"https://b.example/v2/{RPC_URL_CANARY}\"]\n"
        ),
    )
    .expect("write config");

    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(
        out.status.code(),
        Some(17),
        "malformed-config code; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'))
            .expect("one JSON document");
    assert_eq!(doc["error"]["class"], serde_json::json!("malformed-config"));
    let message = doc["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains("`arbitrum_endpoints`")
            && message.contains("[verify.arbitrum-one]")
            && message.contains("config.toml:2"),
        "names the key, the replacement table and the line: {message}"
    );
    for (stream, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains(RPC_URL_CANARY),
            "{stream} must not carry the value: {text}"
        );
    }

    // The control: the same pair, moved to where it now lives, loads.
    std::fs::write(
        layout.beside_path(BesideFile::Config),
        format!(
            "[verify.arbitrum-one]\nrpc_endpoints = [\"https://a.example/v2/{RPC_URL_CANARY}\", \
             \"https://b.example/v2/{RPC_URL_CANARY}\"]\n"
        ),
    )
    .expect("write config");
    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "with the pair under [verify.arbitrum-one] the config loads and the handler's own \
         code follows; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ─────────────────────────────────────────────────────────────────────
// D47 cross-test: exported config survives import and still resolves
// ─────────────────────────────────────────────────────────────────────

#[test]
fn exported_config_survives_import_and_resolves() {
    use antseal_cli::vault::export::{export_vault, import_vault};
    use antseal_cli::vault::kdf::KdfSelection;
    use antseal_cli::vault::session::create_vault;
    use antseal_core::crypto::secrets::SecretBuf;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    let dir = TestDir::new("crosstest");
    let layout = VaultLayout::at(dir.path().join("vault"));
    let passphrase = || SecretBuf::new(b"correct horse battery staple fixture".to_vec());
    let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
    let vault =
        create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng).expect("create");
    // U44 Accept 5, restated (D188 R7): the export round trip carries the new
    // keys and they load. (`init` writes none of them, so there is no "old
    // shape" in `initial_config_text` to replace; `initial_config_round_trips`
    // asserts it still parses with zero warnings.)
    let config_text = "default_network = \"devnet\"\n\n[anchors]\n\
                       tsa_urls = [\"https://freetsa.org/tsr\"]\n\
                       ots_calendars = [\"https://cal.example.org\"]\n\
                       opportunistic_upgrades = false\n\n\
                       [verify.arbitrum-sepolia]\n\
                       rpc_endpoints = [\"https://sep-a.example\", \"https://sep-b.example\"]\n";
    antseal_cli::vault::fs::atomic_write(
        &layout.beside_path(BesideFile::Config),
        config_text.as_bytes(),
    )
    .expect("write config");
    let backup = dir.path().join("backup.sealvault");
    export_vault(&vault, &passphrase(), &backup, &mut rng).expect("export");
    drop(vault);
    std::fs::remove_dir_all(layout.root()).expect("wipe");

    import_vault(&backup, &layout, || Ok(passphrase()), &mut rng).expect("import");
    assert_eq!(
        std::fs::read(layout.beside_path(BesideFile::Config)).expect("config restored"),
        config_text.as_bytes(),
        "byte-identical through the round trip"
    );
    let config = load_from(&layout).expect("restored config loads");
    assert_eq!(config.default_network, Some(NetworkId::Devnet));
    assert_eq!(config.tsa_urls.as_ref().map(Vec::len), Some(1));
    assert_eq!(
        config.ots_calendars.as_deref(),
        Some(&["https://cal.example.org".to_owned()][..])
    );
    assert_eq!(
        config
            .verify_rpc_endpoints(NetworkId::ArbitrumSepolia)
            .map(<[String]>::len),
        Some(2)
    );
    assert_eq!(config.opportunistic_upgrades, Some(false));
    assert!(config.warnings.is_empty(), "{:?}", config.warnings);
    assert_eq!(effective_network(None, &config), NetworkId::Devnet);
}

// ─────────────────────────────────────────────────────────────────────
// U99 (D195 R4) — no URL-list refusal repeats its value
// ─────────────────────────────────────────────────────────────────────

/// What a URL-list refusal must never repeat: a credential in a URL's
/// userinfo. NON-SECRET: a marker string, not a password.
const URL_CANARY: &str = "NOT-A-PW-canary";

/// The three URL-list keys whose refusals repeated their entry before U99,
/// each with its table (`rpc_endpoints`' never did — D188 R5).
const URL_LIST_KEYS: [(&str, &str); 3] = [
    ("anchors", "tsa_urls"),
    ("anchors", "ots_calendars"),
    ("verify", "bitcoin_endpoints"),
];

/// **U99 Accept, at load (D195 R4).** Seven shapes in which a URL-list entry
/// carries a credential, each refused on the key's line naming the key — and
/// no refusal carries the value. The shapes are the three paths that repeated
/// it before: the substrate's parser (userinfo with and without a password,
/// and userinfo in a URL that does not parse at all, where no structural
/// redaction could find the credential), the shape check (no scheme,
/// `ftp://`) and the subset's own sentence (an unquoted entry, an unquoted
/// value). Each hostile entry sits FIRST in a list whose second entry is
/// valid, so a `bitcoin_endpoints` list is refused for its entry and not for
/// its count (U101). The control is the same list without the credential.
#[test]
fn no_url_list_refusal_repeats_its_value() {
    let c = URL_CANARY;
    let ok = "\"https://ok.example/\"";
    let shapes = [
        (
            "https userinfo",
            format!("[\"https://user:{c}@host.example/x\", {ok}]"),
            "entry 0 is not a usable endpoint URL (userinfo",
        ),
        (
            "userinfo without a password",
            format!("[\"http://{c}@host.example/x\", {ok}]"),
            "entry 0 is not a usable endpoint URL (userinfo",
        ),
        (
            "userinfo in a URL that does not parse",
            format!("[\"https://user:{c} x@host.example/x\", {ok}]"),
            "entry 0 is not a usable endpoint URL (not a valid URI)",
        ),
        (
            "no scheme",
            format!("[\"user:{c}@host.example/x\", {ok}]"),
            "entry 0 is not an http:// or https:// URL",
        ),
        (
            "ftp",
            format!("[\"ftp://user:{c}@host.example/x\", {ok}]"),
            "entry 0 is not an http:// or https:// URL",
        ),
        (
            "an unquoted entry",
            format!("[https://user:{c}@host.example/x, {ok}]"),
            "entry 0: the value is not a quoted string",
        ),
        (
            "an unquoted value",
            format!("https://user:{c}@host.example/x"),
            "not a quoted string",
        ),
    ];
    assert_eq!(
        shapes.len() * URL_LIST_KEYS.len(),
        21,
        "seven shapes, three keys"
    );
    let mut checked = 0;
    for (table, key) in URL_LIST_KEYS {
        for (shape, value, needle) in &shapes {
            let err = parse(&format!("[{table}]\n{key} = {value}\n")).expect_err(shape);
            assert_eq!(err.line, 2, "`{key}`, {shape}: the key's line: {err:?}");
            // First, so a restored echo fails on the echo and not on wording.
            assert!(
                !err.detail.contains(c) && !err.detail.contains("example"),
                "`{key}`, {shape}: the refusal must not carry the value — a URL can carry a \
                 credential: {}",
                err.detail
            );
            assert!(
                err.detail.contains(&format!("`{key}`")) && err.detail.contains(needle),
                "`{key}`, {shape}: expected the key and {needle:?} in {}",
                err.detail
            );
            checked += 1;
        }
        let clean = format!("[{table}]\n{key} = [\"https://host.example/x\", {ok}]\n");
        let config = parse(&clean).unwrap_or_else(|e| panic!("`{key}`: the control loads: {e:?}"));
        assert!(config.warnings.is_empty(), "{:?}", config.warnings);
    }
    assert_eq!(checked, 21, "every case ran");
}

/// **U99 Accept, through the binary (D195 R4).** A `tsa_urls`,
/// `ots_calendars` or `bitcoin_endpoints` entry carrying `user:<canary>@` is
/// the malformed-config code (17) with its envelope, on a command that needs
/// no vault and never prompts (`verify`'s own code would be 4 — the bundle
/// does not exist — so the 17 is the config loader's). The message names the
/// key and `config.toml:2`, and the canary is on neither stream, in `--json`
/// mode or plain. The control is the same vehicle with the userinfo removed.
#[test]
fn a_credential_in_a_url_entry_is_exit_17_and_never_printed() {
    let dir = TestDir::new("url-credential-wiring");
    let layout = layout_with_config(&dir, None);
    let root = layout.root().to_path_buf();
    let c = URL_CANARY;
    let mut checked = 0;
    for (table, key) in URL_LIST_KEYS {
        let config = layout.beside_path(BesideFile::Config);
        let hostile = format!(
            "[{table}]\n{key} = [\"https://user:{c}@host.example/x\", \"https://ok.example/\"]\n"
        );
        std::fs::write(&config, hostile).expect("write config");

        let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
        assert_eq!(
            out.status.code(),
            Some(17),
            "`{key}`: malformed-config code; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let doc: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'))
                .expect("one JSON document");
        assert_eq!(doc["error"]["class"], serde_json::json!("malformed-config"));
        let message = doc["error"]["message"].as_str().expect("a message");
        assert!(
            message.contains(&format!("`{key}`")) && message.contains("config.toml:2"),
            "`{key}`: names the key and the line: {message}"
        );
        for (stream, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
            let text = String::from_utf8_lossy(bytes);
            assert!(
                !text.contains(c),
                "`{key}`: --json {stream} must not carry the credential: {text}"
            );
        }

        let out = spawn(&root, &["verify", "b.sealproof"]);
        assert_eq!(
            out.status.code(),
            Some(17),
            "`{key}`: plain mode, the same code"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(&format!("`{key}`")) && !stderr.contains(c),
            "`{key}`: plain stderr names the key and never the credential: {stderr}"
        );
        assert!(
            out.stdout.is_empty(),
            "`{key}`: plain mode prints nothing on stdout"
        );

        let clean =
            format!("[{table}]\n{key} = [\"https://host.example/x\", \"https://ok.example/\"]\n");
        std::fs::write(&config, clean).expect("write config");
        let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
        assert_eq!(
            out.status.code(),
            Some(4),
            "`{key}`: without the userinfo the config loads and the handler's own code \
             follows; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        checked += 1;
    }
    assert_eq!(checked, 3, "every key ran");
}

// ─────────────────────────────────────────────────────────────────────
// U101 (D196 R3) — `[verify] bitcoin_endpoints` is checked when the file is read
// ─────────────────────────────────────────────────────────────────────

/// **U101 Accept, at load (D196 R3).** `[verify] bitcoin_endpoints` is exactly
/// two endpoints at two origins, checked when the file is read by the one
/// validator `verify --online`, `status --upgrade` and the opportunistic pass
/// also build their pair with — so a list of none, one or three, two URLs at
/// one origin, or a bad entry (one with a query or a fragment included: esplora
/// appends request paths to it), is a malformed config naming the key, the
/// table, the line and the count or the entry's position, never a URL (U99).
/// The canary sits in each URL's path. The control is two https endpoints at
/// two origins.
#[test]
fn bitcoin_endpoints_is_exactly_two_distinct_origins_at_load() {
    let c = URL_CANARY;
    let cases = [
        (
            "no entries",
            "[]".to_owned(),
            "must list exactly two endpoints (found 0)",
        ),
        (
            "one entry",
            format!("[\"https://a.example/{c}\"]"),
            "must list exactly two endpoints (found 1)",
        ),
        (
            "three entries",
            format!(
                "[\"https://a.example/{c}\", \"https://b.example/{c}\", \"https://c.example/{c}\"]"
            ),
            "must list exactly two endpoints (found 3)",
        ),
        (
            "one origin, two spellings",
            format!("[\"https://a.example/{c}\", \"https://A.example:443/{c}/y\"]"),
            "entries 0 and 1 are one origin",
        ),
        (
            "userinfo in entry 1",
            format!("[\"https://a.example/{c}\", \"https://user:{c}@b.example/\"]"),
            "entry 1 is not a usable endpoint URL (userinfo",
        ),
        (
            "plain http in entry 1",
            format!("[\"https://a.example/{c}\", \"http://b.example/{c}\"]"),
            "entry 1 must be https",
        ),
        // D196 R3, widened: esplora appends request paths to the base, so a
        // query or a fragment would swallow them. A key in a query is the
        // shape a keyed provider uses, so the canary sits there.
        (
            "a query in entry 0",
            format!("[\"https://a.example/api?key={c}\", \"https://b.example/api\"]"),
            "entry 0 carries a query or a fragment",
        ),
        (
            "a fragment in entry 1",
            format!("[\"https://a.example/api\", \"https://b.example/api#{c}\"]"),
            "entry 1 carries a query or a fragment",
        ),
    ];
    assert_eq!(cases.len(), 8);
    for (shape, value, needle) in &cases {
        let text = format!("[verify]\nbitcoin_endpoints = {value}\n");
        let err = match parse(&text) {
            Err(err) => err,
            Ok(config) => panic!(
                "{shape}: must be refused at load, got {:?}",
                config.verify_bitcoin_endpoints
            ),
        };
        assert_eq!(err.line, 2, "{shape}: the key's line: {err:?}");
        assert!(
            !err.detail.contains(c) && !err.detail.contains("example"),
            "{shape}: never a URL or a host: {}",
            err.detail
        );
        assert!(
            err.detail.contains("`bitcoin_endpoints` under [verify]")
                && err.detail.contains(needle),
            "{shape}: expected the key, the table and {needle:?} in {}",
            err.detail
        );
    }

    let ok = parse(&format!(
        "[verify]\nbitcoin_endpoints = [\"https://a.example/{c}\", \"https://b.example/{c}\"]\n"
    ))
    .expect("two https endpoints at two origins load");
    assert_eq!(ok.verify_bitcoin_endpoints.as_ref().map(Vec::len), Some(2));
}

/// **U101 Accept, through the binary (D196 R3).** A one-entry
/// `bitcoin_endpoints` is the malformed-config code (17) with its envelope on
/// a command that needs no vault and never prompts (`verify`'s own code would
/// be 4 — the bundle does not exist), naming the key, the table, the line and
/// the count. Before U101 the same file loaded, `verify` without `--online`
/// never noticed, and the opportunistic pass skipped silently. The control is
/// the same vehicle with a valid pair.
#[test]
fn a_bad_bitcoin_pair_is_exit_17_before_any_command_runs() {
    let dir = TestDir::new("bitcoin-pair-wiring");
    let layout = layout_with_config(&dir, None);
    let root = layout.root().to_path_buf();
    let config = layout.beside_path(BesideFile::Config);

    std::fs::write(
        &config,
        "[verify]\nbitcoin_endpoints = [\"https://a.example\"]\n",
    )
    .expect("write config");
    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(
        out.status.code(),
        Some(17),
        "malformed-config code; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'))
            .expect("one JSON document");
    assert_eq!(doc["error"]["class"], serde_json::json!("malformed-config"));
    let message = doc["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains("`bitcoin_endpoints` under [verify]")
            && message.contains("config.toml:2")
            && message.contains("found 1"),
        "names the key, the table, the line and the count: {message}"
    );
    assert!(!message.contains("a.example"), "never the URL: {message}");

    std::fs::write(
        &config,
        "[verify]\nbitcoin_endpoints = [\"https://a.example\", \"https://b.example\"]\n",
    )
    .expect("write config");
    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "a valid pair loads and the handler's own code follows; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ─────────────────────────────────────────────────────────────────────
// U100 (D196 R1, R2) — a known key outside its home table is refused
// ─────────────────────────────────────────────────────────────────────

/// **U100 Accept, at load (D196 R1, R2).** Every key this build reads, written
/// in a table where it does not live, is a malformed config — not a warning —
/// naming the key, the table it was found in, the line and where it belongs,
/// and never the value. The value is an inline table holding the canary: it
/// is outside the subset, so a refusal that waited for the value would fail on
/// the value instead, and one that repeated it would carry the canary. The
/// retired `arbitrum_endpoints` is refused in every table, and under a
/// per-network table it points at `rpc_endpoints` in that same table. The
/// control: an unknown key in each of the same tables still only warns
/// (D189 R3).
#[test]
fn a_known_key_outside_its_table_is_refused_by_name() {
    let c = RPC_URL_CANARY;
    let value = format!("{{ url = \"https://a.example/v2/{c}\" }}");
    let tables = [
        None,
        Some("anchors"),
        Some("verify"),
        Some("verify.arbitrum-one"),
        Some("networks.arbitrum-one"),
        Some("future"),
    ];
    // Each key's home and its words, written down here apart from the
    // loader's own table, so the two are independent witnesses.
    let live = [
        (
            "default_network",
            None,
            "it belongs at the top of the file, before the first [table] header",
        ),
        (
            "bootstrap",
            Some("networks.arbitrum-one"),
            "it belongs under [networks.arbitrum-one]",
        ),
        ("tsa_urls", Some("anchors"), "it belongs under [anchors]"),
        (
            "ots_calendars",
            Some("anchors"),
            "it belongs under [anchors]",
        ),
        (
            "opportunistic_upgrades",
            Some("anchors"),
            "it belongs under [anchors]",
        ),
        (
            "bitcoin_endpoints",
            Some("verify"),
            "it belongs under [verify]",
        ),
        (
            "rpc_endpoints",
            Some("verify.arbitrum-one"),
            "it belongs under [verify.arbitrum-one] or [verify.arbitrum-sepolia]",
        ),
    ];
    let mut cases: Vec<(&str, Option<&str>, &str)> = Vec::new();
    for (key, home, belongs) in live {
        for table in tables {
            if table != home {
                cases.push((key, table, belongs));
            }
        }
    }
    for table in [
        None,
        Some("anchors"),
        Some("verify.arbitrum-one"),
        Some("verify.arbitrum-sepolia"),
        Some("networks.arbitrum-one"),
        Some("future"),
    ] {
        let instead = if table.is_some_and(|t| t.starts_with("verify.")) {
            "write `rpc_endpoints` in this table instead"
        } else {
            "write `rpc_endpoints` under [verify.arbitrum-one] or [verify.arbitrum-sepolia] instead"
        };
        cases.push(("arbitrum_endpoints", table, instead));
    }
    assert_eq!(
        cases.len(),
        7 * 6 - 7 + 6,
        "seven live keys in five foreign tables each, and the retired one in six"
    );

    // Every case is judged and every failure kept, so a defect in ONE key's
    // home reddens that key's rows alone and the report shows which.
    let mut failures = Vec::new();
    for (key, table, belongs) in &cases {
        let (text, line, found) = match table {
            None => (
                format!("# misplaced\n{key} = {value}\n"),
                2,
                "at the top level".to_owned(),
            ),
            Some(table) => (
                format!("# misplaced\n[{table}]\n{key} = {value}\n"),
                3,
                format!("under [{table}]"),
            ),
        };
        let failure = match parse(&text) {
            Ok(config) => Some(format!(
                "`{key}` {found} must be refused, not warned on: {:?}",
                config.warnings
            )),
            Err(err) if err.line != line => Some(format!(
                "`{key}` {found}: the key's line is {line}: {err:?}"
            )),
            Err(err) if err.detail.contains(c) => Some(format!(
                "`{key}` {found}: the refusal must not carry the value: {}",
                err.detail
            )),
            Err(err)
                if !(err.detail.contains(&format!("`{key}`"))
                    && err.detail.contains(&found)
                    && err.detail.contains(belongs)) =>
            {
                Some(format!(
                    "`{key}` {found}: expected the key, the table and {belongs:?} in {}",
                    err.detail
                ))
            }
            Err(_) => None,
        };
        failures.extend(failure);
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );

    // The order (D196 R1): a table's network name is judged before its key,
    // so an unknown network keeps its own answer and `[verify.devnet]` its
    // own refusal, whatever known key sits in the table.
    for (text, needle) in [
        (
            "[networks.ropsten]\nrpc_endpoints = [\"https://a.example\"]\n",
            "`[networks.ropsten]` is not a known network",
        ),
        (
            "[verify.ropsten]\nbitcoin_endpoints = [\"https://a.example\"]\n",
            "`[verify.ropsten]` is not a known network",
        ),
        (
            "[verify.devnet]\nbitcoin_endpoints = [\"https://a.example\"]\n",
            "`[verify.devnet]` is refused",
        ),
    ] {
        let err = parse(text).expect_err(text);
        assert!(
            err.detail.contains(needle),
            "{text:?}: the table is judged before the key: {}",
            err.detail
        );
    }

    // The control: a key this build does not know only warns, in each table.
    let unknown: String = tables
        .iter()
        .map(|table| match table {
            None => "future_knob = 1\n".to_owned(),
            Some(table) => format!("[{table}]\nfuture_knob = 1\n"),
        })
        .collect();
    let config = parse(&unknown).expect("an unknown key only warns, in any table");
    assert_eq!(config.warnings.len(), 6, "{:#?}", config.warnings);
}

/// **U100 Accept, through the binary (D196 R1).** A flat `[verify]
/// rpc_endpoints` is exit 17 with its envelope before any command runs (on
/// `verify`, whose own code for a missing bundle would be 4), naming the key,
/// the table it was found in, where it belongs and the line, with the value on
/// neither stream; the control is the same line under `[verify.arbitrum-one]`.
/// And a `default_network` written after a table header — which TOML puts in
/// that table — is exit 17 rather than a run on the built-in arbitrum-one; its
/// control is the same key moved to the top, which the envelope reports.
#[test]
fn a_misplaced_rpc_endpoints_is_exit_17_before_any_command_runs() {
    let dir = TestDir::new("misplaced-key-wiring");
    let layout = layout_with_config(&dir, None);
    let root = layout.root().to_path_buf();
    let config = layout.beside_path(BesideFile::Config);
    let c = RPC_URL_CANARY;
    let pair =
        format!("rpc_endpoints = [\"https://a.example/v2/{c}\", \"https://b.example/v2/{c}\"]\n");
    let message_of = |out: &std::process::Output| -> String {
        let doc: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'))
                .expect("one JSON document");
        assert_eq!(doc["error"]["class"], serde_json::json!("malformed-config"));
        doc["error"]["message"]
            .as_str()
            .expect("a message")
            .to_owned()
    };

    std::fs::write(&config, format!("[verify]\n{pair}")).expect("write config");
    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(
        out.status.code(),
        Some(17),
        "malformed-config code; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let message = message_of(&out);
    assert!(
        message.contains("`rpc_endpoints` is not read under [verify]")
            && message.contains("[verify.arbitrum-one]")
            && message.contains("config.toml:2"),
        "names the key, the table, where it belongs and the line: {message}"
    );
    for (stream, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains(c),
            "{stream} must not carry the value: {text}"
        );
    }

    std::fs::write(&config, format!("[verify.arbitrum-one]\n{pair}")).expect("write config");
    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "under its own table the pair loads and the handler's own code follows; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let anchors = "[anchors]\ntsa_urls = [\"https://tsa.example/tsr\"]\n";
    let sepolia = "default_network = \"arbitrum-sepolia\"\n";
    std::fs::write(&config, format!("{anchors}{sepolia}")).expect("write config");
    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(
        out.status.code(),
        Some(17),
        "a default_network after a header is refused, not ignored; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let message = message_of(&out);
    assert!(
        message.contains("`default_network` is not read under [anchors]")
            && message.contains("config.toml:3"),
        "names the key, the table and the line: {message}"
    );

    std::fs::write(&config, format!("{sepolia}{anchors}")).expect("write config");
    let out = spawn(&root, &["--json", "verify", "b.sealproof"]);
    assert_eq!(out.status.code(), Some(4), "at the top the key loads");
    let doc: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'))
            .expect("one JSON document");
    assert_eq!(doc["network"], serde_json::json!("arbitrum-sepolia"));
}

/// **G100-3 (D196 R5).** Every key of the full schema has a home: moved under a
/// table no key lives in, each is refused, never warned on — so a key added to
/// the loader and to `FULL_SCHEMA` without a home reddens here. Measured yield
/// when written: 0 (every key already had one).
#[test]
fn every_full_schema_key_is_refused_outside_its_home() {
    let keys: Vec<&str> = FULL_SCHEMA
        .lines()
        .filter_map(|line| line.split_once(" = ").map(|(key, _)| key.trim()))
        .collect();
    assert_eq!(keys.len(), 8, "{keys:?}");
    for key in keys {
        let refused = parse(&format!("[future]\n{key} = 1\n")).is_err();
        assert!(refused, "`{key}` only warns outside its home");
    }
}

// ─────────────────────────────────────────────────────────────────────
// U108 (D195 §2 R4) — a list entry outside the subset is named by position
// ─────────────────────────────────────────────────────────────────────

/// **U108 (D195 §2 R4).** A list entry the subset refuses — written without
/// quotes, a boolean, a nested array, an escape sequence, a stray or an
/// unterminated quote — is named by its position, counted from 0, in the house
/// form "`{key}` entry {N}: …", for every list key the subset parses; and
/// `rpc_endpoints`, whose refusal is a sentence of its own, carries the
/// position into it. Never the value: the unquoted entry carries the canary in
/// its userinfo. An unquoted bare value is not a list and has no entry to
/// name, so its refusal stays unnumbered. Every case is judged and every
/// failure kept, so the report shows which keys and positions broke.
#[test]
fn an_array_entry_outside_the_subset_is_named_by_its_position() {
    let c = URL_CANARY;
    let hostile = format!("https://user:{c}@host.example/x");
    let ok = "\"https://ok.example/\"";
    let subset = "the value is not a quoted string";
    // (label, config text, what the refusal must contain, numbered?)
    let mut cases: Vec<(String, String, String, bool)> = Vec::new();
    for (table, key, valid) in [
        ("anchors", "tsa_urls", ok),
        ("anchors", "ots_calendars", ok),
        ("verify", "bitcoin_endpoints", ok),
        ("networks.arbitrum-one", "bootstrap", "\"192.0.2.10:10000\""),
    ] {
        for (shape, value, needle, numbered) in [
            (
                "an unquoted second entry",
                format!("[{valid}, {hostile}]"),
                format!("`{key}` entry 1: {subset}"),
                true,
            ),
            (
                "an unquoted first entry",
                format!("[{hostile}, {valid}]"),
                format!("`{key}` entry 0: {subset}"),
                true,
            ),
            (
                "an unquoted bare value",
                hostile.clone(),
                format!("`{key}`: {subset}"),
                false,
            ),
        ] {
            cases.push((
                format!("`{key}`, {shape}"),
                format!("[{table}]\n{key} = {value}\n"),
                needle,
                numbered,
            ));
        }
    }
    // Every other per-entry reason, at the second position.
    for (shape, entry, reason) in [
        (
            "a boolean",
            "true".to_owned(),
            "array entries must be quoted strings: a boolean inside an array",
        ),
        (
            "a nested array",
            "[\"https://b.example/\"]".to_owned(),
            "nested arrays are outside the config subset",
        ),
        (
            "an escape sequence",
            format!("\"https://b.example/{c}\\t\""),
            "escape sequences are outside the antseal config subset",
        ),
        (
            "a stray quote",
            format!("\"https://b.example/{c}\" \"x\""),
            "stray \" inside a \"-quoted string",
        ),
        (
            "a closing quote followed by text",
            format!("\"https://b.example/{c}\" x"),
            "unterminated \"-quoted string",
        ),
        (
            "a quote that never closes",
            format!("\"https://b.example/{c}"),
            "unterminated string inside array",
        ),
    ] {
        cases.push((
            format!("`tsa_urls`, {shape} as the second entry"),
            format!("[anchors]\ntsa_urls = [{ok}, {entry}]\n"),
            format!("`tsa_urls` entry 1: {reason}"),
            true,
        ));
    }
    // `rpc_endpoints`' own sentence, under both networks.
    let pair = "takes a one-line array of exactly two quoted endpoint URLs";
    for network in ["arbitrum-one", "arbitrum-sepolia"] {
        let sentence = format!("`rpc_endpoints` under [verify.{network}] {pair}");
        for (shape, value, tail, numbered) in [
            (
                "an unquoted second entry",
                format!("[\"https://a.example/\", {hostile}]"),
                ", and entry 1 is not one;",
                true,
            ),
            (
                "an unquoted first entry",
                format!("[{hostile}, \"https://b.example/\"]"),
                ", and entry 0 is not one;",
                true,
            ),
            (
                "a boolean as the second entry",
                "[\"https://a.example/\", true]".to_owned(),
                ", and entry 1 is not one;",
                true,
            ),
            ("an unquoted bare value", hostile.clone(), ";", false),
        ] {
            cases.push((
                format!("`rpc_endpoints` under [verify.{network}], {shape}"),
                format!("[verify.{network}]\nrpc_endpoints = {value}\n"),
                format!("{sentence}{tail}"),
                numbered,
            ));
        }
    }
    assert_eq!(
        cases.len(),
        4 * 3 + 6 + 2 * 4,
        "four list keys in three shapes, six more reasons, and rpc_endpoints in four \
         shapes under two networks"
    );

    let mut failures = Vec::new();
    for (label, text, needle, numbered) in &cases {
        let failure = match parse(text) {
            Ok(_) => Some(format!("{label}: must be refused")),
            Err(err) if err.line != 2 => Some(format!("{label}: the key's line is 2: {err:?}")),
            // First, so a restored echo fails on the echo and not on wording.
            Err(err) if err.detail.contains(c) || err.detail.contains("example") => Some(format!(
                "{label}: the refusal must not carry the value: {}",
                err.detail
            )),
            Err(err) if !err.detail.contains(needle.as_str()) => {
                Some(format!("{label}: expected {needle:?} in {:?}", err.detail))
            }
            Err(err) if !numbered && err.detail.contains("entry") => Some(format!(
                "{label}: a bare value has no entry to name: {:?}",
                err.detail
            )),
            Err(_) => None,
        };
        failures.extend(failure);
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

// ─────────────────────────────────────────────────────────────────────
// U107 (D207) — the retired `rpc_url` is refused in every table
// ─────────────────────────────────────────────────────────────────────

/// **U107 (D207 R1, R4).** `rpc_url` is refused in every table, not only under
/// a `[networks.<id>]` one (D180): a malformed config on the key's line that
/// names the key and the table it was found in, says antseal reads no
/// payment-RPC override, and names the one RPC setting it does read — the
/// receipt check's `rpc_endpoints` pair, "in this table" under a
/// `[verify.<network>]` table. The value is an inline table holding the
/// canary: it is outside the subset, so a refusal that waited for the value
/// would fail on the value instead, and one that repeated it would carry the
/// canary. The controls: `[networks.<id>]` keeps D180's own words, and an
/// unknown key in each of the seven tables still only warns (D189 R3).
#[test]
fn rpc_url_is_refused_in_every_table() {
    let c = RPC_URL_CANARY;
    let value = format!("{{ url = \"https://rpc.example/v2/{c}\" }}");
    let tables = [
        None,
        Some("anchors"),
        Some("verify"),
        Some("verify.arbitrum-one"),
        Some("verify.arbitrum-sepolia"),
        Some("future"),
        Some("networks"),
    ];
    assert_eq!(
        tables.len(),
        7,
        "every kind of table but a [networks.<id>] one"
    );

    let mut failures = Vec::new();
    for table in tables {
        let (text, line, found) = match table {
            None => (
                format!("# retired\nrpc_url = {value}\n"),
                2,
                "at the top level".to_owned(),
            ),
            Some(table) => (
                format!("# retired\n[{table}]\nrpc_url = {value}\n"),
                3,
                format!("under [{table}]"),
            ),
        };
        // Under a per-network table the user is one key name away from the
        // receipt pair's line; anywhere else the text names both tables.
        let pair = if table.is_some_and(|t| t.starts_with("verify.")) {
            "the receipt check takes a pair — write `rpc_endpoints` with two endpoint URLs \
             in this table instead"
        } else {
            "the receipt check's pair is `rpc_endpoints` under [verify.arbitrum-one] or \
             [verify.arbitrum-sepolia]"
        };
        let named = format!("`rpc_url` {found} is retired");
        let failure = match parse(&text) {
            Ok(config) => Some(format!(
                "`rpc_url` {found} must be refused, not warned on: {:?}",
                config.warnings
            )),
            Err(err) if err.line != line => Some(format!(
                "`rpc_url` {found}: the key's line is {line}: {err:?}"
            )),
            Err(err) if err.detail.contains(c) => Some(format!(
                "`rpc_url` {found}: the refusal must not carry the value: {}",
                err.detail
            )),
            Err(err)
                if !(err.detail.contains(&named)
                    && err.detail.contains("antseal reads no payment-RPC override")
                    && err.detail.contains(pair)) =>
            {
                Some(format!(
                    "`rpc_url` {found}: expected the key, the table, \"no payment-RPC \
                     override\" and {pair:?} in {}",
                    err.detail
                ))
            }
            Err(_) => None,
        };
        failures.extend(failure);
    }
    assert!(
        failures.is_empty(),
        "{} of {} tables failed:\n{}",
        failures.len(),
        tables.len(),
        failures.join("\n")
    );

    // Control 1: under `[networks.<id>]` `parse` refuses the key first, in
    // D180's own words, whatever the value.
    for network in ["arbitrum-one", "arbitrum-sepolia", "devnet"] {
        let err = parse(&format!("[networks.{network}]\nrpc_url = {value}\n")).expect_err(network);
        assert!(
            err.detail.contains(&format!(
                "`rpc_url` under [networks.{network}] is refused: antseal reads no \
                 payment-RPC override"
            )) && !err.detail.contains("is retired")
                && !err.detail.contains(c),
            "[networks.{network}] keeps D180's text: {}",
            err.detail
        );
    }

    // Control 2: a key this build does not know only warns, in each table.
    let unknown: String = tables
        .iter()
        .map(|table| match table {
            None => "future_knob = 1\n".to_owned(),
            Some(table) => format!("[{table}]\nfuture_knob = 1\n"),
        })
        .collect();
    let config = parse(&unknown).expect("an unknown key only warns, in any table");
    assert_eq!(config.warnings.len(), 7, "{:#?}", config.warnings);
}

/// **U107 Accept, through the binary (D207 R4).** `rpc_url` under
/// `[verify.arbitrum-one]` and at the top level is the malformed-config code
/// (17) with its envelope before any command runs (on `verify`, whose own
/// code for a missing bundle would be 4), naming the key, the table and the
/// line, with the value on neither stream. The control is an unknown key on
/// the same line, which only warns, so the handler's own code follows.
#[test]
fn an_rpc_url_key_in_any_table_is_exit_17_before_any_command_runs() {
    let dir = TestDir::new("rpc-url-any-table-wiring");
    let layout = layout_with_config(&dir, None);
    let root = layout.root().to_path_buf();
    let config = layout.beside_path(BesideFile::Config);
    let c = RPC_URL_CANARY;
    let cases = [
        (
            "[verify.arbitrum-one]\n",
            "under [verify.arbitrum-one]",
            "config.toml:2",
        ),
        ("", "at the top level", "config.toml:1"),
    ];
    assert_eq!(cases.len(), 2);
    for (header, found, line) in cases {
        std::fs::write(
            &config,
            format!("{header}rpc_url = \"https://rpc.example/v2/{c}\"\n"),
        )
        .expect("write config");
        let out = spawn(&root, &["--json", "verify", "missing.sealproof"]);
        assert_eq!(
            out.status.code(),
            Some(17),
            "{found}: malformed-config code; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let doc: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'))
                .expect("one JSON document");
        assert_eq!(doc["error"]["class"], serde_json::json!("malformed-config"));
        let message = doc["error"]["message"].as_str().expect("a message");
        assert!(
            message.contains(&format!("`rpc_url` {found} is retired"))
                && message.contains("no payment-RPC override")
                && message.contains(line),
            "{found}: names the key, the table and the line: {message}"
        );
        for (stream, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
            let text = String::from_utf8_lossy(bytes);
            assert!(
                !text.contains(c),
                "{found}: {stream} must not carry the value: {text}"
            );
        }
    }

    // The control: an unknown key on the same line only warns, and the
    // handler's own code follows.
    std::fs::write(
        &config,
        format!("[verify.arbitrum-one]\nfuture_knob = \"https://rpc.example/v2/{c}\"\n"),
    )
    .expect("write config");
    let out = spawn(&root, &["--json", "verify", "missing.sealproof"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(4),
        "an unknown key only warns; stderr: {stderr}"
    );
    assert!(
        stderr.contains("unknown key `future_knob` under [verify.arbitrum-one]")
            && !stderr.contains(c),
        "{stderr}"
    );
}
