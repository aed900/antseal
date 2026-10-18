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

#[test]
fn full_schema_parses_with_every_slot() {
    let text = r#"
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
    let config = parse(text).expect("full schema parses");
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
/// Refused at **load**, before any network call. The Bitcoin pair's refusal
/// names the endpoint; the Arbitrum RPC pair's names the entry by INDEX and
/// never the URL (U44, D188 R5: an RPC URL that answers
/// `eth_getTransactionReceipt` commonly carries an API key).
#[test]
fn a_plain_http_verify_endpoint_is_refused_at_config_load() {
    let text = "[verify]\nbitcoin_endpoints = [\"https://good.example\", \"http://plain.example/api\"]\n\
                [verify.arbitrum-one]\nrpc_endpoints = [\"https://a.example\", \"https://b.example\"]\n";
    let err = parse(text).expect_err("a plain-http must-agree endpoint is refused");
    let rendered = err.detail.clone();
    assert!(
        rendered.contains("http://plain.example/api"),
        "the failure must name the offending endpoint: {rendered}"
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
    // and a hostname that merely contains one, are both refused.
    for hostile in ["http://localhost:8332/", "http://127.0.0.1.evil.example/"] {
        let text = format!("[verify]\nbitcoin_endpoints = [\"{hostile}\"]\n");
        parse(&text).expect_err(hostile);
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
/// speak and embedded credentials are refused, naming the key, the entry and
/// the line. Order is kept as written and `[]` loads; that both collapse to
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
            err.detail.contains(entry),
            "{entry}: names the entry (a calendar URL is no credential): {}",
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
/// value, whatever its shape — including the unquoted one, which the subset's
/// own error would have repeated had the refusal waited for the value.
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

    // The retirement is the flat [verify] key's: under a per-network table the
    // name is an ordinary unknown key.
    let elsewhere = parse("[verify.arbitrum-one]\narbitrum_endpoints = [\"https://a.example\"]\n")
        .expect("not the retired key");
    assert_eq!(elsewhere.warnings.len(), 1, "{:?}", elsewhere.warnings);
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
/// that pins *where* the refusal is raised: the subset's own *not a quoted
/// string* error repeats the raw value it rejects, so a refusal raised after
/// the value is parsed would echo the URL for exactly the typo a user makes
/// most. The section name is judged first: an unknown network keeps its own
/// answer.
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
