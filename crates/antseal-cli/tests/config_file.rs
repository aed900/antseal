//! U4 acceptance suite: the config file — precedence (flag > config >
//! default), missing-file defaults, the malformed matrix (typed errors,
//! never silent), unknown-key warnings, network mapping distinctness via
//! S5's schema, and the D47 cross-test (exported config survives import
//! and still resolves).
//!
//! NON-SECRET: config text fixtures only.

use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};

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
rpc_url = "https://my-node.example/rpc"

[anchors]
tsa_urls = ["https://freetsa.org/tsr", "http://timestamp.digicert.com"]

[verify]
bitcoin_endpoints = ["https://btc-a.example", "https://btc-b.example"]
arbitrum_endpoints = ['https://arb-a.example', 'https://arb-b.example']
"#;
    let config = parse(text).expect("full schema parses");
    assert_eq!(config.default_network, Some(NetworkId::Devnet));
    assert_eq!(
        config.rpc_url_override(NetworkId::ArbitrumOne),
        Some("https://my-node.example/rpc")
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
    assert_eq!(
        config.verify_bitcoin_endpoints.as_ref().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        config.verify_arbitrum_endpoints.as_ref().map(Vec::len),
        Some(2)
    );
    assert!(config.warnings.is_empty());
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
        (
            "[networks.devnet]\nrpc_url = \"ftp://x\"\n",
            "http:// or https://",
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
    Process::new(env!("CARGO_BIN_EXE_antseal"))
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

    // Config supplies the network (`status` is an M2 stub → error
    // envelope, but the envelope's network field is the resolved one;
    // `list` played this role until U19 gave it a real handler).
    let out = spawn(&root, &["--json", "status", "w1"]);
    assert_eq!(out.status.code(), Some(3));
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
        &["--json", "--network", "arbitrum-one", "status", "w1"],
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
    let out = spawn(&root, &["--json", "status", "w1"]);
    assert_eq!(
        out.status.code(),
        Some(3),
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
    let out = spawn(&root, &["--json", "status", "w1"]);
    assert_eq!(out.status.code(), Some(17), "malformed-config code");
    let doc: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'))
            .expect("one JSON document");
    assert_eq!(doc["error"]["class"], serde_json::json!("malformed-config"));
    // Plain mode: same code, no stdout.
    let out = spawn(&root, &["status", "w1"]);
    assert_eq!(out.status.code(), Some(17));
    assert!(out.stdout.is_empty());
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
    let config_text =
        "default_network = \"devnet\"\n\n[anchors]\ntsa_urls = [\"https://freetsa.org/tsr\"]\n";
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
    assert_eq!(effective_network(None, &config), NetworkId::Devnet);
}
