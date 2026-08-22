//! The launcher's **exported surface**, rendered purely.
//!
//! P22 gave the launcher a second mode (`--network arbitrum-sepolia`), and
//! the two modes differ almost entirely in what they *export*: a different
//! chain id, and — the part that matters for project rule 6 — one fewer
//! key, because a Sepolia devnet embeds no wallet.
//!
//! Rendering therefore lives here rather than in [`crate::devnet`], for one
//! reason: `devnet.rs` is behind the non-default `devnet` feature, so every
//! assertion about the export text would otherwise cost the ~13-minute
//! release build of the 736-package ant-node graph before it could run
//! once. Nothing in this module touches ant-core, ant-node, tokio or the
//! filesystem — it is a pure `inputs -> String` function plus the flag's
//! value type — so `cargo test -p devnet-launcher` (default features,
//! seconds) is the lane that polices the format, in both modes, including
//! the local mode's byte-for-byte stability.
//!
//! The caller (`devnet.rs`) supplies the values; the rules about *where*
//! each value comes from live there.

use std::fmt;

// ---------------------------------------------------------------------------
// The `--network` flag
// ---------------------------------------------------------------------------

/// Which chain the booted nodes verify payments against.
///
/// `Local` (the default, so every pre-P22 invocation is unchanged) is P16's
/// Anvil devnet: a fresh chain per run, contracts deployed per run, a funded
/// well-known dev key embedded in the export.
///
/// `ArbitrumSepolia` is P17's environment: **the real deployed Arbitrum
/// Sepolia contracts**, no Anvil anywhere, and no wallet — "the user must
/// connect their own funded Sepolia wallet"
/// (`ant-core-0.5.0/examples/start-devnet-sepolia.rs:9-11`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NetworkMode {
    /// P16's local Anvil devnet. The default.
    #[default]
    Local,
    /// P17's Arbitrum Sepolia devnet, chain 421614.
    ArbitrumSepolia,
}

impl NetworkMode {
    /// Anvil's default chain id — `evmlib`'s `Testnet` starts it without
    /// overriding the default, and the boot-evidence procedure re-verifies
    /// this against `eth_chainId` (docs/devnet/local-devnet.md).
    pub const LOCAL_CHAIN_ID: u64 = 31_337;

    /// Arbitrum Sepolia — **NOT** Ethereum Sepolia (11155111). Pinned
    /// identically in `antseal_net::ARBITRUM_SEPOLIA_CHAIN_ID` (S5).
    pub const ARBITRUM_SEPOLIA_CHAIN_ID: u64 = 421_614;

    /// The accepted `--network` values, in the order the usage line lists
    /// them (default first).
    pub const ALL: [Self; 2] = [Self::Local, Self::ArbitrumSepolia];

    /// Parse a `--network` value.
    ///
    /// Case-sensitive by design, matching `antseal_net::NetworkId`'s own
    /// rule: `Local` is not a network name.
    ///
    /// # Errors
    ///
    /// A message naming the accepted set, and — because getting this wrong
    /// silently is the expensive mistake — carrying the wrong-Sepolia
    /// warning.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "local" => Ok(Self::Local),
            "arbitrum-sepolia" => Ok(Self::ArbitrumSepolia),
            other => Err(format!(
                "--network: unknown network: {other} (accepted: {}; arbitrum-sepolia means \
                 Arbitrum Sepolia chain 421614, NOT Ethereum Sepolia)",
                Self::ALL.map(Self::as_str).join(", ")
            )),
        }
    }

    /// The flag value that selects this mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::ArbitrumSepolia => "arbitrum-sepolia",
        }
    }

    /// The EVM chain id the export records for this mode.
    #[must_use]
    pub const fn chain_id(self) -> u64 {
        match self {
            Self::Local => Self::LOCAL_CHAIN_ID,
            Self::ArbitrumSepolia => Self::ARBITRUM_SEPOLIA_CHAIN_ID,
        }
    }

    /// Whether this mode spawns an Anvil subprocess — i.e. whether `anvil`
    /// must be on `PATH`.
    ///
    /// The Sepolia mode has no local chain at all (docs/devnet/
    /// sepolia-devnet.md, Host requirements: "**No `anvil`**"), so demanding
    /// the binary there would refuse a boot that needs nothing from it.
    #[must_use]
    pub const fn spawns_anvil(self) -> bool {
        match self {
            Self::Local => true,
            Self::ArbitrumSepolia => false,
        }
    }

    /// Whether the export carries a wallet key.
    ///
    /// Local: yes — Anvil dev account 0, a well-known public constant.
    /// Sepolia: **no**, and this is a rule-6 boundary rather than a
    /// convenience: a real Sepolia key is a real secret and never reaches a
    /// file the launcher writes.
    #[must_use]
    pub const fn exports_wallet_key(self) -> bool {
        match self {
            Self::Local => true,
            Self::ArbitrumSepolia => false,
        }
    }
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// The flat env export
// ---------------------------------------------------------------------------

/// Every value the flat `.devnet/env` export carries, already stringified
/// by the caller from whichever devnet shape produced it.
///
/// The flat file is the `source`-able side of the export; the JSON manifest
/// is the full-fidelity side. Values are single-quoted and nothing a devnet
/// produces can contain a single quote (ports, hex, URLs, local paths) —
/// [`EnvExport::render`] asserts that in debug builds rather than trusting
/// it.
pub struct EnvExport {
    /// Which mode booted. Decides the chain id and the wallet-key line.
    pub network: NetworkMode,
    /// EVM JSON-RPC endpoint (Anvil's, or Arbitrum Sepolia's public one).
    pub rpc_url: String,
    /// AutonomiNetworkToken address.
    pub token_address: String,
    /// PaymentVault address.
    pub payment_vault_address: String,
    /// The funded wallet key — `Some` only in local mode. Ignored (and
    /// asserted absent) in Sepolia mode.
    pub wallet_private_key: Option<String>,
    /// Node socket addresses (`ip:port`) for `Client::connect`.
    pub bootstrap: Vec<String>,
    /// Actual node count booted.
    pub node_count: usize,
    /// First node port.
    pub base_port: u16,
    /// Node store root.
    pub data_dir: String,
    /// Launcher pid — the devnet's lifetime handle.
    pub pid: u32,
}

impl EnvExport {
    /// The canonical key order, unchanged from P16.
    ///
    /// In Sepolia mode the `ANTSEAL_DEVNET_WALLET_PRIVATE_KEY` line is
    /// **omitted** — nine keys, not ten with an empty value. An empty value
    /// would parse, reach `WalletKey::import`, and fail as "not hex", which
    /// names the wrong problem; an absent key is a `MissingKey` naming the
    /// key, which names the right one.
    pub const KEYS: [&'static str; 10] = [
        "ANTSEAL_DEVNET_RPC_URL",
        "ANTSEAL_DEVNET_CHAIN_ID",
        "ANTSEAL_DEVNET_TOKEN_ADDRESS",
        "ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS",
        "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY",
        "ANTSEAL_DEVNET_BOOTSTRAP",
        "ANTSEAL_DEVNET_NODE_COUNT",
        "ANTSEAL_DEVNET_BASE_PORT",
        "ANTSEAL_DEVNET_DATA_DIR",
        "ANTSEAL_DEVNET_PID",
    ];

    /// Render the flat `KEY='value'` export text.
    ///
    /// Byte-for-byte the P16 format in [`NetworkMode::Local`]: same keys,
    /// same order, same quoting, same trailing newline. The local mode's
    /// stability is the property `p22_local_render_is_the_p16_format`
    /// pins.
    #[must_use]
    pub fn render(&self) -> String {
        let mut env = String::new();
        let mut push = |key: &str, value: &str| {
            debug_assert!(
                !value.contains('\''),
                "a devnet value contained a single quote, which the flat \
                 export format cannot represent: {key}"
            );
            env.push_str(key);
            env.push_str("='");
            env.push_str(value);
            env.push_str("'\n");
        };
        push("ANTSEAL_DEVNET_RPC_URL", &self.rpc_url);
        push(
            "ANTSEAL_DEVNET_CHAIN_ID",
            &self.network.chain_id().to_string(),
        );
        push("ANTSEAL_DEVNET_TOKEN_ADDRESS", &self.token_address);
        push(
            "ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS",
            &self.payment_vault_address,
        );
        // The funded wallet, local mode only: Anvil dev account 0 — the
        // token deployer, holding the entire premined supply. A WELL-KNOWN
        // PUBLIC CONSTANT, never a secret; it still lives only under the
        // gitignored `.devnet/`. In Sepolia mode there is no such constant
        // and no line.
        if self.network.exports_wallet_key()
            && let Some(key) = self.wallet_private_key.as_deref()
        {
            push("ANTSEAL_DEVNET_WALLET_PRIVATE_KEY", key);
        }
        push("ANTSEAL_DEVNET_BOOTSTRAP", &self.bootstrap.join(","));
        push("ANTSEAL_DEVNET_NODE_COUNT", &self.node_count.to_string());
        push("ANTSEAL_DEVNET_BASE_PORT", &self.base_port.to_string());
        push("ANTSEAL_DEVNET_DATA_DIR", &self.data_dir);
        push("ANTSEAL_DEVNET_PID", &self.pid.to_string());
        env
    }
}

// ---------------------------------------------------------------------------
// The JSON manifest — Sepolia mode only
// ---------------------------------------------------------------------------

/// The `DevnetManifest` fields, for the mode that has to render them itself.
///
/// Local mode does **not** come through here: it calls upstream's own
/// `LocalDevnet::write_manifest`, so the P16 manifest keeps upstream's exact
/// serialization and cannot drift. Sepolia mode has no such helper —
/// `LocalDevnet` is Anvil-only (see [`crate::devnet`]) — and
/// `devnet-launcher` declares no `serde_json` edge, so the shape is
/// rendered here, mirroring `ant_protocol::devnet_manifest::DevnetManifest`
/// field for field and matching upstream's own Sepolia example
/// (`ant-core-0.5.0/examples/start-devnet-sepolia.rs:70-82`).
pub struct ManifestExport {
    /// First node port.
    pub base_port: u16,
    /// Node count.
    pub node_count: usize,
    /// Bootstrap multiaddr strings.
    pub bootstrap: Vec<String>,
    /// Node store root.
    pub data_dir: String,
    /// Opaque creation stamp (upstream writes Unix seconds as text).
    pub created_at: String,
    /// EVM JSON-RPC endpoint.
    pub rpc_url: String,
    /// AutonomiNetworkToken address.
    pub payment_token_address: String,
    /// PaymentVault address.
    pub payment_vault_address: String,
}

impl ManifestExport {
    /// Render the manifest JSON.
    ///
    /// `evm.wallet_private_key` is the empty string, exactly as upstream's
    /// Sepolia example writes it (`start-devnet-sepolia.rs:78`): the field
    /// is not `Option` in `DevnetEvmInfo`, and a consumer that reads it
    /// gets an empty string it must reject rather than a key it must not
    /// have. Nothing secret is written, and nothing is invented.
    #[must_use]
    pub fn render_json(&self) -> String {
        let mut json = String::from("{\n");
        json.push_str(&format!("  \"base_port\": {},\n", self.base_port));
        json.push_str(&format!("  \"node_count\": {},\n", self.node_count));
        json.push_str("  \"bootstrap\": [");
        if self.bootstrap.is_empty() {
            json.push(']');
        } else {
            json.push('\n');
            for (index, addr) in self.bootstrap.iter().enumerate() {
                let comma = if index + 1 == self.bootstrap.len() {
                    ""
                } else {
                    ","
                };
                json.push_str(&format!("    {}{comma}\n", json_string(addr)));
            }
            json.push_str("  ]");
        }
        json.push_str(",\n");
        json.push_str(&format!(
            "  \"data_dir\": {},\n",
            json_string(&self.data_dir)
        ));
        json.push_str(&format!(
            "  \"created_at\": {},\n",
            json_string(&self.created_at)
        ));
        json.push_str("  \"evm\": {\n");
        json.push_str(&format!(
            "    \"rpc_url\": {},\n",
            json_string(&self.rpc_url)
        ));
        json.push_str("    \"wallet_private_key\": \"\",\n");
        json.push_str(&format!(
            "    \"payment_token_address\": {},\n",
            json_string(&self.payment_token_address)
        ));
        json.push_str(&format!(
            "    \"payment_vault_address\": {}\n",
            json_string(&self.payment_vault_address)
        ));
        json.push_str("  }\n}\n");
        json
    }
}

/// Render `text` as a JSON string literal (RFC 8259 §7).
///
/// Devnet values are URLs, hex addresses, multiaddrs and local paths, none
/// of which *should* need escaping — but a repo checked out under a path
/// containing a quote or a backslash would otherwise emit a broken
/// document, and "should" is not a parser.
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deliberately **not** hex, and deliberately not the real Anvil dev
    /// key even though that one is a public constant: the renderer does no
    /// hex validation, so a marker string exercises it identically while
    /// making it impossible for this fixture to be mistaken for — or
    /// mistakenly used as — key material (rule 6). If it ever showed up in
    /// a real export, it would be unmistakable.
    const FIXTURE_KEY: &str = "FIXTURE-WALLET-KEY-NOT-A-REAL-KEY";

    fn local_export() -> EnvExport {
        EnvExport {
            network: NetworkMode::Local,
            rpc_url: "http://127.0.0.1:53712/".to_owned(),
            token_address: "0x5FbDB2315678afecb367f032d93F642f64180aa3".to_owned(),
            payment_vault_address: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512".to_owned(),
            wallet_private_key: Some(FIXTURE_KEY.to_owned()),
            bootstrap: vec!["127.0.0.1:20001".to_owned(), "127.0.0.1:20002".to_owned()],
            node_count: 14,
            base_port: 20_001,
            data_dir: "/repo/.devnet/data".to_owned(),
            pid: 12_345,
        }
    }

    /// The Sepolia export — deliberately carrying a **populated** wallet
    /// field.
    ///
    /// A fixture with `wallet_private_key: None` would make every "no wallet
    /// key" assertion below pass for the wrong reason: the input had none,
    /// so the renderer could not have written one whatever the mode said.
    /// Measured, not assumed — flipping `exports_wallet_key()` to `true` for
    /// Sepolia leaves a `None`-fixture test green. The adversarial input is
    /// the one that tests the mode.
    fn sepolia_export() -> EnvExport {
        EnvExport {
            network: NetworkMode::ArbitrumSepolia,
            rpc_url: "https://sepolia-rollup.arbitrum.io/rpc".to_owned(),
            token_address: "0x4bc1aCE0E66170375462cB4E6Af42Ad4D5EC689C".to_owned(),
            payment_vault_address: "0xd742E8CFEf27A9a884F3EFfA239Ee2F39c276522".to_owned(),
            wallet_private_key: Some(FIXTURE_KEY.to_owned()),
            ..local_export()
        }
    }

    /// The keys a rendered export actually carries, in order.
    fn rendered_keys(text: &str) -> Vec<String> {
        text.lines()
            .filter_map(|line| line.split_once('=').map(|(key, _)| key.to_owned()))
            .collect()
    }

    /// P16's format, frozen as a literal. This is the no-regression half of
    /// P22 Accept row 1: `--network local` is the default, and the default's
    /// output is these exact bytes. A golden literal is the only form of
    /// this assertion that cannot pass by accident — computing the expected
    /// text from the same code under test would be green no matter what the
    /// renderer did.
    #[test]
    fn p22_local_render_is_the_p16_format() {
        let expected = format!(
            "ANTSEAL_DEVNET_RPC_URL='http://127.0.0.1:53712/'\n\
             ANTSEAL_DEVNET_CHAIN_ID='31337'\n\
             ANTSEAL_DEVNET_TOKEN_ADDRESS='0x5FbDB2315678afecb367f032d93F642f64180aa3'\n\
             ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS='0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512'\n\
             ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='{FIXTURE_KEY}'\n\
             ANTSEAL_DEVNET_BOOTSTRAP='127.0.0.1:20001,127.0.0.1:20002'\n\
             ANTSEAL_DEVNET_NODE_COUNT='14'\n\
             ANTSEAL_DEVNET_BASE_PORT='20001'\n\
             ANTSEAL_DEVNET_DATA_DIR='/repo/.devnet/data'\n\
             ANTSEAL_DEVNET_PID='12345'\n"
        );
        assert_eq!(local_export().render(), expected);
    }

    /// The default mode IS local — the property that makes every pre-P22
    /// invocation unchanged.
    #[test]
    fn p22_default_network_is_local() {
        assert_eq!(NetworkMode::default(), NetworkMode::Local);
        assert_eq!(NetworkMode::default().chain_id(), 31_337);
        assert!(NetworkMode::default().spawns_anvil());
        assert!(NetworkMode::default().exports_wallet_key());
    }

    /// Sepolia's export: nine keys, chain 421614, and **no** wallet line —
    /// the three things P22's `Do` names, asserted as data rather than
    /// prose.
    #[test]
    fn p22_sepolia_render_omits_the_wallet_and_carries_421614() {
        let text = sepolia_export().render();
        let keys = rendered_keys(&text);

        assert_eq!(keys.len(), 9, "a Sepolia export has nine keys:\n{text}");
        assert!(
            !keys
                .iter()
                .any(|k| k == "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY"),
            "the wallet key must not appear in a Sepolia export:\n{text}"
        );
        assert!(
            !text.contains("WALLET"),
            "no wallet-shaped line at all:\n{text}"
        );
        assert!(
            text.contains("ANTSEAL_DEVNET_CHAIN_ID='421614'"),
            "chain id must be Arbitrum Sepolia's:\n{text}"
        );
        assert!(
            !text.contains("31337"),
            "no Anvil chain id in a Sepolia export:\n{text}"
        );
        assert!(
            !text.contains("11155111"),
            "11155111 is Ethereum Sepolia, the wrong Sepolia:\n{text}"
        );

        // The nine are exactly P16's ten minus the wallet, in P16's order:
        // a consumer needs no second parser.
        let expected: Vec<&str> = EnvExport::KEYS
            .iter()
            .copied()
            .filter(|k| *k != "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY")
            .collect();
        assert_eq!(keys, expected);
    }

    /// A wallet key handed to a Sepolia export is dropped, not written. The
    /// mode is the authority, so a future caller cannot leak a real Sepolia
    /// key into a file by populating the field — and an absent field is not
    /// what makes the omission true.
    #[test]
    fn p22_sepolia_never_writes_a_wallet_key_even_if_given_one() {
        let given = sepolia_export();
        assert!(
            given.wallet_private_key.is_some(),
            "this test is only meaningful on a populated field"
        );
        let text = given.render();
        assert!(!text.contains(FIXTURE_KEY), "key leaked:\n{text}");
        assert_eq!(rendered_keys(&text).len(), 9);

        // …and the same when the caller supplies nothing.
        let empty = EnvExport {
            wallet_private_key: None,
            ..sepolia_export()
        };
        assert_eq!(rendered_keys(&empty.render()).len(), 9);
    }

    /// Sepolia mode requires **no** Anvil — the clause P22 Accept row 1
    /// names ("no Anvil anywhere in the process tree") reduced to the
    /// decision that produces it. Without this, flipping `spawns_anvil()`
    /// to `true` for Sepolia was measured to leave the whole suite green.
    #[test]
    fn p22_only_local_mode_spawns_anvil() {
        assert!(
            NetworkMode::Local.spawns_anvil(),
            "the local devnet IS an Anvil chain"
        );
        assert!(
            !NetworkMode::ArbitrumSepolia.spawns_anvil(),
            "a Sepolia devnet has no local chain: demanding `anvil` on PATH \
             would refuse a boot that needs nothing from it"
        );
    }

    /// The local export is ten keys — the count `DevnetEnv` requires. Pins
    /// the other side of the nine-vs-ten distinction.
    #[test]
    fn p22_local_export_is_ten_keys_in_the_documented_order() {
        let keys = rendered_keys(&local_export().render());
        assert_eq!(keys.len(), 10);
        assert_eq!(keys, EnvExport::KEYS.to_vec());
    }

    #[test]
    fn p22_network_flag_parses_and_round_trips() {
        for mode in NetworkMode::ALL {
            assert_eq!(NetworkMode::parse(mode.as_str()), Ok(mode));
        }
        assert_eq!(
            NetworkMode::parse("arbitrum-sepolia"),
            Ok(NetworkMode::ArbitrumSepolia)
        );
        // Case-sensitive, and the near-miss names are refused.
        for bad in ["Local", "sepolia", "arbitrum-one", "ethereum-sepolia", ""] {
            let err = NetworkMode::parse(bad).expect_err("must be refused");
            assert!(err.contains("local, arbitrum-sepolia"), "{err}");
            assert!(err.contains("NOT Ethereum Sepolia"), "{err}");
        }
    }

    #[test]
    fn p22_sepolia_manifest_json_is_wellformed_and_keyless() {
        let manifest = ManifestExport {
            base_port: 20_001,
            node_count: 14,
            bootstrap: vec![
                "/ip4/127.0.0.1/udp/20001/quic-v1".to_owned(),
                "/ip4/127.0.0.1/udp/20002/quic-v1".to_owned(),
            ],
            data_dir: "/repo/.devnet/data".to_owned(),
            created_at: "1755000000".to_owned(),
            rpc_url: "https://sepolia-rollup.arbitrum.io/rpc".to_owned(),
            payment_token_address: "0x4bc1aCE0E66170375462cB4E6Af42Ad4D5EC689C".to_owned(),
            payment_vault_address: "0xd742E8CFEf27A9a884F3EFfA239Ee2F39c276522".to_owned(),
        };
        let json = manifest.render_json();

        // Every DevnetManifest field is present, and the wallet slot is
        // upstream's empty string rather than anything key-shaped.
        for field in [
            "\"base_port\": 20001",
            "\"node_count\": 14",
            "\"data_dir\":",
            "\"created_at\":",
            "\"evm\":",
            "\"rpc_url\":",
            "\"wallet_private_key\": \"\"",
            "\"payment_token_address\":",
            "\"payment_vault_address\":",
        ] {
            assert!(json.contains(field), "missing {field} in:\n{json}");
        }
        assert!(json.contains("/ip4/127.0.0.1/udp/20002/quic-v1"), "{json}");

        // Balanced structure: a hand-rolled document that does not close is
        // the failure mode worth checking, and quote-counting catches an
        // unescaped value.
        assert_eq!(
            json.matches('{').count(),
            json.matches('}').count(),
            "unbalanced braces:\n{json}"
        );
        assert_eq!(
            json.matches('[').count(),
            json.matches(']').count(),
            "unbalanced brackets:\n{json}"
        );
        assert_eq!(json.matches('"').count() % 2, 0, "odd quote count:\n{json}");
    }

    /// A path containing a quote or a backslash must not break the
    /// document. `--dir` takes an arbitrary path, so this is reachable.
    #[test]
    fn p22_manifest_escapes_hostile_paths() {
        let manifest = ManifestExport {
            base_port: 1,
            node_count: 5,
            bootstrap: Vec::new(),
            data_dir: "/tmp/a\"b\\c\td".to_owned(),
            created_at: "0".to_owned(),
            rpc_url: "https://example.invalid/".to_owned(),
            payment_token_address: "0x00".to_owned(),
            payment_vault_address: "0x01".to_owned(),
        };
        let json = manifest.render_json();
        assert!(json.contains(r#""/tmp/a\"b\\c\td""#), "{json}");
        assert_eq!(json.matches('{').count(), json.matches('}').count());
        assert!(json.contains("\"bootstrap\": [],"), "{json}");
    }

    #[test]
    fn p22_json_string_escapes_the_rfc8259_set() {
        assert_eq!(json_string("plain"), "\"plain\"");
        assert_eq!(json_string("a\"b"), "\"a\\\"b\"");
        assert_eq!(json_string("a\\b"), "\"a\\\\b\"");
        assert_eq!(json_string("a\nb"), "\"a\\nb\"");
        assert_eq!(json_string("a\u{1}b"), "\"a\\u0001b\"");
    }
}
