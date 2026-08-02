//! Network selection (task S5): the three network identities antseal can
//! seal against — `arbitrum-one` (default), `arbitrum-sepolia`, `devnet` —
//! mapped to EVM chain id, payment contracts, RPC endpoint, and Autonomi
//! bootstrap configuration (MVP-SPEC.md lines 20, 149).
//!
//! # The pure data half (this module) vs the heavy half
//!
//! This module is **pure data**: chain ids, contract addresses, URL and
//! bootstrap strings, and the devnet environment parser — no `ant-core`,
//! no evmlib, no network I/O. It compiles in the default feature set so
//! U4/U11's `--network` wiring and consent rendering can consume it
//! without the ~600-package backend graph. The conversion into upstream's
//! `EvmNetwork` lives behind the non-default **`ant-backend`** feature
//! ([`crate::evm`]); S6's adapter extends the same feature. The wallet
//! operations do **not**: since D89 they are [`crate::wallet`], in this
//! same default set, over `k256` + `sha3`.
//!
//! # Where each value comes from (citation-pinned)
//!
//! Mainnet and sepolia contract addresses and RPC endpoints are
//! transcribed verbatim from the pinned evmlib's built-in network
//! definitions — the same constants `EvmNetwork::ArbitrumOne` /
//! `ArbitrumSepoliaTest` resolve to at payment time — and the
//! feature-gated consistency test in [`crate::evm`] asserts byte equality
//! against the running evmlib, so a silent upstream bump cannot leave
//! these stale. Chain ids are **not** defined anywhere in evmlib (it
//! trusts the RPC); they are pinned here from the canonical chain
//! registry values (42161 / 421614) that D38's scripts assert via
//! `eth_chainId`.
//!
//! The devnet has no built-in definition anywhere: every `local-up` mints
//! a fresh Anvil chain with freshly deployed contracts, exported under the
//! repo-local gitignored `.devnet/` (docs/devnet/local-devnet.md). The
//! [`DevnetEnv`] parser consumes that **run-scoped** export.

use core::fmt;
use std::collections::BTreeMap;
use std::net::SocketAddr;

use antseal_core::crypto::secrets::SecretBuf;

// ---------------------------------------------------------------------------
// Chain ids and built-in contract addresses
// ---------------------------------------------------------------------------

/// Arbitrum One (mainnet) chain id.
///
/// evmlib defines no chain-id constant (its `Network` carries only RPC +
/// contract addresses, `evmlib-0.9.0/src/lib.rs:102-158`); 42161 is the
/// canonical Arbitrum One chain id (EIP-155 registry), asserted at runtime
/// against the RPC by the P17-class scripts (`eth_chainId == 0xa4b1`).
pub const ARBITRUM_ONE_CHAIN_ID: u64 = 42_161;

/// Arbitrum Sepolia chain id — **NOT Ethereum Sepolia** (11155111).
///
/// 421614 (`0x66eee`), per D38 (docs/decisions/D38-sepolia-test-ant-
/// acquisition.md §1: P17 scripts assert `eth_chainId == 0x66eee`). The
/// wrong-Sepolia hazard is real: the public *gas faucets* are where a
/// developer most easily wanders onto Ethereum Sepolia, whose ETH and
/// contracts are useless here.
pub const ARBITRUM_SEPOLIA_CHAIN_ID: u64 = 421_614;

/// Arbitrum One payment-token (ANT ERC-20) contract, checksummed hex —
/// verbatim from `evmlib-0.9.0/src/lib.rs:64-65`
/// (`ARBITRUM_ONE_PAYMENT_TOKEN_ADDRESS`).
pub const ARBITRUM_ONE_PAYMENT_TOKEN: &str = "0xa78d8321B20c4Ef90eCd72f2588AA985A4BDb684";

/// Arbitrum One unified payment-vault (data payments) contract — verbatim
/// from `evmlib-0.9.0/src/lib.rs:71-72`
/// (`ARBITRUM_ONE_PAYMENT_VAULT_ADDRESS`).
pub const ARBITRUM_ONE_PAYMENT_VAULT: &str = "0x9A3EcAc693b699Fc0B2B6A50B5549e50c2320A26";

/// Arbitrum One public RPC endpoint — verbatim from
/// `evmlib-0.9.0/src/lib.rs:52-56` (`PUBLIC_ARBITRUM_ONE_HTTP_RPC_URL`).
pub const ARBITRUM_ONE_RPC_URL: &str = "https://arb1.arbitrum.io/rpc";

/// Arbitrum Sepolia test-ANT token contract — verbatim from
/// `evmlib-0.9.0/src/lib.rs:67-68`
/// (`ARBITRUM_SEPOLIA_TEST_PAYMENT_TOKEN_ADDRESS`); cross-recorded in D38
/// §1 (verified "Exact Match" on sepolia.arbiscan.io, no mint function).
pub const ARBITRUM_SEPOLIA_PAYMENT_TOKEN: &str = "0x4bc1aCE0E66170375462cB4E6Af42Ad4D5EC689C";

/// Arbitrum Sepolia unified payment-vault contract (a **proxy** — D38
/// residual risk 3) — verbatim from `evmlib-0.9.0/src/lib.rs:75-76`
/// (`ARBITRUM_SEPOLIA_TEST_PAYMENT_VAULT_ADDRESS`).
pub const ARBITRUM_SEPOLIA_PAYMENT_VAULT: &str = "0xd742E8CFEf27A9a884F3EFfA239Ee2F39c276522";

/// Arbitrum Sepolia public RPC endpoint — verbatim from
/// `evmlib-0.9.0/src/lib.rs:58-62`
/// (`PUBLIC_ARBITRUM_SEPOLIA_HTTP_RPC_URL`).
pub const ARBITRUM_SEPOLIA_RPC_URL: &str = "https://sepolia-rollup.arbitrum.io/rpc";

// ---------------------------------------------------------------------------
// EvmAddress20
// ---------------------------------------------------------------------------

/// A 20-byte EVM address (contract or wallet) at the **data** level:
/// parse, hold, render — nothing else. Distinct on purpose from
/// [`crate::Address`], the 32-byte Autonomi *chunk* address; the two are
/// different universes and must never convert into each other.
///
/// Rendering is `0x` + lowercase hex (valid everywhere addresses are
/// accepted). EIP-55 checksummed rendering — the mixed-case form users
/// see — is [`crate::wallet::checksummed`], in the **default** feature set
/// since D89 (it needs Keccak-256, which the wallet light half already
/// brings); U11 shows that form.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvmAddress20([u8; Self::LEN]);

impl EvmAddress20 {
    /// Length in bytes.
    pub const LEN: usize = 20;

    /// Construct from exactly-sized bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Parse `0x`-optional, case-insensitive, exactly-40-hex-digit text.
    ///
    /// # Errors
    ///
    /// [`EvmAddressParseError`] naming the structural problem (never
    /// echoing the input — uniform hygiene with the rest of this module).
    pub fn parse(text: &str) -> Result<Self, EvmAddressParseError> {
        let digits = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(text);
        if digits.len() != Self::LEN * 2 {
            return Err(EvmAddressParseError::WrongLength { got: digits.len() });
        }
        let mut bytes = [0u8; Self::LEN];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let pair = &digits[index * 2..index * 2 + 2];
            *byte = u8::from_str_radix(pair, 16).map_err(|_| EvmAddressParseError::NotHex)?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for EvmAddress20 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for EvmAddress20 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EvmAddress20({self})")
    }
}

/// Serde as the canonical **string** form (`0x` + lowercase hex, the
/// `Display` rendering): an EVM address is an interchange identifier and
/// the S8 balance/preflight reports feed `--json` consumers, where a
/// 20-number byte array would be hostile. Deserialization runs the same
/// [`EvmAddress20::parse`] every other input path uses.
impl serde::Serialize for EvmAddress20 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for EvmAddress20 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Why an EVM address string failed to parse. Structural only — the
/// offending input is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EvmAddressParseError {
    /// Not exactly 40 hex digits after the optional `0x`.
    #[error("EVM address must be exactly 40 hex digits (optional 0x prefix); got {got} digits")]
    WrongLength {
        /// Number of digits found after prefix stripping.
        got: usize,
    },
    /// A character outside `0-9a-fA-F`.
    #[error("EVM address contains a character outside 0-9a-fA-F")]
    NotHex,
}

// ---------------------------------------------------------------------------
// NetworkId + NetworkConfig
// ---------------------------------------------------------------------------

/// The three network identities the `--network` flag selects between
/// (MVP-SPEC.md lines 20, 149). Anything else is a hard
/// [`NetworkConfigError::UnknownNetwork`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum NetworkId {
    /// Arbitrum One — mainnet, real ANT, permanent paid storage. The
    /// default.
    #[default]
    ArbitrumOne,
    /// **Arbitrum** Sepolia (chain 421614) — NOT Ethereum Sepolia
    /// (11155111). Real deployed test contracts (D38), self-hosted nodes
    /// (there is no public Autonomi testnet).
    ArbitrumSepolia,
    /// The local devnet: in-process nodes + a fresh Anvil chain per run
    /// (P16; docs/devnet/local-devnet.md). Config comes exclusively from
    /// the run-scoped [`DevnetEnv`] export.
    Devnet,
}

impl NetworkId {
    /// The canonical CLI name (`--network` value).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArbitrumOne => "arbitrum-one",
            Self::ArbitrumSepolia => "arbitrum-sepolia",
            Self::Devnet => "devnet",
        }
    }

    /// All valid names, for error messages and CLI help.
    pub const ALL: [Self; 3] = [Self::ArbitrumOne, Self::ArbitrumSepolia, Self::Devnet];
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for NetworkId {
    type Err = NetworkConfigError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "arbitrum-one" => Ok(Self::ArbitrumOne),
            "arbitrum-sepolia" => Ok(Self::ArbitrumSepolia),
            "devnet" => Ok(Self::Devnet),
            other => Err(NetworkConfigError::UnknownNetwork {
                name: other.to_owned(),
            }),
        }
    }
}

/// Everything backend construction needs to know about one network: EVM
/// chain id, payment-token and payment-vault contracts, payment-RPC
/// endpoint, and Autonomi bootstrap peers.
///
/// Pure data (module docs); [`crate::evm::to_evm_network`] converts it
/// into upstream's `EvmNetwork` under `ant-backend`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    /// Which network this is.
    pub id: NetworkId,
    /// EVM chain id — asserted against the RPC's `eth_chainId` before any
    /// payment (the wrong-Sepolia guard).
    pub evm_chain_id: u64,
    /// Payment (EVM JSON-RPC) endpoint. **Payment** RPC is in this
    /// crate's scope per D33; anchor-evidence RPC is not.
    pub rpc_url: String,
    /// ANT (payment token) ERC-20 contract.
    pub payment_token: EvmAddress20,
    /// Unified data-payments vault contract.
    pub payment_vault: EvmAddress20,
    /// Autonomi bootstrap peers for `Client::connect`. Empty for
    /// `arbitrum-one`/`arbitrum-sepolia`: the pinned ant-core 0.5.0
    /// compiles in **no** peer list (`Client::connect(bootstrap_peers,
    /// ..)` is caller-supplied, `ant-core-0.5.0/src/data/client/
    /// mod.rs:410-433`; its examples read peers from files/flags), so
    /// live-network peers arrive from the caller at S6/S17 — for the
    /// sepolia devnet they are the launcher's own nodes. The devnet
    /// variant fills them from [`DevnetEnv`].
    pub bootstrap: Vec<SocketAddr>,
}

impl NetworkConfig {
    /// Arbitrum One — the default network (MVP scope decision 4).
    #[must_use]
    pub fn arbitrum_one() -> Self {
        Self {
            id: NetworkId::ArbitrumOne,
            evm_chain_id: ARBITRUM_ONE_CHAIN_ID,
            rpc_url: ARBITRUM_ONE_RPC_URL.to_owned(),
            payment_token: parse_pinned(ARBITRUM_ONE_PAYMENT_TOKEN),
            payment_vault: parse_pinned(ARBITRUM_ONE_PAYMENT_VAULT),
            bootstrap: Vec::new(),
        }
    }

    /// **Arbitrum** Sepolia (chain 421614) — NOT Ethereum Sepolia.
    ///
    /// Real deployed test contracts (D38 §1); nodes are always
    /// self-hosted (no public Autonomi testnet exists — docs/devnet/
    /// local-devnet.md). Test ANT is acquired per D38 (ERC-20 transfer
    /// from a holder; there is no faucet and no mint).
    #[must_use]
    pub fn arbitrum_sepolia() -> Self {
        Self {
            id: NetworkId::ArbitrumSepolia,
            evm_chain_id: ARBITRUM_SEPOLIA_CHAIN_ID,
            rpc_url: ARBITRUM_SEPOLIA_RPC_URL.to_owned(),
            payment_token: parse_pinned(ARBITRUM_SEPOLIA_PAYMENT_TOKEN),
            payment_vault: parse_pinned(ARBITRUM_SEPOLIA_PAYMENT_VAULT),
            bootstrap: Vec::new(),
        }
    }

    /// The local devnet, from its **run-scoped** environment export.
    ///
    /// Every `local-up` mints a fresh chain, fresh contract addresses and
    /// fresh ports, so a `NetworkConfig` built here is valid only for the
    /// devnet run whose export produced `env` — re-read the export after
    /// every up (docs/devnet/local-devnet.md, "Environment surface").
    #[must_use]
    pub fn devnet(env: &DevnetEnv) -> Self {
        Self {
            id: NetworkId::Devnet,
            evm_chain_id: env.chain_id,
            rpc_url: env.rpc_url.clone(),
            payment_token: env.payment_token,
            payment_vault: env.payment_vault,
            bootstrap: env.bootstrap.clone(),
        }
    }

    /// Select by [`NetworkId`], the shape U4's `--network` wiring calls.
    ///
    /// # Errors
    ///
    /// [`NetworkConfigError::DevnetEnvironmentRequired`] when `id` is
    /// [`NetworkId::Devnet`] and no [`DevnetEnv`] is supplied — the devnet
    /// has no built-in definition anywhere, by design.
    pub fn select(
        id: NetworkId,
        devnet_env: Option<&DevnetEnv>,
    ) -> Result<Self, NetworkConfigError> {
        match id {
            NetworkId::ArbitrumOne => Ok(Self::arbitrum_one()),
            NetworkId::ArbitrumSepolia => Ok(Self::arbitrum_sepolia()),
            NetworkId::Devnet => devnet_env
                .map(Self::devnet)
                .ok_or(NetworkConfigError::DevnetEnvironmentRequired),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self::arbitrum_one()
    }
}

/// Parse a compile-time-pinned address constant. The constants above are
/// tested to parse (and to match evmlib byte-for-byte under
/// `ant-backend`), so this cannot fail at runtime for them; the fallback
/// keeps the function total without a panic path.
fn parse_pinned(text: &str) -> EvmAddress20 {
    debug_assert!(
        EvmAddress20::parse(text).is_ok(),
        "pinned constant must parse"
    );
    EvmAddress20::parse(text).unwrap_or(EvmAddress20([0u8; EvmAddress20::LEN]))
}

/// Network selection failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkConfigError {
    /// The name is not one of the three network identities — a hard error
    /// (S5 accept), never a fallback to the default.
    #[error(
        "unknown network `{name}` — valid networks: arbitrum-one (default), arbitrum-sepolia \
         (Arbitrum Sepolia, chain 421614 — NOT Ethereum Sepolia), devnet"
    )]
    UnknownNetwork {
        /// The rejected name.
        name: String,
    },
    /// `devnet` was selected but no devnet environment was supplied: the
    /// devnet is run-scoped and has no built-in definition — boot one
    /// (`scripts/devnet/local-up`) and read its export.
    #[error(
        "network `devnet` needs a running local devnet's environment export (scripts/devnet/local-up \
         writes .devnet/env; every run mints fresh contracts and ports)"
    )]
    DevnetEnvironmentRequired,
}

// ---------------------------------------------------------------------------
// DevnetEnv — the run-scoped `.devnet/` export (P16)
// ---------------------------------------------------------------------------

/// The ten `ANTSEAL_DEVNET_*` keys of the launcher's environment export
/// (docs/devnet/local-devnet.md, "Environment surface"), parsed and typed.
///
/// **Run-scoped**: every `local-up` boots a fresh Anvil chain, deploys
/// fresh contracts, and picks fresh ports; consumers must re-read the
/// export per run and never cache it across a `local-down`.
///
/// **Key material**: the funded wallet key (Anvil dev account 0) is a
/// well-known public Anvil constant, but it is key-*shaped*, so it is held
/// in [`SecretBuf`] (zeroize-on-drop), redacted from `Debug`, and never
/// echoed by any error this module produces — project rule 6 applies to
/// the pattern, not just to real secrets.
pub struct DevnetEnv {
    rpc_url: String,
    chain_id: u64,
    payment_token: EvmAddress20,
    payment_vault: EvmAddress20,
    wallet_private_key: SecretBuf,
    bootstrap: Vec<SocketAddr>,
    node_count: u32,
    base_port: u16,
    data_dir: String,
    pid: u32,
}

/// The ten export keys, in the documented order.
pub mod devnet_keys {
    /// Anvil EVM JSON-RPC endpoint.
    pub const RPC_URL: &str = "ANTSEAL_DEVNET_RPC_URL";
    /// EVM chain id (31337, Anvil's default — re-verified per run).
    pub const CHAIN_ID: &str = "ANTSEAL_DEVNET_CHAIN_ID";
    /// AutonomiNetworkToken address (deployed fresh per run).
    pub const TOKEN_ADDRESS: &str = "ANTSEAL_DEVNET_TOKEN_ADDRESS";
    /// PaymentVault address (deployed fresh per run).
    pub const PAYMENT_VAULT_ADDRESS: &str = "ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS";
    /// Funded wallet key (Anvil dev account 0) — key-shaped material.
    pub const WALLET_PRIVATE_KEY: &str = "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY";
    /// Comma-separated node `SocketAddr`s for `Client::connect`.
    pub const BOOTSTRAP: &str = "ANTSEAL_DEVNET_BOOTSTRAP";
    /// Actual node count booted.
    pub const NODE_COUNT: &str = "ANTSEAL_DEVNET_NODE_COUNT";
    /// First node port (OS-random per run).
    pub const BASE_PORT: &str = "ANTSEAL_DEVNET_BASE_PORT";
    /// Node store root (under `.devnet/`).
    pub const DATA_DIR: &str = "ANTSEAL_DEVNET_DATA_DIR";
    /// Launcher pid (the devnet's lifetime handle).
    pub const PID: &str = "ANTSEAL_DEVNET_PID";

    /// All ten, for completeness checks.
    pub const ALL: [&str; 10] = [
        RPC_URL,
        CHAIN_ID,
        TOKEN_ADDRESS,
        PAYMENT_VAULT_ADDRESS,
        WALLET_PRIVATE_KEY,
        BOOTSTRAP,
        NODE_COUNT,
        BASE_PORT,
        DATA_DIR,
        PID,
    ];
}

impl DevnetEnv {
    /// Parse from any key→value lookup (the seam every other constructor
    /// funnels through; tests drive it directly).
    ///
    /// # Errors
    ///
    /// [`DevnetEnvError`] naming the offending **key** and the structural
    /// problem. Values are never echoed — uniformly, so the wallet-key
    /// line cannot become the exception by accident.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, DevnetEnvError> {
        let require = |key: &'static str| lookup(key).ok_or(DevnetEnvError::MissingKey { key });
        let invalid = |key: &'static str, problem: &str| DevnetEnvError::InvalidValue {
            key,
            problem: problem.to_owned(),
        };

        let rpc_url = require(devnet_keys::RPC_URL)?;
        if rpc_url.trim().is_empty() {
            return Err(invalid(devnet_keys::RPC_URL, "empty"));
        }

        let chain_id = require(devnet_keys::CHAIN_ID)?
            .trim()
            .parse::<u64>()
            .map_err(|_| invalid(devnet_keys::CHAIN_ID, "not a decimal u64"))?;

        let payment_token = EvmAddress20::parse(require(devnet_keys::TOKEN_ADDRESS)?.trim())
            .map_err(|e| invalid(devnet_keys::TOKEN_ADDRESS, &e.to_string()))?;
        let payment_vault =
            EvmAddress20::parse(require(devnet_keys::PAYMENT_VAULT_ADDRESS)?.trim())
                .map_err(|e| invalid(devnet_keys::PAYMENT_VAULT_ADDRESS, &e.to_string()))?;

        // Key-shaped material: moved into a SecretBuf immediately; only a
        // structural emptiness check here (real validation is the D44
        // parse-through-pinned-stack in `crate::evm`, behind the feature).
        let wallet_raw = require(devnet_keys::WALLET_PRIVATE_KEY)?;
        if wallet_raw.trim().is_empty() {
            return Err(invalid(devnet_keys::WALLET_PRIVATE_KEY, "empty"));
        }
        let wallet_private_key = SecretBuf::new(wallet_raw.into_bytes());

        let bootstrap_raw = require(devnet_keys::BOOTSTRAP)?;
        let mut bootstrap = Vec::new();
        for (index, part) in bootstrap_raw.split(',').enumerate() {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let addr: SocketAddr = part.parse().map_err(|_| DevnetEnvError::InvalidValue {
                key: devnet_keys::BOOTSTRAP,
                problem: format!("entry {index} is not a socket address (ip:port)"),
            })?;
            bootstrap.push(addr);
        }
        if bootstrap.is_empty() {
            return Err(invalid(
                devnet_keys::BOOTSTRAP,
                "no socket addresses (comma-separated ip:port list required)",
            ));
        }

        let node_count = require(devnet_keys::NODE_COUNT)?
            .trim()
            .parse::<u32>()
            .map_err(|_| invalid(devnet_keys::NODE_COUNT, "not a decimal u32"))?;
        let base_port = require(devnet_keys::BASE_PORT)?
            .trim()
            .parse::<u16>()
            .map_err(|_| invalid(devnet_keys::BASE_PORT, "not a decimal u16 port"))?;
        let data_dir = require(devnet_keys::DATA_DIR)?;
        if data_dir.trim().is_empty() {
            return Err(invalid(devnet_keys::DATA_DIR, "empty"));
        }
        let pid = require(devnet_keys::PID)?
            .trim()
            .parse::<u32>()
            .map_err(|_| invalid(devnet_keys::PID, "not a decimal u32 pid"))?;

        Ok(Self {
            rpc_url,
            chain_id,
            payment_token,
            payment_vault,
            wallet_private_key,
            bootstrap,
            node_count,
            base_port,
            data_dir,
            pid,
        })
    }

    /// Parse from the process environment (after `source .devnet/env`, or
    /// under a harness that exported the keys).
    ///
    /// # Errors
    ///
    /// As [`Self::from_lookup`]; a present-but-non-unicode variable reads
    /// as an invalid value for its key.
    pub fn from_process_env() -> Result<Self, DevnetEnvError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Parse the launcher's flat `KEY='value'` env-file **text**
    /// (`.devnet/env` — `source`-able single-quoted lines; the caller does
    /// the file I/O, keeping this module I/O-free and the parse testable
    /// on fixtures).
    ///
    /// Blank lines and `#` comments are skipped; unknown
    /// `ANTSEAL_DEVNET_*` keys are ignored (forward compatibility with a
    /// launcher that exports more); the ten required keys must all be
    /// present. Values may be wrapped in single quotes (the launcher's
    /// format) or bare; embedded quotes are not supported (the launcher
    /// never emits them — addresses, hex, numbers, socket lists, paths).
    ///
    /// # Errors
    ///
    /// As [`Self::from_lookup`].
    pub fn from_env_file(text: &str) -> Result<Self, DevnetEnvError> {
        let mut map: BTreeMap<&str, String> = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            if !key.starts_with("ANTSEAL_DEVNET_") {
                continue;
            }
            let value = value.trim();
            let value = value
                .strip_prefix('\'')
                .and_then(|v| v.strip_suffix('\''))
                .unwrap_or(value);
            map.insert(key, value.to_owned());
        }
        Self::from_lookup(|key| map.get(key).cloned())
    }

    /// Anvil EVM JSON-RPC endpoint.
    #[must_use]
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// EVM chain id the export recorded (31337 for Anvil's default).
    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The per-run AutonomiNetworkToken address.
    #[must_use]
    pub const fn payment_token(&self) -> EvmAddress20 {
        self.payment_token
    }

    /// The per-run PaymentVault address.
    #[must_use]
    pub const fn payment_vault(&self) -> EvmAddress20 {
        self.payment_vault
    }

    /// The funded dev wallet key (key-shaped material — zeroizing buffer;
    /// feed it to `crate::wallet::WalletKey::import`).
    #[must_use]
    pub const fn wallet_private_key(&self) -> &SecretBuf {
        &self.wallet_private_key
    }

    /// Node bootstrap addresses for `Client::connect`.
    #[must_use]
    pub fn bootstrap(&self) -> &[SocketAddr] {
        &self.bootstrap
    }

    /// Actual node count booted.
    #[must_use]
    pub const fn node_count(&self) -> u32 {
        self.node_count
    }

    /// First node port (OS-random per run).
    #[must_use]
    pub const fn base_port(&self) -> u16 {
        self.base_port
    }

    /// Node store root (under the run's `.devnet/`).
    #[must_use]
    pub fn data_dir(&self) -> &str {
        &self.data_dir
    }

    /// Launcher pid — the devnet's lifetime handle.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }
}

impl fmt::Debug for DevnetEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DevnetEnv")
            .field("rpc_url", &self.rpc_url)
            .field("chain_id", &self.chain_id)
            .field("payment_token", &self.payment_token)
            .field("payment_vault", &self.payment_vault)
            // SecretBuf's own Debug is already redacted; keep the field so
            // the redaction is visible rather than the field invisible.
            .field("wallet_private_key", &self.wallet_private_key)
            .field("bootstrap", &self.bootstrap)
            .field("node_count", &self.node_count)
            .field("base_port", &self.base_port)
            .field("data_dir", &self.data_dir)
            .field("pid", &self.pid)
            .finish()
    }
}

/// The devnet environment export was missing or malformed. Names the
/// **key**; never echoes a value (uniform hygiene — see [`DevnetEnv`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DevnetEnvError {
    /// A required `ANTSEAL_DEVNET_*` key is absent — usually "no devnet is
    /// running" or "the export was not sourced/read".
    #[error(
        "devnet environment key {key} is missing — is a devnet up? (scripts/devnet/local-up; the \
         export is run-scoped and lives at .devnet/env)"
    )]
    MissingKey {
        /// The absent key.
        key: &'static str,
    },
    /// A key is present but its value is structurally invalid.
    #[error("devnet environment key {key} has an invalid value: {problem}")]
    InvalidValue {
        /// The offending key.
        key: &'static str,
        /// Structural description of the problem (never the value).
        problem: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use antseal_core::test_util::alternate_test_secret;

    /// A key-shaped fixture value derived per the house convention
    /// (`SHA-256(label ‖ W)`, testdata/README.md) — never a fresh
    /// committed 64-hex literal.
    fn fixture_key_hex() -> String {
        alternate_test_secret(b"antseal-net/S5 devnet env fixture wallet key")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The launcher's env-file shape, with the key line filled at runtime.
    fn fixture_env_file() -> String {
        format!(
            "# antseal devnet environment (run-scoped)\n\
             ANTSEAL_DEVNET_RPC_URL='http://127.0.0.1:53712/'\n\
             ANTSEAL_DEVNET_CHAIN_ID='31337'\n\
             ANTSEAL_DEVNET_TOKEN_ADDRESS='0x5FbDB2315678afecb367f032d93F642f64180aa3'\n\
             ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS='0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512'\n\
             ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='{key}'\n\
             ANTSEAL_DEVNET_BOOTSTRAP='127.0.0.1:20001,127.0.0.1:20002, 127.0.0.1:20003'\n\
             ANTSEAL_DEVNET_NODE_COUNT='14'\n\
             ANTSEAL_DEVNET_BASE_PORT='20001'\n\
             ANTSEAL_DEVNET_DATA_DIR='.devnet/data'\n\
             ANTSEAL_DEVNET_PID='12345'\n",
            key = fixture_key_hex()
        )
    }

    #[test]
    fn network_names_round_trip_and_unknown_is_a_hard_error() {
        for id in NetworkId::ALL {
            assert_eq!(id.as_str().parse::<NetworkId>().expect("round-trips"), id);
        }
        let err = "ropsten".parse::<NetworkId>().expect_err("unknown name");
        assert_eq!(
            err,
            NetworkConfigError::UnknownNetwork {
                name: "ropsten".into()
            }
        );
        // The message teaches the valid set and carries the
        // wrong-Sepolia warning.
        let msg = err.to_string();
        assert!(msg.contains("arbitrum-one"), "{msg}");
        assert!(msg.contains("NOT Ethereum Sepolia"), "{msg}");
        // Case-sensitive by design: "Devnet" is not a network name.
        assert!("Devnet".parse::<NetworkId>().is_err());
    }

    #[test]
    fn default_is_arbitrum_one_and_chain_ids_are_pinned() {
        let config = NetworkConfig::default();
        assert_eq!(config.id, NetworkId::ArbitrumOne);
        assert_eq!(config.evm_chain_id, 42_161);

        let sepolia = NetworkConfig::arbitrum_sepolia();
        // S5 accept: chain id 421614 pinned for arbitrum-sepolia.
        assert_eq!(sepolia.evm_chain_id, 421_614);
        assert_ne!(
            sepolia.evm_chain_id, 11_155_111,
            "Ethereum Sepolia is the wrong Sepolia"
        );
    }

    #[test]
    fn builtin_configs_carry_the_documented_contracts_and_rpc() {
        let one = NetworkConfig::arbitrum_one();
        assert_eq!(one.rpc_url, "https://arb1.arbitrum.io/rpc");
        assert_eq!(
            one.payment_token.to_string(),
            ARBITRUM_ONE_PAYMENT_TOKEN.to_lowercase()
        );
        assert_eq!(
            one.payment_vault.to_string(),
            ARBITRUM_ONE_PAYMENT_VAULT.to_lowercase()
        );
        assert!(one.bootstrap.is_empty(), "no compiled-in mainnet peers");

        let sepolia = NetworkConfig::arbitrum_sepolia();
        assert_eq!(sepolia.rpc_url, "https://sepolia-rollup.arbitrum.io/rpc");
        assert_eq!(
            sepolia.payment_token.to_string(),
            ARBITRUM_SEPOLIA_PAYMENT_TOKEN.to_lowercase()
        );
        assert_eq!(
            sepolia.payment_vault.to_string(),
            ARBITRUM_SEPOLIA_PAYMENT_VAULT.to_lowercase()
        );
    }

    #[test]
    fn select_covers_all_three_and_devnet_needs_an_environment() {
        assert_eq!(
            NetworkConfig::select(NetworkId::ArbitrumOne, None).expect("built-in"),
            NetworkConfig::arbitrum_one()
        );
        assert_eq!(
            NetworkConfig::select(NetworkId::ArbitrumSepolia, None).expect("built-in"),
            NetworkConfig::arbitrum_sepolia()
        );
        assert_eq!(
            NetworkConfig::select(NetworkId::Devnet, None).expect_err("no env"),
            NetworkConfigError::DevnetEnvironmentRequired
        );

        let env = DevnetEnv::from_env_file(&fixture_env_file()).expect("fixture parses");
        let config = NetworkConfig::select(NetworkId::Devnet, Some(&env)).expect("with env");
        assert_eq!(config.id, NetworkId::Devnet);
        assert_eq!(config.evm_chain_id, 31_337);
        assert_eq!(config.rpc_url, "http://127.0.0.1:53712/");
        assert_eq!(config.bootstrap.len(), 3);
    }

    #[test]
    fn env_file_fixture_parses_completely() {
        let env = DevnetEnv::from_env_file(&fixture_env_file()).expect("fixture parses");
        assert_eq!(env.chain_id(), 31_337);
        assert_eq!(env.node_count(), 14);
        assert_eq!(env.base_port(), 20_001);
        assert_eq!(env.data_dir(), ".devnet/data");
        assert_eq!(env.pid(), 12_345);
        assert_eq!(env.bootstrap().len(), 3);
        assert_eq!(
            env.payment_token().to_string(),
            "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        );
        // The key round-trips into the zeroizing buffer byte-for-byte.
        assert_eq!(
            env.wallet_private_key().as_bytes(),
            fixture_key_hex().as_bytes()
        );
    }

    #[test]
    fn env_lookup_and_env_file_agree() {
        let text = fixture_env_file();
        let from_file = DevnetEnv::from_env_file(&text).expect("file form");
        // Rebuild the same map by hand and drive the lookup seam.
        let mut map = BTreeMap::new();
        for line in text.lines() {
            if let Some((k, v)) = line.trim().split_once('=')
                && k.starts_with("ANTSEAL_DEVNET_")
            {
                map.insert(k.to_owned(), v.trim_matches('\'').to_owned());
            }
        }
        let from_lookup = DevnetEnv::from_lookup(|key| map.get(key).cloned()).expect("lookup form");
        assert_eq!(
            NetworkConfig::devnet(&from_file),
            NetworkConfig::devnet(&from_lookup)
        );
    }

    #[test]
    fn every_missing_key_is_named() {
        let text = fixture_env_file();
        for missing in devnet_keys::ALL {
            let filtered: String = text
                .lines()
                .filter(|line| !line.starts_with(missing))
                .map(|line| format!("{line}\n"))
                .collect();
            let err = DevnetEnv::from_env_file(&filtered).expect_err("must fail");
            assert_eq!(err, DevnetEnvError::MissingKey { key: missing });
            // Every error message points at the runbook entry point.
            assert!(err.to_string().contains("local-up"), "{err}");
        }
    }

    #[test]
    fn malformed_values_name_the_key_and_never_echo_the_value() {
        let cases: [(&str, &str); 5] = [
            (devnet_keys::CHAIN_ID, "ANTSEAL_DEVNET_CHAIN_ID='banana'"),
            (
                devnet_keys::TOKEN_ADDRESS,
                "ANTSEAL_DEVNET_TOKEN_ADDRESS='0x1234'",
            ),
            (
                devnet_keys::BOOTSTRAP,
                "ANTSEAL_DEVNET_BOOTSTRAP='not-a-socket'",
            ),
            (devnet_keys::BASE_PORT, "ANTSEAL_DEVNET_BASE_PORT='70000'"),
            (devnet_keys::PID, "ANTSEAL_DEVNET_PID='-4'"),
        ];
        for (key, replacement) in cases {
            let text: String = fixture_env_file()
                .lines()
                .map(|line| {
                    if line.starts_with(key) {
                        format!("{replacement}\n")
                    } else {
                        format!("{line}\n")
                    }
                })
                .collect();
            let err = DevnetEnv::from_env_file(&text).expect_err("must fail");
            match &err {
                DevnetEnvError::InvalidValue {
                    key: named,
                    problem,
                } => {
                    assert_eq!(*named, key);
                    assert!(
                        !problem.contains("banana")
                            && !problem.contains("0x1234")
                            && !problem.contains("not-a-socket")
                            && !problem.contains("70000"),
                        "value echoed in problem: {problem}"
                    );
                }
                other => panic!("expected InvalidValue for {key}, got {other:?}"),
            }
        }
    }

    #[test]
    fn debug_output_never_contains_the_wallet_key() {
        let env = DevnetEnv::from_env_file(&fixture_env_file()).expect("fixture parses");
        let debug = format!("{env:?}");
        assert!(
            !debug.contains(&fixture_key_hex()),
            "wallet key leaked into Debug"
        );
        assert!(debug.contains("SecretBuf(<redacted>)"), "{debug}");
    }

    #[test]
    fn evm_address_parse_accepts_both_cases_and_rejects_structurally() {
        let lower =
            EvmAddress20::parse("0xa78d8321b20c4ef90ecd72f2588aa985a4bdb684").expect("lower");
        let mixed = EvmAddress20::parse(ARBITRUM_ONE_PAYMENT_TOKEN).expect("mixed");
        let bare = EvmAddress20::parse("a78d8321B20c4Ef90eCd72f2588AA985A4BDb684").expect("bare");
        assert_eq!(lower, mixed);
        assert_eq!(lower, bare);
        assert_eq!(
            EvmAddress20::parse("0x1234").expect_err("short"),
            EvmAddressParseError::WrongLength { got: 4 }
        );
        assert_eq!(
            EvmAddress20::parse("0xzz8d8321b20c4ef90ecd72f2588aa985a4bdb684").expect_err("nonhex"),
            EvmAddressParseError::NotHex
        );
    }
}
