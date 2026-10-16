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
//! (`crate::evm`); S6's adapter extends the same feature. The wallet
//! operations do **not**: since D89 they are [`crate::wallet`], in this
//! same default set, over `k256` + `sha3`.
//!
//! # Where each value comes from (citation-pinned)
//!
//! Mainnet and sepolia contract addresses and RPC endpoints are
//! transcribed verbatim from the pinned evmlib's built-in network
//! definitions — the same constants `EvmNetwork::ArbitrumOne` /
//! `ArbitrumSepoliaTest` resolve to at payment time — and the
//! feature-gated consistency test in `crate::evm` asserts byte equality
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
//!
//! **[D159 §2 R2, 2026-08-22]** `crate::evm` is named here as a plain code
//! span and NOT as an intra-doc link: this module is ungated while `evm` is
//! behind the non-default `ant-backend` feature (`lib.rs:95-96`), so a
//! default-feature `cargo doc` resolved the link against a module that is
//! not there — six such warnings across this file and `wallet.rs`.
//! `crate::ant_backend`'s own docs keep the link form, because that module is
//! only ever rendered with the feature on. Nothing mechanical enforces this;
//! the doc build that would is armed at first publication (D159 §2 R6).

use core::fmt;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

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
    /// Never panics, whatever the input (S44).
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
        // S44: every byte is validated BEFORE the slicing below. The length
        // above is in bytes, so a multibyte character used to pass it and put
        // a slice boundary inside itself — a panic. Only an all-ASCII-hex
        // string reaches the pairing now, so every boundary is a character
        // boundary, and `from_str_radix`'s optional `+` sign can no longer
        // pass for a digit.
        if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(EvmAddressParseError::NotHex);
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
        /// Length in bytes after prefix stripping — the digit count for ASCII
        /// input (S44: a multibyte character counts once per byte).
        got: usize,
    },
    /// A character outside `0-9a-fA-F`, including a `+` sign and any
    /// non-ASCII character.
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
/// Pure data (module docs); `crate::evm::to_evm_network` converts it
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
    /// Autonomi bootstrap peers for `Client::connect`.
    ///
    /// - `arbitrum-one`: upstream's published list at the pin, vendored byte for
    ///   byte ([`ARBITRUM_ONE_PEERS_FILE`], D173 §2 R1) — the bytes upstream
    ///   published, not a claim that any seed is live.
    /// - `arbitrum-sepolia`: none built in. The production list must never attach
    ///   to a test chain, and there is no public Autonomi network on Arbitrum
    ///   Sepolia; its peers come only from a validated Sepolia export
    ///   ([`NetworkConfig::arbitrum_sepolia_from_export`], D174 §2 R2).
    /// - `devnet`: filled from [`DevnetEnv`].
    ///
    /// **[D173 §2 R12, 2026-09-15] A retired control.** This field was empty for
    /// both public ids until D173, because the pinned ant-core compiles in no
    /// peer list (`Client::connect(bootstrap_peers, ..)` is caller-supplied,
    /// `ant-core-0.5.0/src/data/client/mod.rs:410-433`). That emptiness was the
    /// only thing that made a test holding a public-id configuration dial no
    /// peer: a control, recorded nowhere as one, and deleted by the act that
    /// vendored the list. Its replacement is the [`storage_gate`], which makes
    /// such a dial fail.
    ///
    /// Which peers may be dialed together, and in which transport mode, is
    /// [`NetworkConfig::peer_locality`]'s decision (D173 §2 R8).
    pub bootstrap: Vec<SocketAddr>,
}

impl NetworkConfig {
    /// Arbitrum One — the default network (MVP scope decision 4), with
    /// upstream's vendored bootstrap peers ([`arbitrum_one_vendored_peers`],
    /// D173 §2 R1).
    #[must_use]
    pub fn arbitrum_one() -> Self {
        Self {
            id: NetworkId::ArbitrumOne,
            evm_chain_id: ARBITRUM_ONE_CHAIN_ID,
            rpc_url: ARBITRUM_ONE_RPC_URL.to_owned(),
            payment_token: parse_pinned(ARBITRUM_ONE_PAYMENT_TOKEN),
            payment_vault: parse_pinned(ARBITRUM_ONE_PAYMENT_VAULT),
            bootstrap: arbitrum_one_vendored_peers(),
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
    /// Generic over the wallet slot (P22): a `NetworkConfig` describes the
    /// *chain*, and none of its fields is the wallet, so a walletless
    /// Sepolia-devnet export builds one exactly as a local export does.
    #[must_use]
    pub fn devnet<W>(env: &DevnetEnv<W>) -> Self {
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

// ---------------------------------------------------------------------------
// arbitrum-one's vendored bootstrap peers (D173 §2 R1–R3)
// ---------------------------------------------------------------------------

/// `arbitrum-one`'s built-in bootstrap peer list: a **byte-identical** copy of
/// the peer list upstream published in `WithAutonomi/ant-client` at tag
/// `ant-core-v0.5.0` — the tag the pinned `ant-core = "=0.5.0"` was published
/// from — embedded at compile time (D173 §2 R1).
///
/// Upstream's file is `resources/bootstrap_peers.toml`, audited at
/// <https://github.com/WithAutonomi/ant-client/blob/d93a9719041e0acbafd3eb07feeb9cc06f3fff0b/resources/bootstrap_peers.toml>.
/// The tag and the commit are what is cited, never a branch: upstream rewrites
/// its `main`.
///
/// **What this is, and what it is not.** These are the bytes upstream published
/// at the pin, and that is the whole claim. The entries are `ip:port` addresses
/// with no pinned peer identity, so nothing here claims that any seed is
/// authenticated, is operated by a named party, or is live today (D173 §2 R2).
/// The list belongs to `arbitrum-one` alone: its own header calls it the
/// production list, and there is no public Autonomi network on Arbitrum Sepolia.
///
/// Re-transcribe it from upstream at a pin bump (S20), with the constants below
/// re-derived from upstream and never from this copy. Never hand-edit it.
pub const ARBITRUM_ONE_PEERS_FILE: &[u8] = include_bytes!("arbitrum_one_peers.toml");

/// SHA-256 of [`ARBITRUM_ONE_PEERS_FILE`] — the **integrity** constant (D173 §2
/// R2), computed over the bytes fetched from upstream at the tag.
pub const ARBITRUM_ONE_PEERS_SHA256: &str =
    "9f372ec1c54e25d55cde380dbb7df358345112be26bffc57c167451e935f3e02";

/// Upstream's git blob id for the file at the tag — the **selector** a freshness
/// check compares with the id upstream reports for the same path and tag (D173
/// §2 R2, R18). A git blob id is SHA-1: it selects and never decides trust. The
/// provenance test recomputes it over the embedded bytes, so a stale constant
/// cannot make that comparison report "unchanged" over edited bytes.
pub const ARBITRUM_ONE_PEERS_UPSTREAM_BLOB: &str = "ce77014eb4f387ff8c345473b4bffc68d445d8fd";

/// Where the bytes came from — the **audit path** (D173 §2 R2): repository, tag
/// and commit. The file's own path and URL are in [`ARBITRUM_ONE_PEERS_FILE`]'s
/// documentation.
pub const ARBITRUM_ONE_PEERS_UPSTREAM: &str = "WithAutonomi/ant-client at tag ant-core-v0.5.0, \
                                               commit d93a9719041e0acbafd3eb07feeb9cc06f3fff0b";

/// Why a peer list failed [`parse_vendored_peers`] (D173 §2 R3).
///
/// Names a 1-based line number, or entry indices in file order — never a
/// line's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VendoredPeersError {
    /// The bytes are not UTF-8.
    #[error("the vendored peer list is not UTF-8")]
    NotUtf8,
    /// A line is none of the shapes the format allows.
    #[error(
        "line {line} of the vendored peer list is not a blank line, a `#` comment, `peers = [`, \
         one quoted ip:port entry followed by a comma, or `]`"
    )]
    UnexpectedLine {
        /// 1-based line number.
        line: usize,
    },
    /// An entry does not parse as an IP-literal socket address.
    #[error("line {line} of the vendored peer list is not an IP-literal ip:port socket address")]
    NotSocketAddr {
        /// 1-based line number.
        line: usize,
    },
    /// There is no `peers = [` line.
    #[error("the vendored peer list has no `peers = [` line")]
    NoArray,
    /// The array is never closed.
    #[error("the vendored peer list's `peers = [` array is never closed with `]`")]
    Unclosed,
    /// The entries are not a dialable set: empty, an unspecified address, port
    /// 0, a repeat, or mixed loopback and non-loopback (indices in file order).
    #[error("the vendored peer list's entries are not a dialable set: {0}")]
    Set(#[from] PeerSetError),
}

/// Parse a peer list in upstream's file format, **strictly** (D173 §2 R3).
///
/// The format is exactly: blank lines, `#` comment lines, one `peers = [` line,
/// one `"<ip>:<port>",` entry per line, and one `]` line — with leading and
/// trailing spaces or tabs, and nothing else. Anything else is an error,
/// including a carriage return: a line-ending conversion is a changed file,
/// and it must fail here rather than parse into a list whose bytes are no
/// longer upstream's. Every entry must be an IP-literal socket address (no
/// hostname: nothing on the pinned client path resolves DNS), and the entries
/// must form a set [`classify_peers`] accepts.
///
/// Upstream's own loader silently drops an entry it cannot parse; this never
/// skips one.
///
/// # Errors
///
/// [`VendoredPeersError`].
pub fn parse_vendored_peers(bytes: &[u8]) -> Result<Vec<SocketAddr>, VendoredPeersError> {
    /// Where the parse is relative to the one `peers = [` … `]` array.
    #[derive(Clone, Copy)]
    enum Position {
        Header,
        Entries,
        Trailer,
    }

    let text = core::str::from_utf8(bytes).map_err(|_| VendoredPeersError::NotUtf8)?;
    let mut position = Position::Header;
    let mut peers = Vec::new();
    for (index, raw) in text.split('\n').enumerate() {
        let line = index + 1;
        let content = raw.trim_matches([' ', '\t']);
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        position = match position {
            Position::Header if content == "peers = [" => Position::Entries,
            Position::Entries if content == "]" => Position::Trailer,
            Position::Entries => {
                let entry = content
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix("\","))
                    .filter(|entry| !entry.contains('"'))
                    .ok_or(VendoredPeersError::UnexpectedLine { line })?;
                let peer = entry
                    .parse::<SocketAddr>()
                    .map_err(|_| VendoredPeersError::NotSocketAddr { line })?;
                peers.push(peer);
                Position::Entries
            }
            Position::Header | Position::Trailer => {
                return Err(VendoredPeersError::UnexpectedLine { line });
            }
        };
    }
    match position {
        Position::Header => Err(VendoredPeersError::NoArray),
        Position::Entries => Err(VendoredPeersError::Unclosed),
        Position::Trailer => {
            classify_peers(&peers)?;
            Ok(peers)
        }
    }
}

/// [`ARBITRUM_ONE_PEERS_FILE`], parsed — or an **empty** list if the embedded
/// bytes ever fail [`parse_vendored_peers`] (D173 §2 R3).
///
/// Infallible on purpose, like `parse_pinned`: [`NetworkConfig::arbitrum_one`]
/// is a plain constructor every build calls. An empty list never becomes an
/// isolated client: the adapter refuses an empty set before `Client::connect`
/// ([`classify_peers`]), and the CLI's peer resolution refuses it with a usage
/// error (D173 §2 R7). The provenance and transcription tests make a failing
/// parse of the committed bytes a red test rather than a runtime state.
#[must_use]
pub fn arbitrum_one_vendored_peers() -> Vec<SocketAddr> {
    let parsed = parse_vendored_peers(ARBITRUM_ONE_PEERS_FILE);
    debug_assert!(
        parsed.is_ok(),
        "the vendored arbitrum-one peer list must pass its strict parse"
    );
    parsed.unwrap_or_default()
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
// Peer locality (D173 §2 R8): the one classifier that decides "loopback"
// ---------------------------------------------------------------------------

/// Whether one bootstrap peer is a loopback address, **after** IPv4-mapped
/// canonicalization.
///
/// The one predicate behind every "is this peer loopback?" the workspace asks
/// (D173 §2 R8): [`classify_peers`] and the [`storage_gate`] both call it, so
/// the transport mode a client is built with and the gate that guards it
/// cannot disagree about what loopback means.
///
/// `[::ffff:127.0.0.1]` is loopback here. `Ipv6Addr::is_loopback` is true for
/// `::1` alone, so without the canonicalization a mapped loopback address
/// would classify as public — the opposite of what the transport concludes,
/// because saorsa-core canonicalizes before its own loopback test
/// (`saorsa-core-0.26.2/src/security.rs:30-38`, `canonicalize_ip`, applied at
/// `src/dht_network_manager.rs:322-326`), and `IpAddr::to_canonical` is that
/// same mapping. IPv4 loopback is all of `127.0.0.0/8`; IPv6 loopback is `::1`.
#[must_use]
pub fn is_loopback_peer(peer: &SocketAddr) -> bool {
    peer.ip().to_canonical().is_loopback()
}

/// The transport mode a bootstrap peer set needs (D173 §2 R8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerLocality {
    /// Every peer is loopback. The client must bind loopback only: upstream's
    /// `ClientConfig::allow_loopback` is threaded to saorsa-core's `local`
    /// mode, which binds `127.0.0.1`/`::1` and admits loopback candidates.
    Loopback,
    /// No peer is loopback. The client binds all interfaces and refuses
    /// loopback candidates — the only mode production peers accept.
    Public,
}

/// Why a bootstrap peer set cannot be dialed at all (D173 §2 R8).
///
/// Every variant names **indices** into the set, never an address: a peer set
/// arrives from a configuration file or an environment export, and an error
/// that echoed it would carry that input into logs — the same hygiene the rest
/// of this module keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PeerSetError {
    /// No peer at all.
    ///
    /// Never "loopback": a bare `iter().all(is_loopback)` is `true` for an
    /// empty slice, and a loopback-bound client with nothing to dial is an
    /// isolated client, which upstream starts `Ok` (45 ms, measured by D170)
    /// and which then answers nothing.
    #[error("the bootstrap peer set is empty — there is no peer to connect to")]
    Empty,
    /// An entry is an unspecified address (`0.0.0.0`, `::` or
    /// `::ffff:0.0.0.0`): a bind wildcard, not a peer.
    #[error("bootstrap peer {index} is an unspecified address, which is not a dialable peer")]
    Unspecified {
        /// Zero-based position in the set.
        index: usize,
    },
    /// An entry has port 0.
    #[error("bootstrap peer {index} has port 0, which is not a dialable peer")]
    PortZero {
        /// Zero-based position in the set.
        index: usize,
    },
    /// An entry repeats an earlier one, compared after canonicalization (so
    /// `127.0.0.1:9` and `[::ffff:127.0.0.1]:9` are the same peer).
    #[error("bootstrap peer {index} repeats peer {first}")]
    Duplicate {
        /// Zero-based position of the repeat.
        index: usize,
        /// Zero-based position of the entry it repeats.
        first: usize,
    },
    /// Loopback and non-loopback peers together. One client binds loopback
    /// only, or all interfaces with loopback refused, so no transport mode can
    /// dial both halves: the refusal is forced by the transport, not chosen.
    #[error(
        "the bootstrap peer set mixes loopback peers (peer {loopback} is one) with non-loopback \
         peers (peer {public} is one), and no transport mode can dial both"
    )]
    Mixed {
        /// Zero-based position of the first loopback peer.
        loopback: usize,
        /// Zero-based position of the first non-loopback peer.
        public: usize,
    },
}

/// Classify a bootstrap peer set (D173 §2 R8).
///
/// Entries are checked in order — unspecified, port 0, repeated — so an error
/// names the earliest structurally invalid entry; only a set whose every entry
/// is dialable is then classified, and a mixed one refused.
///
/// # Errors
///
/// [`PeerSetError`], naming indices and never addresses.
pub fn classify_peers(peers: &[SocketAddr]) -> Result<PeerLocality, PeerSetError> {
    if peers.is_empty() {
        return Err(PeerSetError::Empty);
    }
    let mut seen: Vec<(IpAddr, u16)> = Vec::with_capacity(peers.len());
    for (index, peer) in peers.iter().enumerate() {
        let canonical = (peer.ip().to_canonical(), peer.port());
        if canonical.0.is_unspecified() {
            return Err(PeerSetError::Unspecified { index });
        }
        if canonical.1 == 0 {
            return Err(PeerSetError::PortZero { index });
        }
        if let Some(first) = seen.iter().position(|earlier| *earlier == canonical) {
            return Err(PeerSetError::Duplicate { index, first });
        }
        seen.push(canonical);
    }
    let first_loopback = peers.iter().position(is_loopback_peer);
    let first_public = peers.iter().position(|peer| !is_loopback_peer(peer));
    match (first_loopback, first_public) {
        (Some(loopback), Some(public)) => Err(PeerSetError::Mixed { loopback, public }),
        // "Every peer is loopback" — vacuously true of an empty set, which is
        // exactly why `Empty` is refused before this point.
        (_, None) => Ok(PeerLocality::Loopback),
        (None, Some(_)) => Ok(PeerLocality::Public),
    }
}

/// Why a network refuses a bootstrap peer set (D173 §2 R8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PeerLocalityError {
    /// The set cannot be dialed on any network.
    #[error(transparent)]
    Set(#[from] PeerSetError),
    /// `arbitrum-one` was handed loopback peers. A loopback storage network
    /// paired with mainnet payment contracts is either a mistake or a setup
    /// that captures real payments, and it would let a test hold a mainnet
    /// configuration while passing the loopback-only [`storage_gate`].
    #[error(
        "network `{network}` pays mainnet contracts and dials only non-loopback peers, but every \
         bootstrap peer here is loopback"
    )]
    LoopbackForbidden {
        /// The network that refused.
        network: NetworkId,
    },
}

/// The transport mode a connect over `peers` must use on `network` (D173 §2
/// R8), or why it must not connect at all.
///
/// `arbitrum-one` requires [`PeerLocality::Public`]. `arbitrum-sepolia` and
/// `devnet` accept either class — a Sepolia devnet's nodes are loopback, a
/// devnet on a LAN is not — and every network refuses what
/// [`classify_peers`] refuses.
///
/// **Recorded behaviour change (D173 §2 R8):** the adapter used to key
/// loopback on the network id alone, so a `devnet` export with non-loopback
/// peers bound loopback only. It now binds all interfaces.
///
/// # Errors
///
/// [`PeerLocalityError`].
pub fn peer_locality(
    network: NetworkId,
    peers: &[SocketAddr],
) -> Result<PeerLocality, PeerLocalityError> {
    let locality = classify_peers(peers)?;
    match (network, locality) {
        (NetworkId::ArbitrumOne, PeerLocality::Loopback) => {
            Err(PeerLocalityError::LoopbackForbidden { network })
        }
        _ => Ok(locality),
    }
}

impl NetworkConfig {
    /// [`peer_locality`] over this configuration's own id and bootstrap set —
    /// the question the adapter asks before `Client::connect`.
    ///
    /// # Errors
    ///
    /// [`PeerLocalityError`].
    pub fn peer_locality(&self) -> Result<PeerLocality, PeerLocalityError> {
        peer_locality(self.id, &self.bootstrap)
    }
}

// ---------------------------------------------------------------------------
// The no-real-storage-network gate (D173 §2 R9)
// ---------------------------------------------------------------------------

pub mod storage_gate {
    //! The no-real-storage-network gate (D173 §2 R9): the storage twin of
    //! `antseal-anchor`'s Q16 gate (`antseal_anchor::http::offline`), with one
    //! more arm.
    //!
    //! # What it refuses
    //!
    //! When armed, a storage connect whose bootstrap set holds any peer that
    //! [`super::is_loopback_peer`] does not call loopback is refused with a
    //! [`StorageGateRefusal`], which the adapter reports as
    //! `StorageError::Network` — no new variant — as the **first fallible step**
    //! of both storage constructors: before the payer's `eth_chainId` call and
    //! before `Client::connect` (D173 §2 R10). An empty set is admitted, because
    //! there is no peer to refuse; [`super::classify_peers`] refuses it next.
    //!
    //! # Why it exists
    //!
    //! Until D173 the public network configurations carried no bootstrap peers,
    //! and that empty list was the only thing that made a test building a
    //! public-id configuration dial no peer: a control, recorded nowhere as one,
    //! deleted in the very act that vendored upstream's list (D173 §2 R1, R12).
    //! This gate replaces it with a mechanism that makes the dial fail.
    //!
    //! # The arms
    //!
    //! | build | `ANTSEAL_NO_REAL_STORAGE_NETWORK` | gate |
    //! | --- | --- | --- |
    //! | `cfg(test)` of this crate | anything | armed — no off switch |
    //! | any | `0` | disarmed — the only off switch |
    //! | any | any other value, including empty or not Unicode | armed — fails closed |
    //! | debug assertions on | unset | armed |
    //! | release | unset | disarmed |
    //!
    //! The debug-assertions arm is what reaches the tests no venue can arm: the
    //! in-process library suites, which no spawn helper constructs and which
    //! cannot arm themselves (`set_var` is `unsafe`, and `unsafe_code` is
    //! denied). A bare `cargo test` of any devnet suite is therefore armed. It is
    //! a profile property, not a feature, so feature unification can neither arm
    //! nor disarm anything — the reason D99 refused a compile-time arm for the
    //! anchor gate does not transfer, because no storage test may ever need a
    //! public network. The release binary is unaffected unless the variable is
    //! set, and no script runs `cargo test --release` (D173 §2 R9).
    //!
    //! Consulted per connect and never cached, like the anchor gate: a cache
    //! would make the answer depend on which test ran first.
    //!
    //! # What it does not cover (D173 §2 R13)
    //!
    //! Peers learned from the DHT after bootstrap (safe only because an
    //! all-loopback set binds loopback, [`super::peer_locality`]); the payer's
    //! EVM RPC; the UPnP gateway discovery the pinned transport starts on every
    //! connect; and upstream's own on-disk client state.

    use core::fmt;
    use std::ffi::OsStr;
    use std::net::SocketAddr;

    /// The environment variable that arms, or with `0` disarms, the gate.
    pub const ENV: &str = "ANTSEAL_NO_REAL_STORAGE_NETWORK";

    /// The sentence every refusal's text begins with: it names the variable.
    /// The count of refused peers follows it (see [`StorageGateRefusal`]).
    pub const REFUSAL: &str = "the no-real-storage-network gate refused this connection: \
                               ANTSEAL_NO_REAL_STORAGE_NETWORK is armed, and an armed gate lets \
                               a storage client dial loopback peers only";

    /// Why the gate is armed, when the compiler armed it.
    pub const REASON_TEST_BUILD: &str =
        "this is a cfg(test) build of antseal-net, where the gate has no off switch";

    /// Why the gate is armed, when the environment armed it.
    pub const REASON_ENVIRONMENT: &str =
        "ANTSEAL_NO_REAL_STORAGE_NETWORK is set to a value other than 0";

    /// Why the gate is armed, when the build profile armed it.
    pub const REASON_DEBUG_BUILD: &str = "ANTSEAL_NO_REAL_STORAGE_NETWORK is unset in a build with debug assertions, which arms \
         the gate by default";

    /// Why storage connections to non-loopback peers are refused in this
    /// process right now, or [`None`] if they are permitted.
    #[must_use]
    pub fn arming() -> Option<&'static str> {
        decide(
            cfg!(test),
            cfg!(debug_assertions),
            std::env::var_os(ENV).as_deref(),
        )
    }

    /// [`arming`]'s decision as a pure function of its three inputs, so every
    /// arm is testable from inside a `cfg(test)` build, where [`arming`] can
    /// only ever give the `cfg(test)` answer.
    #[must_use]
    pub fn decide(
        test_build: bool,
        debug_build: bool,
        env: Option<&OsStr>,
    ) -> Option<&'static str> {
        if test_build {
            return Some(REASON_TEST_BUILD);
        }
        match env {
            // The one explicit off switch: a real-network run is a script over
            // the release binary, or a debug build that says so.
            Some(value) if value == OsStr::new("0") => None,
            // Everything else arms it, including "", "false" and typos: the
            // failure mode being guarded is a test dialing a public network.
            Some(_) => Some(REASON_ENVIRONMENT),
            None if debug_build => Some(REASON_DEBUG_BUILD),
            None => None,
        }
    }

    /// An armed gate's refusal of one bootstrap set.
    ///
    /// Carries counts and the arming reason — never an address.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct StorageGateRefusal {
        /// How many peers the gate refused (every non-loopback one).
        pub refused: usize,
        /// How many peers the set held.
        pub peers: usize,
        /// Why the gate was armed: one of this module's `REASON_*` constants.
        pub armed_because: &'static str,
    }

    impl fmt::Display for StorageGateRefusal {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{REFUSAL}: {refused} of {peers} bootstrap peer(s) are not loopback. It is armed \
                 because {because}. A build with debug assertions is armed whenever the variable \
                 is unset, so reaching a public network from one needs \
                 ANTSEAL_NO_REAL_STORAGE_NETWORK=0 (D173 §2 R9)",
                refused = self.refused,
                peers = self.peers,
                because = self.armed_because,
            )
        }
    }

    impl std::error::Error for StorageGateRefusal {}

    /// The gate's verdict on `peers` under `armed` (an [`arming`] or
    /// [`decide`] answer).
    ///
    /// # Errors
    ///
    /// [`StorageGateRefusal`] when the gate is armed and any peer is not
    /// loopback. An empty set is admitted.
    pub fn verdict(
        armed: Option<&'static str>,
        peers: &[SocketAddr],
    ) -> Result<(), StorageGateRefusal> {
        let Some(armed_because) = armed else {
            return Ok(());
        };
        let refused = peers
            .iter()
            .filter(|peer| !super::is_loopback_peer(peer))
            .count();
        if refused == 0 {
            return Ok(());
        }
        Err(StorageGateRefusal {
            refused,
            peers: peers.len(),
            armed_because,
        })
    }

    /// [`verdict`] under this process's [`arming`], read afresh on every call —
    /// what the adapter consults first in each storage constructor.
    ///
    /// # Errors
    ///
    /// As [`verdict`].
    pub fn check(peers: &[SocketAddr]) -> Result<(), StorageGateRefusal> {
        verdict(arming(), peers)
    }
}

// ---------------------------------------------------------------------------
// Upstream's state file outside the vault (S42, D178)
// ---------------------------------------------------------------------------

pub mod upstream_state {
    //! The one file the pinned client keeps outside the vault, and the refusal
    //! of an environment in which upstream would panic or write that file into
    //! the current directory (S42, D178 R1).
    //!
    //! # What upstream does
    //!
    //! Every `Client::connect` of `ant-core` 0.5.0 computes
    //! `adaptive::default_persist_path()` — `<data dir>/client_adaptive.json`
    //! ([`FILE_NAME`]) — and reads the file while adaptation is on, which is
    //! the default antseal keeps; `impl Drop for Client` writes it on every
    //! drop, creating the directory if it is missing
    //! (`ant-core-0.5.0/src/data/client/mod.rs:323-338,587-595`,
    //! `adaptive.rs:1491-1594`). The file holds three concurrency starting
    //! values and no peers. The data directory is `config::data_dir()`
    //! (`ant-core-0.5.0/src/config.rs:11-24`):
    //!
    //! | [`Os`] | data directory | with nothing set |
    //! | --- | --- | --- |
    //! | [`Os::Other`] (Linux, and every target that is neither macOS nor Windows) | `$XDG_DATA_HOME/ant`, else `<home>/.local/share/ant` | **panics**: `home_dir().unwrap()` on `HomeDirNotFound` |
    //! | [`Os::MacOs`] | `<home>/Library/Application Support/ant` | no file: `data_dir()` is `Err`, so the path is `None` |
    //! | [`Os::Windows`] | `%APPDATA%\ant`, else `<home>\AppData\Roaming\ant` | **panics**, as on Linux |
    //!
    //! `<home>` is `HOME`, else `USERPROFILE` — upstream's own `home_dir()`
    //! (`config.rs:87-92`), which reads those two variables and nothing else:
    //! **no passwd fallback**, unlike the standard library's `home_dir`, which
    //! antseal's own vault lookup uses. So a process with no `HOME` finds its
    //! vault and then panics inside upstream. Every variable is read with
    //! `std::env::var`, so a value that is not valid Unicode counts as unset,
    //! and a `HOME` that is not valid Unicode panics although it is set. A set
    //! but empty or relative value is used as it is, which puts the file under
    //! the process's **current directory**.
    //!
    //! The panic comes **after** the client node has started and dialed:
    //! `Client::connect` runs `Network::new` before `build_controller`
    //! (`mod.rs:420-421`).
    //!
    //! # What antseal does
    //!
    //! [`check`] mirrors that lookup ([`resolve`]) and refuses
    //! ([`UpstreamStateRefusal`]) when upstream would panic or resolve a
    //! directory that is not absolute. Both storage constructors consult it
    //! right after the storage gate — before the payer's `eth_chainId` and
    //! before `Client::connect`, so before any socket — and report it in the
    //! network class, as they report the gate. Its text begins with
    //! [`REFUSAL`], names the variables, and never echoes a value.
    //!
    //! An absolute directory is left alone: upstream's write is kept, and
    //! documented (D178 R6). macOS without a home is left alone too: upstream
    //! writes nothing there.
    //!
    //! # A copy of upstream's logic, pinned twice
    //!
    //! This module is a transcription, so it is held to its original (D178
    //! R2): unit rows over an injected environment cover every [`Os`] arm in
    //! the default build, and in the feature build `tests/storage_constants.rs`
    //! compares [`resolve`] with upstream's own `default_persist_path()` in a
    //! child process per row, the panic rows included. An `ant-core` bump
    //! re-verifies both (`docs/dependency-policy.md` §4).
    //!
    //! # Tests
    //!
    //! `.cargo/config.toml` sets `XDG_DATA_HOME` to `<workspace>/target/
    //! upstream-data-home` for every process cargo runs from inside the tree
    //! (D178 R3), so no test client writes into the developer's own
    //! `~/.local/share/ant`. `crates/antseal-cli/tests/upstream_state.rs`
    //! asserts it, with a positive control.

    use core::fmt;
    use std::ffi::OsString;
    use std::path::PathBuf;

    /// The file upstream keeps in its data directory
    /// (`ant-core-0.5.0/src/data/client/adaptive.rs:1491`).
    pub const FILE_NAME: &str = "client_adaptive.json";

    /// The sentence every refusal's text begins with. It names the variables
    /// upstream reads; the rest of the text says which case this environment
    /// is, and never what a variable holds.
    pub const REFUSAL: &str = "refusing to start a storage client: the pinned Autonomi client keeps \
                               a state file, client_adaptive.json, in a data directory it finds \
                               through XDG_DATA_HOME, else HOME, else USERPROFILE (APPDATA first \
                               on Windows; only HOME or USERPROFILE on macOS), and in this \
                               environment it would panic or write that file into the current \
                               directory";

    /// The operating-system families upstream's lookup tells apart — its own
    /// `cfg!(target_os = ...)` arms.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Os {
        /// `target_os = "macos"`.
        MacOs,
        /// `target_os = "windows"`.
        Windows,
        /// Every other target, Linux included.
        Other,
    }

    impl Os {
        /// The family this build targets: the arm upstream's `cfg!` takes in
        /// the same build.
        #[must_use]
        pub const fn current() -> Self {
            if cfg!(target_os = "macos") {
                Self::MacOs
            } else if cfg!(target_os = "windows") {
                Self::Windows
            } else {
                Self::Other
            }
        }
    }

    /// What upstream would do with [`FILE_NAME`] in one environment.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Resolution {
        /// Read and write the file in `dir`, which upstream builds from the
        /// value of `from`.
        Dir {
            /// The data directory, joined as this build's path rules join it —
            /// so, for the arm of the OS this build targets, exactly upstream's.
            dir: PathBuf,
            /// The variable whose value the directory is built on.
            from: &'static str,
            /// How that value reads under the [`Os`]'s own rules
            /// ([`is_absolute_on`]). Unless it is absolute, the file lands
            /// under the current directory.
            base: Base,
        },
        /// No file at all: macOS with no home, where `data_dir()` is `Err` and
        /// `default_persist_path()` is `None`.
        NoFile,
        /// `home_dir().unwrap()` panics with `HomeDirNotFound`.
        Panic,
    }

    /// How the value a data directory is built on reads.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Base {
        /// An absolute path.
        Absolute,
        /// A non-empty path that is not absolute.
        Relative,
        /// The empty string.
        Empty,
    }

    impl Resolution {
        /// The file's path, as upstream's `default_persist_path()` returns it:
        /// `None` for [`Resolution::NoFile`], and for [`Resolution::Panic`],
        /// where upstream returns nothing at all.
        #[must_use]
        pub fn file(&self) -> Option<PathBuf> {
            match self {
                Self::Dir { dir, .. } => Some(dir.join(FILE_NAME)),
                Self::NoFile | Self::Panic => None,
            }
        }
    }

    /// Upstream's lookup, for `os`, over `var` — one environment variable's
    /// value, `None` when it is unset (`std::env::var_os`'s contract).
    ///
    /// A transcription of `ant-core-0.5.0/src/config.rs:11-24,87-92`; module
    /// docs.
    #[must_use]
    pub fn resolve(os: Os, var: impl Fn(&str) -> Option<OsString>) -> Resolution {
        // `std::env::var`: unset and not valid Unicode are both `Err`.
        let text = |name: &'static str| {
            var(name)
                .and_then(|value| value.into_string().ok())
                .map(|value| (name, value))
        };
        let home = || text("HOME").or_else(|| text("USERPROFILE"));
        let dir = |(from, value): (&'static str, String), tail: &[&str]| {
            let base = if value.is_empty() {
                Base::Empty
            } else if is_absolute_on(os, &value) {
                Base::Absolute
            } else {
                Base::Relative
            };
            let mut dir = PathBuf::from(value);
            for part in tail {
                dir.push(part);
            }
            Resolution::Dir { dir, from, base }
        };
        match os {
            Os::MacOs => home().map_or(Resolution::NoFile, |home| {
                dir(home, &["Library", "Application Support", "ant"])
            }),
            Os::Windows => match text("APPDATA") {
                Some(appdata) => dir(appdata, &["ant"]),
                None => home().map_or(Resolution::Panic, |home| {
                    dir(home, &["AppData", "Roaming", "ant"])
                }),
            },
            Os::Other => match text("XDG_DATA_HOME") {
                Some(xdg) => dir(xdg, &["ant"]),
                None => home().map_or(Resolution::Panic, |home| {
                    dir(home, &[".local", "share", "ant"])
                }),
            },
        }
    }

    /// Whether `value` is an absolute path under `os`'s rules — judged by
    /// text, so every arm is testable on any host.
    ///
    /// Unix-likes: a leading `/`. Windows: a drive letter, a colon and a
    /// separator (`C:\`, `C:/`), or two leading separators (UNC, `\\?\`,
    /// `\\.\`). `\x` and `C:x` are relative on Windows: the first to the
    /// current drive, the second to that drive's current directory.
    #[must_use]
    pub fn is_absolute_on(os: Os, value: &str) -> bool {
        match os {
            Os::MacOs | Os::Other => value.starts_with('/'),
            Os::Windows => {
                let is_separator = |byte: u8| byte == b'\\' || byte == b'/';
                match value.as_bytes() {
                    [first, second, ..] if is_separator(*first) && is_separator(*second) => true,
                    [drive, b':', separator, ..] => {
                        drive.is_ascii_alphabetic() && is_separator(*separator)
                    }
                    _ => false,
                }
            }
        }
    }

    /// Why this environment cannot hold upstream's state file. Carries
    /// variable names and never a value.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum UpstreamStateRefusal {
        /// No variable gives upstream a directory: it would panic with
        /// `HomeDirNotFound`, after dialing.
        Unresolvable {
            /// The family whose lookup found nothing.
            os: Os,
        },
        /// `variable` is set, and valid Unicode, but empty or relative:
        /// upstream would write the file under the current directory.
        NotAbsolute {
            /// The variable upstream would build the directory on.
            variable: &'static str,
            /// Whether it is empty, rather than a relative path.
            empty: bool,
        },
    }

    impl fmt::Display for UpstreamStateRefusal {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Unresolvable { os } => {
                    let variables = match os {
                        Os::Windows => "APPDATA, HOME and USERPROFILE",
                        Os::MacOs => "HOME and USERPROFILE",
                        Os::Other => "XDG_DATA_HOME, HOME and USERPROFILE",
                    };
                    write!(
                        f,
                        "{REFUSAL}: {variables} are all unset or not valid Unicode, so upstream \
                         would panic after dialing. Set HOME to an absolute directory (S42)"
                    )
                }
                Self::NotAbsolute { variable, empty } => {
                    let what = if *empty {
                        "set but empty"
                    } else {
                        "set to a relative path"
                    };
                    write!(
                        f,
                        "{REFUSAL}: {variable} is {what}, so upstream would write the file under \
                         the current directory. Set {variable} to an absolute directory, or \
                         unset it (S42)"
                    )
                }
            }
        }
    }

    impl std::error::Error for UpstreamStateRefusal {}

    /// The verdict on one environment (D178 R1): refuse when upstream would
    /// panic or resolve a directory that is not absolute.
    ///
    /// # Errors
    ///
    /// [`UpstreamStateRefusal`] in exactly those two cases.
    pub fn verdict(
        os: Os,
        var: impl Fn(&str) -> Option<OsString>,
    ) -> Result<(), UpstreamStateRefusal> {
        match resolve(os, var) {
            Resolution::Panic => Err(UpstreamStateRefusal::Unresolvable { os }),
            Resolution::Dir {
                base: base @ (Base::Relative | Base::Empty),
                from,
                ..
            } => Err(UpstreamStateRefusal::NotAbsolute {
                variable: from,
                empty: base == Base::Empty,
            }),
            Resolution::Dir {
                base: Base::Absolute,
                ..
            }
            | Resolution::NoFile => Ok(()),
        }
    }

    /// [`verdict`] over this process's environment, for the [`Os`] this
    /// build targets, read afresh on every call — what both storage
    /// constructors consult right after the storage gate.
    ///
    /// # Errors
    ///
    /// As [`verdict`].
    pub fn check() -> Result<(), UpstreamStateRefusal> {
        verdict(Os::current(), |name| std::env::var_os(name))
    }

    #[cfg(test)]
    mod tests {
        use std::ffi::OsString;
        use std::path::PathBuf;

        use super::*;

        /// An injected environment: the only variables set, in order.
        type Env = Vec<(&'static str, OsString)>;

        fn lookup(env: &Env) -> impl Fn(&str) -> Option<OsString> + '_ {
            move |name| {
                env.iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.clone())
            }
        }

        fn set(pairs: &[(&'static str, &str)]) -> Env {
            pairs
                .iter()
                .map(|(key, value)| (*key, OsString::from(*value)))
                .collect()
        }

        /// A value that is not valid Unicode, for the rows that need one.
        #[cfg(unix)]
        fn not_unicode(prefix: &str) -> OsString {
            use std::os::unix::ffi::OsStringExt;
            let mut bytes = prefix.as_bytes().to_vec();
            bytes.push(0xFF);
            OsString::from_vec(bytes)
        }

        fn dir(path: &str, from: &'static str, base: Base) -> Resolution {
            Resolution::Dir {
                dir: PathBuf::from(path),
                from,
                base,
            }
        }

        /// **D178 R1/R2, the Linux arm** — the rows P2 measured against a
        /// byte-identical transcription of upstream (`env -i`), and the
        /// verdict on each.
        #[test]
        fn s42_the_linux_arm_follows_upstreams_lookup_row_by_row() {
            use Base::{Absolute, Empty, Relative};
            let rows: Vec<(&str, Env, Resolution)> = vec![
                ("nothing set", set(&[]), Resolution::Panic),
                (
                    "HOME",
                    set(&[("HOME", "/tmp/h2")]),
                    dir("/tmp/h2/.local/share/ant", "HOME", Absolute),
                ),
                (
                    "XDG_DATA_HOME",
                    set(&[("XDG_DATA_HOME", "/tmp/x3")]),
                    dir("/tmp/x3/ant", "XDG_DATA_HOME", Absolute),
                ),
                (
                    "USERPROFILE alone prevents the panic",
                    set(&[("USERPROFILE", "/tmp/u4")]),
                    dir("/tmp/u4/.local/share/ant", "USERPROFILE", Absolute),
                ),
                (
                    "empty XDG_DATA_HOME",
                    set(&[("XDG_DATA_HOME", ""), ("HOME", "/tmp/h5")]),
                    dir("ant", "XDG_DATA_HOME", Empty),
                ),
                (
                    "empty HOME",
                    set(&[("HOME", "")]),
                    dir(".local/share/ant", "HOME", Empty),
                ),
                (
                    "relative XDG_DATA_HOME",
                    set(&[("XDG_DATA_HOME", "rel/dir"), ("HOME", "/tmp/h7")]),
                    dir("rel/dir/ant", "XDG_DATA_HOME", Relative),
                ),
                (
                    "USER and LOGNAME are never read (no passwd fallback)",
                    set(&[("USER", "someone"), ("LOGNAME", "someone")]),
                    Resolution::Panic,
                ),
                (
                    "XDG_DATA_HOME wins over a relative HOME",
                    set(&[("XDG_DATA_HOME", "/tmp/x12"), ("HOME", "rel")]),
                    dir("/tmp/x12/ant", "XDG_DATA_HOME", Absolute),
                ),
                (
                    "HOME wins over USERPROFILE",
                    set(&[("HOME", "/tmp/h13"), ("USERPROFILE", "/tmp/u13")]),
                    dir("/tmp/h13/.local/share/ant", "HOME", Absolute),
                ),
            ];
            for (label, env, expected) in rows {
                assert_eq!(resolve(Os::Other, lookup(&env)), expected, "{label}");
            }
        }

        /// The verdicts over the same arm: refuse exactly the panics and the
        /// directories that are not absolute.
        #[test]
        fn s42_the_linux_verdict_refuses_panics_and_non_absolute_directories() {
            let verdict_of =
                |pairs: &[(&'static str, &str)]| verdict(Os::Other, lookup(&set(pairs)));
            assert_eq!(
                verdict_of(&[]),
                Err(UpstreamStateRefusal::Unresolvable { os: Os::Other })
            );
            assert_eq!(verdict_of(&[("HOME", "/tmp/h")]), Ok(()));
            assert_eq!(verdict_of(&[("XDG_DATA_HOME", "/tmp/x")]), Ok(()));
            assert_eq!(verdict_of(&[("USERPROFILE", "/tmp/u")]), Ok(()));
            assert_eq!(
                verdict_of(&[("XDG_DATA_HOME", ""), ("HOME", "/tmp/h")]),
                Err(UpstreamStateRefusal::NotAbsolute {
                    variable: "XDG_DATA_HOME",
                    empty: true
                })
            );
            assert_eq!(
                verdict_of(&[("HOME", "")]),
                Err(UpstreamStateRefusal::NotAbsolute {
                    variable: "HOME",
                    empty: true
                })
            );
            assert_eq!(
                verdict_of(&[("XDG_DATA_HOME", "rel/dir")]),
                Err(UpstreamStateRefusal::NotAbsolute {
                    variable: "XDG_DATA_HOME",
                    empty: false
                })
            );
            assert_eq!(
                verdict_of(&[("HOME", "relative-home")]),
                Err(UpstreamStateRefusal::NotAbsolute {
                    variable: "HOME",
                    empty: false
                })
            );
        }

        /// The non-Unicode rows: `std::env::var` reads such a value as unset,
        /// so a set `HOME` still panics, `USERPROFILE` rescues it, and a
        /// non-Unicode `XDG_DATA_HOME` falls through to `HOME`.
        #[cfg(unix)]
        #[test]
        fn s42_a_value_that_is_not_unicode_counts_as_unset() {
            let home = vec![("HOME", not_unicode("/tmp/"))];
            assert_eq!(resolve(Os::Other, lookup(&home)), Resolution::Panic);
            assert_eq!(
                verdict(Os::Other, lookup(&home)),
                Err(UpstreamStateRefusal::Unresolvable { os: Os::Other })
            );

            let rescued = vec![
                ("HOME", not_unicode("/tmp/")),
                ("USERPROFILE", OsString::from("/tmp/u9")),
            ];
            assert_eq!(
                resolve(Os::Other, lookup(&rescued)),
                dir("/tmp/u9/.local/share/ant", "USERPROFILE", Base::Absolute)
            );

            let fallthrough = vec![
                ("XDG_DATA_HOME", not_unicode("/tmp/x")),
                ("HOME", OsString::from("/tmp/h10")),
            ];
            assert_eq!(
                resolve(Os::Other, lookup(&fallthrough)),
                dir("/tmp/h10/.local/share/ant", "HOME", Base::Absolute)
            );

            // macOS: a non-Unicode HOME is no home — no file, no refusal.
            assert_eq!(resolve(Os::MacOs, lookup(&home)), Resolution::NoFile);
            assert_eq!(verdict(Os::MacOs, lookup(&home)), Ok(()));
        }

        /// **The macOS arm**: no home means no file and no refusal;
        /// `XDG_DATA_HOME` is never read; an empty or relative home still
        /// writes under the current directory and is refused.
        #[test]
        fn s42_the_macos_arm_writes_nothing_without_a_home_and_ignores_xdg() {
            for env in [set(&[]), set(&[("XDG_DATA_HOME", "/tmp/x")])] {
                assert_eq!(resolve(Os::MacOs, lookup(&env)), Resolution::NoFile);
                assert_eq!(resolve(Os::MacOs, lookup(&env)).file(), None);
                assert_eq!(verdict(Os::MacOs, lookup(&env)), Ok(()));
            }
            assert_eq!(
                resolve(Os::MacOs, lookup(&set(&[("HOME", "/Users/user")]))),
                dir(
                    "/Users/user/Library/Application Support/ant",
                    "HOME",
                    Base::Absolute
                )
            );
            assert_eq!(
                resolve(Os::MacOs, lookup(&set(&[("USERPROFILE", "/Users/x")]))),
                dir(
                    "/Users/x/Library/Application Support/ant",
                    "USERPROFILE",
                    Base::Absolute
                )
            );
            assert_eq!(
                verdict(Os::MacOs, lookup(&set(&[("HOME", "")]))),
                Err(UpstreamStateRefusal::NotAbsolute {
                    variable: "HOME",
                    empty: true
                })
            );
            assert_eq!(
                verdict(Os::MacOs, lookup(&set(&[("HOME", "Users/x")]))),
                Err(UpstreamStateRefusal::NotAbsolute {
                    variable: "HOME",
                    empty: false
                })
            );
        }

        /// **The Windows arm**: `APPDATA`, else the home's
        /// `AppData\Roaming`; `XDG_DATA_HOME` is never read; nothing set
        /// panics. Directories are joined by this host's rules, so only the
        /// source variable and its reading are compared here.
        #[test]
        fn s42_the_windows_arm_reads_appdata_then_the_home_and_never_xdg() {
            let source = |env: Env| match resolve(Os::Windows, lookup(&env)) {
                Resolution::Dir { from, base, .. } => Some((from, base)),
                Resolution::NoFile | Resolution::Panic => None,
            };
            assert_eq!(resolve(Os::Windows, lookup(&set(&[]))), Resolution::Panic);
            assert_eq!(
                resolve(Os::Windows, lookup(&set(&[("XDG_DATA_HOME", "C:\\x")]))),
                Resolution::Panic,
                "XDG_DATA_HOME is never read on Windows"
            );
            assert_eq!(
                verdict(Os::Windows, lookup(&set(&[]))),
                Err(UpstreamStateRefusal::Unresolvable { os: Os::Windows })
            );
            assert_eq!(
                source(set(&[
                    ("APPDATA", "C:\\Users\\user\\AppData\\Roaming"),
                    ("HOME", "C:\\Users\\x")
                ])),
                Some(("APPDATA", Base::Absolute))
            );
            assert_eq!(
                source(set(&[("USERPROFILE", "C:\\Users\\user")])),
                Some(("USERPROFILE", Base::Absolute))
            );
            assert_eq!(
                source(set(&[
                    ("HOME", "C:/Users/x"),
                    ("USERPROFILE", "C:\\Users\\user")
                ])),
                Some(("HOME", Base::Absolute))
            );
            assert_eq!(
                source(set(&[("APPDATA", "")])),
                Some(("APPDATA", Base::Empty))
            );
            assert_eq!(
                source(set(&[("APPDATA", "AppData")])),
                Some(("APPDATA", Base::Relative))
            );
            assert_eq!(
                verdict(Os::Windows, lookup(&set(&[("APPDATA", "")]))),
                Err(UpstreamStateRefusal::NotAbsolute {
                    variable: "APPDATA",
                    empty: true
                })
            );
        }

        /// The Windows absoluteness rule by text, and the Unix one.
        #[test]
        fn s42_absoluteness_is_judged_by_each_systems_own_rule() {
            for (value, absolute) in [
                ("C:\\Users\\user", true),
                ("C:/Users/u", true),
                ("c:\\", true),
                ("\\\\server\\share\\a", true),
                ("\\\\?\\C:\\a", true),
                ("//server/share", true),
                ("C:a", false),
                ("C:", false),
                ("\\Users\\x", false),
                ("/Users/user", false),
                ("a\\b", false),
                ("", false),
                ("1:\\a", false),
            ] {
                assert_eq!(
                    is_absolute_on(Os::Windows, value),
                    absolute,
                    "windows {value:?}"
                );
            }
            for (value, absolute) in [
                ("/", true),
                ("/tmp/x", true),
                ("", false),
                ("rel", false),
                ("./x", false),
                ("~/x", false),
                ("C:\\x", false),
            ] {
                assert_eq!(is_absolute_on(Os::Other, value), absolute, "unix {value:?}");
                assert_eq!(
                    is_absolute_on(Os::MacOs, value),
                    absolute,
                    "macos {value:?}"
                );
            }
        }

        /// The text rule agrees with this host's own `Path::is_absolute` for
        /// the arm this host runs.
        #[test]
        fn s42_the_text_rule_agrees_with_this_hosts_path_rules() {
            let samples = [
                "/",
                "/tmp/x",
                "",
                "rel",
                "./x",
                "C:\\x",
                "C:/x",
                "C:x",
                "\\x",
                "\\\\s\\h\\x",
            ];
            for value in samples {
                assert_eq!(
                    is_absolute_on(Os::current(), value),
                    std::path::Path::new(value).is_absolute(),
                    "{value:?} on {:?}",
                    Os::current()
                );
            }
        }

        /// The refusal's text: the constant first, the variables named, the
        /// values never.
        #[test]
        fn s42_the_refusal_names_variables_and_never_values() {
            let value = "hostile-relative-dir-value";
            let refusal = verdict(Os::Other, lookup(&set(&[("XDG_DATA_HOME", value)])))
                .expect_err("a relative XDG_DATA_HOME is refused");
            let text = refusal.to_string();
            assert!(text.starts_with(REFUSAL), "{text}");
            assert!(
                text.contains("XDG_DATA_HOME is set to a relative path"),
                "{text}"
            );
            assert!(!text.contains(value), "the value leaked: {text}");

            let text = verdict(Os::Other, lookup(&set(&[])))
                .expect_err("nothing set is refused")
                .to_string();
            assert!(text.starts_with(REFUSAL), "{text}");
            assert!(
                text.contains("XDG_DATA_HOME, HOME and USERPROFILE are all unset"),
                "{text}"
            );
            assert!(
                REFUSAL.contains("XDG_DATA_HOME")
                    && REFUSAL.contains("HOME")
                    && REFUSAL.contains("USERPROFILE")
                    && REFUSAL.contains("APPDATA"),
                "the constant names every variable upstream reads"
            );
        }

        /// The path `resolve` reports is the file upstream would touch.
        #[test]
        fn s42_the_file_is_the_data_directory_plus_the_snapshot_name() {
            let resolution = resolve(Os::Other, lookup(&set(&[("XDG_DATA_HOME", "/tmp/x")])));
            assert_eq!(
                resolution.file(),
                Some(PathBuf::from("/tmp/x/ant/client_adaptive.json"))
            );
            assert_eq!(Resolution::Panic.file(), None);
            assert_eq!(FILE_NAME, "client_adaptive.json");
        }
    }
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
///
/// # The wallet slot (P22)
///
/// `W` is the wallet slot, and it is a **type-level** statement about
/// whether this environment has a key at all:
///
/// | `W` | written | wallet accessor | produced by |
/// | --- | --- | --- | --- |
/// | `SecretBuf` (the default, so `DevnetEnv` means this) | ten keys | [`Self::wallet_private_key`] → `&SecretBuf` | [`Self::from_env_file`], [`Self::from_lookup`], [`Self::from_process_env`] |
/// | `Option<SecretBuf>` | nine or ten | [`Self::wallet_private_key`] → `Option<&SecretBuf>` | [`Self::from_env_file_optional_wallet`] and siblings |
///
/// P22's Sepolia devnet writes **nine** keys — a Sepolia key is a real
/// secret and never reaches a file the launcher writes — so its
/// `.devnet/env` does not parse as the ten-key form, by design. Read it as
/// `DevnetEnv<Option<SecretBuf>>` and, if you need to pay, complete it with
/// [`Self::with_wallet`] from wherever your key management lives
/// (docs/devnet/sepolia-devnet.md, "The wallet key is never written to a
/// file").
///
/// A slot rather than an `Option` field because the ten-key form's
/// `wallet_private_key(&self) -> &SecretBuf` is the contract every existing
/// consumer is written against: an `Option`-returning accessor would push
/// an `unwrap`-shaped decision into call sites that cannot reach a
/// walletless export in the first place. Here a consumer that needs a key
/// asks for the type that has one, and the compiler — not a runtime check —
/// is what refuses the walletless case.
pub struct DevnetEnv<W = SecretBuf> {
    rpc_url: String,
    chain_id: u64,
    payment_token: EvmAddress20,
    payment_vault: EvmAddress20,
    wallet_private_key: W,
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

    /// The nine a **Sepolia** devnet export carries: [`ALL`] minus
    /// [`WALLET_PRIVATE_KEY`], in the same order (P22).
    ///
    /// The launcher omits the wallet line entirely rather than writing it
    /// empty, so the absence is a `MissingKey` naming the key — the right
    /// problem — instead of an "invalid hex" three layers downstream.
    pub const ALL_WITHOUT_WALLET: [&str; 9] = [
        RPC_URL,
        CHAIN_ID,
        TOKEN_ADDRESS,
        PAYMENT_VAULT_ADDRESS,
        BOOTSTRAP,
        NODE_COUNT,
        BASE_PORT,
        DATA_DIR,
        PID,
    ];
}

/// Parse every field, in the documented key order, with the wallet either
/// required or optional.
///
/// One body for both shapes so the *order* of checks — and therefore which
/// key a malformed export names first — cannot drift between them. The
/// wallet is checked in its documented position (fifth) in both, so
/// `wallet_required` changes only whether an **absent** key is an error; a
/// present-but-empty value is malformed either way, because an empty value
/// is not the same statement as an omitted line.
///
/// Returns the nine common fields with an empty wallet slot, plus the
/// wallet if the export carried one; the callers fill the slot.
fn parse_devnet_fields(
    lookup: &impl Fn(&str) -> Option<String>,
    wallet_required: bool,
) -> Result<(DevnetEnv<()>, Option<SecretBuf>), DevnetEnvError> {
    {
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
        //
        // P22: an ABSENT key is `MissingKey` only when the caller asked for
        // the ten-key form; a PRESENT-but-empty value is malformed in both
        // forms, so a launcher that ever wrote `WALLET_PRIVATE_KEY=''`
        // cannot pass itself off as a walletless export.
        let wallet_private_key = match lookup(devnet_keys::WALLET_PRIVATE_KEY) {
            Some(raw) => {
                if raw.trim().is_empty() {
                    return Err(invalid(devnet_keys::WALLET_PRIVATE_KEY, "empty"));
                }
                Some(SecretBuf::new(raw.into_bytes()))
            }
            None if wallet_required => {
                return Err(DevnetEnvError::MissingKey {
                    key: devnet_keys::WALLET_PRIVATE_KEY,
                });
            }
            None => None,
        };

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

        Ok((
            DevnetEnv {
                rpc_url,
                chain_id,
                payment_token,
                payment_vault,
                wallet_private_key: (),
                bootstrap,
                node_count,
                base_port,
                data_dir,
                pid,
            },
            wallet_private_key,
        ))
    }
}

/// Split the launcher's flat `KEY='value'` env-file text into a map.
///
/// Blank lines and `#` comments are skipped; unknown `ANTSEAL_DEVNET_*`
/// keys are ignored (forward compatibility with a launcher that exports
/// more). Values may be wrapped in single quotes (the launcher's format) or
/// bare; embedded quotes are not supported (the launcher never emits them —
/// addresses, hex, numbers, socket lists, paths).
fn env_file_map(text: &str) -> BTreeMap<&str, String> {
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
    map
}

impl<W> DevnetEnv<W> {
    /// Move the nine common fields into a different wallet slot.
    fn with_slot<X>(self, wallet_private_key: X) -> DevnetEnv<X> {
        DevnetEnv {
            rpc_url: self.rpc_url,
            chain_id: self.chain_id,
            payment_token: self.payment_token,
            payment_vault: self.payment_vault,
            wallet_private_key,
            bootstrap: self.bootstrap,
            node_count: self.node_count,
            base_port: self.base_port,
            data_dir: self.data_dir,
            pid: self.pid,
        }
    }
}

/// The ten-key form: the local devnet's export, wallet **required**.
impl DevnetEnv<SecretBuf> {
    /// Parse from any key→value lookup (the seam every other constructor
    /// funnels through; tests drive it directly).
    ///
    /// # Errors
    ///
    /// [`DevnetEnvError`] naming the offending **key** and the structural
    /// problem. Values are never echoed — uniformly, so the wallet-key
    /// line cannot become the exception by accident.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, DevnetEnvError> {
        let (base, wallet) = parse_devnet_fields(&lookup, true)?;
        // `wallet_required` already refused an absent key by name; this
        // keeps the function total without a second failure mode.
        let wallet = wallet.ok_or(DevnetEnvError::MissingKey {
            key: devnet_keys::WALLET_PRIVATE_KEY,
        })?;
        Ok(base.with_slot(wallet))
    }

    /// Parse from the process environment (after `source .devnet/env`, or
    /// under a harness that exported the keys).
    ///
    /// This is the shape the Sepolia recipe produces: source the chain half
    /// **and** the launcher half, export the key, and all ten are present
    /// with none of them on disk (docs/devnet/sepolia-devnet.md).
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
    /// All ten keys must be present. A P22 **Sepolia** export carries nine
    /// and is refused here, naming `ANTSEAL_DEVNET_WALLET_PRIVATE_KEY` —
    /// read it with [`Self::from_env_file_optional_wallet`] instead.
    ///
    /// # Errors
    ///
    /// As [`Self::from_lookup`].
    pub fn from_env_file(text: &str) -> Result<Self, DevnetEnvError> {
        let map = env_file_map(text);
        Self::from_lookup(|key| map.get(key).cloned())
    }

    /// The funded dev wallet key (key-shaped material — zeroizing buffer;
    /// feed it to `crate::wallet::WalletKey::import`).
    ///
    /// Infallible **by type**: this form parses only from an export that
    /// carried a key. The walletless form's accessor of the same name
    /// returns an `Option` instead.
    #[must_use]
    pub const fn wallet_private_key(&self) -> &SecretBuf {
        &self.wallet_private_key
    }
}

/// The nine-or-ten-key form: an export that **may** omit the wallet — P22's
/// Arbitrum-Sepolia devnet, whose key is a real secret and is never written
/// to any file.
impl DevnetEnv<Option<SecretBuf>> {
    /// Parse from any key→value lookup, tolerating an absent wallet key.
    ///
    /// # Errors
    ///
    /// As [`DevnetEnv::from_lookup`], except that an absent
    /// `ANTSEAL_DEVNET_WALLET_PRIVATE_KEY` is not an error. A *present but
    /// empty* one still is.
    pub fn from_lookup_optional_wallet(
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, DevnetEnvError> {
        let (base, wallet) = parse_devnet_fields(&lookup, false)?;
        Ok(base.with_slot(wallet))
    }

    /// Parse the launcher's flat env-file text, tolerating an absent wallet
    /// key — the P22 Sepolia `.devnet/env`.
    ///
    /// # Errors
    ///
    /// As [`Self::from_lookup_optional_wallet`].
    pub fn from_env_file_optional_wallet(text: &str) -> Result<Self, DevnetEnvError> {
        let map = env_file_map(text);
        Self::from_lookup_optional_wallet(|key| map.get(key).cloned())
    }

    /// Parse from the process environment, tolerating an absent wallet key.
    ///
    /// # Errors
    ///
    /// As [`Self::from_lookup_optional_wallet`].
    pub fn from_process_env_optional_wallet() -> Result<Self, DevnetEnvError> {
        Self::from_lookup_optional_wallet(|key| std::env::var(key).ok())
    }

    /// Complete a walletless environment with a key supplied out of band —
    /// the code form of the Sepolia recipe, for a caller whose key lives in
    /// a key manager rather than in the process environment.
    ///
    /// Any key already parsed is **replaced**: the caller's is the one they
    /// meant.
    #[must_use]
    pub fn with_wallet(self, wallet_private_key: SecretBuf) -> DevnetEnv<SecretBuf> {
        self.with_slot(wallet_private_key)
    }

    /// Promote to the ten-key form if this export did carry a wallet.
    ///
    /// # Errors
    ///
    /// [`DevnetEnvError::MissingKey`] naming
    /// `ANTSEAL_DEVNET_WALLET_PRIVATE_KEY` when it did not — the same error
    /// the ten-key parse would have produced, so a consumer that discovers
    /// the need for a key late reports it identically to one that demanded
    /// it up front.
    pub fn require_wallet(self) -> Result<DevnetEnv<SecretBuf>, DevnetEnvError> {
        let DevnetEnv {
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
        } = self;
        let Some(wallet_private_key) = wallet_private_key else {
            return Err(DevnetEnvError::MissingKey {
                key: devnet_keys::WALLET_PRIVATE_KEY,
            });
        };
        Ok(DevnetEnv {
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

    /// The funded wallet key, if this export carried one.
    ///
    /// Feed it to `crate::wallet::WalletKey::import`; a `None` here is the
    /// normal, designed state of a Sepolia devnet export, not a fault.
    #[must_use]
    pub fn wallet_private_key(&self) -> Option<&SecretBuf> {
        self.wallet_private_key.as_ref()
    }
}

impl<W> DevnetEnv<W> {
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

impl<W: fmt::Debug> fmt::Debug for DevnetEnv<W> {
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

// ---------------------------------------------------------------------------
// Export classification (D174 §2 R1–R2): which network an export belongs to
// ---------------------------------------------------------------------------

/// The network a devnet environment export belongs to, decided by its chain id
/// alone (D174 §2 R1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportChain {
    /// Chain 421614: a Sepolia-mode export. It belongs to `arbitrum-sepolia`,
    /// never to `devnet`, which would record a payment on a public chain as
    /// `devnet` (D174 §2 R3).
    ArbitrumSepolia,
    /// Chain 42161: a chain no export may carry — `arbitrum-one` never reads
    /// an export (D174 §2 R4).
    ArbitrumOne,
    /// Any other chain: a local devnet export (Anvil's 31337 in practice).
    LocalDevnet,
}

/// Classify an export by its `ANTSEAL_DEVNET_CHAIN_ID` (D174 §2 R1).
///
/// The argument is the chain id and nothing else, so the classification cannot
/// be made on what D174 refuses to decide it by: the key count (nine keys
/// versus ten says who funds the wallet, U89), the path or the file name.
#[must_use]
pub const fn classify_export_chain(chain_id: u64) -> ExportChain {
    match chain_id {
        ARBITRUM_SEPOLIA_CHAIN_ID => ExportChain::ArbitrumSepolia,
        ARBITRUM_ONE_CHAIN_ID => ExportChain::ArbitrumOne,
        _ => ExportChain::LocalDevnet,
    }
}

/// Why an export is not one `arbitrum-sepolia` may read (D174 §2 R2).
///
/// A wrong chain names the chain the export carries. A contract mismatch names
/// the export **key** and the **pinned** address — never the export's own
/// value, the hygiene every other refusal in this module keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SepoliaExportMismatch {
    /// The export's chain is not Arbitrum Sepolia's.
    #[error("the export carries chain {chain_id}, not Arbitrum Sepolia's chain 421614")]
    Chain {
        /// The chain id the export carries.
        chain_id: u64,
    },
    /// A payment contract differs from the pinned D38 deployment.
    #[error("the export's {key} is not the pinned Arbitrum Sepolia contract {pinned}")]
    Contract {
        /// The export key whose value differs.
        key: &'static str,
        /// The pinned address that key must equal.
        pinned: &'static str,
    },
}

/// Accept an export for `arbitrum-sepolia` iff its chain is 421614 **and** its
/// payment token **and** its payment vault equal the D38 pins byte for byte
/// (D174 §2 R2, the pure half).
///
/// The chain is compared first, so a local export is refused for its chain
/// rather than masked by a contract refusal. The contract comparison is
/// load-bearing, not decorative: `crate::evm` maps `arbitrum-sepolia` to
/// evmlib's built-in network and never reads an export's contracts, so an
/// export naming other contracts would have its nodes verifying payments to
/// contracts the client never pays.
///
/// # Errors
///
/// [`SepoliaExportMismatch`].
pub fn check_sepolia_export<W>(env: &DevnetEnv<W>) -> Result<(), SepoliaExportMismatch> {
    if classify_export_chain(env.chain_id) != ExportChain::ArbitrumSepolia {
        return Err(SepoliaExportMismatch::Chain {
            chain_id: env.chain_id,
        });
    }
    let contracts = [
        (
            devnet_keys::TOKEN_ADDRESS,
            ARBITRUM_SEPOLIA_PAYMENT_TOKEN,
            env.payment_token,
        ),
        (
            devnet_keys::PAYMENT_VAULT_ADDRESS,
            ARBITRUM_SEPOLIA_PAYMENT_VAULT,
            env.payment_vault,
        ),
    ];
    for (key, pinned, exported) in contracts {
        if exported != parse_pinned(pinned) {
            return Err(SepoliaExportMismatch::Contract { key, pinned });
        }
    }
    Ok(())
}

impl NetworkConfig {
    /// `arbitrum-sepolia` as read from a validated Sepolia-mode export (D174 §2
    /// R2): [`Self::arbitrum_sepolia`]'s pinned chain id, RPC and contracts,
    /// with `bootstrap` **replaced** by the export's peers — replaced, never
    /// merged (D173 §2 R6).
    ///
    /// **The export's `ANTSEAL_DEVNET_RPC_URL` is not used.** `crate::evm` maps
    /// `arbitrum-sepolia` to evmlib's built-in network, whose RPC is the pinned
    /// [`ARBITRUM_SEPOLIA_RPC_URL`] (held equal by `crate::evm`'s agreement
    /// test), and the payer's `eth_chainId` guard is the chain check.
    ///
    /// # Errors
    ///
    /// [`SepoliaExportMismatch`], from [`check_sepolia_export`].
    pub fn arbitrum_sepolia_from_export<W>(
        env: &DevnetEnv<W>,
    ) -> Result<Self, SepoliaExportMismatch> {
        check_sepolia_export(env)?;
        Ok(Self {
            bootstrap: env.bootstrap.clone(),
            ..Self::arbitrum_sepolia()
        })
    }
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
        // D173 §2 R12 — the assertion that stood here was
        // `one.bootstrap.is_empty()`, "no compiled-in mainnet peers": a fact
        // about upstream, recorded as if it were not also a control. It was
        // the control that kept every public-id connect peerless; vendoring
        // upstream's list retired it, and the storage gate replaced it.
        assert_eq!(
            one.bootstrap,
            peers(&UPSTREAM_PEERS_IN_FILE_ORDER),
            "arbitrum-one carries upstream's vendored peer list at the pin (D173 §2 R1)"
        );

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
        // D174 §5 / D173 §2 R1: there is no public Autonomi storage network on
        // Arbitrum Sepolia, so nothing may be vendored for it — its peers come
        // only from a validated Sepolia export.
        assert!(
            sepolia.bootstrap.is_empty(),
            "arbitrum-sepolia must carry no built-in peers — the production list must never \
             attach to a test chain"
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

    // ── P22: the walletless (Arbitrum-Sepolia) export ──────────────────

    /// The launcher's Sepolia export **shape**: P16's ten keys minus the wallet
    /// line, with Arbitrum Sepolia's chain id. Built by FILTERING the ten-key
    /// fixture rather than by retyping it, so the two fixtures cannot drift
    /// into disagreeing about anything but the wallet.
    ///
    /// **Its contracts are Anvil's, not the D38 pins** — this doc used to call
    /// them canonical. Since D174 §2 R2 that makes it the contract-MISMATCH
    /// case; the canonical export is [`fixture_canonical_sepolia_env_file`].
    fn fixture_sepolia_env_file() -> String {
        fixture_env_file()
            .lines()
            .filter(|line| !line.starts_with(devnet_keys::WALLET_PRIVATE_KEY))
            .map(|line| {
                if line.starts_with(devnet_keys::CHAIN_ID) {
                    "ANTSEAL_DEVNET_CHAIN_ID='421614'".to_owned()
                } else {
                    line.to_owned()
                }
            })
            .map(|line| format!("{line}\n"))
            .collect()
    }

    /// The nine-vs-ten distinction, from both sides: the Sepolia export is
    /// refused by the ten-key parse — **naming the wallet key**, not some
    /// downstream symptom — and accepted by the optional-wallet parse.
    #[test]
    fn p22_a_sepolia_export_needs_the_optional_wallet_parse() {
        let text = fixture_sepolia_env_file();
        assert_eq!(
            text.lines().filter(|l| l.contains('=')).count(),
            devnet_keys::ALL_WITHOUT_WALLET.len(),
            "the fixture must be the nine-key shape"
        );

        // Ten-key form: refused, by name.
        assert_eq!(
            DevnetEnv::from_env_file(&text).expect_err("nine keys is not ten"),
            DevnetEnvError::MissingKey {
                key: devnet_keys::WALLET_PRIVATE_KEY
            }
        );

        // Optional-wallet form: parses, and says so honestly.
        let env = DevnetEnv::<Option<SecretBuf>>::from_env_file_optional_wallet(&text)
            .expect("the Sepolia export parses");
        assert!(env.wallet_private_key().is_none());
        assert_eq!(env.chain_id(), ARBITRUM_SEPOLIA_CHAIN_ID);
        assert_ne!(env.chain_id(), 11_155_111, "that is Ethereum Sepolia");
        assert_eq!(env.node_count(), 14);
        assert_eq!(env.bootstrap().len(), 3);

        // And it is enough to describe the network: a NetworkConfig has no
        // wallet field, so nothing about paying is being smuggled in here.
        let config = NetworkConfig::devnet(&env);
        assert_eq!(config.id, NetworkId::Devnet);
        assert_eq!(config.evm_chain_id, ARBITRUM_SEPOLIA_CHAIN_ID);
        assert_eq!(config.bootstrap.len(), 3);
    }

    /// The recipe, in code: nine keys off disk plus a key from somewhere
    /// that is not disk. Both completions produce the ten-key form.
    #[test]
    fn p22_a_walletless_export_completes_with_an_out_of_band_key() {
        let text = fixture_sepolia_env_file();
        let supplied = || SecretBuf::new(fixture_key_hex().into_bytes());

        let completed = DevnetEnv::<Option<SecretBuf>>::from_env_file_optional_wallet(&text)
            .expect("parses")
            .with_wallet(supplied());
        assert_eq!(
            completed.wallet_private_key().as_bytes(),
            fixture_key_hex().as_bytes()
        );
        assert_eq!(completed.chain_id(), ARBITRUM_SEPOLIA_CHAIN_ID);

        // Without a key, promotion fails with the SAME error the ten-key
        // parse gives — a late discovery reports identically to an early one.
        assert_eq!(
            DevnetEnv::<Option<SecretBuf>>::from_env_file_optional_wallet(&text)
                .expect("parses")
                .require_wallet()
                .map(|_| ())
                .expect_err("no wallet to promote"),
            DevnetEnvError::MissingKey {
                key: devnet_keys::WALLET_PRIVATE_KEY
            }
        );

        // The layered lookup — file keys first, the key from elsewhere —
        // is the same recipe through the ten-key seam directly.
        let map = env_file_map(&text);
        let layered = DevnetEnv::from_lookup(|key| {
            if key == devnet_keys::WALLET_PRIVATE_KEY {
                Some(fixture_key_hex())
            } else {
                map.get(key).cloned()
            }
        })
        .expect("nine from the file plus one from elsewhere is ten");
        assert_eq!(
            layered.wallet_private_key().as_bytes(),
            fixture_key_hex().as_bytes()
        );
    }

    /// A ten-key export still promotes, so the optional parse is a
    /// widening rather than a second dialect.
    #[test]
    fn p22_the_optional_parse_also_accepts_a_ten_key_export() {
        let env =
            DevnetEnv::<Option<SecretBuf>>::from_env_file_optional_wallet(&fixture_env_file())
                .expect("ten keys parse in the optional form too");
        assert!(env.wallet_private_key().is_some());
        let promoted = env.require_wallet().expect("a key is present");
        assert_eq!(
            promoted.wallet_private_key().as_bytes(),
            fixture_key_hex().as_bytes()
        );
        assert_eq!(promoted.chain_id(), 31_337);
    }

    /// An **empty** wallet value is malformed in both forms. Absent and
    /// empty are different statements: a launcher that wrote
    /// `WALLET_PRIVATE_KEY=''` must not pass as a walletless export.
    #[test]
    fn p22_an_empty_wallet_value_is_malformed_in_both_forms() {
        let text: String = fixture_env_file()
            .lines()
            .map(|line| {
                if line.starts_with(devnet_keys::WALLET_PRIVATE_KEY) {
                    "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY=\'\'".to_owned()
                } else {
                    line.to_owned()
                }
            })
            .map(|line| format!("{line}\n"))
            .collect();

        for err in [
            DevnetEnv::from_env_file(&text)
                .map(|_| ())
                .expect_err("ten"),
            DevnetEnv::<Option<SecretBuf>>::from_env_file_optional_wallet(&text)
                .map(|_| ())
                .expect_err("optional"),
        ] {
            match err {
                DevnetEnvError::InvalidValue { key, problem } => {
                    assert_eq!(key, devnet_keys::WALLET_PRIVATE_KEY);
                    assert_eq!(problem, "empty");
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        }
    }

    /// The optional parse relaxes exactly one key. Every one of the other
    /// nine is still required, and still named.
    #[test]
    fn p22_the_optional_parse_relaxes_only_the_wallet_key() {
        let text = fixture_sepolia_env_file();
        for missing in devnet_keys::ALL_WITHOUT_WALLET {
            let filtered: String = text
                .lines()
                .filter(|line| !line.starts_with(missing))
                .map(|line| format!("{line}\n"))
                .collect();
            let err = DevnetEnv::<Option<SecretBuf>>::from_env_file_optional_wallet(&filtered)
                .map(|_| ())
                .expect_err("must fail");
            assert_eq!(err, DevnetEnvError::MissingKey { key: missing });
        }
        // …and the nine are the ten minus exactly the wallet key.
        let expected: Vec<&str> = devnet_keys::ALL
            .iter()
            .copied()
            .filter(|k| *k != devnet_keys::WALLET_PRIVATE_KEY)
            .collect();
        assert_eq!(devnet_keys::ALL_WITHOUT_WALLET.to_vec(), expected);
    }

    /// No error this parser can raise about a wallet-bearing export ever
    /// carries the key.
    ///
    /// `malformed_values_name_the_key_and_never_echo_the_value` checks five
    /// keys and the wallet is not among them — the one key where an echo
    /// would matter most was the one not swept. P22 touches this parse, so
    /// it closes that here rather than leaving it for the change that
    /// starts echoing.
    #[test]
    fn p22_no_parse_error_ever_carries_the_wallet_key() {
        let key = fixture_key_hex();
        let base = fixture_env_file();

        let mut broken = vec![
            // wallet absent, wallet empty
            base.lines()
                .filter(|l| !l.starts_with(devnet_keys::WALLET_PRIVATE_KEY))
                .map(|l| format!("{l}\n"))
                .collect::<String>(),
            base.lines()
                .map(|l| {
                    if l.starts_with(devnet_keys::WALLET_PRIVATE_KEY) {
                        "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY=\'\'".to_owned()
                    } else {
                        l.to_owned()
                    }
                })
                .map(|l| format!("{l}\n"))
                .collect::<String>(),
        ];
        // …and every other key broken in turn, with the wallet still present.
        for other in devnet_keys::ALL_WITHOUT_WALLET {
            broken.push(
                base.lines()
                    .map(|l| {
                        if l.starts_with(other) {
                            format!("{other}='!!not-a-valid-value!!'")
                        } else {
                            l.to_owned()
                        }
                    })
                    .map(|l| format!("{l}\n"))
                    .collect::<String>(),
            );
        }

        let mut errors = 0;
        for text in &broken {
            for message in [
                DevnetEnv::from_env_file(text).map(|_| ()).err(),
                DevnetEnv::<Option<SecretBuf>>::from_env_file_optional_wallet(text)
                    .map(|_| ())
                    .err(),
            ]
            .into_iter()
            .flatten()
            .map(|e| e.to_string())
            {
                errors += 1;
                assert!(!message.contains(&key), "wallet key echoed: {message}");
            }
        }
        // The sweep must actually have produced errors — a matrix that
        // silently parsed everything would assert nothing at all.
        assert!(
            errors >= broken.len(),
            "only {errors} errors from {} cases",
            broken.len()
        );
    }

    /// Rule 6 holds on the new shape too: a completed walletless export
    /// redacts exactly as the ten-key one does, and the walletless one
    /// shows an absent slot rather than an invisible field.
    #[test]
    fn p22_debug_redacts_on_the_walletless_shape_too() {
        let walletless = DevnetEnv::<Option<SecretBuf>>::from_env_file_optional_wallet(
            &fixture_sepolia_env_file(),
        )
        .expect("parses");
        let debug = format!("{walletless:?}");
        assert!(!debug.contains(&fixture_key_hex()), "{debug}");
        assert!(debug.contains("wallet_private_key: None"), "{debug}");

        let completed = walletless.with_wallet(SecretBuf::new(fixture_key_hex().into_bytes()));
        let debug = format!("{completed:?}");
        assert!(!debug.contains(&fixture_key_hex()), "key leaked: {debug}");
        assert!(debug.contains("SecretBuf(<redacted>)"), "{debug}");
    }

    // ── D173 §2 R1–R3: arbitrum-one's vendored peers ──────────────────────

    /// The seven entries of upstream's list at `ant-core-v0.5.0`, transcribed by
    /// hand from the bytes, in file order — independently of the parser, so a
    /// parser that skips an entry cannot agree with it.
    const UPSTREAM_PEERS_IN_FILE_ORDER: [&str; 7] = [
        "207.148.94.42:10000",
        "45.77.50.10:10000",
        "66.135.23.83:10000",
        "149.248.9.2:10000",
        "49.12.119.240:10000",
        "5.161.25.133:10000",
        "18.228.202.183:10000",
    ];

    fn lower_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// git's blob id: SHA-1 over `blob <length>\0` followed by the bytes.
    fn git_blob_id(bytes: &[u8]) -> String {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
        hasher.update(bytes);
        lower_hex(hasher.finalize().as_slice())
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        lower_hex(Sha256::digest(bytes).as_slice())
    }

    /// **D173 §2 R2.** The embedded bytes are upstream's at the pin: both
    /// hashes recomputed over them, each hash function first shown to compute
    /// (known answers), and one flipped byte shown to change both — so neither a
    /// function that returns its constant nor a comparison that cannot differ
    /// passes.
    #[test]
    fn d173_the_vendored_arbitrum_one_peer_list_is_upstreams_bytes_at_the_pin() {
        // Known answers: git's ids for the empty blob and for "hello\n", and
        // SHA-256 of "" and of "abc".
        assert_eq!(git_blob_id(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
        assert_eq!(
            git_blob_id(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let sha256 = sha256_hex(ARBITRUM_ONE_PEERS_FILE);
        let blob = git_blob_id(ARBITRUM_ONE_PEERS_FILE);
        assert!(
            sha256 == ARBITRUM_ONE_PEERS_SHA256 && blob == ARBITRUM_ONE_PEERS_UPSTREAM_BLOB,
            "the vendored arbitrum-one peer list is not upstream's bytes at \
             {ARBITRUM_ONE_PEERS_UPSTREAM}: sha256 {sha256} != {ARBITRUM_ONE_PEERS_SHA256}; git \
             blob {blob} != {ARBITRUM_ONE_PEERS_UPSTREAM_BLOB}. Re-transcribe it from upstream at \
             a pin bump (S20), with both constants re-derived from upstream — never hand-edit it"
        );

        let mut flipped = ARBITRUM_ONE_PEERS_FILE.to_vec();
        if let Some(last) = flipped.last_mut() {
            *last ^= 0x01;
        }
        assert_ne!(sha256_hex(&flipped), ARBITRUM_ONE_PEERS_SHA256);
        assert_ne!(git_blob_id(&flipped), ARBITRUM_ONE_PEERS_UPSTREAM_BLOB);
    }

    /// **The vendored list's checkout bytes.** `.gitattributes` must keep the
    /// data file behind [`ARBITRUM_ONE_PEERS_FILE`] byte-exact on every checkout.
    ///
    /// The `windows-latest` image sets `core.autocrlf=true` machine-wide, and
    /// no rule covered this file when D173 vendored it: a Windows checkout
    /// would turn every `0x0A` into `0x0D 0x0A`, so the embedded bytes would no
    /// longer be upstream's and the strict parser would refuse them —
    /// `arbitrum-one` with no peers at all. No CI lane builds this crate on
    /// Windows, so the damage would show nowhere; this fails everywhere
    /// instead, mirroring antseal-core's
    /// `anchor::roots::tests::the_gitattributes_binary_rule_covers_this_directory`.
    ///
    /// Two checks, neither of which evaluates a glob: the exact rule is present,
    /// and no later line sets an end-of-line attribute at all. In
    /// `.gitattributes` the last matching line wins, so a later `*.toml text`
    /// would undo the rule while leaving it in place — this refuses any later
    /// `text`, `eol` or `crlf` setting rather than guessing whether it matches.
    #[test]
    fn the_gitattributes_rule_keeps_the_vendored_peer_list_byte_exact() {
        const GITATTRIBUTES: &str =
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.gitattributes"));
        const RULE: &str = "crates/antseal-net/src/arbitrum_one_peers.toml -text";

        let lines: Vec<&str> = GITATTRIBUTES.lines().map(str::trim).collect();
        let position = lines
            .iter()
            .position(|line| *line == RULE)
            .unwrap_or_else(|| {
                panic!(
                    "`.gitattributes` must carry the line `{RULE}`; without it a Windows \
                     checkout CRLF-mangles the vendored arbitrum-one peer list, which is then not \
                     upstream's bytes and parses to no peers"
                )
            });
        let later: Vec<&str> = lines
            .iter()
            .skip(position + 1)
            .copied()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter(|line| {
                line.split_whitespace().skip(1).any(|attribute| {
                    let name = attribute.trim_start_matches(['-', '!']);
                    let name = name.split('=').next().unwrap_or(name);
                    matches!(name, "text" | "eol" | "crlf")
                })
            })
            .collect();
        assert!(
            later.is_empty(),
            "`.gitattributes` sets an end-of-line attribute after `{RULE}`: {later:?}. The last \
             matching line wins, so a later line can undo the rule for the vendored peer list — \
             keep `{RULE}` below every such line"
        );
    }

    /// **D173 §2 R1, R3.** The strict parse equals the independent
    /// transcription, in file order; `arbitrum-one` carries exactly it; it is a
    /// set `arbitrum-one` may dial; and `arbitrum-sepolia` carries none of it.
    #[test]
    fn d173_the_vendored_list_parses_to_exactly_upstreams_seven_peers_in_order() {
        let transcription = peers(&UPSTREAM_PEERS_IN_FILE_ORDER);
        let mut distinct = transcription.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            7,
            "the transcription itself must be seven distinct addresses"
        );

        let parsed = parse_vendored_peers(ARBITRUM_ONE_PEERS_FILE).unwrap_or_else(|error| {
            panic!("the vendored arbitrum-one peer list must pass its strict parse: {error}")
        });
        assert_eq!(
            parsed.len(),
            transcription.len(),
            "parse must equal the independent transcription: {} vs {}",
            parsed.len(),
            transcription.len()
        );
        assert_eq!(
            parsed, transcription,
            "parse must equal the independent transcription, in file order"
        );
        assert_eq!(arbitrum_one_vendored_peers(), transcription);
        assert_eq!(NetworkConfig::arbitrum_one().bootstrap, transcription);
        assert_eq!(NetworkConfig::default().bootstrap, transcription);
        assert_eq!(
            NetworkConfig::arbitrum_one().peer_locality(),
            Ok(PeerLocality::Public),
            "the vendored list must be a set arbitrum-one may dial"
        );
        assert!(
            NetworkConfig::arbitrum_sepolia().bootstrap.is_empty(),
            "arbitrum-sepolia must carry no built-in peers — the production list must never \
             attach to a test chain"
        );
        let env = DevnetEnv::from_env_file(&fixture_env_file()).expect("fixture parses");
        let devnet = NetworkConfig::devnet(&env);
        assert_eq!(
            devnet.bootstrap,
            env.bootstrap(),
            "devnet carries its export's peers and no built-in ones"
        );
        assert!(
            devnet
                .bootstrap
                .iter()
                .all(|peer| !transcription.contains(peer)),
            "devnet must carry none of the vendored production peers"
        );
    }

    /// **D173 §2 R3.** Strictness, one malformed shape per row: each is refused,
    /// by line — never skipped, never repaired.
    #[test]
    fn d173_the_strict_parser_refuses_every_shape_but_upstreams() {
        use VendoredPeersError::{NoArray, NotSocketAddr, NotUtf8, Set, Unclosed, UnexpectedLine};

        let good = "# header\n\npeers = [\n    \"192.0.2.1:10000\",\n\t\"192.0.2.2:10000\",\n]\n";
        assert_eq!(
            parse_vendored_peers(good.as_bytes()),
            Ok(peers(&["192.0.2.1:10000", "192.0.2.2:10000"])),
            "the format's own shape parses"
        );

        let rows: [(&str, &str, VendoredPeersError); 17] = [
            (
                "an entry that is a hostname",
                "peers = [\n  \"example.org:10000\",\n  \"192.0.2.2:10000\",\n]\n",
                NotSocketAddr { line: 2 },
            ),
            (
                "an entry without a port",
                "peers = [\n  \"192.0.2.1\",\n]\n",
                NotSocketAddr { line: 2 },
            ),
            (
                "an entry without its comma",
                "peers = [\n  \"192.0.2.1:10000\"\n]\n",
                UnexpectedLine { line: 2 },
            ),
            (
                "two entries on one line",
                "peers = [\n  \"192.0.2.1:1\", \"192.0.2.2:2\",\n]\n",
                UnexpectedLine { line: 2 },
            ),
            (
                "a trailing comment on an entry",
                "peers = [\n  \"192.0.2.1:1\", # a seed\n]\n",
                UnexpectedLine { line: 2 },
            ),
            (
                "an unquoted entry",
                "peers = [\n  192.0.2.1:1,\n]\n",
                UnexpectedLine { line: 2 },
            ),
            (
                "a carriage return",
                "peers = [\r\n  \"192.0.2.1:1\",\r\n]\r\n",
                UnexpectedLine { line: 1 },
            ),
            (
                "a second key",
                "peers = [\n  \"192.0.2.1:1\",\n]\nextra = 1\n",
                UnexpectedLine { line: 4 },
            ),
            (
                "an entry before the array",
                "\"192.0.2.1:1\",\npeers = [\n]\n",
                UnexpectedLine { line: 1 },
            ),
            (
                "an inline array",
                "peers = [\"192.0.2.1:1\"]\n",
                UnexpectedLine { line: 1 },
            ),
            (
                "a second array",
                "peers = [\n  \"192.0.2.1:1\",\n]\npeers = [\n]\n",
                UnexpectedLine { line: 4 },
            ),
            ("no array", "# only a comment\n", NoArray),
            (
                "an unclosed array",
                "peers = [\n  \"192.0.2.1:1\",\n",
                Unclosed,
            ),
            ("an empty array", "peers = [\n]\n", Set(PeerSetError::Empty)),
            (
                "an unspecified address",
                "peers = [\n  \"0.0.0.0:10000\",\n]\n",
                Set(PeerSetError::Unspecified { index: 0 }),
            ),
            (
                "port 0",
                "peers = [\n  \"192.0.2.1:0\",\n]\n",
                Set(PeerSetError::PortZero { index: 0 }),
            ),
            (
                "a repeated entry",
                "peers = [\n  \"192.0.2.1:1\",\n  \"192.0.2.1:1\",\n]\n",
                Set(PeerSetError::Duplicate { index: 1, first: 0 }),
            ),
        ];
        for (label, text, expected) in rows {
            assert_eq!(
                parse_vendored_peers(text.as_bytes()),
                Err(expected),
                "{label} must be refused"
            );
        }
        assert_eq!(parse_vendored_peers(&[0xff, 0xfe]), Err(NotUtf8));
    }

    // ── D174 §2 R1–R2: which network an export belongs to ─────────────────

    /// Replace one key's line in an env-file text.
    fn with_line(text: &str, key: &str, value: &str) -> String {
        text.lines()
            .map(|line| {
                if line.starts_with(key) {
                    format!("{key}='{value}'")
                } else {
                    line.to_owned()
                }
            })
            .map(|line| format!("{line}\n"))
            .collect()
    }

    /// The **canonical** Sepolia-mode export (D174 §5): nine keys, chain
    /// 421614, the D38 pinned token and vault, loopback peers — the shape a
    /// real `sepolia-up` export carried (docs/devnet/sepolia-devnet.md). Built
    /// from [`fixture_sepolia_env_file`], its contract-mismatch sibling, by
    /// replacing exactly the two contract lines.
    fn fixture_canonical_sepolia_env_file() -> String {
        let text = with_line(
            &fixture_sepolia_env_file(),
            devnet_keys::TOKEN_ADDRESS,
            ARBITRUM_SEPOLIA_PAYMENT_TOKEN,
        );
        with_line(
            &text,
            devnet_keys::PAYMENT_VAULT_ADDRESS,
            ARBITRUM_SEPOLIA_PAYMENT_VAULT,
        )
    }

    fn optional_wallet_env(text: &str) -> DevnetEnv<Option<SecretBuf>> {
        DevnetEnv::<Option<SecretBuf>>::from_env_file_optional_wallet(text)
            .expect("the fixture parses in the optional-wallet form")
    }

    /// D174 §2 R1: the chain id decides, and nothing else does.
    #[test]
    fn d174_an_export_is_classified_by_its_chain_id_alone() {
        assert_eq!(classify_export_chain(421_614), ExportChain::ArbitrumSepolia);
        assert_eq!(classify_export_chain(42_161), ExportChain::ArbitrumOne);
        for local in [31_337, 1, 11_155_111, 0, u64::MAX] {
            assert_eq!(
                classify_export_chain(local),
                ExportChain::LocalDevnet,
                "chain {local} is a local devnet export"
            );
        }
        // Not the key count: a nine-key and a ten-key export carrying 421614
        // classify alike.
        let nine = optional_wallet_env(&fixture_canonical_sepolia_env_file());
        let ten = DevnetEnv::from_env_file(&with_line(
            &fixture_env_file(),
            devnet_keys::CHAIN_ID,
            "421614",
        ))
        .expect("a ten-key export carrying 421614 parses");
        assert!(nine.wallet_private_key().is_none());
        assert_eq!(
            classify_export_chain(nine.chain_id()),
            ExportChain::ArbitrumSepolia
        );
        assert_eq!(
            classify_export_chain(ten.chain_id()),
            ExportChain::ArbitrumSepolia
        );
    }

    /// D174 §2 R2's pure half: the canonical export is accepted and becomes
    /// `arbitrum-sepolia` with the export's peers and the pinned everything
    /// else; every other shape is refused — for its chain first.
    #[test]
    fn d174_arbitrum_sepolia_accepts_only_a_chain_and_contract_matching_export() {
        let canonical_text = fixture_canonical_sepolia_env_file();
        let canonical = optional_wallet_env(&canonical_text);
        assert_eq!(check_sepolia_export(&canonical), Ok(()));

        let config = NetworkConfig::arbitrum_sepolia_from_export(&canonical)
            .expect("the canonical Sepolia export is accepted");
        let pinned = NetworkConfig::arbitrum_sepolia();
        assert_eq!(config.id, NetworkId::ArbitrumSepolia);
        assert_eq!(config.evm_chain_id, pinned.evm_chain_id);
        assert_eq!(config.payment_token, pinned.payment_token);
        assert_eq!(config.payment_vault, pinned.payment_vault);
        assert_eq!(
            config.rpc_url, pinned.rpc_url,
            "the pinned RPC, not the export's"
        );
        assert_ne!(
            config.rpc_url,
            canonical.rpc_url(),
            "the export's RPC_URL is not used"
        );
        assert_eq!(
            config.bootstrap,
            canonical.bootstrap(),
            "a 421614 export yields arbitrum-sepolia with the export's peers"
        );
        assert!(!config.bootstrap.is_empty());

        let anvil_token = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
        let anvil_vault = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
        let token_mismatch = SepoliaExportMismatch::Contract {
            key: devnet_keys::TOKEN_ADDRESS,
            pinned: ARBITRUM_SEPOLIA_PAYMENT_TOKEN,
        };
        let vault_mismatch = SepoliaExportMismatch::Contract {
            key: devnet_keys::PAYMENT_VAULT_ADDRESS,
            pinned: ARBITRUM_SEPOLIA_PAYMENT_VAULT,
        };
        let rows: [(&str, String, SepoliaExportMismatch); 6] = [
            (
                "the P22 Sepolia fixture: chain 421614 with Anvil's contracts",
                fixture_sepolia_env_file(),
                token_mismatch,
            ),
            (
                "a foreign payment token alone",
                with_line(&canonical_text, devnet_keys::TOKEN_ADDRESS, anvil_token),
                token_mismatch,
            ),
            (
                "a foreign payment vault alone",
                with_line(
                    &canonical_text,
                    devnet_keys::PAYMENT_VAULT_ADDRESS,
                    anvil_vault,
                ),
                vault_mismatch,
            ),
            (
                "a local 31337 export carrying the Sepolia contracts",
                with_line(&canonical_text, devnet_keys::CHAIN_ID, "31337"),
                SepoliaExportMismatch::Chain { chain_id: 31_337 },
            ),
            (
                "a local 31337 export with Anvil's contracts: the chain refusal is not masked",
                with_line(&fixture_sepolia_env_file(), devnet_keys::CHAIN_ID, "31337"),
                SepoliaExportMismatch::Chain { chain_id: 31_337 },
            ),
            (
                "an export carrying arbitrum-one's chain",
                with_line(&canonical_text, devnet_keys::CHAIN_ID, "42161"),
                SepoliaExportMismatch::Chain { chain_id: 42_161 },
            ),
        ];
        for (label, text, expected) in rows {
            let env = optional_wallet_env(&text);
            assert_eq!(check_sepolia_export(&env), Err(expected), "{label}");
            assert_eq!(
                NetworkConfig::arbitrum_sepolia_from_export(&env),
                Err(expected),
                "{label}"
            );
        }
    }

    /// D174 §2 R2's hygiene: a contract refusal names the key and the pin, and
    /// never the export's own address.
    #[test]
    fn d174_a_contract_refusal_names_the_key_and_the_pin_never_the_exports_value() {
        let canonical_text = fixture_canonical_sepolia_env_file();
        let cases = [
            (
                devnet_keys::TOKEN_ADDRESS,
                ARBITRUM_SEPOLIA_PAYMENT_TOKEN,
                "0x5FbDB2315678afecb367f032d93F642f64180aa3",
            ),
            (
                devnet_keys::PAYMENT_VAULT_ADDRESS,
                ARBITRUM_SEPOLIA_PAYMENT_VAULT,
                "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
            ),
        ];
        for (key, pinned, foreign) in cases {
            let env = optional_wallet_env(&with_line(&canonical_text, key, foreign));
            let message = check_sepolia_export(&env)
                .expect_err("a foreign contract is refused")
                .to_string();
            assert!(message.contains(key), "names the key: {message}");
            assert!(message.contains(pinned), "names the pin: {message}");
            assert!(
                !message
                    .to_lowercase()
                    .contains(&foreign.trim_start_matches("0x").to_lowercase()),
                "the refusal never echoes the export's value: {message}"
            );
        }
    }

    /// **S44.** Malformed address text is an error — never a panic, and never
    /// an acceptance.
    ///
    /// The parse checked the digit string's **byte** length and then sliced it
    /// two bytes at a time, so a 40-byte string holding a multibyte character
    /// panicked as soon as a slice boundary fell inside one (*"byte index 2 is
    /// not a char boundary"*) — in the parse that reads devnet exports and
    /// deserializes every serialized address. Measured on the same code:
    /// `u8::from_str_radix` takes an optional leading `+`, so forty characters
    /// of `+f` parsed as an address. The measured panic is the first row, so a
    /// regression fails on that panic's own message.
    #[test]
    fn s44_malformed_address_text_is_an_error_never_a_panic_or_an_acceptance() {
        use EvmAddressParseError::{NotHex, WrongLength};

        let euro = "\u{20ac}"; // three bytes
        let rows: [(&str, String, EvmAddressParseError); 9] = [
            (
                "the measured input: 0x, one hex digit, thirteen 3-byte characters (42 bytes)",
                format!("0xa{}", euro.repeat(13)),
                NotHex,
            ),
            (
                "the measured input without its prefix (40 bytes)",
                format!("a{}", euro.repeat(13)),
                NotHex,
            ),
            (
                "a 2-byte character at an odd byte offset",
                format!("a\u{e9}{}", "0".repeat(37)),
                NotHex,
            ),
            (
                "a 4-byte character at the end",
                format!("{}\u{1f600}", "0".repeat(36)),
                NotHex,
            ),
            (
                "2-byte characters that fall on pair boundaries",
                format!("0X{}", "\u{e9}".repeat(20)),
                NotHex,
            ),
            (
                "forty characters of +f, which from_str_radix reads as signed digits",
                "+f".repeat(20),
                NotHex,
            ),
            (
                "one + sign inside otherwise hex digits",
                format!("0x+a{}", "0".repeat(38)),
                NotHex,
            ),
            (
                "a space among hex digits",
                format!("0x {}", "0".repeat(39)),
                NotHex,
            ),
            (
                "a multibyte character that makes the byte length 41",
                format!("0x{}\u{e9}", "0".repeat(39)),
                WrongLength { got: 41 },
            ),
        ];
        for (label, input, expected) in rows {
            let error = match EvmAddress20::parse(&input) {
                Ok(parsed) => panic!("{label}: accepted as {parsed:?}"),
                Err(error) => error,
            };
            assert_eq!(error, expected, "{label}");
            let message = error.to_string();
            for character in input.chars().filter(|c| !c.is_ascii() || *c == '+') {
                assert!(
                    !message.contains(character),
                    "{label}: the error echoes the input's {character:?}: {message}"
                );
            }
        }
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

    // ── D173 §2 R8: the locality classifier ───────────────────────────────

    /// A socket-address fixture, named in the panic if it does not parse.
    fn peer(text: &str) -> SocketAddr {
        text.parse()
            .unwrap_or_else(|_| panic!("fixture {text:?} is not a socket address"))
    }

    fn peers(texts: &[&str]) -> Vec<SocketAddr> {
        texts.iter().map(|text| peer(text)).collect()
    }

    /// The classifier's table (D173 §2 R8), edge rows first: canonicalized
    /// loopback, the empty set that must never read as loopback, the address
    /// classes an armed gate refuses, and every structural refusal by index.
    #[test]
    fn d173_the_classifier_canonicalizes_and_never_calls_an_empty_set_loopback() {
        use PeerLocality::{Loopback, Public};
        use PeerSetError::{Duplicate, Empty, Mixed, PortZero, Unspecified};

        let rows: &[(&[&str], Result<PeerLocality, PeerSetError>)] = &[
            // An empty set is an error — never "loopback".
            (&[], Err(Empty)),
            // Loopback, including the forms a bare `is_loopback` misreads.
            (&["127.0.0.1:9"], Ok(Loopback)),
            (&["127.0.0.2:9"], Ok(Loopback)),
            (&["[::1]:9"], Ok(Loopback)),
            (&["[::ffff:127.0.0.1]:9"], Ok(Loopback)),
            (&["127.0.0.1:9", "[::1]:10", "127.9.9.9:11"], Ok(Loopback)),
            // Same host, two ports: two peers, not a repeat.
            (&["127.0.0.1:9", "127.0.0.1:10"], Ok(Loopback)),
            // Public: documentation, RFC 1918, RFC 6666's discard prefix, and a
            // mapped public address.
            (&["192.0.2.1:9"], Ok(Public)),
            (&["10.0.0.1:9"], Ok(Public)),
            (&["172.16.0.1:9"], Ok(Public)),
            (&["192.168.1.1:9"], Ok(Public)),
            (&["[100::1]:9"], Ok(Public)),
            (&["[::ffff:192.0.2.1]:9"], Ok(Public)),
            // Structural refusals, each naming the earliest offending index.
            (&["0.0.0.0:9"], Err(Unspecified { index: 0 })),
            (&["[::]:9"], Err(Unspecified { index: 0 })),
            (&["[::ffff:0.0.0.0]:9"], Err(Unspecified { index: 0 })),
            (
                &["192.0.2.1:9", "192.0.2.2:9", "0.0.0.0:9"],
                Err(Unspecified { index: 2 }),
            ),
            (&["127.0.0.1:0"], Err(PortZero { index: 0 })),
            (
                &["127.0.0.1:9", "127.0.0.1:9"],
                Err(Duplicate { index: 1, first: 0 }),
            ),
            (
                &["127.0.0.1:9", "[::ffff:127.0.0.1]:9"],
                Err(Duplicate { index: 1, first: 0 }),
            ),
            // Mixed, from either side.
            (
                &["127.0.0.1:9", "192.0.2.1:9"],
                Err(Mixed {
                    loopback: 0,
                    public: 1,
                }),
            ),
            (
                &["192.0.2.1:9", "[::1]:9", "192.0.2.2:9"],
                Err(Mixed {
                    loopback: 1,
                    public: 0,
                }),
            ),
        ];
        for (texts, expected) in rows {
            assert_eq!(
                classify_peers(&peers(texts)),
                *expected,
                "classify_peers({texts:?})"
            );
        }
        assert!(
            rows.len() >= 20,
            "the table collapsed to {} rows",
            rows.len()
        );
    }

    /// The one predicate, on its own: the gate and the classifier both call it.
    #[test]
    fn d173_the_loopback_predicate_canonicalizes_mapped_addresses() {
        for loopback in [
            "127.0.0.1:9",
            "127.255.255.254:9",
            "[::1]:9",
            "[::ffff:127.0.0.1]:9",
        ] {
            assert!(is_loopback_peer(&peer(loopback)), "{loopback} is loopback");
        }
        for public in [
            "0.0.0.0:9",
            "[::]:9",
            "10.0.0.1:9",
            "192.0.2.1:9",
            "[100::1]:9",
            "[::ffff:192.0.2.1]:9",
            // IPv4-compatible (deprecated) is not IPv4-mapped; saorsa-core's
            // canonicalization does not map it either.
            "[::127.0.0.1]:9",
        ] {
            assert!(!is_loopback_peer(&peer(public)), "{public} is not loopback");
        }
    }

    /// `arbitrum-one` dials only public peers; `arbitrum-sepolia` and `devnet`
    /// accept either class; every network refuses what the classifier refuses.
    #[test]
    fn d173_arbitrum_one_dials_only_public_peers_and_the_others_accept_either_class() {
        use NetworkId::{ArbitrumOne, ArbitrumSepolia, Devnet};

        let loopback = peers(&["127.0.0.1:20001", "127.0.0.1:20002"]);
        let public = peers(&["192.0.2.1:10000"]);
        let mixed = peers(&["127.0.0.1:20001", "192.0.2.1:10000"]);

        assert_eq!(
            peer_locality(ArbitrumOne, &public),
            Ok(PeerLocality::Public)
        );
        assert_eq!(
            peer_locality(ArbitrumOne, &loopback),
            Err(PeerLocalityError::LoopbackForbidden {
                network: ArbitrumOne
            }),
            "arbitrum-one must refuse loopback peers"
        );
        for id in [ArbitrumSepolia, Devnet] {
            assert_eq!(
                peer_locality(id, &loopback),
                Ok(PeerLocality::Loopback),
                "{id} accepts a loopback devnet's peers"
            );
            assert_eq!(
                peer_locality(id, &public),
                Ok(PeerLocality::Public),
                "{id} accepts non-loopback peers (for devnet, the recorded behaviour change)"
            );
        }
        for id in NetworkId::ALL {
            assert_eq!(
                peer_locality(id, &mixed),
                Err(PeerLocalityError::Set(PeerSetError::Mixed {
                    loopback: 0,
                    public: 1
                })),
                "{id} refuses a mixed set"
            );
            assert_eq!(
                peer_locality(id, &[]),
                Err(PeerLocalityError::Set(PeerSetError::Empty)),
                "{id} refuses an empty set"
            );
        }

        let config = NetworkConfig {
            bootstrap: loopback,
            ..NetworkConfig::arbitrum_sepolia()
        };
        assert_eq!(config.peer_locality(), Ok(PeerLocality::Loopback));
    }

    /// Refusals name indices, never addresses — asserted over messages the
    /// classifier and the gate really produce, so a variant that later grew an
    /// address field reddens here.
    #[test]
    fn d173_locality_and_gate_refusals_never_echo_an_address() {
        let cases: [&[&str]; 5] = [
            &["192.0.2.77:9", "0.0.0.0:9"],
            &["192.0.2.77:9", "192.0.2.77:0"],
            &["192.0.2.77:9", "192.0.2.77:9"],
            &["127.0.0.77:9", "192.0.2.77:9"],
            &["127.0.0.77:9"],
        ];
        let mut messages = Vec::new();
        for texts in cases {
            let set = peers(texts);
            if let Err(error) = peer_locality(NetworkId::ArbitrumOne, &set) {
                messages.push(error.to_string());
            }
            if let Err(refusal) = storage_gate::verdict(Some(storage_gate::REASON_TEST_BUILD), &set)
            {
                messages.push(refusal.to_string());
            }
        }
        assert!(
            messages.len() >= cases.len() + 3,
            "only {} refusals were produced — the sweep asserts little",
            messages.len()
        );
        for message in messages {
            for echo in ["192.0.2.77", "127.0.0.77", "0.0.0.0"] {
                assert!(
                    !message.contains(echo),
                    "a refusal echoed {echo}: {message}"
                );
            }
        }
    }

    // ── D173 §2 R9: the storage gate ──────────────────────────────────────

    /// The armed gate's predicate as a table: loopback (canonicalized) and the
    /// empty set are admitted; every other class is refused and counted; and
    /// the disarmed gate admits a public peer, so a gate that refused
    /// everything reddens too.
    #[test]
    fn d173_the_armed_storage_gate_admits_loopback_and_refuses_everything_else() {
        let armed = Some(storage_gate::REASON_TEST_BUILD);
        let admitted: [&[&str]; 6] = [
            &[],
            &["127.0.0.1:9"],
            &["127.0.0.2:9"],
            &["[::1]:9"],
            &["[::ffff:127.0.0.1]:9"],
            &["127.0.0.1:9", "[::1]:10"],
        ];
        for texts in admitted {
            assert_eq!(
                storage_gate::verdict(armed, &peers(texts)),
                Ok(()),
                "{texts:?} must be admitted by the armed storage gate"
            );
        }
        let refused: [(&[&str], usize); 10] = [
            (&["192.0.2.1:9"], 1),
            (&["0.0.0.0:9"], 1),
            (&["[::]:9"], 1),
            (&["10.0.0.1:9"], 1),
            (&["172.16.0.1:9"], 1),
            (&["192.168.1.1:9"], 1),
            (&["[100::1]:9"], 1),
            (&["[::ffff:192.0.2.1]:9"], 1),
            (&["127.0.0.1:9", "192.0.2.1:9"], 1),
            (&["192.0.2.1:9", "[::1]:9", "[100::1]:9"], 2),
        ];
        for (texts, count) in refused {
            let set = peers(texts);
            match storage_gate::verdict(armed, &set) {
                Err(refusal) => {
                    assert_eq!(refusal.refused, count, "{texts:?}: refused count");
                    assert_eq!(refusal.peers, set.len(), "{texts:?}: set size");
                    assert_eq!(refusal.armed_because, storage_gate::REASON_TEST_BUILD);
                }
                Ok(()) => panic!(
                    "{texts:?} holds a non-loopback bootstrap peer and the armed storage gate \
                     admitted it"
                ),
            }
        }
        assert_eq!(
            storage_gate::verdict(None, &peers(&["192.0.2.1:9"])),
            Ok(()),
            "the disarmed gate must admit a public peer"
        );
        // This unit-test build is armed by the compiler, and the live check
        // reads that arm on every call.
        assert_eq!(
            storage_gate::arming(),
            Some(storage_gate::REASON_TEST_BUILD)
        );
        assert!(
            storage_gate::check(&peers(&["192.0.2.1:9"])).is_err(),
            "the live check must refuse a public peer in a cfg(test) build"
        );
        assert_eq!(storage_gate::check(&peers(&["127.0.0.1:9"])), Ok(()));
    }

    /// The arms (D173 §2 R9): `cfg(test)` has no off switch; `0` is the only
    /// off switch; every other value fails closed; and with the variable unset
    /// the profile decides — armed with debug assertions, disarmed without.
    #[test]
    fn d173_the_storage_gate_arms_in_test_and_debug_builds_and_fails_closed() {
        use std::ffi::OsStr;
        use storage_gate::{REASON_DEBUG_BUILD, REASON_ENVIRONMENT, REASON_TEST_BUILD, decide};

        for debug_build in [false, true] {
            assert_eq!(decide(true, debug_build, None), Some(REASON_TEST_BUILD));
            assert_eq!(
                decide(true, debug_build, Some(OsStr::new("0"))),
                Some(REASON_TEST_BUILD),
                "the cfg(test) arm has no off switch"
            );
        }

        assert_eq!(
            decide(false, true, None),
            Some(REASON_DEBUG_BUILD),
            "a debug build with the variable unset must arm the storage gate — a bare cargo test \
             is the venue"
        );
        assert_eq!(
            decide(false, false, None),
            None,
            "a release build with the variable unset is disarmed: the release binary dials"
        );

        for debug_build in [false, true] {
            assert_eq!(
                decide(false, debug_build, Some(OsStr::new("0"))),
                None,
                "`0` is the one off switch (debug_build = {debug_build})"
            );
            for value in ["1", "", "0 ", " 0", "00", "false", "no", "off", "ture"] {
                assert_eq!(
                    decide(false, debug_build, Some(OsStr::new(value))),
                    Some(REASON_ENVIRONMENT),
                    "{value:?} must arm the storage gate: anything but a literal 0 fails closed"
                );
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            assert_eq!(
                decide(false, false, Some(OsStr::from_bytes(b"\xff"))),
                Some(REASON_ENVIRONMENT),
                "a value that is not Unicode arms the gate"
            );
        }
    }

    /// The refusal begins with the one sentence, which names the variable; it
    /// counts the refused peers and says how a debug build reaches a public
    /// network.
    #[test]
    fn d173_the_storage_gate_refusal_names_the_variable_and_the_count() {
        assert!(
            storage_gate::REFUSAL.contains(storage_gate::ENV),
            "the refusal sentence must name the variable"
        );
        let refusal = storage_gate::verdict(
            Some(storage_gate::REASON_DEBUG_BUILD),
            &peers(&["192.0.2.1:9", "127.0.0.1:9", "[100::1]:9"]),
        )
        .expect_err("two public peers");
        let text = refusal.to_string();
        assert!(text.starts_with(storage_gate::REFUSAL), "{text}");
        assert!(text.contains("2 of 3"), "{text}");
        assert!(text.contains(storage_gate::REASON_DEBUG_BUILD), "{text}");
        assert!(
            text.contains(&format!("{}=0", storage_gate::ENV)),
            "the refusal says how a debug build reaches a public network: {text}"
        );
    }
}
