//! Resolving `ANTSEAL_DEVNET_ENV` into a network definition (U89, D174), and
//! a definition's bootstrap peers into the set a command may dial (D173).
//!
//! # Two steps, on purpose
//!
//! [`select_network`] answers *which network*: the chain half — id, chain id,
//! payment contracts, payment RPC — plus whatever peers that network's own
//! source carries. It **never refuses because peers are absent** (D173 §2
//! R7). [`resolve_peers`] answers *which peers may be dialed*, per D173 §2
//! R6's per-network tables, and refuses an empty or undialable set as a
//! usage error (2). They are two functions because `status`'s receipt
//! backfill needs a network's chain half and no peers at all (D173 §2 R7,
//! R14): a peer refusal inside `select_network` would break it for every
//! `arbitrum-sepolia` work read without an export. Only commands that dial
//! call `resolve_peers`, and each at the point its own ordering allows:
//! `seal` before any passphrase, unlock, connection or journal write;
//! `verify --live` before verification (D170 §2 R6); `restore` after the
//! unlock, because its network is in the vault record (D170 §2 R3), and
//! before any connection or output write; `reveal` lazily, at its first
//! needed fetch (D175); `status` never.
//!
//! # Why this is a module and not three lines in `commands.rs`
//!
//! It was three lines in `commands.rs`, and they read:
//!
//! ```ignore
//! let path = std::env::var_os("ANTSEAL_DEVNET_ENV")?;
//! let text = std::fs::read_to_string(path).ok()?;
//! antseal_net::DevnetEnv::from_env_file(&text).ok()
//! ```
//!
//! Three distinguishable outcomes collapsed into one `None`: *nothing was
//! pointed at*, *something was pointed at and could not be read*, and
//! *something was pointed at and did not parse*. `NetworkConfig::select`
//! then rendered all three as
//! [`DevnetEnvironmentRequired`](antseal_net::NetworkConfigError::DevnetEnvironmentRequired)
//! — "no devnet" — including for the one case P22 had just made a real
//! product state: a **nine-key** Arbitrum-Sepolia export, which is a
//! complete and correct devnet definition that
//! [`DevnetEnv::from_env_file`] refuses because it demands all ten keys.
//! The user was told a devnet did not exist while nine of its keys sat in
//! the file they had just exported.
//!
//! So the resolution lives here, returns a `Result` whose error arms name
//! what actually happened, and reads the wallet slot as optional.
//!
//! # Which network reads an export (D174 §2 R1–R4)
//!
//! An export belongs to a network by its `ANTSEAL_DEVNET_CHAIN_ID` alone
//! ([`antseal_net::classify_export_chain`]) — never by its key count (nine
//! versus ten says who funds the wallet, U89), its path or its name:
//!
//! | the export's chain | read by | refused by |
//! |---|---|---|
//! | 421614 (Arbitrum Sepolia) | `--network arbitrum-sepolia`, and only when its payment token and vault equal the D38 pins byte for byte | `--network devnet`, naming the chain and `--network arbitrum-sepolia` |
//! | any other (a local Anvil chain) | `--network devnet` | `--network arbitrum-sepolia`, naming the chain, the path and `--network devnet` |
//! | 42161 (Arbitrum One) | nobody: `arbitrum-one` never reads an export | both, by name |
//!
//! A payment made on a public chain must be recorded under that chain's
//! own network name, which is why `devnet` refuses the Sepolia export
//! rather than reading it as it did before D174. An export's refusal is
//! never a fall-through to another layer, and an unreadable or malformed
//! export keeps U89's arms under either reading network.
//!
//! # The wallet key is not this CLI's to want
//!
//! [`NetworkConfig`] carries no wallet field — chain id, RPC, the two
//! contracts, bootstrap peers, and nothing else — and
//! [`NetworkConfig::devnet`] is generic over the wallet slot for exactly
//! that reason (P22). `antseal` signs with the wallet key in the **vault**
//! (`crate::vault::wallet::load_wallet_key`), never with the devnet's. A
//! walletless export is therefore not a degraded devnet here: it is a
//! complete one, and the only thing that changes is who funded the
//! spending key. [`SelectedNetwork::walletless_devnet`] carries that fact
//! out as one line for the caller to log, rather than as a failure — on
//! the `arbitrum-sepolia` arm, whose export is the nine-key shape by
//! design (D174 §2 R2).
//!
//! # Laziness is load-bearing, and now provable
//!
//! [`select_network`] consults the environment for
//! [`NetworkId::ArbitrumSepolia`] and [`NetworkId::Devnet`] and **never for
//! [`NetworkId::ArbitrumOne`]** (U89, D174 §2 R4). The old call site read
//! the file on every invocation and discarded it for the other networks;
//! making the read fallible without making it lazy would have turned a
//! stale `ANTSEAL_DEVNET_ENV` — which survives a `local-down` in any shell
//! that exported it — into a hard failure of `--network arbitrum-one`. The
//! lookup is injected ([`select_network_with`]) so a test can hand
//! `arbitrum-one` a lookup that panics when called, and a second test can
//! count the lookup's calls for the two networks that do read it — the
//! panicking test cannot pass on a seam nothing is wired through.

use std::net::SocketAddr;

use antseal_core::crypto::secrets::SecretBuf;
use antseal_net::{
    DevnetEnv, DevnetEnvError, ExportChain, NetworkConfig, NetworkConfigError, NetworkId,
    PeerLocalityError, SepoliaExportMismatch, classify_export_chain, peer_locality,
};

use crate::config::Config;
use crate::error::CliError;

/// The variable that names a running devnet's run-scoped export.
pub(crate) const DEVNET_ENV_VAR: &str = "ANTSEAL_DEVNET_ENV";

/// A devnet export as this CLI reads one: nine keys or ten.
///
/// The wallet slot is [`Option`] because nothing here spends the devnet's
/// key — see the module docs.
pub(crate) type CliDevnetEnv = DevnetEnv<Option<SecretBuf>>;

/// The one line to log when the export carried no wallet key.
///
/// A constant rather than an inline `tracing::debug!` literal so the copy
/// has one author and the branch that selects it is assertable — a message
/// that only ever exists inside a disabled log macro is a message nothing
/// can test.
pub(crate) const WALLETLESS_DEVNET_NOTE: &str = concat!(
    "this devnet export carries no ANTSEAL_DEVNET_WALLET_PRIVATE_KEY, which is the designed ",
    "shape of an arbitrum-sepolia devnet (chain 421614): that key is real key material and is ",
    "never written to a file. antseal does not need it — it signs with the wallet key in your ",
    "vault, which you must fund yourself on that chain.",
);

/// What `ANTSEAL_DEVNET_ENV` named, read and parsed, with the path it was
/// read from — the path is what a refusal names, so a user can tell which
/// file was judged (D174 §2 R2).
#[derive(Debug)]
pub(crate) struct DevnetExport {
    /// The path `ANTSEAL_DEVNET_ENV` named, as displayed.
    pub(crate) path: String,
    /// The parsed export.
    pub(crate) env: CliDevnetEnv,
}

/// `ANTSEAL_DEVNET_ENV` was set, and what it named is not a usable devnet.
///
/// Every variant says **a devnet was pointed at**. That is the whole
/// difference from the `None` this used to return: "you pointed at nothing"
/// and "you pointed at something broken" are different problems with
/// different remedies, and the old `.ok()` erased the distinction.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DevnetEnvUnusable {
    /// The path is set but the file behind it could not be read.
    #[error(
        "the devnet export at {path} (named by {var}) could not be read: {source} — the export \
         is run-scoped, so a devnet that has been shut down leaves this variable pointing at \
         nothing; re-run scripts/devnet/local-up and re-point {var}"
    )]
    Unreadable {
        /// The path `ANTSEAL_DEVNET_ENV` named.
        path: String,
        /// The variable's name, so the message is self-locating.
        var: &'static str,
        /// The I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// The file was read and is not a devnet export.
    ///
    /// The inner [`DevnetEnvError`] names the offending **key** and never
    /// its value; nothing added here echoes one either (the path is a
    /// filesystem path, not export content).
    #[error("the devnet export at {path} (named by {var}) is not usable: {source}")]
    Malformed {
        /// The path `ANTSEAL_DEVNET_ENV` named.
        path: String,
        /// The variable's name.
        var: &'static str,
        /// Which key is missing or malformed.
        #[source]
        source: DevnetEnvError,
    },
}

/// No usable network definition could be produced for the requested id.
///
/// Every arm is a usage error (2) at the surface
/// ([`From<NetworkSelectError> for CliError`](CliError)). None echoes an
/// export's value: a contract refusal names the export **key** and the
/// **pinned** address; a chain refusal names the chain id, which is the
/// classification itself; every arm names the path, which is where the
/// judged file lives and not what it contains.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NetworkSelectError {
    /// `devnet` was asked for and nothing was pointed at. One message per
    /// id (D174 §2 R7): it names `scripts/devnet/local-up` (through the
    /// inner error) and `ANTSEAL_DEVNET_ENV`, and offers no other network —
    /// the copy used to end *"or seal to `--network arbitrum-sepolia`"*,
    /// advice that resolved to a configuration with no peers (`U92`).
    #[error("{0} — export ANTSEAL_DEVNET_ENV pointing at that devnet's .devnet/env")]
    NoDefinition(NetworkConfigError),

    /// A devnet **was** pointed at and it is not usable. Before U89 this
    /// was reported as [`Self::NoDefinition`], which was a false statement
    /// about the user's own environment. Under D174 it is the arm for
    /// `arbitrum-sepolia` too: an unreadable or malformed export is refused
    /// the same way whichever network was asked to read it.
    #[error(transparent)]
    Devnet(#[from] DevnetEnvUnusable),

    /// `--network arbitrum-sepolia` was handed a local devnet's export
    /// (D174 §2 R2): the chain it carries, the path, and the network that
    /// does read it.
    #[error(
        "the devnet export at {path} (named by {var}) carries chain {chain_id}, not Arbitrum \
         Sepolia's chain 421614, so `--network arbitrum-sepolia` cannot read it: a local \
         devnet's export is read with `--network devnet`"
    )]
    SepoliaExportOnLocalChain {
        /// The path `ANTSEAL_DEVNET_ENV` named.
        path: String,
        /// The variable's name.
        var: &'static str,
        /// The chain the export carries.
        chain_id: u64,
    },

    /// `--network arbitrum-sepolia` was handed an export claiming Arbitrum
    /// One's chain (D174 §2 R2). No `--network devnet` is offered: that is
    /// not a chain a devnet runs either.
    #[error(
        "the devnet export at {path} (named by {var}) carries chain 42161, which is Arbitrum \
         One's: no export may carry that chain, because `arbitrum-one` never reads an export, \
         and `--network arbitrum-sepolia` reads only an export on chain 421614"
    )]
    SepoliaExportOnMainnetChain {
        /// The path `ANTSEAL_DEVNET_ENV` named.
        path: String,
        /// The variable's name.
        var: &'static str,
    },

    /// A Sepolia-mode export names a payment contract that is not the
    /// pinned D38 deployment (D174 §2 R2). The inner mismatch names the
    /// key and the pin; the export's own value appears nowhere.
    #[error(
        "the devnet export at {path} (named by {var}) is not one `--network arbitrum-sepolia` \
         can use: {mismatch}"
    )]
    SepoliaExportContract {
        /// The path `ANTSEAL_DEVNET_ENV` named.
        path: String,
        /// The variable's name.
        var: &'static str,
        /// Which contract differs, and from which pin.
        #[source]
        mismatch: SepoliaExportMismatch,
    },

    /// `--network devnet` was handed a Sepolia-mode export (D174 §2 R3).
    #[error(
        "the devnet export at {path} (named by {var}) carries chain 421614, which is Arbitrum \
         Sepolia: read it with `--network arbitrum-sepolia`, not `--network devnet`, so that a \
         payment on that public chain is recorded under its own network"
    )]
    DevnetExportIsSepolia {
        /// The path `ANTSEAL_DEVNET_ENV` named.
        path: String,
        /// The variable's name.
        var: &'static str,
    },

    /// `--network devnet` was handed an export claiming Arbitrum One's
    /// chain (D174 §2 R3).
    #[error(
        "the devnet export at {path} (named by {var}) carries chain 42161, which is Arbitrum \
         One: no export may carry that chain, because `arbitrum-one` never reads an export"
    )]
    DevnetExportIsMainnet {
        /// The path `ANTSEAL_DEVNET_ENV` named.
        path: String,
        /// The variable's name.
        var: &'static str,
    },
}

impl From<NetworkSelectError> for CliError {
    /// Every selection failure is a usage error (2): the remedy is to the
    /// environment or the command line, never a retry (D173 §2 R7).
    fn from(error: NetworkSelectError) -> Self {
        CliError::Usage {
            message: error.to_string(),
        }
    }
}

/// A resolved network definition, plus what the resolution learned.
#[derive(Debug)]
pub(crate) struct SelectedNetwork {
    /// What backend construction needs — once [`resolve_peers`] has
    /// decided its `bootstrap`, for a command that dials.
    pub(crate) config: NetworkConfig,
    /// [`WALLETLESS_DEVNET_NOTE`] when the export carried no wallet key.
    ///
    /// Returned rather than logged in place so a test can assert which
    /// branch ran; the caller decides where it goes.
    pub(crate) walletless_devnet: Option<&'static str>,
}

impl SelectedNetwork {
    /// A built-in definition: nothing was read, so there is nothing to note.
    fn built_in(config: NetworkConfig) -> Self {
        Self {
            config,
            walletless_devnet: None,
        }
    }
}

/// Read the export `ANTSEAL_DEVNET_ENV` names, if it names one.
///
/// # Errors
///
/// [`DevnetEnvUnusable`] when the variable is set and what it names cannot
/// be read or is not a devnet export. An **unset** variable is `Ok(None)`,
/// not an error: pointing at no devnet is the normal state of every
/// invocation that is not using one.
pub(crate) fn devnet_env() -> Result<Option<DevnetExport>, DevnetEnvUnusable> {
    read_devnet_env(
        std::env::var_os(DEVNET_ENV_VAR),
        |path: &std::path::Path| {
            // A closure rather than `std::fs::read_to_string` itself: the free
            // function is generic over `AsRef<Path>`, so passing it bare binds a
            // single concrete lifetime and cannot satisfy the higher-ranked
            // `FnOnce(&Path)` bound below.
            std::fs::read_to_string(path)
        },
    )
}

/// [`devnet_env`] with the environment lookup and the file read injected,
/// so the classification is testable on fixtures without mutating the
/// process environment (which is `unsafe` in edition 2024 and racy across
/// a test binary's threads).
fn read_devnet_env(
    path: Option<std::ffi::OsString>,
    read: impl FnOnce(&std::path::Path) -> std::io::Result<String>,
) -> Result<Option<DevnetExport>, DevnetEnvUnusable> {
    let Some(path) = path else {
        return Ok(None);
    };
    let path = std::path::PathBuf::from(path);
    let shown = path.display().to_string();
    let text = read(&path).map_err(|source| DevnetEnvUnusable::Unreadable {
        path: shown.clone(),
        var: DEVNET_ENV_VAR,
        source,
    })?;
    // The optional-wallet parse (P22, `network.rs`) rather than
    // `from_env_file`: a nine-key arbitrum-sepolia export is a devnet.
    DevnetEnv::from_env_file_optional_wallet(&text)
        .map(|env| {
            Some(DevnetExport {
                path: shown.clone(),
                env,
            })
        })
        .map_err(|source| DevnetEnvUnusable::Malformed {
            path: shown,
            var: DEVNET_ENV_VAR,
            source,
        })
}

/// Resolve the network `id` names, consulting `ANTSEAL_DEVNET_ENV` for
/// [`NetworkId::ArbitrumSepolia`] and [`NetworkId::Devnet`] and never for
/// [`NetworkId::ArbitrumOne`].
///
/// The definition's `bootstrap` holds whatever peers the network's own
/// source carried — the vendored list for `arbitrum-one`, a validated
/// export's peers for `arbitrum-sepolia` (none without an export), the
/// export's for `devnet` — and is **not** yet the set a command may dial:
/// that is [`resolve_peers`]'s decision, and absence is not refused here
/// (D173 §2 R7).
///
/// # Errors
///
/// [`NetworkSelectError`]: nothing was pointed at (`devnet` only),
/// something was pointed at and is unusable, or the export belongs to
/// another network (D174 §2 R2–R3).
pub(crate) fn select_network(id: NetworkId) -> Result<SelectedNetwork, NetworkSelectError> {
    select_network_with(id, devnet_env)
}

/// [`select_network`] with the export read injected (D174 §2 R4).
///
/// `lookup` is consulted **exactly once** for `arbitrum-sepolia` and for
/// `devnet`, and **never** for `arbitrum-one` — the property the module
/// docs call load-bearing, made provable: a test hands `arbitrum-one` a
/// lookup that panics, and a second counts the calls for the other two.
pub(crate) fn select_network_with(
    id: NetworkId,
    lookup: impl FnOnce() -> Result<Option<DevnetExport>, DevnetEnvUnusable>,
) -> Result<SelectedNetwork, NetworkSelectError> {
    match id {
        // `Ok(None)` is not a lie: nothing was consulted, and this arm of
        // `resolve` never looks at it.
        NetworkId::ArbitrumOne => resolve(id, Ok(None)),
        // Only here is the environment read at all.
        NetworkId::ArbitrumSepolia | NetworkId::Devnet => resolve(id, lookup()),
    }
}

/// [`select_network`]'s decision table over an already-read export.
fn resolve(
    id: NetworkId,
    export: Result<Option<DevnetExport>, DevnetEnvUnusable>,
) -> Result<SelectedNetwork, NetworkSelectError> {
    match id {
        // Built in, peers vendored (D173 §2 R1); the export is never read
        // (D174 §2 R4), so even a broken one changes nothing here.
        NetworkId::ArbitrumOne => Ok(SelectedNetwork::built_in(NetworkConfig::arbitrum_one())),

        NetworkId::ArbitrumSepolia => match export? {
            // Built in with no peers: there is no public Autonomi network on
            // Arbitrum Sepolia to take any from. Not refused here — D173 §2
            // R7 keeps absence out of this step; `resolve_peers` refuses it
            // for a command that dials, with the text naming the export.
            None => Ok(SelectedNetwork::built_in(NetworkConfig::arbitrum_sepolia())),
            // The pinned chain half with the export's peers, iff the export
            // is a Sepolia-mode one whose contracts equal the pins (D174 §2
            // R2). Its `RPC_URL` is not used: `antseal_net::evm` maps this
            // id to evmlib's built-in network, whose RPC is the pinned one.
            Some(DevnetExport { path, env }) => {
                let config = NetworkConfig::arbitrum_sepolia_from_export(&env)
                    .map_err(|mismatch| sepolia_refusal(path, mismatch))?;
                Ok(SelectedNetwork {
                    config,
                    // The nine-key shape is this network's designed one; the
                    // note moved here from the `devnet` arm with D174 §2 R2.
                    walletless_devnet: env
                        .wallet_private_key()
                        .is_none()
                        .then_some(WALLETLESS_DEVNET_NOTE),
                })
            }
        },

        NetworkId::Devnet => match export? {
            None => Err(NetworkSelectError::NoDefinition(
                NetworkConfigError::DevnetEnvironmentRequired,
            )),
            Some(DevnetExport { path, env }) => match classify_export_chain(env.chain_id()) {
                // A public chain's export is refused by name (D174 §2 R3):
                // reading it here would record `devnet` for a payment made on
                // a public chain.
                ExportChain::ArbitrumSepolia => Err(NetworkSelectError::DevnetExportIsSepolia {
                    path,
                    var: DEVNET_ENV_VAR,
                }),
                ExportChain::ArbitrumOne => Err(NetworkSelectError::DevnetExportIsMainnet {
                    path,
                    var: DEVNET_ENV_VAR,
                }),
                // Generic over the wallet slot (P22): none of this struct's
                // fields is the wallet, so nine keys build it as well as ten.
                ExportChain::LocalDevnet => Ok(SelectedNetwork {
                    config: NetworkConfig::devnet(&env),
                    walletless_devnet: None,
                }),
            },
        },
    }
}

/// The `arbitrum-sepolia` arm's refusal of an export, by what the pure
/// check found: a chain is named with the network that does read it (for a
/// chain some devnet could run) or without one (for Arbitrum One's), and a
/// contract mismatch carries the key and the pin through.
fn sepolia_refusal(path: String, mismatch: SepoliaExportMismatch) -> NetworkSelectError {
    match mismatch {
        SepoliaExportMismatch::Chain { chain_id } => match classify_export_chain(chain_id) {
            ExportChain::ArbitrumOne => NetworkSelectError::SepoliaExportOnMainnetChain {
                path,
                var: DEVNET_ENV_VAR,
            },
            // `ArbitrumSepolia` cannot reach here — the check reports a
            // chain mismatch only for a chain that is not 421614 — and is
            // folded into the local arm rather than panicked on.
            ExportChain::LocalDevnet | ExportChain::ArbitrumSepolia => {
                NetworkSelectError::SepoliaExportOnLocalChain {
                    path,
                    var: DEVNET_ENV_VAR,
                    chain_id,
                }
            }
        },
        SepoliaExportMismatch::Contract { .. } => NetworkSelectError::SepoliaExportContract {
            path,
            var: DEVNET_ENV_VAR,
            mismatch,
        },
    }
}

// ---------------------------------------------------------------------------
// Peer resolution (D173 §2 R6–R8): which peers a command that dials may dial
// ---------------------------------------------------------------------------

/// Why a network's bootstrap peers could not be resolved (D173 §2 R6–R8).
///
/// Every arm is a usage error (2): nothing was attempted, and a retry fixes
/// nothing — 23 is the transient class a caller is right to retry, and this
/// is not it. Set-level refusals name peer **indices**, never addresses
/// (the classifier's hygiene, D173 §2 R8).
#[derive(Debug, thiserror::Error)]
pub(crate) enum PeerResolveError {
    /// No layer of the network's table carried a peer (D173 §2 R6, "none
    /// present").
    #[error("{}", no_peers_text(*.network))]
    NoPeers {
        /// The network whose table was empty.
        network: NetworkId,
    },
    /// The resolved set is one no transport mode can dial on this network
    /// (D173 §2 R8): mixed loopback and public, a repeat, an unspecified
    /// address, port 0, or loopback peers under `arbitrum-one`.
    #[error("network `{network}` cannot dial its bootstrap peer set: {source}")]
    Undialable {
        /// The network that refused.
        network: NetworkId,
        /// The classifier's finding.
        #[source]
        source: PeerLocalityError,
    },
}

impl From<PeerResolveError> for CliError {
    /// Usage (2), as the no-definition refusal it sits beside (D173 §2 R7).
    fn from(error: PeerResolveError) -> Self {
        CliError::Usage {
            message: error.to_string(),
        }
    }
}

/// The "no peers" text, one per network (D173 §2 R6; D174 §2 R7).
///
/// `arbitrum-one`'s is reachable only if the vendored list is unusable (its
/// own tests make that a red test rather than a runtime state, D173 §2 R3).
/// `devnet`'s is the no-definition refusal: its one layer is the export,
/// whose parser already refuses an empty `BOOTSTRAP`, so an empty set here
/// means no export was read.
fn no_peers_text(network: NetworkId) -> String {
    match network {
        NetworkId::ArbitrumOne => "network `arbitrum-one` has no bootstrap peers to dial: its \
                                   built-in peer list could not be used, and config.toml sets \
                                   no `[networks.arbitrum-one] bootstrap` override \
                                   (docs/config.md, \"Bootstrap peers\")"
            .to_owned(),
        NetworkId::ArbitrumSepolia => "network `arbitrum-sepolia` has no bootstrap peers to \
                                       dial: there is no public Autonomi storage network on \
                                       Arbitrum Sepolia, so its peers come only from a Sepolia \
                                       devnet's export — run scripts/devnet/sepolia-up and \
                                       export ANTSEAL_DEVNET_ENV pointing at the .devnet/env \
                                       it writes"
            .to_owned(),
        NetworkId::Devnet => {
            NetworkSelectError::NoDefinition(NetworkConfigError::DevnetEnvironmentRequired)
                .to_string()
        }
    }
}

/// Decide the bootstrap peers a command that dials may dial (D173 §2 R6),
/// over the definition [`select_network`] returned and the loaded
/// `config.toml`, and classify them (D173 §2 R8).
///
/// Per-network tables; the first present layer wins, and **replaces**:
///
/// | network | layer 1 | layer 2 |
/// |---|---|---|
/// | `arbitrum-one` | `[networks.arbitrum-one] bootstrap` (validated at load, D173 §2 R4) | the vendored list the definition carries |
/// | `arbitrum-sepolia` | the validated Sepolia export's peers the definition carries (D174 §2 R2) | — |
/// | `devnet` | the export's peers the definition carries | — |
///
/// No layer is ever unioned into another, no peer cache and no upstream
/// file is ever consulted: one resolved set has one provenance, an
/// override exists to stop dialing seeds the user does not want dialed, and
/// a merge of loopback with public peers would manufacture the mixed state
/// no transport mode can serve. A present layer is non-empty where it is
/// parsed (the override at load, the export at parse), so no layer is ever
/// silently skipped. The export is never consulted here at all — it was
/// `select_network`'s to read, for the two networks that read one.
///
/// # Errors
///
/// [`PeerResolveError`] — usage (2) at the surface: the table is empty, or
/// the set is one no transport mode can dial on this network.
pub(crate) fn resolve_peers(
    definition: NetworkConfig,
    config: &Config,
) -> Result<NetworkConfig, PeerResolveError> {
    resolve_peers_from(definition, config.arbitrum_one_bootstrap.as_deref())
}

/// [`resolve_peers`]'s table over its two inputs, injected so the table is
/// testable row by row: `definition` as [`select_network`] built it, and
/// config.toml's `[networks.arbitrum-one] bootstrap` — a layer that exists
/// for `arbitrum-one` alone, which is why the parameter is named for it
/// rather than for a network (the loader refuses the key under any other).
fn resolve_peers_from(
    mut definition: NetworkConfig,
    arbitrum_one_override: Option<&[SocketAddr]>,
) -> Result<NetworkConfig, PeerResolveError> {
    let network = definition.id;
    let peers: Vec<SocketAddr> = match (network, arbitrum_one_override) {
        // Layer 1 of `arbitrum-one`'s table replaces layer 2 — the vendored
        // list the definition carries is dropped, never merged in.
        (NetworkId::ArbitrumOne, Some(override_peers)) => override_peers.to_vec(),
        // The only remaining layer of every table is what the definition's
        // own source carried: the vendored list, or an export's peers. An
        // `arbitrum-one` override set in config.toml is not a layer of the
        // other two networks' tables and is not consulted for them.
        (NetworkId::ArbitrumOne, None) | (NetworkId::ArbitrumSepolia | NetworkId::Devnet, _) => {
            core::mem::take(&mut definition.bootstrap)
        }
    };
    if peers.is_empty() {
        return Err(PeerResolveError::NoPeers { network });
    }
    // One classifier (D173 §2 R8): the adapter asks the same question again
    // before it connects, so a set refused here is refused there too.
    peer_locality(network, &peers)
        .map_err(|source| PeerResolveError::Undialable { network, source })?;
    definition.bootstrap = peers;
    Ok(definition)
}

/// D174 §2 R8 — the recorded network is the resolved network.
///
/// A seal records `planned` as the work's network; the definition it pays
/// and stores through must be that network's. With D174's arms in force
/// the two cannot differ — `select_network` builds `arbitrum-sepolia` only
/// from a Sepolia export and `devnet` only from a local one — so a mismatch
/// is a bug in this module, reported as the internal class and never as a
/// panic.
///
/// # Errors
///
/// [`CliError::Internal`], naming both ids.
pub(crate) fn check_resolved_network(
    planned: NetworkId,
    resolved: &NetworkConfig,
) -> Result<(), CliError> {
    if resolved.id == planned {
        return Ok(());
    }
    Err(CliError::Internal {
        detail: format!(
            "the seal planned network `{planned}` but resolved a definition for `{}`; a work is \
             recorded on the network it is paid and stored on, so the two must agree",
            resolved.id
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use antseal_core::test_util::alternate_test_secret;
    use antseal_net::network::{
        ARBITRUM_SEPOLIA_PAYMENT_TOKEN, ARBITRUM_SEPOLIA_PAYMENT_VAULT, ARBITRUM_SEPOLIA_RPC_URL,
    };
    use antseal_net::{PeerSetError, arbitrum_one_vendored_peers};

    use crate::error::ErrorClass;

    /// Where every fixture export "lives": a path, so the refusals that name
    /// one can be asserted to.
    const FIXTURE_PATH: &str = "/run/antseal/env";

    /// Anvil's deterministic first two deployments — the contracts a LOCAL
    /// export carries, and therefore the wrong ones for Arbitrum Sepolia.
    const ANVIL_TOKEN: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
    const ANVIL_VAULT: &str = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";

    /// A devnet's peers: loopback, as the launcher binds them.
    const LOOPBACK_PEERS: &str = "127.0.0.1:20001,127.0.0.1:20002";

    /// A key-shaped fixture derived per the house convention
    /// (`SHA-256(label ‖ W)`), never a committed 64-hex literal.
    fn fixture_key_hex() -> String {
        alternate_test_secret(b"antseal-cli/U89 devnet env fixture wallet key")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The nine keys every export carries, in the documented order.
    fn nine_keys(chain_id: u64, token: &str, vault: &str, bootstrap: &str) -> Vec<String> {
        vec![
            "ANTSEAL_DEVNET_RPC_URL='http://127.0.0.1:53712/'".to_owned(),
            format!("ANTSEAL_DEVNET_CHAIN_ID='{chain_id}'"),
            format!("ANTSEAL_DEVNET_TOKEN_ADDRESS='{token}'"),
            format!("ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS='{vault}'"),
            format!("ANTSEAL_DEVNET_BOOTSTRAP='{bootstrap}'"),
            "ANTSEAL_DEVNET_NODE_COUNT='14'".to_owned(),
            "ANTSEAL_DEVNET_BASE_PORT='20001'".to_owned(),
            "ANTSEAL_DEVNET_DATA_DIR='.devnet/data'".to_owned(),
            "ANTSEAL_DEVNET_PID='12345'".to_owned(),
        ]
    }

    fn export(lines: &[String]) -> String {
        format!("# antseal devnet environment\n{}\n", lines.join("\n"))
    }

    /// The **canonical** Sepolia-mode export (D174 §5): nine keys, chain
    /// 421614, the D38 pinned token and vault, loopback peers — the shape a
    /// real `sepolia-up` export carries.
    fn canonical_sepolia_export() -> String {
        export(&nine_keys(
            421_614,
            ARBITRUM_SEPOLIA_PAYMENT_TOKEN,
            ARBITRUM_SEPOLIA_PAYMENT_VAULT,
            LOOPBACK_PEERS,
        ))
    }

    /// The contract-**mismatch** Sepolia export: chain 421614 with Anvil's
    /// addresses. Until D174 this fixture was called the Sepolia export and
    /// was accepted; now it is the refusal case, kept as the plant.
    fn mismatch_sepolia_export() -> String {
        export(&nine_keys(
            421_614,
            ANVIL_TOKEN,
            ANVIL_VAULT,
            LOOPBACK_PEERS,
        ))
    }

    /// The local devnet's export: nine keys on chain 31337 with Anvil's
    /// contracts, plus the funded key.
    fn local_export() -> String {
        let mut lines = nine_keys(31337, ANVIL_TOKEN, ANVIL_VAULT, LOOPBACK_PEERS);
        lines.push(format!(
            "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='{}'",
            fixture_key_hex()
        ));
        export(&lines)
    }

    /// A local chain carrying the Sepolia pins: refused by chain alone.
    fn local_export_with_sepolia_contracts() -> String {
        export(&nine_keys(
            31337,
            ARBITRUM_SEPOLIA_PAYMENT_TOKEN,
            ARBITRUM_SEPOLIA_PAYMENT_VAULT,
            LOOPBACK_PEERS,
        ))
    }

    /// An export claiming Arbitrum One's chain — a chain no export may carry.
    fn mainnet_chain_export() -> String {
        export(&nine_keys(
            42_161,
            ARBITRUM_SEPOLIA_PAYMENT_TOKEN,
            ARBITRUM_SEPOLIA_PAYMENT_VAULT,
            LOOPBACK_PEERS,
        ))
    }

    /// An eight-key export: the row's planted fault — one of the nine
    /// structural keys dropped, which is a real defect and not a mode.
    fn eight_key_export() -> String {
        let lines: Vec<String> = nine_keys(421_614, ANVIL_TOKEN, ANVIL_VAULT, LOOPBACK_PEERS)
            .into_iter()
            .filter(|line| !line.starts_with("ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS"))
            .collect();
        export(&lines)
    }

    fn from_text(text: &'static str) -> Result<Option<DevnetExport>, DevnetEnvUnusable> {
        read_devnet_env(Some(std::ffi::OsString::from(FIXTURE_PATH)), |_| {
            Ok(text.to_owned())
        })
    }

    fn from_owned(text: String) -> Result<Option<DevnetExport>, DevnetEnvUnusable> {
        read_devnet_env(Some(std::ffi::OsString::from(FIXTURE_PATH)), move |_| {
            Ok(text)
        })
    }

    /// A fixture that must parse, read as the resolver reads it.
    fn parsed(text: String) -> DevnetExport {
        from_owned(text)
            .expect("the fixture parses")
            .expect("a named export is Some")
    }

    fn malformed() -> DevnetEnvUnusable {
        DevnetEnvUnusable::Malformed {
            path: FIXTURE_PATH.to_owned(),
            var: DEVNET_ENV_VAR,
            source: DevnetEnvError::MissingKey {
                key: "ANTSEAL_DEVNET_RPC_URL",
            },
        }
    }

    fn peers(text: &str) -> Vec<SocketAddr> {
        text.split(',')
            .map(|peer| peer.parse().expect("a fixture peer parses"))
            .collect()
    }

    /// **U89's defect, stated as a test — the parse-level half.** Three
    /// outcomes that the `.ok()` call site could not tell apart must be
    /// three different values; which network a parsed export then selects
    /// is D174's, below.
    #[test]
    fn an_unset_variable_is_not_an_error_and_a_nine_key_export_is_a_parsed_export() {
        // 1. Nothing pointed at: `Ok(None)`, and no file is read.
        let absent = read_devnet_env(None, |_| panic!("must not read a file"));
        assert!(
            matches!(absent, Ok(None)),
            "an unset {DEVNET_ENV_VAR} is not an error: {absent:?}"
        );

        // 2. A nine-key sepolia export: a parsed export with an empty wallet
        //    slot, carrying the path it was read from.
        let sepolia = parsed(canonical_sepolia_export());
        assert_eq!(sepolia.path, FIXTURE_PATH, "the export remembers its path");
        assert!(
            sepolia.env.wallet_private_key().is_none(),
            "the sepolia export carries no wallet key"
        );
        assert_eq!(
            sepolia.env.chain_id(),
            421_614,
            "chain id survives the parse"
        );
        assert_eq!(
            sepolia.env.bootstrap().len(),
            2,
            "the nine keys the file DID carry are all present"
        );

        // 3. A genuinely absent devnet is still an error, and DISTINGUISHABLE
        //    from case 2.
        let none = resolve(NetworkId::Devnet, Ok(None)).expect_err("no devnet is still an error");
        assert!(
            matches!(none, NetworkSelectError::NoDefinition(_)),
            "an absent devnet is NoDefinition: {none:?}"
        );
    }

    /// **D174 §2 R2 (U92 Accept row 1).** A canonical 421614 export selects
    /// `arbitrum-sepolia` — the pinned chain half with the export's peers —
    /// and not `devnet`, which is what the same export selected before D174.
    #[test]
    fn a_canonical_sepolia_export_selects_arbitrum_sepolia_with_the_exports_peers() {
        let DevnetExport { path: _, env } = parsed(canonical_sepolia_export());
        let export_peers = env.bootstrap().to_vec();
        let export_rpc = env.rpc_url().to_owned();
        let selected = resolve(
            NetworkId::ArbitrumSepolia,
            Ok(Some(parsed(canonical_sepolia_export()))),
        )
        .expect("a canonical Sepolia export selects a network");
        assert_eq!(
            selected.config.id,
            NetworkId::ArbitrumSepolia,
            "a 421614 export yields arbitrum-sepolia, never devnet"
        );
        assert_eq!(
            selected.config.bootstrap, export_peers,
            "a 421614 export yields arbitrum-sepolia with the export's peers"
        );
        assert_eq!(selected.config.bootstrap.len(), 2, "both peers, in order");
        // The chain half is the pinned one, not the export's.
        let pinned = NetworkConfig::arbitrum_sepolia();
        assert_eq!(selected.config.evm_chain_id, pinned.evm_chain_id);
        assert_eq!(selected.config.payment_token, pinned.payment_token);
        assert_eq!(selected.config.payment_vault, pinned.payment_vault);
        assert_eq!(selected.config.rpc_url, ARBITRUM_SEPOLIA_RPC_URL);
        assert_ne!(
            selected.config.rpc_url, export_rpc,
            "the export's RPC_URL is not used (D174 §2 R2)"
        );
        assert_eq!(
            selected.walletless_devnet,
            Some(WALLETLESS_DEVNET_NOTE),
            "the walletless note is this arm's now (D174 §2 R2)"
        );
    }

    /// **D174 §2 R2.** A local export under `arbitrum-sepolia` is refused by
    /// its chain — naming the chain, the path and `--network devnet` — and
    /// the chain is judged before the contracts, so a local export carrying
    /// the Sepolia pins is refused the same way rather than accepted.
    #[test]
    fn a_local_export_under_arbitrum_sepolia_is_refused_by_chain_before_contracts() {
        let error = resolve(NetworkId::ArbitrumSepolia, Ok(Some(parsed(local_export()))))
            .expect_err("a 31337 export is refused by name");
        assert!(
            matches!(
                error,
                NetworkSelectError::SepoliaExportOnLocalChain {
                    chain_id: 31337,
                    ..
                }
            ),
            "{error:?}"
        );
        let message = error.to_string();
        for fragment in ["31337", "--network devnet", FIXTURE_PATH, "421614"] {
            assert!(
                message.contains(fragment),
                "a 31337 export is refused by name — `{fragment}`: {message}"
            );
        }
        assert!(
            !message.contains("ANTSEAL_DEVNET_TOKEN_ADDRESS"),
            "the contract refusal must not mask the chain refusal: {message}"
        );

        let with_pins = resolve(
            NetworkId::ArbitrumSepolia,
            Ok(Some(parsed(local_export_with_sepolia_contracts()))),
        )
        .expect_err("a 31337 export with the Sepolia contracts is still refused by chain");
        assert!(
            matches!(
                with_pins,
                NetworkSelectError::SepoliaExportOnLocalChain {
                    chain_id: 31337,
                    ..
                }
            ),
            "{with_pins:?}"
        );
    }

    /// **D174 §2 R2 (the contract check is mandatory).** A 421614 export
    /// naming a foreign contract is refused naming the export **key** and the
    /// **pinned** address — never the export's own value, which would carry
    /// export content into logs.
    #[test]
    fn a_sepolia_export_with_a_foreign_contract_is_refused_naming_the_key_and_the_pin_never_the_value()
     {
        let foreign_token = export(&nine_keys(
            421_614,
            ANVIL_TOKEN,
            ARBITRUM_SEPOLIA_PAYMENT_VAULT,
            LOOPBACK_PEERS,
        ));
        let foreign_vault = export(&nine_keys(
            421_614,
            ARBITRUM_SEPOLIA_PAYMENT_TOKEN,
            ANVIL_VAULT,
            LOOPBACK_PEERS,
        ));
        for (label, text, key, pinned, foreign) in [
            (
                "a foreign payment token",
                foreign_token,
                "ANTSEAL_DEVNET_TOKEN_ADDRESS",
                ARBITRUM_SEPOLIA_PAYMENT_TOKEN,
                ANVIL_TOKEN,
            ),
            (
                "a foreign payment vault",
                foreign_vault,
                "ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS",
                ARBITRUM_SEPOLIA_PAYMENT_VAULT,
                ANVIL_VAULT,
            ),
            // Both foreign: the token is compared first, so it is the one named.
            (
                "the pre-D174 Sepolia fixture, Anvil contracts on chain 421614",
                mismatch_sepolia_export(),
                "ANTSEAL_DEVNET_TOKEN_ADDRESS",
                ARBITRUM_SEPOLIA_PAYMENT_TOKEN,
                ANVIL_TOKEN,
            ),
        ] {
            let error = match resolve(NetworkId::ArbitrumSepolia, Ok(Some(parsed(text)))) {
                Err(error) => error,
                Ok(selected) => {
                    panic!("a 421614 export with {label} is refused: got Ok({selected:?})")
                }
            };
            assert!(
                matches!(error, NetworkSelectError::SepoliaExportContract { .. }),
                "{label}: {error:?}"
            );
            let message = error.to_string();
            assert!(message.contains(key), "{label}: names the key: {message}");
            assert!(
                message.contains(pinned),
                "{label}: names the pin: {message}"
            );
            assert!(
                message.contains(FIXTURE_PATH),
                "{label}: names the path: {message}"
            );
            let lowered = message.to_lowercase();
            assert!(
                !lowered.contains(&foreign.to_lowercase()),
                "{label}: the refusal never echoes the export's value: {message}"
            );
        }
    }

    /// **D174 §2 R2–R3.** Chain 42161 is one no export may carry: under
    /// `arbitrum-sepolia` the refusal says so without offering `--network
    /// devnet` (no devnet runs that chain), and under `devnet` it names the
    /// chain and that `arbitrum-one` never reads an export.
    #[test]
    fn a_mainnet_chain_export_is_refused_under_both_reading_networks_and_offers_no_devnet() {
        let under_sepolia = resolve(
            NetworkId::ArbitrumSepolia,
            Ok(Some(parsed(mainnet_chain_export()))),
        )
        .expect_err("a 42161 export is refused under arbitrum-sepolia");
        assert!(
            matches!(
                under_sepolia,
                NetworkSelectError::SepoliaExportOnMainnetChain { .. }
            ),
            "{under_sepolia:?}"
        );
        let message = under_sepolia.to_string();
        assert!(message.contains("42161"), "{message}");
        assert!(message.contains("never reads an export"), "{message}");
        assert!(
            !message.contains("--network devnet"),
            "no devnet runs chain 42161, so none is offered: {message}"
        );

        let under_devnet = resolve(NetworkId::Devnet, Ok(Some(parsed(mainnet_chain_export()))))
            .expect_err("devnet refuses a 42161 export by name");
        assert!(
            matches!(
                under_devnet,
                NetworkSelectError::DevnetExportIsMainnet { .. }
            ),
            "{under_devnet:?}"
        );
        let message = under_devnet.to_string();
        assert!(message.contains("42161"), "{message}");
        assert!(message.contains("never reads an export"), "{message}");
    }

    /// **D174 §2 R4 (U92 Accept: a stale export does not affect
    /// `arbitrum-one`, planted).** The lookup handed to `arbitrum-one`
    /// panics if called, so widening the read to every id is a panic in this
    /// test rather than a silently consulted export; and the table arm
    /// succeeds even when handed an outright failure.
    #[test]
    fn arbitrum_one_never_consults_the_export() {
        let selected = select_network_with(NetworkId::ArbitrumOne, || {
            panic!("arbitrum-one consulted ANTSEAL_DEVNET_ENV (U89, D174 §2 R4)")
        })
        .expect("arbitrum-one always resolves");
        assert_eq!(selected.config, NetworkConfig::arbitrum_one());
        assert_eq!(selected.walletless_devnet, None);
        assert!(
            !selected.config.bootstrap.is_empty(),
            "the built-in definition carries the vendored list (D173 §2 R1)"
        );

        // Even handed an outright failure, the table's arm succeeds — the
        // export is not an input of it.
        let selected = resolve(NetworkId::ArbitrumOne, Err(malformed()))
            .expect("a broken export cannot break arbitrum-one");
        assert_eq!(selected.config.id, NetworkId::ArbitrumOne);

        // And the real entry point resolves it without touching a file.
        assert_eq!(
            select_network(NetworkId::ArbitrumOne)
                .expect("arbitrum-one always resolves")
                .config,
            NetworkConfig::arbitrum_one()
        );
    }

    /// **D174 §2 R4's second half — the seam is wired.** Without this the
    /// panicking test above would pass on a `select_network_with` that
    /// ignored its lookup altogether: the injected lookup is consulted
    /// exactly once for each of the two networks that read an export. For
    /// `arbitrum-sepolia`, `Ok(None)` is **not** a refusal here (D174 §2
    /// R2, D173 §2 R7): the definition is the built-in one with no peers.
    #[test]
    fn the_injected_lookup_is_consulted_exactly_once_for_arbitrum_sepolia_and_devnet() {
        for id in [NetworkId::ArbitrumSepolia, NetworkId::Devnet] {
            let calls = Cell::new(0usize);
            let outcome = select_network_with(id, || {
                calls.set(calls.get() + 1);
                Ok(None)
            });
            assert_eq!(
                calls.get(),
                1,
                "the resolver reads the injected lookup for {id} exactly once"
            );
            match id {
                NetworkId::ArbitrumSepolia => {
                    let selected = outcome.expect("an unset export is not refused here");
                    assert_eq!(selected.config.id, NetworkId::ArbitrumSepolia);
                    assert!(
                        selected.config.bootstrap.is_empty(),
                        "nothing is built in for Arbitrum Sepolia"
                    );
                    assert_eq!(selected.walletless_devnet, None);
                }
                NetworkId::Devnet | NetworkId::ArbitrumOne => {
                    let error = outcome.expect_err("devnet with no export is NoDefinition");
                    assert!(
                        matches!(error, NetworkSelectError::NoDefinition(_)),
                        "{error:?}"
                    );
                }
            }
        }
    }

    /// **D174 §2 R2's last clause.** An unreadable or malformed export keeps
    /// U89's arms under `arbitrum-sepolia` exactly as under `devnet`: a
    /// pointed-at export that is broken is reported as broken, never as
    /// absence and never as a wrong-network refusal.
    #[test]
    fn an_unreadable_or_malformed_export_keeps_u89s_arms_under_both_reading_networks() {
        for id in [NetworkId::ArbitrumSepolia, NetworkId::Devnet] {
            let error = resolve(id, Err(malformed())).expect_err("a broken export is an error");
            assert!(
                matches!(
                    error,
                    NetworkSelectError::Devnet(DevnetEnvUnusable::Malformed { .. })
                ),
                "{id}: {error:?}"
            );
            let unreadable = DevnetEnvUnusable::Unreadable {
                path: FIXTURE_PATH.to_owned(),
                var: DEVNET_ENV_VAR,
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "gone"),
            };
            let error = resolve(id, Err(unreadable)).expect_err("an unreadable export is an error");
            assert!(
                matches!(
                    error,
                    NetworkSelectError::Devnet(DevnetEnvUnusable::Unreadable { .. })
                ),
                "{id}: {error:?}"
            );
        }
    }

    /// **D174 §2 R3 (U92 Accept row 4).** `devnet` refuses a 421614 export by
    /// name — whatever its contracts say, since the chain decides — and
    /// reads a local export exactly as before.
    #[test]
    fn devnet_refuses_a_sepolia_export_by_name_and_reads_a_local_one_as_today() {
        for (label, text) in [
            ("the canonical Sepolia export", canonical_sepolia_export()),
            (
                "a 421614 export with Anvil contracts",
                mismatch_sepolia_export(),
            ),
        ] {
            let error = match resolve(NetworkId::Devnet, Ok(Some(parsed(text)))) {
                Err(error) => error,
                Ok(selected) => {
                    panic!("devnet refuses a 421614 export by name ({label}): got Ok({selected:?})")
                }
            };
            assert!(
                matches!(error, NetworkSelectError::DevnetExportIsSepolia { .. }),
                "{label}: not NoDefinition, a refusal by name: {error:?}"
            );
            let message = error.to_string();
            for fragment in ["421614", "--network arbitrum-sepolia", FIXTURE_PATH] {
                assert!(
                    message.contains(fragment),
                    "{label}: `{fragment}`: {message}"
                );
            }
        }

        let local = resolve(NetworkId::Devnet, Ok(Some(parsed(local_export()))))
            .expect("a local export under devnet resolves as today");
        assert_eq!(local.config.id, NetworkId::Devnet);
        assert_eq!(local.config.evm_chain_id, 31337);
        assert_eq!(local.config.bootstrap, peers(LOOPBACK_PEERS));
    }

    /// The walletless note belongs to the `arbitrum-sepolia` arm (D174 §2
    /// R2) and to no other: a ten-key local export does not take it, and
    /// neither does a nine-key local one — its text describes the Sepolia
    /// shape, and would be false of a local export that merely lacks a key.
    /// Without the ten-key control, the Sepolia assertion would pass with
    /// the branch wired to a constant `Some`.
    #[test]
    fn the_walletless_note_is_the_sepolia_arms_and_never_devnets() {
        let ten_keys = parsed(local_export());
        assert!(
            ten_keys.env.wallet_private_key().is_some(),
            "the local export carries its funded key"
        );
        let selected =
            resolve(NetworkId::Devnet, Ok(Some(ten_keys))).expect("a local export selects");
        assert_eq!(selected.config.evm_chain_id, 31337);
        assert_eq!(
            selected.walletless_devnet, None,
            "a ten-key export is not walletless"
        );

        let nine_local = export(&nine_keys(31337, ANVIL_TOKEN, ANVIL_VAULT, LOOPBACK_PEERS));
        let selected = resolve(NetworkId::Devnet, Ok(Some(parsed(nine_local))))
            .expect("a nine-key local export still selects devnet");
        assert_eq!(
            selected.walletless_devnet, None,
            "the note describes the Sepolia shape and is not logged for a local export"
        );

        let selected = resolve(
            NetworkId::ArbitrumSepolia,
            Ok(Some(parsed(canonical_sepolia_export()))),
        )
        .expect("the canonical export selects");
        assert_eq!(selected.walletless_devnet, Some(WALLETLESS_DEVNET_NOTE));
    }

    /// The row's planted fault: an **eight**-key export must still fail,
    /// with a message that names what is missing.
    #[test]
    fn an_eight_key_export_still_fails_and_names_the_missing_key() {
        let error = from_owned(eight_key_export()).expect_err("eight keys is not a devnet");
        assert!(
            matches!(error, DevnetEnvUnusable::Malformed { .. }),
            "a short export is Malformed, not Unreadable: {error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains("ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS"),
            "the message names the missing key: {message}"
        );
        assert!(
            message.contains(FIXTURE_PATH),
            "the message names the file it read: {message}"
        );
        // And it reaches the surface as the devnet arm, not as
        // "no devnet at all".
        let selected = resolve(NetworkId::Devnet, Err(error)).expect_err("selection fails");
        assert!(
            matches!(selected, NetworkSelectError::Devnet(_)),
            "a broken export is Devnet(_), never NoDefinition: {selected:?}"
        );
    }

    /// Accept row 2: a malformed **value** still fails, and no message
    /// echoes a value — least of all the wallet key's.
    ///
    /// The wallet key's structural check at this layer is **emptiness and
    /// nothing else**, by design: real validation is D44's
    /// parse-through-the-pinned-stack in `antseal_net::evm`, behind
    /// `ant-backend` (`network.rs`, `parse_devnet_fields`). This test
    /// asserted a 66-character key would be refused here and was wrong —
    /// the code is right and the test now says what it actually does.
    #[test]
    fn a_malformed_value_fails_without_echoing_it() {
        // An EMPTY wallet line is malformed in both forms, so a launcher
        // that wrote one cannot pass itself off as a walletless export.
        // This is the arm U89 must not blur: `WALLET_PRIVATE_KEY=''` is a
        // broken ten-key export, not a nine-key sepolia one.
        let secret = fixture_key_hex();
        let text = local_export().replace(
            &format!("ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='{secret}'"),
            "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY=''",
        );
        assert!(
            !text.contains(&secret),
            "the fixture edit applied (a no-op replace would make this test vacuous)"
        );
        let error = from_owned(text).expect_err("an empty wallet line is refused, not tolerated");
        let message = error.to_string();
        assert!(
            message.contains("ANTSEAL_DEVNET_WALLET_PRIVATE_KEY") && message.contains("empty"),
            "the message names the key and the problem: {message}"
        );

        // A malformed NON-secret value: the message names the key and not
        // the value, and the wallet key present in the same file does not
        // leak through the failure either.
        let text = local_export().replace("'31337'", "'not-a-chain-id'");
        assert!(text.contains("not-a-chain-id"), "the fixture edit applied");
        let message = from_owned(text)
            .expect_err("a malformed chain id is refused")
            .to_string();
        assert!(
            message.contains("ANTSEAL_DEVNET_CHAIN_ID"),
            "names the key: {message}"
        );
        assert!(
            !message.contains("not-a-chain-id"),
            "never echoes the value: {message}"
        );
        assert!(
            !message.contains(&secret),
            "and never echoes the wallet key that sat in the same file"
        );
    }

    /// An unreadable path is its own arm — not "no devnet", and not
    /// "malformed".
    #[test]
    fn an_unreadable_path_is_its_own_failure() {
        let error = read_devnet_env(Some(std::ffi::OsString::from("/run/antseal/gone")), |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no such file or directory",
            ))
        })
        .expect_err("an unreadable export is an error, not None");
        assert!(
            matches!(error, DevnetEnvUnusable::Unreadable { .. }),
            "{error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains("/run/antseal/gone") && message.contains("could not be read"),
            "{message}"
        );
    }

    /// The note names the key and the mode (Accept row 1), and never
    /// carries key material.
    #[test]
    fn the_walletless_note_names_the_key_and_the_mode() {
        assert!(WALLETLESS_DEVNET_NOTE.contains("ANTSEAL_DEVNET_WALLET_PRIVATE_KEY"));
        assert!(WALLETLESS_DEVNET_NOTE.contains("arbitrum-sepolia"));
        assert!(WALLETLESS_DEVNET_NOTE.contains("421614"));
        assert!(
            WALLETLESS_DEVNET_NOTE.contains("vault"),
            "it says where the key antseal DOES use comes from"
        );
    }

    /// A file that is not an export at all reads as malformed, not as
    /// absence — `from_text` proves the seam takes borrowed fixtures too.
    #[test]
    fn an_unrelated_file_is_malformed_not_absent() {
        let error = from_text("this is a README, not a devnet export\n")
            .expect_err("an unrelated file is not a devnet");
        assert!(
            matches!(error, DevnetEnvUnusable::Malformed { .. }),
            "{error:?}"
        );
    }

    /// **D174 §2 R7 — one no-definition message per id.** `devnet`'s names
    /// `scripts/devnet/local-up`; `arbitrum-sepolia`'s no-peers text names
    /// `scripts/devnet/sepolia-up` and that no public network exists; both
    /// name `ANTSEAL_DEVNET_ENV`; neither offers another network as an
    /// export-free alternative. `arbitrum-one`'s names its two layers.
    #[test]
    fn the_no_definition_messages_name_their_script_and_the_variable_and_offer_no_other_network() {
        let devnet = resolve(NetworkId::Devnet, Ok(None))
            .expect_err("no devnet")
            .to_string();
        for fragment in ["scripts/devnet/local-up", "ANTSEAL_DEVNET_ENV"] {
            assert!(devnet.contains(fragment), "`{fragment}`: {devnet}");
        }
        assert!(
            !devnet.contains("arbitrum-sepolia"),
            "the devnet refusal no longer offers arbitrum-sepolia as an export-free alternative: \
             {devnet}"
        );

        let sepolia = PeerResolveError::NoPeers {
            network: NetworkId::ArbitrumSepolia,
        }
        .to_string();
        for fragment in [
            "scripts/devnet/sepolia-up",
            "ANTSEAL_DEVNET_ENV",
            "no public Autonomi storage network on Arbitrum Sepolia",
        ] {
            assert!(sepolia.contains(fragment), "`{fragment}`: {sepolia}");
        }
        assert!(
            !sepolia.contains("--network devnet") && !sepolia.contains("arbitrum-one"),
            "the sepolia refusal offers no other network: {sepolia}"
        );

        let one = PeerResolveError::NoPeers {
            network: NetworkId::ArbitrumOne,
        }
        .to_string();
        assert!(one.contains("[networks.arbitrum-one] bootstrap"), "{one}");
        assert!(one.contains("built-in"), "{one}");
        assert!(
            !one.contains("ANTSEAL_DEVNET_ENV"),
            "arbitrum-one never reads an export, so its refusal must not point at one: {one}"
        );

        // `devnet`'s no-peers text is its no-definition text: its one layer
        // is the export.
        let devnet_peers = PeerResolveError::NoPeers {
            network: NetworkId::Devnet,
        }
        .to_string();
        assert_eq!(devnet_peers, devnet);
    }

    /// **D173 §2 R6 (S40 Accept row 1) — the resolution table.** Per
    /// network, the first present layer wins and **replaces**: an
    /// `arbitrum-one` override is the whole set (never the override plus
    /// the vendored list), the vendored list is the whole set without one,
    /// an export's peers are the whole set for the networks that read one,
    /// and an `arbitrum-one` override is not a layer of any other network's
    /// table.
    #[test]
    fn peer_resolution_is_per_network_first_present_wins_replace_never_merge() {
        let config = Config::default();
        let vendored = arbitrum_one_vendored_peers();
        assert!(
            vendored.len() >= 2,
            "the vendored list must hold several peers for a merge to be distinguishable"
        );
        let override_peer: SocketAddr = "192.0.2.10:10000".parse().expect("a documentation peer");
        assert!(
            !vendored.contains(&override_peer),
            "the override must not be a vendored peer, or `exactly the override` is vacuous"
        );

        // Row 1: arbitrum-one, no override → exactly the vendored list.
        let one = NetworkConfig::arbitrum_one();
        let resolved = resolve_peers(one.clone(), &config).expect("the vendored list resolves");
        assert_eq!(
            resolved.bootstrap, vendored,
            "no override → the vendored list, whole"
        );
        assert_eq!(resolved.id, NetworkId::ArbitrumOne);

        // Row 2: arbitrum-one, override [A] → exactly [A]. The replace-not-
        // merge row: a merge would be the vendored list plus one.
        let resolved =
            resolve_peers_from(one.clone(), Some(&[override_peer])).expect("an override resolves");
        assert_eq!(
            resolved.bootstrap,
            vec![override_peer],
            "arbitrum-one with an override must dial exactly the override (replace, never \
             merge): {} peers resolved, 1 expected",
            resolved.bootstrap.len()
        );

        // Row 3: through the loaded config, the same answer — the consumer
        // reads `config.arbitrum_one_bootstrap`.
        let with_override = Config {
            arbitrum_one_bootstrap: Some(vec![override_peer]),
            ..Config::default()
        };
        let resolved = resolve_peers(one.clone(), &with_override).expect("resolves");
        assert_eq!(resolved.bootstrap, vec![override_peer]);

        // Row 4: a stale export plus arbitrum-one → the vendored list, and the
        // export reader is never called.
        let selected = select_network_with(NetworkId::ArbitrumOne, || {
            panic!("the export must never be read for arbitrum-one (U89)")
        })
        .expect("resolves");
        let resolved = resolve_peers(selected.config, &config).expect("resolves");
        assert_eq!(resolved.bootstrap, vendored);

        // Row 5: arbitrum-sepolia, export [L1, L2] → exactly [L1, L2] — and an
        // arbitrum-one override set in the same config is not its layer.
        let sepolia = resolve(
            NetworkId::ArbitrumSepolia,
            Ok(Some(parsed(canonical_sepolia_export()))),
        )
        .expect("selects")
        .config;
        let resolved = resolve_peers(sepolia.clone(), &with_override).expect("resolves");
        assert_eq!(resolved.bootstrap, peers(LOOPBACK_PEERS));
        assert_eq!(resolved.id, NetworkId::ArbitrumSepolia);

        // Row 6: devnet, the export's peers → exactly those, override ignored.
        let devnet = resolve(NetworkId::Devnet, Ok(Some(parsed(local_export()))))
            .expect("selects")
            .config;
        let resolved = resolve_peers(devnet, &with_override).expect("resolves");
        assert_eq!(resolved.bootstrap, peers(LOOPBACK_PEERS));

        // Row 7: a public export under arbitrum-sepolia is accepted too — the
        // network takes either class (D173 §2 R8).
        let public = NetworkConfig {
            bootstrap: peers("203.0.113.5:20001,203.0.113.6:20001"),
            ..NetworkConfig::arbitrum_sepolia()
        };
        let resolved = resolve_peers(public.clone(), &config).expect("public peers resolve");
        assert_eq!(resolved.bootstrap, public.bootstrap);
    }

    /// **D173 §2 R6–R8 (S40 Accept row 1's planted empty list, at the unit
    /// level).** An empty resolved set and an undialable one are refused,
    /// and every refusal is usage (2) — never the transient class, never a
    /// panic, never an isolated client.
    #[test]
    fn an_empty_or_undialable_resolved_set_is_refused_as_usage_before_any_dial() {
        let config = Config::default();

        // Row A: arbitrum-sepolia with no export → NoPeers → 2.
        let sepolia = select_network_with(NetworkId::ArbitrumSepolia, || Ok(None))
            .expect("not refused at selection")
            .config;
        let error = resolve_peers(sepolia, &config)
            .expect_err("an empty resolved set must be refused (NoPeers → usage 2)");
        assert!(
            matches!(
                error,
                PeerResolveError::NoPeers {
                    network: NetworkId::ArbitrumSepolia
                }
            ),
            "{error:?}"
        );
        let cli = CliError::from(error);
        assert_eq!(cli.class(), ErrorClass::Usage);
        assert_eq!(cli.exit_code(), 2);

        // Row B: arbitrum-one with the vendored list unusable (injected as
        // empty) → NoPeers → 2, never Ok with 0 peers.
        let unusable = NetworkConfig {
            bootstrap: Vec::new(),
            ..NetworkConfig::arbitrum_one()
        };
        match resolve_peers(unusable, &config) {
            Err(PeerResolveError::NoPeers {
                network: NetworkId::ArbitrumOne,
            }) => {}
            other => {
                panic!("an empty resolved set must be refused (NoPeers → usage 2), got {other:?}")
            }
        }

        // Row C: a mixed export under devnet → Mixed → 2.
        let mixed = NetworkConfig {
            bootstrap: peers("127.0.0.1:20001,203.0.113.5:20001"),
            ..NetworkConfig::arbitrum_sepolia()
        };
        let mixed = NetworkConfig {
            id: NetworkId::Devnet,
            ..mixed
        };
        let error =
            resolve_peers(mixed, &config).expect_err("a mixed loopback/public set must be refused");
        assert!(
            matches!(
                error,
                PeerResolveError::Undialable {
                    network: NetworkId::Devnet,
                    source: PeerLocalityError::Set(PeerSetError::Mixed { .. })
                }
            ),
            "{error:?}"
        );
        let message = error.to_string();
        assert!(message.contains("mixes loopback"), "{message}");
        assert!(
            !message.contains("203.0.113.5"),
            "the refusal names indices, never addresses: {message}"
        );
        assert_eq!(CliError::from(error).exit_code(), 2);

        // Row D: loopback peers under arbitrum-one → LoopbackForbidden → 2,
        // whether they arrive as an override (the loader refuses that first)
        // or any other way.
        let loopback: Vec<SocketAddr> = peers("127.0.0.1:10000");
        let error = resolve_peers_from(NetworkConfig::arbitrum_one(), Some(&loopback))
            .expect_err("arbitrum-one must not dial loopback peers");
        assert!(
            matches!(
                error,
                PeerResolveError::Undialable {
                    network: NetworkId::ArbitrumOne,
                    source: PeerLocalityError::LoopbackForbidden { .. }
                }
            ),
            "{error:?}"
        );
        assert_eq!(CliError::from(error).exit_code(), 2);

        // Row E: a repeated peer → Duplicate → 2.
        let repeated = NetworkConfig {
            bootstrap: peers("127.0.0.1:20001,127.0.0.1:20001"),
            ..NetworkConfig::arbitrum_sepolia()
        };
        let error = resolve_peers(repeated, &config).expect_err("a repeat is refused");
        assert!(
            matches!(
                error,
                PeerResolveError::Undialable {
                    source: PeerLocalityError::Set(PeerSetError::Duplicate { .. }),
                    ..
                }
            ),
            "{error:?}"
        );

        // And the selection errors map to the same class, so a dialing
        // command's two refusals are one class at the surface.
        let selection = CliError::from(NetworkSelectError::NoDefinition(
            NetworkConfigError::DevnetEnvironmentRequired,
        ));
        assert_eq!(selection.class(), ErrorClass::Usage);
        assert_eq!(selection.exit_code(), 2);
    }

    /// **D174 §2 R8.** The seal refuses a resolved definition whose id is not
    /// the planned network, as the internal class — a bug, never a usage
    /// error and never a panic — naming both; a matching pair passes.
    #[test]
    fn the_seal_refuses_a_resolved_network_that_is_not_the_planned_one() {
        let error =
            check_resolved_network(NetworkId::ArbitrumOne, &NetworkConfig::arbitrum_sepolia())
                .expect_err("the seal refuses a resolved network that is not the planned one");
        assert!(matches!(error, CliError::Internal { .. }), "{error:?}");
        assert_eq!(error.class(), ErrorClass::Internal);
        assert_eq!(error.exit_code(), 1);
        let message = error.to_string();
        assert!(message.contains("arbitrum-one"), "{message}");
        assert!(message.contains("arbitrum-sepolia"), "{message}");

        for (planned, resolved) in [
            (NetworkId::ArbitrumOne, NetworkConfig::arbitrum_one()),
            (
                NetworkId::ArbitrumSepolia,
                NetworkConfig::arbitrum_sepolia(),
            ),
        ] {
            check_resolved_network(planned, &resolved).expect("a matching pair passes");
        }
    }
}
