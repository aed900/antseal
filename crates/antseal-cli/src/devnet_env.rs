//! Resolving `ANTSEAL_DEVNET_ENV` into a network definition (U89).
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
//! out as one line for the caller to log, rather than as a failure.
//!
//! # Laziness is load-bearing
//!
//! [`select_network`] consults the environment **only** for
//! [`NetworkId::Devnet`]. The old call site read the file on every
//! invocation and discarded it for the other two networks; making the read
//! fallible without making it lazy would have turned a stale
//! `ANTSEAL_DEVNET_ENV` — which survives a `local-down` in any shell that
//! exported it — into a hard failure of `--network arbitrum-one`.

use antseal_core::crypto::secrets::SecretBuf;
use antseal_net::{DevnetEnv, DevnetEnvError, NetworkConfig, NetworkConfigError, NetworkId};

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
#[derive(Debug, thiserror::Error)]
pub(crate) enum NetworkSelectError {
    /// The network itself has no definition here — in practice always
    /// "devnet, and nothing was pointed at one". The copy is the pre-U89
    /// copy verbatim: this arm's behaviour is unchanged, and only the arms
    /// that used to be *misrouted into* it are new.
    #[error(
        "{0} — export ANTSEAL_DEVNET_ENV pointing at a running devnet's .devnet/env \
         (scripts/devnet/local-up), or seal to --network arbitrum-sepolia"
    )]
    NoDefinition(NetworkConfigError),

    /// A devnet **was** pointed at and it is not usable. Before U89 this
    /// was reported as [`Self::NoDefinition`], which was a false statement
    /// about the user's own environment.
    #[error(transparent)]
    Devnet(#[from] DevnetEnvUnusable),
}

/// A resolved network definition, plus what the resolution learned.
#[derive(Debug)]
pub(crate) struct SelectedNetwork {
    /// What backend construction needs.
    pub(crate) config: NetworkConfig,
    /// [`WALLETLESS_DEVNET_NOTE`] when the export carried no wallet key.
    ///
    /// Returned rather than logged in place so a test can assert which
    /// branch ran; the caller decides where it goes.
    pub(crate) walletless_devnet: Option<&'static str>,
}

/// Read the export `ANTSEAL_DEVNET_ENV` names, if it names one.
///
/// # Errors
///
/// [`DevnetEnvUnusable`] when the variable is set and what it names cannot
/// be read or is not a devnet export. An **unset** variable is `Ok(None)`,
/// not an error: pointing at no devnet is the normal state of every
/// invocation that is not using one.
pub(crate) fn devnet_env() -> Result<Option<CliDevnetEnv>, DevnetEnvUnusable> {
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
) -> Result<Option<CliDevnetEnv>, DevnetEnvUnusable> {
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
        .map(Some)
        .map_err(|source| DevnetEnvUnusable::Malformed {
            path: shown,
            var: DEVNET_ENV_VAR,
            source,
        })
}

/// Resolve the network `id` names, consulting `ANTSEAL_DEVNET_ENV` only
/// for [`NetworkId::Devnet`].
///
/// # Errors
///
/// [`NetworkSelectError`], whose two arms are the U89 distinction: nothing
/// was pointed at, versus something was pointed at and is unusable.
pub(crate) fn select_network(id: NetworkId) -> Result<SelectedNetwork, NetworkSelectError> {
    match id {
        // Only here is the environment read at all.
        NetworkId::Devnet => resolve(id, devnet_env()),
        // `Ok(None)` is not a lie: nothing was consulted, and this arm of
        // `resolve` never looks at it.
        other => resolve(other, Ok(None)),
    }
}

/// [`select_network`]'s decision table over an already-resolved export.
fn resolve(
    id: NetworkId,
    devnet: Result<Option<CliDevnetEnv>, DevnetEnvUnusable>,
) -> Result<SelectedNetwork, NetworkSelectError> {
    if !matches!(id, NetworkId::Devnet) {
        return NetworkConfig::select(id, None)
            .map(|config| SelectedNetwork {
                config,
                walletless_devnet: None,
            })
            .map_err(NetworkSelectError::NoDefinition);
    }
    match devnet? {
        Some(env) => Ok(SelectedNetwork {
            // Generic over the wallet slot (P22): none of this struct's
            // fields is the wallet, so nine keys build it as well as ten.
            config: NetworkConfig::devnet(&env),
            walletless_devnet: env
                .wallet_private_key()
                .is_none()
                .then_some(WALLETLESS_DEVNET_NOTE),
        }),
        None => Err(NetworkSelectError::NoDefinition(
            NetworkConfigError::DevnetEnvironmentRequired,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antseal_core::test_util::alternate_test_secret;

    /// A key-shaped fixture derived per the house convention
    /// (`SHA-256(label ‖ W)`), never a committed 64-hex literal.
    fn fixture_key_hex() -> String {
        alternate_test_secret(b"antseal-cli/U89 devnet env fixture wallet key")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The nine keys every export carries, in the documented order.
    fn nine_keys(chain_id: u64) -> Vec<String> {
        vec![
            "ANTSEAL_DEVNET_RPC_URL='http://127.0.0.1:53712/'".to_owned(),
            format!("ANTSEAL_DEVNET_CHAIN_ID='{chain_id}'"),
            "ANTSEAL_DEVNET_TOKEN_ADDRESS='0x5FbDB2315678afecb367f032d93F642f64180aa3'".to_owned(),
            "ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS='0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512'"
                .to_owned(),
            "ANTSEAL_DEVNET_BOOTSTRAP='127.0.0.1:20001,127.0.0.1:20002'".to_owned(),
            "ANTSEAL_DEVNET_NODE_COUNT='14'".to_owned(),
            "ANTSEAL_DEVNET_BASE_PORT='20001'".to_owned(),
            "ANTSEAL_DEVNET_DATA_DIR='.devnet/data'".to_owned(),
            "ANTSEAL_DEVNET_PID='12345'".to_owned(),
        ]
    }

    /// P22's arbitrum-sepolia export: the nine keys, no wallet line.
    fn sepolia_export() -> String {
        format!(
            "# antseal devnet environment\n{}\n",
            nine_keys(421_614).join("\n")
        )
    }

    /// The local devnet's export: the same nine plus the funded key.
    fn local_export() -> String {
        let mut lines = nine_keys(31337);
        lines.push(format!(
            "ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='{}'",
            fixture_key_hex()
        ));
        format!("# antseal devnet environment\n{}\n", lines.join("\n"))
    }

    /// An eight-key export: the row's planted fault — one of the nine
    /// structural keys dropped, which is a real defect and not a mode.
    fn eight_key_export() -> String {
        let lines: Vec<String> = nine_keys(421_614)
            .into_iter()
            .filter(|line| !line.starts_with("ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS"))
            .collect();
        format!("# antseal devnet environment\n{}\n", lines.join("\n"))
    }

    fn from_text(text: &'static str) -> Result<Option<CliDevnetEnv>, DevnetEnvUnusable> {
        read_devnet_env(Some(std::ffi::OsString::from("/run/antseal/env")), |_| {
            Ok(text.to_owned())
        })
    }

    fn from_owned(text: String) -> Result<Option<CliDevnetEnv>, DevnetEnvUnusable> {
        read_devnet_env(
            Some(std::ffi::OsString::from("/run/antseal/env")),
            move |_| Ok(text),
        )
    }

    /// **U89's defect, stated as a test.** Three outcomes that the `.ok()`
    /// call site could not tell apart must now be three different values.
    #[test]
    fn a_walletless_sepolia_export_is_a_devnet_and_an_absent_one_is_not() {
        // 1. Nothing pointed at: still `Ok(None)`, still "no devnet".
        let absent = read_devnet_env(None, |_| panic!("must not read a file"));
        assert!(
            matches!(absent, Ok(None)),
            "an unset {DEVNET_ENV_VAR} is not an error: {absent:?}"
        );

        // 2. A nine-key sepolia export: a devnet, with an empty wallet slot.
        let sepolia = from_owned(sepolia_export()).expect("nine keys is a devnet");
        let sepolia = sepolia.expect("a nine-key export is Some, not None");
        assert!(
            sepolia.wallet_private_key().is_none(),
            "the sepolia export carries no wallet key"
        );
        assert_eq!(sepolia.chain_id(), 421_614, "chain id survives the parse");
        assert_eq!(
            sepolia.bootstrap().len(),
            2,
            "the nine keys the file DID carry are all present"
        );

        // 3. …and it selects a real network definition.
        let selected = resolve(NetworkId::Devnet, Ok(Some(sepolia)))
            .expect("a nine-key devnet selects a network");
        assert_eq!(selected.config.id, NetworkId::Devnet);
        assert_eq!(selected.config.evm_chain_id, 421_614);
        assert_eq!(
            selected.walletless_devnet,
            Some(WALLETLESS_DEVNET_NOTE),
            "the walletless branch is the one that ran"
        );

        // 4. The pre-U89 behaviour for a genuinely absent devnet is
        //    unchanged, and is now DISTINGUISHABLE from case 2.
        let none = resolve(NetworkId::Devnet, Ok(None)).expect_err("no devnet is still an error");
        assert!(
            matches!(none, NetworkSelectError::NoDefinition(_)),
            "an absent devnet is NoDefinition: {none:?}"
        );
        assert!(
            none.to_string().contains("export ANTSEAL_DEVNET_ENV"),
            "the absent-devnet remedy is the pre-U89 copy: {none}"
        );
    }

    /// The ten-key control: a local export must NOT take the walletless
    /// branch. Without this, step 3 above would pass with the branch wired
    /// to a constant `Some`.
    #[test]
    fn a_ten_key_local_export_does_not_take_the_walletless_branch() {
        let local = from_owned(local_export())
            .expect("ten keys parse")
            .expect("ten keys are Some");
        assert!(
            local.wallet_private_key().is_some(),
            "the local export carries its funded key"
        );
        let selected = resolve(NetworkId::Devnet, Ok(Some(local))).expect("selects");
        assert_eq!(selected.config.evm_chain_id, 31337);
        assert_eq!(
            selected.walletless_devnet, None,
            "a ten-key export is not walletless"
        );
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
            message.contains("/run/antseal/env"),
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

    /// The public chains never consult the environment, so a stale
    /// `ANTSEAL_DEVNET_ENV` cannot break `--network arbitrum-one`.
    #[test]
    fn a_public_chain_ignores_the_devnet_environment() {
        for id in [NetworkId::ArbitrumOne, NetworkId::ArbitrumSepolia] {
            // Even handed an outright failure, the public arms succeed —
            // `select_network` would never have called the resolver here.
            let selected = resolve(
                id,
                Err(DevnetEnvUnusable::Malformed {
                    path: "/run/antseal/env".to_owned(),
                    var: DEVNET_ENV_VAR,
                    source: DevnetEnvError::MissingKey {
                        key: "ANTSEAL_DEVNET_RPC_URL",
                    },
                }),
            )
            .expect("a public chain has a built-in definition");
            assert_eq!(selected.config.id, id);
            assert_eq!(selected.walletless_devnet, None);
        }
        // And the real entry point resolves them without touching a file.
        assert_eq!(
            select_network(NetworkId::ArbitrumOne)
                .expect("arbitrum-one always resolves")
                .config,
            NetworkConfig::arbitrum_one()
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
}
