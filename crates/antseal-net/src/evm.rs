//! EVM-side operations that genuinely need the pinned
//! ant-core/evmlib/alloy stack (task S5; feature **`ant-backend`** — never
//! in the default graph).
//!
//! Two jobs live here:
//!
//! 1. **[`to_evm_network`]** — convert the pure-data
//!    [`NetworkConfig`](crate::NetworkConfig) into upstream's
//!    [`EvmNetwork`], the value `Client::with_wallet`/`with_evm_network`
//!    and every payment call consume.
//! 2. **[`WalletKey::evm_wallet`]** — build the payment [`Wallet`] the
//!    S6 adapter signs with. An inherent impl block for a type defined in
//!    [`crate::wallet`]: ordinary Rust, and it keeps `WalletKey` **one
//!    type** across the feature gate rather than two that must be kept in
//!    step.
//!
//! # What moved out, and why (D89, 2026-08-02)
//!
//! The wallet **light half** — [`WalletKey::generate`],
//! [`WalletKey::import`], [`WalletKey::address`] and
//! [`checksummed`](crate::wallet::checksummed) — now lives in the ungated
//! [`crate::wallet`], over a direct exact-pinned `k256`
//! (`arithmetic` only) plus `sha3`. It had to: `init`'s whole UX surface
//! was `#[cfg]`-inactive in a default build, and **no required CI context
//! compiles this feature** (`ci.yml:122,148` are default-feature) while
//! S22's tier-2 trigger does not name `init`'s files — so four of U11's
//! Accept rows were being asserted by nothing at all. D89 Evidence 3
//! measures that; the nine packages it costs the default graph are
//! enumerated there and cost the **heavy** graphs zero.
//!
//! # The D44 acceptance rule, and this file's remaining role in it
//!
//! D44 defines the accepted import set **extensionally**: "whatever the
//! pinned evmlib/alloy parse accepts" — concretely
//! `Wallet::new_from_private_key` (`evmlib-0.9.0/src/wallet.rs:71-75`) →
//! alloy `PrivateKeySigner: FromStr`
//! (`alloy-signer-local-1.8.3/src/private_key.rs:224-230`:
//! `hex::decode_to_array::<_, 32>` — optional `0x`, case-insensitive,
//! exactly 64 hex digits — then `LocalSigner::from_slice`
//! (`private_key.rs:52-54`) → `ecdsa::SigningKey::from_slice`
//! (`ecdsa-0.16.9/src/signing.rs:99-103`) → **`k256::SecretKey::from_slice`**,
//! which rejects zero and ≥-group-order scalars.
//!
//! [`crate::wallet`] now calls that same bottom function on the same
//! locked `k256`, so acceptance is identical *by construction*. What used
//! to be a tautology is therefore now the only executable statement that
//! two independently-reached implementations agree —
//! [`tests::import_acceptance_equals_the_pinned_stack_acceptance`] (lane
//! δ's agreement test, retained byte-for-byte) and the EIP-55 agreement
//! assertions below. **Treat them as guards, not niceties**: they are what
//! makes "the light half cannot fork the accepted set" a checked fact.
//! Because `crates/antseal-net/` is already a tier-2 trigger path
//! (`scripts/gate-features.sh:88`), any change to the light half runs them
//! locally without a new trigger.
//!
//! # Key-material hygiene (project rule 6)
//!
//! [`crate::wallet`] holds the hygiene contract (zeroizing buffer,
//! redacted `Debug`, no `Display`, no `Clone`, no error echoes input).
//! The one unavoidable exception is upstream's own types: a constructed
//! [`Wallet`] holds the signer in alloy's (non-zeroizing) structures for
//! the lifetime of the payment session — inherent to the payment path and
//! accepted by D44; keep [`Wallet`] values short-lived.

use crate::network::{EvmAddress20, NetworkConfig, NetworkId};
use crate::wallet::{WalletKey, WalletOpsError};

/// Upstream's EVM network selector, re-exported through the single
/// version-pin chain (`ant_core::data` ← `ant_protocol::evm` ← `evmlib`;
/// `ant-core-0.5.0/src/data/mod.rs:61-63`).
pub use ant_core::data::EvmNetwork;
/// Upstream's payment wallet (same re-export chain).
pub use ant_core::data::Wallet;

use ant_core::data::CustomNetwork;

/// Convert the pure-data config into upstream's [`EvmNetwork`].
///
/// - `arbitrum-one` → [`EvmNetwork::ArbitrumOne`], `arbitrum-sepolia` →
///   [`EvmNetwork::ArbitrumSepoliaTest`] — upstream's **built-in**
///   definitions (`evmlib-0.9.0/src/lib.rs:52-76`); the tests below pin
///   our transcribed constants byte-for-byte against them, so the pure
///   half cannot go stale without a red test.
/// - `devnet` → [`EvmNetwork::Custom`] built as a **struct literal** from
///   the run-scoped values. Deliberately not `CustomNetwork::new`, whose
///   parses `expect` (`evmlib-0.9.0/src/lib.rs:90-99`) — a malformed RPC
///   URL must surface as [`EvmConfigError::InvalidRpcUrl`], never a
///   panic.
///
/// # Errors
///
/// [`EvmConfigError::InvalidRpcUrl`] when the devnet RPC URL does not
/// parse.
pub fn to_evm_network(config: &NetworkConfig) -> Result<EvmNetwork, EvmConfigError> {
    match config.id {
        NetworkId::ArbitrumOne => Ok(EvmNetwork::ArbitrumOne),
        NetworkId::ArbitrumSepolia => Ok(EvmNetwork::ArbitrumSepoliaTest),
        NetworkId::Devnet => {
            let rpc_url_http: url::Url = config
                .rpc_url
                .parse()
                .map_err(|_| EvmConfigError::InvalidRpcUrl { network: config.id })?;
            Ok(EvmNetwork::Custom(CustomNetwork {
                rpc_url_http,
                payment_token_address: evm_address(config.payment_token),
                payment_vault_address: evm_address(config.payment_vault),
            }))
        }
    }
}

/// Our 20-byte address into alloy's (via the ant-core re-export chain).
fn evm_address(address: EvmAddress20) -> ant_core::data::EvmAddress {
    ant_core::data::EvmAddress::from(*address.as_bytes())
}

/// Network-config → EVM conversion failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EvmConfigError {
    /// The configured payment-RPC URL is not a valid URL. (Reachable only
    /// for `devnet`, whose URL is runtime data; the built-in networks
    /// carry compile-time-pinned URLs.)
    #[error("the {network} payment RPC URL is not a valid URL")]
    InvalidRpcUrl {
        /// Which network's config was rejected.
        network: NetworkId,
    },
}

// ---------------------------------------------------------------------------
// The one WalletKey operation that needs upstream
// ---------------------------------------------------------------------------

impl WalletKey {
    /// Build the payment [`Wallet`] for `config`'s network — what S6's
    /// `pay()` drives and what a devnet payment signs with (S17's E2E).
    ///
    /// The key's canonical hex spelling goes back into upstream through
    /// the very parse D44 names, so a key this crate accepted is a key the
    /// payment path accepts.
    ///
    /// # Errors
    ///
    /// [`WalletOpsError::Config`] when the config's network cannot
    /// convert (devnet with a malformed RPC URL);
    /// [`WalletOpsError::KeyRejectedByStack`] if upstream refuses a key
    /// this type already validated (an internal-invariant breach surfaced
    /// as an error, never a panic).
    pub fn evm_wallet(&self, config: &NetworkConfig) -> Result<Wallet, WalletOpsError> {
        let network = to_evm_network(config).map_err(WalletOpsError::Config)?;
        // Invariant: the light half's parse accepted this exact byte
        // string at construction.
        Wallet::new_from_private_key(network, self.hex_str())
            .map_err(|_| WalletOpsError::KeyRejectedByStack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{ARBITRUM_ONE_PAYMENT_TOKEN, ARBITRUM_ONE_PAYMENT_VAULT};
    use crate::network::{ARBITRUM_ONE_RPC_URL, ARBITRUM_SEPOLIA_RPC_URL, DevnetEnv};
    use crate::network::{ARBITRUM_SEPOLIA_PAYMENT_TOKEN, ARBITRUM_SEPOLIA_PAYMENT_VAULT};
    use crate::wallet::checksummed;
    use antseal_core::crypto::secrets::SecretBuf;
    use antseal_core::test_util::alternate_test_secret;

    /// secp256k1 group order n, big-endian hex — the smallest invalid
    /// scalar (public curve constant, not key material).
    const SECP256K1_ORDER: &str =
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    /// n − 1: the largest VALID scalar.
    const SECP256K1_ORDER_MINUS_ONE: &str =
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";

    fn buf(text: &str) -> SecretBuf {
        SecretBuf::new(text.as_bytes().to_vec())
    }

    /// Fixture key per the house convention (derived, never a fresh
    /// committed literal) — the same label the light half's suite uses, so
    /// both sides exercise the identical key.
    fn fixture_key_hex() -> String {
        let hex: String = alternate_test_secret(b"antseal-net/S5 wallet import fixture")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(
            WalletKey::import(&buf(&hex)).is_ok(),
            "fixture label derives an invalid scalar — pick another label"
        );
        hex
    }

    // ── network conversion: ours ≡ evmlib's built-ins ──────────────────

    #[test]
    fn builtin_networks_map_to_evmlib_variants_and_constants_agree() {
        // arbitrum-one / arbitrum-sepolia map to upstream's built-ins…
        let one = NetworkConfig::arbitrum_one();
        let sepolia = NetworkConfig::arbitrum_sepolia();
        assert_eq!(
            to_evm_network(&one).expect("built-in"),
            EvmNetwork::ArbitrumOne
        );
        assert_eq!(
            to_evm_network(&sepolia).expect("built-in"),
            EvmNetwork::ArbitrumSepoliaTest
        );

        // …and every transcribed constant equals the running evmlib's own
        // value, byte for byte — the test that makes the pure data half
        // unable to go stale (S5 accept: "config values traced to pinned
        // upstream sources").
        let up_one = EvmNetwork::ArbitrumOne;
        assert_eq!(
            up_one.payment_token_address().0.0,
            *one.payment_token.as_bytes()
        );
        assert_eq!(
            up_one.payment_vault_address().0.0,
            *one.payment_vault.as_bytes()
        );
        assert_eq!(up_one.rpc_url().as_str(), ARBITRUM_ONE_RPC_URL);
        assert_eq!(checksummed(one.payment_token), ARBITRUM_ONE_PAYMENT_TOKEN);
        assert_eq!(checksummed(one.payment_vault), ARBITRUM_ONE_PAYMENT_VAULT);

        let up_sepolia = EvmNetwork::ArbitrumSepoliaTest;
        assert_eq!(
            up_sepolia.payment_token_address().0.0,
            *sepolia.payment_token.as_bytes()
        );
        assert_eq!(
            up_sepolia.payment_vault_address().0.0,
            *sepolia.payment_vault.as_bytes()
        );
        assert_eq!(up_sepolia.rpc_url().as_str(), ARBITRUM_SEPOLIA_RPC_URL);
        assert_eq!(
            checksummed(sepolia.payment_token),
            ARBITRUM_SEPOLIA_PAYMENT_TOKEN
        );
        assert_eq!(
            checksummed(sepolia.payment_vault),
            ARBITRUM_SEPOLIA_PAYMENT_VAULT
        );
    }

    #[test]
    fn devnet_maps_to_custom_network_with_the_run_scoped_values() {
        let key = fixture_key_hex();
        let env_text = format!(
            "ANTSEAL_DEVNET_RPC_URL='http://127.0.0.1:39001/'\n\
             ANTSEAL_DEVNET_CHAIN_ID='31337'\n\
             ANTSEAL_DEVNET_TOKEN_ADDRESS='0x5FbDB2315678afecb367f032d93F642f64180aa3'\n\
             ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS='0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512'\n\
             ANTSEAL_DEVNET_WALLET_PRIVATE_KEY='{key}'\n\
             ANTSEAL_DEVNET_BOOTSTRAP='127.0.0.1:39002'\n\
             ANTSEAL_DEVNET_NODE_COUNT='5'\n\
             ANTSEAL_DEVNET_BASE_PORT='39002'\n\
             ANTSEAL_DEVNET_DATA_DIR='.devnet/data'\n\
             ANTSEAL_DEVNET_PID='4242'\n"
        );
        let env = DevnetEnv::from_env_file(&env_text).expect("fixture parses");
        let config = NetworkConfig::devnet(&env);
        let evm = to_evm_network(&config).expect("devnet converts");
        match evm {
            EvmNetwork::Custom(custom) => {
                assert_eq!(custom.rpc_url_http.as_str(), "http://127.0.0.1:39001/");
                assert_eq!(
                    custom.payment_token_address.0.0,
                    *config.payment_token.as_bytes()
                );
                assert_eq!(
                    custom.payment_vault_address.0.0,
                    *config.payment_vault.as_bytes()
                );
            }
            other => panic!("expected Custom, got {other:?}"),
        }

        // A malformed devnet RPC URL is a typed error, never a panic
        // (the CustomNetwork::new expect path is deliberately unused).
        let mut broken = config;
        broken.rpc_url = "not a url".into();
        assert_eq!(
            to_evm_network(&broken).expect_err("must reject"),
            EvmConfigError::InvalidRpcUrl {
                network: crate::network::NetworkId::Devnet
            }
        );

        // And the env's funded key imports + builds a wallet for the
        // devnet config (the offline half of "signs a devnet payment";
        // the live signature is S17's E2E).
        let wallet_key =
            WalletKey::import(env.wallet_private_key()).expect("funded dev key imports");
        let rebuilt = NetworkConfig::devnet(&env);
        let wallet = wallet_key.evm_wallet(&rebuilt).expect("wallet builds");
        assert_eq!(wallet.address().0.0, *wallet_key.address().as_bytes());
    }

    // ── the D89 drift guards ───────────────────────────────────────────

    #[test]
    fn import_acceptance_equals_the_pinned_stack_acceptance() {
        // D44's defining property, asserted directly: for every fixture in
        // both classes, our verdict ≡ Wallet::new_from_private_key's.
        let valid = [
            fixture_key_hex(),
            SECP256K1_ORDER_MINUS_ONE.to_owned(),
            format!("0x{}", fixture_key_hex()),
            // `0X` + uppercase digits: const-hex strips `b'x' | b'X'`
            // (const-hex-1.19.1/src/lib.rs:702-707), so upstream accepts
            // this spelling too — asserted, not assumed.
            format!("0X{}", fixture_key_hex().to_uppercase()),
        ];
        let invalid = [
            "0".repeat(64),
            SECP256K1_ORDER.to_owned(),
            "f".repeat(64),
            "zz".repeat(32),
            "1234".to_owned(),
        ];
        for candidate in &valid {
            assert!(
                Wallet::new_from_private_key(EvmNetwork::ArbitrumOne, candidate).is_ok(),
                "upstream must accept"
            );
            assert!(WalletKey::import(&buf(candidate)).is_ok(), "we must accept");
        }
        for candidate in &invalid {
            assert!(
                Wallet::new_from_private_key(EvmNetwork::ArbitrumOne, candidate).is_err(),
                "upstream must reject"
            );
            assert!(
                WalletKey::import(&buf(candidate)).is_err(),
                "we must reject"
            );
        }
    }

    /// D89 §5: our address derivation ≡ alloy's, on the same keys — the
    /// half of the agreement story `import_acceptance…` does not cover
    /// (it compares *verdicts*, not derived addresses).
    #[test]
    fn address_derivation_equals_the_pinned_stack_derivation() {
        // The committed known answer, derived here through ALLOY: the two
        // suites now pin the same constant from opposite implementations.
        let one = format!("{}1", "0".repeat(63));
        let generator = Wallet::new_from_private_key(EvmNetwork::ArbitrumOne, &one)
            .expect("scalar 1 is valid upstream");
        assert_eq!(
            generator.address().to_string(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );

        // Fixture, boundary and freshly-generated keys all derive the same
        // address on both sides — and `checksummed` (ours) equals alloy's
        // own `Display`, which is the EIP-55 agreement assertion.
        let generated = WalletKey::generate().expect("OS CSPRNG available");
        let mut candidates = vec![fixture_key_hex(), SECP256K1_ORDER_MINUS_ONE.to_owned(), one];
        candidates.push(
            core::str::from_utf8(generated.as_hex().as_bytes())
                .expect("canonical hex is ASCII")
                .to_owned(),
        );
        for candidate in &candidates {
            let ours = WalletKey::import(&buf(candidate)).expect("we accept");
            let theirs = Wallet::new_from_private_key(EvmNetwork::ArbitrumOne, candidate)
                .expect("upstream accepts");
            assert_eq!(
                *ours.address().as_bytes(),
                theirs.address().0.0,
                "address bytes must agree"
            );
            assert_eq!(
                checksummed(ours.address()),
                theirs.address().to_string(),
                "EIP-55 rendering must agree with alloy's Display"
            );
        }
    }

    /// A freshly generated key is accepted by the payment stack — the
    /// property `generate()`'s own default-lane test cannot state, because
    /// upstream is not in that graph.
    #[test]
    fn generated_keys_are_accepted_by_the_pinned_stack() {
        for _ in 0..4 {
            let key = WalletKey::generate().expect("OS CSPRNG available");
            let hex = core::str::from_utf8(key.as_hex().as_bytes()).expect("canonical hex");
            let wallet = Wallet::new_from_private_key(EvmNetwork::ArbitrumOne, hex)
                .expect("a generated key must be spendable");
            assert_eq!(wallet.address().0.0, *key.address().as_bytes());
        }
    }
}
