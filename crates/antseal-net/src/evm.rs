//! EVM-side operations over the pinned ant-core/evmlib/alloy stack
//! (task S5; feature **`ant-backend`** — never in the default graph).
//!
//! Two jobs live here:
//!
//! 1. **[`to_evm_network`]** — convert the pure-data
//!    [`NetworkConfig`](crate::NetworkConfig) into upstream's
//!    [`EvmNetwork`], the value `Client::with_wallet`/`with_evm_network`
//!    and every payment call consume.
//! 2. **[`WalletKey`]** — the EVM wallet key operations U's `init`
//!    consumes (U11): secp256k1 keygen from the OS CSPRNG, import
//!    validation per **D44**, and address derivation — all through the
//!    exact stack ant-core pays with, so a key this module accepts is a
//!    key the payment path accepts, *by construction*.
//!
//! # The D44 acceptance rule, implemented literally
//!
//! D44 defines the accepted import set **extensionally**: "whatever the
//! pinned evmlib/alloy parse accepts" — concretely
//! `Wallet::new_from_private_key` (`evmlib-0.9.0/src/wallet.rs:71-75`) →
//! alloy `PrivateKeySigner: FromStr`
//! (`alloy-signer-local-1.8.3/src/private_key.rs:224-230`:
//! `hex::decode_to_array::<_, 32>` — optional `0x`, case-insensitive,
//! exactly 64 hex digits — then k256 `SigningKey::from_slice`, which
//! rejects zero and ≥-group-order scalars). This module's structural
//! pre-checks exist only to *name* the failure class in a typed error
//! (wrong length vs non-hex vs invalid scalar vs mnemonic); the
//! **acceptance gate is the upstream parse itself** — nothing is ever
//! accepted that did not round-trip through it, so validation and payment
//! path cannot drift.
//!
//! # Key-material hygiene (project rule 6)
//!
//! Key bytes live in [`SecretBuf`] (zeroize-on-drop) from the moment they
//! exist; [`WalletKey`]'s `Debug` is redacted, it has no `Display`, no
//! `Clone`, and no error in this module ever echoes input material. The
//! one unavoidable exception is upstream's own types: a constructed
//! [`Wallet`] holds the signer in alloy's (non-zeroizing) structures for
//! the lifetime of the payment session — inherent to the payment path and
//! accepted by D44; keep [`Wallet`] values short-lived.

use antseal_core::crypto::secrets::SecretBuf;
use zeroize::Zeroize;

use crate::network::{EvmAddress20, NetworkConfig, NetworkId};

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

/// EIP-55 checksummed rendering of an EVM address (alloy's `Display`),
/// for U11's display surfaces. The pure-data
/// [`EvmAddress20`](crate::network::EvmAddress20) `Display` is plain
/// lowercase hex; this is the pretty form, available only where the
/// backend graph already is.
#[must_use]
pub fn checksummed(address: EvmAddress20) -> String {
    evm_address(address).to_string()
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
// WalletKey (U11's keygen / import / address surface)
// ---------------------------------------------------------------------------

/// Retry budget for OS-CSPRNG keygen. A draw is rejected only when it is
/// zero or ≥ the secp256k1 group order (probability < 2⁻¹²⁸ per draw);
/// the budget exists so a broken entropy source becomes a typed error
/// instead of a spin.
const GENERATE_ATTEMPTS: u32 = 64;

/// A validated EVM wallet private key, held as **64 lowercase hex ASCII
/// bytes** inside a zeroizing buffer.
///
/// The hex-string form is the canonical at-rest shape on purpose: it is
/// exactly what D44 accepts, exactly what the vault stores (U10), and
/// exactly what [`Wallet::new_from_private_key`] consumes — so every use
/// re-enters upstream through the same parse that validated it, and this
/// type never needs its own scalar arithmetic.
///
/// No `Clone` (copies of key material don't multiply silently), no
/// `Display`, redacted `Debug`.
pub struct WalletKey {
    /// Invariant: exactly 64 ASCII lowercase hex digits, accepted by the
    /// pinned upstream parse at construction time.
    hex: SecretBuf,
}

impl WalletKey {
    /// Generate a fresh key from the **OS CSPRNG** (`getrandom` 0.3 via the `getrandom03` alias, the OS
    /// entropy syscall surface), validated through the pinned upstream
    /// parse before it is ever returned (D44: generation and import share
    /// one acceptance gate).
    ///
    /// # Errors
    ///
    /// [`WalletOpsError::EntropySource`] if the OS RNG fails;
    /// [`WalletOpsError::KeyGenerationFailed`] if no draw passed the
    /// scalar check within the retry budget (statistically unreachable —
    /// it means the entropy source is returning garbage).
    pub fn generate() -> Result<Self, WalletOpsError> {
        for _ in 0..GENERATE_ATTEMPTS {
            let mut raw = [0u8; 32];
            if getrandom03::fill(&mut raw).is_err() {
                raw.zeroize();
                return Err(WalletOpsError::EntropySource);
            }
            let hex = SecretBuf::new(lowercase_hex(&raw));
            raw.zeroize();
            // The one acceptance gate (D44): the pinned upstream parse.
            if parse_through_pinned_stack(&hex).is_ok() {
                return Ok(Self { hex });
            }
            // Astronomically rare (zero or ≥ order): draw again. The
            // rejected buffer zeroizes on drop.
        }
        Err(WalletOpsError::KeyGenerationFailed)
    }

    /// Import a candidate key per **D44**: optional `0x`, 64 hex digits,
    /// either case, valid secp256k1 scalar — with one trailing LF/CRLF
    /// tolerated (the D41 fd-read channel's newline; idempotent with U's
    /// own strip). Everything else is a typed rejection.
    ///
    /// The input is borrowed; the normalized (lowercased, de-prefixed)
    /// copy this constructor builds is zeroizing from birth, and rejected
    /// copies zeroize on drop. The caller keeps responsibility for its
    /// own buffer (U11's channel hands a [`SecretBuf`]).
    ///
    /// # Errors
    ///
    /// [`WalletImportError`], one variant per D44 rejection class. No
    /// variant echoes any part of the input.
    pub fn import(candidate: &SecretBuf) -> Result<Self, WalletImportError> {
        let Ok(text) = core::str::from_utf8(candidate.as_bytes()) else {
            // Non-UTF-8 bytes cannot be hex digits.
            return Err(WalletImportError::NotHex);
        };
        // D41 channel tolerance: exactly one trailing newline.
        let text = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(text);

        if text.is_empty() {
            return Err(WalletImportError::WrongLength { got: 0 });
        }

        // Mnemonic detection before hex checks: multiple whitespace-
        // separated alphabetic words is a seed phrase, and D44 owes it a
        // distinct "not supported in this version" rejection (U11 owns
        // the user-facing copy).
        if text.split_whitespace().count() >= 2
            && text
                .split_whitespace()
                .all(|word| word.chars().all(|c| c.is_ascii_alphabetic()))
        {
            return Err(WalletImportError::MnemonicNotSupported);
        }
        // Any other whitespace (surrounding included) is not hex (D44's
        // "surrounding whitespace" rejection).
        if text.chars().any(char::is_whitespace) {
            return Err(WalletImportError::NotHex);
        }

        let digits = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(text);
        if digits.len() != 64 {
            return Err(WalletImportError::WrongLength { got: digits.len() });
        }
        if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(WalletImportError::NotHex);
        }

        // Normalized zeroizing copy (single allocation, moved — no stray
        // intermediate survives).
        let hex = SecretBuf::new(digits.to_ascii_lowercase().into_bytes());

        // The acceptance gate (D44): structure is right, so the only
        // remaining refusal upstream can issue is the k256 scalar check —
        // zero or ≥ the group order.
        match parse_through_pinned_stack(&hex) {
            Ok(()) => Ok(Self { hex }),
            Err(()) => Err(WalletImportError::InvalidScalar),
        }
    }

    /// Derive the wallet's EVM address through the pinned stack.
    ///
    /// Network-independent (the address is a pure function of the key);
    /// returned as the pure-data
    /// [`EvmAddress20`](crate::network::EvmAddress20) so U's consent and
    /// display surfaces can hold it without the backend graph
    /// ([`checksummed`] pretty-prints it where the graph is available).
    #[must_use]
    pub fn address(&self) -> EvmAddress20 {
        // Invariant-backed: construction proved the pinned parse accepts
        // this key, and the parse is deterministic; the fallback keeps
        // the function total without a panic path all the same.
        let Ok(wallet) = self.wallet_probe() else {
            debug_assert!(
                false,
                "WalletKey invariant: pinned parse accepted at construction"
            );
            return EvmAddress20::from_bytes([0u8; EvmAddress20::LEN]);
        };
        EvmAddress20::from_bytes(wallet.address().0.0)
    }

    /// Build the payment [`Wallet`] for `config`'s network — what S6's
    /// `pay()` drives and what a devnet payment signs with (S17's E2E).
    ///
    /// # Errors
    ///
    /// [`WalletOpsError::Config`] when the config's network cannot
    /// convert (devnet with a malformed RPC URL).
    pub fn evm_wallet(&self, config: &NetworkConfig) -> Result<Wallet, WalletOpsError> {
        let network = to_evm_network(config).map_err(WalletOpsError::Config)?;
        // Invariant: the parse accepted this exact byte string at
        // construction.
        Wallet::new_from_private_key(network, self.hex_str())
            .map_err(|_| WalletOpsError::KeyRejectedByStack)
    }

    /// The canonical at-rest form: 64 lowercase hex ASCII bytes, in the
    /// zeroizing buffer. This is what U10 persists in the vault — and
    /// being borrowed, the vault's copy is the vault's own zeroizing
    /// allocation.
    #[must_use]
    pub const fn as_hex(&self) -> &SecretBuf {
        &self.hex
    }

    /// Consume the key, handing the zeroizing buffer to the caller (the
    /// vault-storage move: no copy left behind).
    #[must_use]
    pub fn into_hex(self) -> SecretBuf {
        self.hex
    }

    /// &str view of the invariant-held hex (construction guarantees
    /// ASCII).
    fn hex_str(&self) -> &str {
        core::str::from_utf8(self.hex.as_bytes()).unwrap_or_default()
    }

    /// Probe wallet on a fixed network (network choice is irrelevant to
    /// key validity and address derivation — `from_private_key` never
    /// touches it: `evmlib-0.9.0/src/wallet.rs:242-248`).
    fn wallet_probe(&self) -> Result<Wallet, ()> {
        Wallet::new_from_private_key(EvmNetwork::ArbitrumOne, self.hex_str()).map_err(|_| ())
    }
}

impl core::fmt::Debug for WalletKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WalletKey(<redacted>)")
    }
}

/// Run a candidate hex string through the D44 acceptance gate — the
/// pinned upstream parse, nothing else. Unit type results on purpose:
/// upstream's error carries no detail (`Error::PrivateKeyInvalid`), and
/// this function must never learn to say more than "yes" or "no" about
/// key material.
fn parse_through_pinned_stack(hex: &SecretBuf) -> Result<(), ()> {
    let Ok(text) = core::str::from_utf8(hex.as_bytes()) else {
        return Err(());
    };
    Wallet::new_from_private_key(EvmNetwork::ArbitrumOne, text)
        .map(|_wallet| ())
        .map_err(|_| ())
}

/// Lowercase-hex encode 32 raw bytes into a fresh Vec (single allocation;
/// the caller wraps it in [`SecretBuf`] and wipes the source).
fn lowercase_hex(bytes: &[u8; 32]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(64);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)]);
        out.push(DIGITS[usize::from(byte & 0x0F)]);
    }
    out
}

/// Import rejection classes (D44's test set, one variant each). No
/// variant carries or echoes input material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WalletImportError {
    /// A seed phrase was pasted. Distinct by D44's ruling; the wording
    /// deliberately says *this version* — U11 owns the user-facing copy
    /// and must not claim forever.
    #[error(
        "mnemonic (seed-phrase) import is not supported in this version — export the account's raw \
         hex private key (64 hex digits) instead"
    )]
    MnemonicNotSupported,
    /// Not exactly 64 hex digits after the optional `0x`.
    #[error("a wallet private key is exactly 64 hex digits (optional 0x prefix); got {got}")]
    WrongLength {
        /// Digits found after prefix stripping (0 for empty input).
        got: usize,
    },
    /// A character outside `0-9a-fA-F` (surrounding whitespace included —
    /// the D41 channel already stripped the one legal trailing newline).
    #[error(
        "not a hex private key: contains a character outside 0-9a-fA-F (whitespace around the key \
         is not tolerated)"
    )]
    NotHex,
    /// Structurally valid hex whose value the pinned stack refuses: zero,
    /// or ≥ the secp256k1 group order (k256's scalar check, D44).
    #[error("not a valid secp256k1 private key (zero or out of range)")]
    InvalidScalar,
}

/// Wallet-operation failures outside the import classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WalletOpsError {
    /// The OS entropy source failed (`getrandom`).
    #[error("the OS random-number source failed; cannot generate a wallet key")]
    EntropySource,
    /// No CSPRNG draw passed the scalar check within the retry budget —
    /// statistically impossible with a working entropy source.
    #[error(
        "wallet key generation failed repeatedly; the system entropy source appears to be \
         returning invalid data"
    )]
    KeyGenerationFailed,
    /// The network config could not convert for wallet construction.
    #[error("network configuration rejected: {0}")]
    Config(#[from] EvmConfigError),
    /// The pinned stack refused a key this type already validated —
    /// an internal-invariant breach surfaced as an error (never a panic).
    #[error("the payment stack rejected an already-validated key (internal invariant breach)")]
    KeyRejectedByStack,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{ARBITRUM_ONE_PAYMENT_TOKEN, ARBITRUM_ONE_PAYMENT_VAULT};
    use crate::network::{ARBITRUM_ONE_RPC_URL, ARBITRUM_SEPOLIA_RPC_URL, DevnetEnv};
    use crate::network::{ARBITRUM_SEPOLIA_PAYMENT_TOKEN, ARBITRUM_SEPOLIA_PAYMENT_VAULT};
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
    /// committed literal). Checked valid once here: if a future label
    /// change ever derived an out-of-range scalar, this test names it.
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

    // ── D44 import classes ─────────────────────────────────────────────

    #[test]
    fn valid_keys_import_in_all_documented_spellings() {
        let bare = fixture_key_hex();
        let prefixed = format!("0x{bare}");
        let upper = format!("0X{}", bare.to_uppercase());
        let with_newline = format!("{bare}\n");
        let with_crlf = format!("0x{bare}\r\n");

        let reference = WalletKey::import(&buf(&bare)).expect("bare");
        for (label, spelling) in [
            ("0x-prefixed", &prefixed),
            ("uppercase", &upper),
            ("trailing LF", &with_newline),
            ("0x + trailing CRLF", &with_crlf),
        ] {
            let imported = WalletKey::import(&buf(spelling))
                .unwrap_or_else(|e| panic!("{label} must import: {e}"));
            // All spellings are the same key: same canonical form, same
            // address.
            assert_eq!(
                imported.as_hex().as_bytes(),
                reference.as_hex().as_bytes(),
                "{label} canonical form"
            );
            assert_eq!(imported.address(), reference.address(), "{label} address");
        }
        // Canonical form is lowercase, unprefixed, 64 bytes.
        assert_eq!(reference.as_hex().as_bytes().len(), 64);
        assert_eq!(reference.as_hex().as_bytes(), bare.as_bytes());
    }

    #[test]
    fn rejection_classes_are_distinct_and_typed() {
        let key = fixture_key_hex();

        // Wrong length: 63 and 65 digits, and empty.
        assert_eq!(
            WalletKey::import(&buf(&key[..63])).expect_err("63"),
            WalletImportError::WrongLength { got: 63 }
        );
        let long = format!("{key}0");
        assert_eq!(
            WalletKey::import(&buf(&long)).expect_err("65"),
            WalletImportError::WrongLength { got: 65 }
        );
        assert_eq!(
            WalletKey::import(&buf("")).expect_err("empty"),
            WalletImportError::WrongLength { got: 0 }
        );

        // Non-hex.
        let nonhex = format!("g{}", &key[1..]);
        assert_eq!(
            WalletKey::import(&buf(&nonhex)).expect_err("non-hex"),
            WalletImportError::NotHex
        );

        // Surrounding whitespace (D44: rejected; the one trailing newline
        // is the only tolerated decoration).
        let leading = format!(" {key}");
        assert_eq!(
            WalletKey::import(&buf(&leading)).expect_err("leading space"),
            WalletImportError::NotHex
        );
        let double_newline = format!("{key}\n\n");
        assert_eq!(
            WalletKey::import(&buf(&double_newline)).expect_err("two newlines"),
            WalletImportError::NotHex
        );

        // Scalar range: zero, the group order, all-FF — all InvalidScalar;
        // order − 1 is valid.
        let zero = "0".repeat(64);
        assert_eq!(
            WalletKey::import(&buf(&zero)).expect_err("zero scalar"),
            WalletImportError::InvalidScalar
        );
        assert_eq!(
            WalletKey::import(&buf(SECP256K1_ORDER)).expect_err("order"),
            WalletImportError::InvalidScalar
        );
        assert_eq!(
            WalletKey::import(&buf(&"f".repeat(64))).expect_err("all-ff"),
            WalletImportError::InvalidScalar
        );
        WalletKey::import(&buf(SECP256K1_ORDER_MINUS_ONE)).expect("order - 1 is valid");

        // Mnemonic: the distinct not-in-this-version rejection.
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon about";
        let err = WalletKey::import(&buf(mnemonic)).expect_err("mnemonic");
        assert_eq!(err, WalletImportError::MnemonicNotSupported);
        assert!(err.to_string().contains("this version"), "{err}");

        // Non-UTF-8 input folds into NotHex (bytes can't be hex digits).
        let invalid_utf8 = SecretBuf::new(vec![0xFF, 0xFE, 0x61, 0x62]);
        assert_eq!(
            WalletKey::import(&invalid_utf8).expect_err("non-utf8"),
            WalletImportError::NotHex
        );
    }

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

    // ── keygen + address derivation ────────────────────────────────────

    #[test]
    fn generated_keys_are_valid_distinct_and_derive_consistent_addresses() {
        let first = WalletKey::generate().expect("OS CSPRNG available");
        let second = WalletKey::generate().expect("OS CSPRNG available");

        // Canonical shape.
        assert_eq!(first.as_hex().as_bytes().len(), 64);
        assert!(
            first
                .as_hex()
                .as_bytes()
                .iter()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        // Two draws are distinct (a collision means the RNG is broken).
        assert_ne!(first.as_hex().as_bytes(), second.as_hex().as_bytes());

        // A generated key re-imports to the same key and the same
        // address (S5 accept: "a generated key derives a valid address").
        let reimported = WalletKey::import(first.as_hex()).expect("round-trips");
        assert_eq!(reimported.address(), first.address());

        // Address shape + checksummed rendering agree on the bytes.
        let address = first.address();
        let pretty = checksummed(address);
        assert!(pretty.starts_with("0x") && pretty.len() == 42);
        assert_eq!(pretty.to_lowercase(), address.to_string());
    }

    #[test]
    fn known_scalar_derives_the_known_address() {
        // Scalar 1 ⇒ the address of the secp256k1 generator point G — a
        // public curve constant, universally documented, unmistakably not
        // a real wallet (committed under the fixture convention as a
        // derived-from-nothing value). Pinned against the stack at
        // landing; S17's devnet payment is the live cross-check.
        let one = format!("{}1", "0".repeat(63));
        let key = WalletKey::import(&buf(&one)).expect("scalar 1 is valid");
        assert_eq!(
            checksummed(key.address()),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
    }

    #[test]
    fn debug_and_errors_never_leak_key_material() {
        let key_hex = fixture_key_hex();
        let key = WalletKey::import(&buf(&key_hex)).expect("valid");
        let debug = format!("{key:?}");
        assert_eq!(debug, "WalletKey(<redacted>)");
        assert!(!debug.contains(&key_hex));

        // Every import error's Display is free of the candidate bytes.
        for candidate in [key_hex.as_str(), "1234", "zzzz"] {
            if let Err(err) = WalletKey::import(&buf(candidate)) {
                let rendered = err.to_string();
                assert!(
                    !rendered.contains(candidate),
                    "error echoed input: {rendered}"
                );
            }
        }
    }
}
