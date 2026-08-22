//! The wallet **light half** — secp256k1 keygen, D44 import validation,
//! address derivation and EIP-55 rendering, in the **default** feature set
//! (decision [D89], 2026-08-02).
//!
//! # Why this is not in `evm.rs`
//!
//! Everything here used to live inside the `ant-backend`-gated
//! `crate::evm`, which made `init`'s entire UX surface — the wizard, the
//! D44 rejection classes, the funding copy, the `--json` fixture —
//! `#[cfg]`-inactive in a default build. Inactive code is not compiled, not
//! type-checked and not linted, and **no required CI context and no local
//! tier trigger builds that feature for these files**, so four of U11's six
//! Accept rows would have been asserted by nothing. D89 Evidence 3 measures
//! that gap; this module is its remedy. The nine packages it costs the
//! default graph (120 → 129) are enumerated, already in `Cargo.lock`, and
//! add **zero** to the 447/475 heavy graphs.
//!
//! # D44 acceptance, still by construction — not a second implementation
//!
//! D44 defines the accepted import set **extensionally**: "whatever the
//! pinned evmlib/alloy parse accepts". Traced in vendored source, that parse
//! is:
//!
//! ```text
//! evmlib::Wallet::new_from_private_key            (evmlib-0.9.0/src/wallet.rs:71-75)
//!   -> <PrivateKeySigner as FromStr>::from_str    (alloy-signer-local-1.8.3/src/private_key.rs:224-230)
//!        hex::decode_to_array::<_, 32>            — optional 0x, case-insensitive, exactly 64 digits
//!   -> LocalSigner::from_slice                    (private_key.rs:52-54)
//!   -> ecdsa::SigningKey::from_slice              (ecdsa-0.16.9/src/signing.rs:99-103)
//!   -> k256::SecretKey::from_slice                — rejects zero and >= the group order
//! ```
//!
//! [`WalletKey::import`] calls that **same bottom function on the same
//! locked version** ([`Cargo.lock`] records `alloy-signer-local`'s
//! dependency as a bare `"k256"` entry — the lock's own statement that
//! exactly one k256 exists; `dep-graph` rule 5 keeps it that way). The hex
//! layer around it was always ours: the structural pre-checks below exist
//! only to *name* the failure class in a typed error, exactly as they did
//! when they sat above the alloy call. So this is one indirection removed
//! from a two-layer arrangement, not a fork of the accepted set — and lane
//! δ's `import_acceptance_equals_the_pinned_stack_acceptance` (in
//! `crate::evm`'s gated test module) is retained unchanged as the
//! executable drift guard between the two.
//!
//! # Key-material hygiene (project rule 6)
//!
//! Key bytes live in [`SecretBuf`] (zeroize-on-drop) from the moment they
//! exist; every intermediate raw buffer is wiped explicitly; [`WalletKey`]'s
//! `Debug` is redacted, it has no `Display`, no `Clone`, and no error in
//! this module ever echoes input material.
//!
//! **[D159 §2 R2, 2026-08-22]** `crate::evm` is named here as a plain code
//! span and NOT as an intra-doc link: this module is ungated while `evm` is
//! behind the non-default `ant-backend` feature (`lib.rs:95-96`), so a
//! default-feature `cargo doc` resolved the link against a module that is
//! not there — six such warnings across this file and `network.rs`.
//! `crate::ant_backend`'s own docs keep the link form, because that module is
//! only ever rendered with the feature on. Nothing mechanical enforces this;
//! the doc build that would is armed at first publication (D159 §2 R6).
//!
//! [D89]: ../../../docs/decisions/D89-wallet-primitives-below-the-gate.md

use antseal_core::crypto::secrets::SecretBuf;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

use crate::network::EvmAddress20;

/// Retry budget for OS-CSPRNG keygen. A draw is rejected only when it is
/// zero or ≥ the secp256k1 group order (probability < 2⁻¹²⁸ per draw);
/// the budget exists so a broken entropy source becomes a typed error
/// instead of a spin.
const GENERATE_ATTEMPTS: u32 = 64;

/// Length of a raw secp256k1 scalar in bytes.
const SCALAR_LEN: usize = 32;

/// Length of the canonical at-rest hex form.
const HEX_LEN: usize = SCALAR_LEN * 2;

/// A validated EVM wallet private key, held as **64 lowercase hex ASCII
/// bytes** inside a zeroizing buffer.
///
/// The hex-string form is the canonical at-rest shape on purpose: it is
/// exactly what D44 accepts, exactly what the vault stores (U10), and
/// exactly what upstream's `Wallet::new_from_private_key` consumes — so the
/// payment path re-enters upstream through the same spelling that was
/// validated here.
///
/// No `Clone` (copies of key material don't multiply silently), no
/// `Display`, redacted `Debug`.
pub struct WalletKey {
    /// Invariant: exactly 64 ASCII lowercase hex digits, accepted by
    /// `k256::SecretKey::from_slice` at construction time.
    hex: SecretBuf,
}

impl WalletKey {
    /// Generate a fresh key from the **OS CSPRNG** (`getrandom` 0.4.3 — the
    /// project's own pinned generation, D89 §2), validated through the same
    /// acceptance gate an import passes (D44: generation and import share
    /// one gate).
    ///
    /// # Errors
    ///
    /// [`WalletOpsError::EntropySource`] if the OS RNG fails;
    /// [`WalletOpsError::KeyGenerationFailed`] if no draw passed the
    /// scalar check within the retry budget (statistically unreachable —
    /// it means the entropy source is returning garbage).
    pub fn generate() -> Result<Self, WalletOpsError> {
        for _ in 0..GENERATE_ATTEMPTS {
            let mut raw = [0u8; SCALAR_LEN];
            if getrandom::fill(&mut raw).is_err() {
                raw.zeroize();
                return Err(WalletOpsError::EntropySource);
            }
            let hex = SecretBuf::new(lowercase_hex(&raw));
            raw.zeroize();
            // The one acceptance gate (D44), same call an import makes.
            if parse_scalar(&hex).is_ok() {
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
        if digits.len() != HEX_LEN {
            return Err(WalletImportError::WrongLength { got: digits.len() });
        }
        if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(WalletImportError::NotHex);
        }

        // Normalized zeroizing copy (single allocation, moved — no stray
        // intermediate survives).
        let hex = SecretBuf::new(digits.to_ascii_lowercase().into_bytes());

        // The acceptance gate (D44): structure is right, so the only
        // remaining refusal is the k256 scalar check — zero or ≥ the
        // group order.
        match parse_scalar(&hex) {
            Ok(_secret) => Ok(Self { hex }),
            Err(()) => Err(WalletImportError::InvalidScalar),
        }
    }

    /// Derive the wallet's EVM address: `keccak256(uncompressed public key
    /// without its 0x04 SEC1 tag)`, last 20 bytes — the Ethereum/EVM rule.
    ///
    /// Network-independent (the address is a pure function of the key);
    /// returned as the pure-data [`EvmAddress20`] so U's consent and
    /// display surfaces can hold it ([`checksummed`] pretty-prints it).
    ///
    /// Pinned by a committed known answer: scalar 1 ⇒ the address of the
    /// secp256k1 generator point (see this module's tests), which is the
    /// same value the feature-path test asserts against alloy.
    #[must_use]
    pub fn address(&self) -> EvmAddress20 {
        // Invariant-backed: construction proved the scalar parse accepts
        // this key, and the parse is deterministic; the fallback keeps
        // the function total without a panic path all the same.
        let Ok(secret) = parse_scalar(&self.hex) else {
            debug_assert!(
                false,
                "WalletKey invariant: the scalar parse accepted at construction"
            );
            return EvmAddress20::from_bytes([0u8; EvmAddress20::LEN]);
        };
        let point = secret.public_key().to_encoded_point(false);
        // SEC1 uncompressed encoding is 0x04 || X(32) || Y(32); the EVM
        // address hashes the 64 coordinate bytes, never the tag.
        let Some(coordinates) = point.as_bytes().get(1..1 + 2 * SCALAR_LEN) else {
            debug_assert!(false, "uncompressed SEC1 point is always 65 bytes");
            return EvmAddress20::from_bytes([0u8; EvmAddress20::LEN]);
        };
        let digest = Keccak256::digest(coordinates);
        let mut out = [0u8; EvmAddress20::LEN];
        out.copy_from_slice(&digest[digest.len() - EvmAddress20::LEN..]);
        EvmAddress20::from_bytes(out)
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
    /// ASCII). Crate-internal, and feature-gated because it has exactly
    /// one caller: `crate::evm`'s `evm_wallet`, which hands this
    /// spelling back to upstream. Nothing in the default graph needs a
    /// `&str` view of key material, and not offering one is the point.
    #[cfg(feature = "ant-backend")]
    pub(crate) fn hex_str(&self) -> &str {
        core::str::from_utf8(self.hex.as_bytes()).unwrap_or_default()
    }
}

impl core::fmt::Debug for WalletKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WalletKey(<redacted>)")
    }
}

/// EIP-55 checksummed rendering of an EVM address, for U11's display
/// surfaces. The pure-data [`EvmAddress20`] `Display` is plain lowercase
/// hex; this is the mixed-case form wallets and explorers show, and the
/// form that catches a mistyped address.
///
/// The rule (EIP-55): hash the 40 lowercase hex digits with Keccak-256;
/// digit *i* is uppercased iff it is a letter and nibble *i* of the hash is
/// ≥ 8.
///
/// Pinned by the three committed contract constants in
/// [`crate::network`], round-tripped in this module's tests and compared
/// against alloy's own `Display` on the feature path.
#[must_use]
pub fn checksummed(address: EvmAddress20) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut lower = [0u8; EvmAddress20::LEN * 2];
    for (index, byte) in address.as_bytes().iter().enumerate() {
        lower[index * 2] = DIGITS[usize::from(byte >> 4)];
        lower[index * 2 + 1] = DIGITS[usize::from(byte & 0x0F)];
    }
    let hash = Keccak256::digest(lower);
    let mut out = String::with_capacity(2 + lower.len());
    out.push_str("0x");
    for (index, &digit) in lower.iter().enumerate() {
        // Nibble `index` of the hash, high nibble first.
        let nibble = if index % 2 == 0 {
            hash[index / 2] >> 4
        } else {
            hash[index / 2] & 0x0F
        };
        if digit.is_ascii_alphabetic() && nibble >= 8 {
            out.push(char::from(digit.to_ascii_uppercase()));
        } else {
            out.push(char::from(digit));
        }
    }
    out
}

/// Run a candidate hex string through the D44 acceptance gate — the same
/// `k256::SecretKey::from_slice` alloy's parse bottoms out in, and nothing
/// else. Unit-type error on purpose: this function must never learn to say
/// more than "yes" or "no" about key material.
fn parse_scalar(hex: &SecretBuf) -> Result<k256::SecretKey, ()> {
    let mut raw = decode_hex32(hex.as_bytes()).ok_or(())?;
    // Exactly 32 bytes: `from_slice`'s short-input zero-padding branch
    // (elliptic-curve-0.13.8/src/secret_key.rs:161-173) is unreachable
    // from here, so this is byte-for-byte the call alloy makes after its
    // own `decode_to_array::<_, 32>`.
    let parsed = k256::SecretKey::from_slice(&raw).map_err(|_| ());
    raw.zeroize();
    parsed
}

/// Decode exactly 64 lowercase-or-uppercase hex ASCII bytes into 32 raw
/// bytes. `None` for any other length or a non-hex digit. The returned
/// array is key material — the caller wipes it.
fn decode_hex32(hex: &[u8]) -> Option<[u8; SCALAR_LEN]> {
    if hex.len() != HEX_LEN {
        return None;
    }
    let mut out = [0u8; SCALAR_LEN];
    for (index, byte) in out.iter_mut().enumerate() {
        let high = (hex[index * 2] as char).to_digit(16)?;
        let low = (hex[index * 2 + 1] as char).to_digit(16)?;
        *byte = ((high << 4) | low) as u8;
    }
    Some(out)
}

/// Lowercase-hex encode 32 raw bytes into a fresh Vec (single allocation;
/// the caller wraps it in [`SecretBuf`] and wipes the source).
fn lowercase_hex(bytes: &[u8; SCALAR_LEN]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(HEX_LEN);
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
    /// Structurally valid hex whose value is not a secp256k1 scalar: zero,
    /// or ≥ the group order (k256's own check, D44).
    #[error("not a valid secp256k1 private key (zero or out of range)")]
    InvalidScalar,
}

/// Wallet-operation failures outside the import classes.
///
/// The two upstream-dependent arms are `ant-backend`-gated: they can only
/// be produced by [`WalletKey::evm_wallet`], which lives in
/// `crate::evm`. Keeping them on **one** error type rather than splitting
/// it means the gate never changes an error's name or its `Display` string
/// — the deviation-in-mechanism D89's "the non-config arms of
/// `WalletOpsError`" allows for, recorded here rather than left implicit.
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
    #[cfg(feature = "ant-backend")]
    #[error("network configuration rejected: {0}")]
    Config(#[from] crate::evm::EvmConfigError),
    /// The pinned stack refused a key this type already validated —
    /// an internal-invariant breach surfaced as an error (never a panic).
    #[cfg(feature = "ant-backend")]
    #[error("the payment stack rejected an already-validated key (internal invariant breach)")]
    KeyRejectedByStack,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{
        ARBITRUM_ONE_PAYMENT_TOKEN, ARBITRUM_ONE_PAYMENT_VAULT, ARBITRUM_SEPOLIA_PAYMENT_TOKEN,
        ARBITRUM_SEPOLIA_PAYMENT_VAULT,
    };
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

    // ── D44 import classes (moved below the gate by D89) ───────────────

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
        assert_eq!(reference.as_hex().as_bytes().len(), HEX_LEN);
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
        // order − 1 is valid. This is the whole boundary set the gated
        // suite asserts, now asserted in the DEFAULT lane too (D89 §5).
        let zero = "0".repeat(HEX_LEN);
        assert_eq!(
            WalletKey::import(&buf(&zero)).expect_err("zero scalar"),
            WalletImportError::InvalidScalar
        );
        assert_eq!(
            WalletKey::import(&buf(SECP256K1_ORDER)).expect_err("order"),
            WalletImportError::InvalidScalar
        );
        assert_eq!(
            WalletKey::import(&buf(&"f".repeat(HEX_LEN))).expect_err("all-ff"),
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

    // ── keygen + address derivation ────────────────────────────────────

    #[test]
    fn generated_keys_are_valid_distinct_and_derive_consistent_addresses() {
        let first = WalletKey::generate().expect("OS CSPRNG available");
        let second = WalletKey::generate().expect("OS CSPRNG available");

        // Canonical shape.
        assert_eq!(first.as_hex().as_bytes().len(), HEX_LEN);
        assert!(
            first
                .as_hex()
                .as_bytes()
                .iter()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        // Two draws are distinct (a collision means the RNG is broken).
        assert_ne!(first.as_hex().as_bytes(), second.as_hex().as_bytes());

        // A generated key re-imports to the same key and the same address.
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
        // a real wallet. This is the SAME known answer the feature-path
        // suite asserts against alloy's derivation (evm.rs), which is what
        // makes the two implementations comparable byte-for-byte.
        let one = format!("{}1", "0".repeat(HEX_LEN - 1));
        let key = WalletKey::import(&buf(&one)).expect("scalar 1 is valid");
        assert_eq!(
            checksummed(key.address()),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
        // …and the plain lowercase Display is the same 20 bytes.
        assert_eq!(
            key.address().to_string(),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn eip55_rendering_round_trips_the_committed_contract_constants() {
        // Three already-committed checksummed constants, transcribed from
        // evmlib and asserted byte-for-byte against upstream's `Display`
        // on the feature path — so the ungated renderer inherits three
        // known-answer vectors in the DEFAULT lane for free (D89 §4).
        for constant in [
            ARBITRUM_ONE_PAYMENT_TOKEN,
            ARBITRUM_ONE_PAYMENT_VAULT,
            ARBITRUM_SEPOLIA_PAYMENT_TOKEN,
            ARBITRUM_SEPOLIA_PAYMENT_VAULT,
        ] {
            let parsed = EvmAddress20::parse(constant).expect("committed constant parses");
            assert_eq!(checksummed(parsed), constant, "EIP-55 round trip");
            // The all-lowercase spelling checksums back to the same
            // mixed-case form — the property EIP-55 actually states.
            let lowercased =
                EvmAddress20::parse(&constant.to_lowercase()).expect("lowercase parses");
            assert_eq!(checksummed(lowercased), constant);
        }
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

    #[test]
    fn hex_decoder_rejects_everything_that_is_not_64_hex_digits() {
        // The decoder under `parse_scalar` is total and never panics on
        // adversarial input (project rule: no panics on malformed input).
        assert!(decode_hex32(b"").is_none());
        assert!(decode_hex32(&[b'a'; HEX_LEN - 1]).is_none());
        assert!(decode_hex32(&[b'a'; HEX_LEN + 1]).is_none());
        assert!(decode_hex32(&[0xFF; HEX_LEN]).is_none());
        assert_eq!(decode_hex32(&[b'0'; HEX_LEN]), Some([0u8; SCALAR_LEN]));
        // Mixed case decodes identically (import lowercases first, but the
        // decoder must not depend on that).
        assert_eq!(
            decode_hex32(b"AbCdEf0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"),
            decode_hex32(b"abcdef0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
        );
    }
}
