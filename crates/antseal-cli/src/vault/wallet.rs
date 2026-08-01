//! The Arbitrum wallet-key record (U10): the 32 secret wallet-key bytes,
//! stored at `store/wallet` under a **dedicated sub-key** of the vault
//! key, separately from every work record.
//!
//! # Why a sub-key (spec line 143: "wallet key lives inside the encrypted
//! vault but under its own sub-key")
//!
//! ```text
//! wallet_subkey = HKDF-SHA256(salt = "", ikm = vault key,
//!                             info = WALLET_SUBKEY_INFO)      // 32 bytes
//! blob          = nonce ‖ AEAD_{wallet_subkey}(key bytes,
//!                             AAD = header ‖ [1])             // cipher.rs
//! ```
//!
//! The sub-key decouples the wallet's blast radius from the work records:
//! the two domains share no AEAD key, so corruption or (hypothetical)
//! compromise of one record class says nothing about the other, and a
//! future external-signer build deletes this record and the derivation
//! without touching any work record's schedule. This is the **one
//! recorded exception** to U6's single-vault-key schedule (see
//! `vault/kdf.rs` module docs, "key schedule").
//!
//! Both defenses of the splice matrix apply independently: a wallet blob
//! moved into a work slot fails on the AAD identity *and* on the key; a
//! work blob moved into the wallet slot likewise. The unit tests below
//! prove the key half in isolation (same identity, main key vs sub-key).
//!
//! # The narrow accessor and the validation seam (rustdoc contract)
//!
//! [`WalletKeyHandle`] is the *entire* surface other code sees: no
//! `Clone`, no `Display`, redacted `Debug`, zeroize-on-drop, and exactly
//! one byte accessor, [`WalletKeyHandle::secret_bytes`]. For M1 the
//! "sign-capable handle" IS this raw-bytes-under-narrow-scope accessor —
//! the seal pipeline's pay path (S6/S8, behind `antseal-net`'s
//! `ant-backend` feature) consumes the bytes to construct the evmlib
//! wallet at spend time. **No evmlib/ant-core dependency enters
//! `antseal-cli` for this** (containment, D34/P15): type-level validation
//! that the bytes are a usable secp256k1 scalar happens (a) at `init`
//! against the pinned evmlib parse — U11, next wave, behind the feature
//! on the S side — and (b) at seal time in the backend adapter. This
//! module stores and returns 32 opaque secret bytes, full stop.

use std::io::ErrorKind;

use rand_core::TryCryptoRng;
use zeroize::Zeroize;

use super::cipher::{RecordIdentity, open_record, seal_record};
use super::fs::atomic_write;
use super::session::{UnlockedVault, read_bounded};
use crate::error::CliError;

/// HKDF-Expand `info` label for the wallet sub-key. Versioned into the
/// string: a future schedule change mints a new label, never reuses this
/// one (domain-separation discipline).
pub(crate) const WALLET_SUBKEY_INFO: &[u8] = b"antseal-cli vault v1: wallet record sub-key";

/// Length of the stored wallet secret (a secp256k1 private-key scalar).
pub const WALLET_KEY_LEN: usize = 32;

/// Bounded-read cap for the wallet record file (a real blob is
/// nonce + 32 + tag = 72 bytes; the cap is defensive slack, D10 style).
const MAX_WALLET_RECORD_BYTES: usize = 4096;

/// The 32 wallet-key bytes, held under the narrowest possible scope: no
/// `Clone`, no `Display`, `Debug` redacts, memory wiped on drop. See the
/// module docs for the validation seam this type deliberately does NOT
/// implement.
pub struct WalletKeyHandle([u8; WALLET_KEY_LEN]);

impl WalletKeyHandle {
    /// Wrap exactly 32 secret bytes (length enforced by the type).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; WALLET_KEY_LEN]) -> Self {
        WalletKeyHandle(bytes)
    }

    /// The raw secret bytes — the minimum accessor the M1 pay path needs
    /// (module docs). Callers must not copy these into non-zeroizing
    /// storage; the U21 harness scans for exactly that class of leak.
    #[must_use]
    pub const fn secret_bytes(&self) -> &[u8; WALLET_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for WalletKeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WalletKeyHandle(<redacted>)")
    }
}

impl Drop for WalletKeyHandle {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Encrypt and durably store the wallet key record (atomic write; the
/// caller holds the U5 vault lock for mutation, as with every store
/// write).
///
/// # Errors
///
/// Cipher/RNG failures via [`CliError`]; I/O errors from the atomic
/// write.
pub fn store_wallet_key<R: TryCryptoRng + ?Sized>(
    vault: &UnlockedVault,
    key: &WalletKeyHandle,
    rng: &mut R,
) -> Result<(), CliError> {
    let subkey = vault.wallet_subkey()?;
    let blob = seal_record(
        &subkey,
        vault.header_bytes(),
        RecordIdentity::Wallet,
        key.secret_bytes(),
        rng,
    )?;
    let path = vault.layout().wallet_record_path();
    atomic_write(&path, &blob).map_err(|source| CliError::Io {
        context: format!("writing {}", path.display()),
        source,
    })
}

/// Load the wallet key record; `Ok(None)` when no wallet has been stored
/// (a state — a vault created but not yet `init`-completed — not an
/// error).
///
/// # Errors
///
/// [`CliError::VaultAuthFailure`] for tamper, splice, corruption, or an
/// authenticated record of impossible length; I/O errors otherwise.
pub fn load_wallet_key(vault: &UnlockedVault) -> Result<Option<WalletKeyHandle>, CliError> {
    let path = vault.layout().wallet_record_path();
    let blob = match read_bounded(&path, MAX_WALLET_RECORD_BYTES) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(CliError::Io {
                context: format!("reading {}", path.display()),
                source,
            });
        }
    };
    let subkey = vault.wallet_subkey()?;
    let plaintext = open_record(&subkey, vault.header_bytes(), RecordIdentity::Wallet, &blob)?;
    let bytes: [u8; WALLET_KEY_LEN] = plaintext.as_bytes().try_into().map_err(
        |_| // An authenticated record of the wrong length is a corrupt
                // store (same collapse as store.rs's Corrupt class).
                CliError::VaultAuthFailure,
    )?;
    // `plaintext` (SecretBuf) wipes on drop; `bytes` moves into the
    // handle, which wipes on ITS drop.
    Ok(Some(WalletKeyHandle::from_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::kdf::KdfSelection;
    use crate::vault::layout::VaultLayout;
    use crate::vault::session::create_vault;
    use antseal_core::crypto::secrets::SecretBuf;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    /// Fixed, public, NON-SECRET fixtures (project rule 6).
    const TEST_RNG_SEED: [u8; 32] = [0x42u8; 32];
    const FIXTURE_KEY: [u8; 32] = [0x77u8; 32];

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "antseal-cli-wallet-{tag}-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("create test dir");
            TestDir(dir)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The sub-key is not the vault key, and the separation is the KEY,
    /// not merely the AAD identity: a blob sealed under the MAIN vault
    /// key with the very same `Wallet` identity fails to open on the
    /// sub-key path. (The integration suite proves the file-level splice
    /// directions; this pins the key half in isolation, which only a
    /// crate-internal test can reach.)
    #[test]
    fn wallet_record_opens_only_under_the_sub_key() {
        let dir = TestDir::new("subkey-only");
        let layout = VaultLayout::at(dir.0.join("vault"));
        let mut rng = ChaCha20Rng::from_seed(TEST_RNG_SEED);
        let vault = create_vault(
            &layout,
            &SecretBuf::new(b"correct horse battery staple fixture".to_vec()),
            KdfSelection::Argon2id,
            &mut rng,
        )
        .expect("create");

        // Forge the exact record shape under the WRONG (main) key.
        let forged = vault
            .seal_record(RecordIdentity::Wallet, &FIXTURE_KEY, &mut rng)
            .expect("seal under main key");
        atomic_write(&vault.layout().wallet_record_path(), &forged).expect("install forgery");
        assert!(matches!(
            load_wallet_key(&vault).expect_err("main-key blob must fail on the sub-key path"),
            CliError::VaultAuthFailure
        ));

        // And the genuine path works where the forgery failed.
        store_wallet_key(&vault, &WalletKeyHandle::from_bytes(FIXTURE_KEY), &mut rng)
            .expect("store");
        let loaded = load_wallet_key(&vault).expect("load").expect("present");
        assert_eq!(loaded.secret_bytes(), &FIXTURE_KEY);
    }

    /// The derivation is deterministic per vault (same unlock → same
    /// sub-key) and label-bound (documented constant; changing it orphans
    /// every stored wallet record — this test is the tripwire).
    #[test]
    fn subkey_is_deterministic_and_label_bound() {
        let dir = TestDir::new("determinism");
        let layout = VaultLayout::at(dir.0.join("vault"));
        let mut rng = ChaCha20Rng::from_seed(TEST_RNG_SEED);
        let vault = create_vault(
            &layout,
            &SecretBuf::new(b"correct horse battery staple fixture".to_vec()),
            KdfSelection::Argon2id,
            &mut rng,
        )
        .expect("create");
        let a = vault.wallet_subkey().expect("derive");
        let b = vault.wallet_subkey().expect("derive again");
        assert_eq!(a.as_bytes(), b.as_bytes(), "deterministic per vault");
        assert_eq!(
            WALLET_SUBKEY_INFO, b"antseal-cli vault v1: wallet record sub-key",
            "label is frozen: changing it orphans every stored wallet record"
        );
    }

    /// The handle's Debug is redacted and the module exposes no Display
    /// (the narrow-accessor Accept; the end-to-end sentinel scan is
    /// U21's).
    #[test]
    fn handle_debug_redacts() {
        let handle = WalletKeyHandle::from_bytes(FIXTURE_KEY);
        let rendered = format!("{handle:?}");
        assert_eq!(rendered, "WalletKeyHandle(<redacted>)");
        assert!(!rendered.contains("77"), "no key byte in Debug");
    }
}
