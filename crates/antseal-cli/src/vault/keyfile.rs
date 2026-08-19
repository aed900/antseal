//! The optional keyfile wrap for the vault key (U8; D50 wrap-mode 1).
//!
//! MVP-SPEC.md line 143: the vault "offers a high-entropy keyfile /
//! OS-keystore wrap for `W`". D50 re-scoped that to **the keyfile alone at
//! M1**, with mode 2 (OS keystore) format-reserved and refused distinctly,
//! and with **zero new dependencies** — the whole mechanism below is
//! `getrandom` (already present) plus the `hkdf`/`sha2` pair the wallet
//! sub-key already uses.
//!
//! # The combination, and why it is a KDF rather than a XOR
//!
//! ```text
//! kdf_key   = Argon2id|scrypt(passphrase, salt)          // unchanged, U6
//! vault_key = HKDF-SHA256(salt = keyfile_bytes,
//!                         ikm  = kdf_key,
//!                         info = WRAP_INFO)              // 32 bytes
//! ```
//!
//! Both factors are required and neither is recoverable from the vault:
//! HKDF-Extract over an unknown 32-byte salt leaves an attacker holding
//! the passphrase with no shortcut, and an attacker holding the keyfile
//! still faces the full Argon2id cost. A XOR would have been cheaper and
//! wrong — it makes the two factors *additively* related, so a leak of the
//! final key plus either factor discloses the other.
//!
//! The keyfile is **32 bytes of OS CSPRNG output**, not a passphrase: it
//! is a key, so it gets full entropy and no stretching. It is written with
//! owner-only permissions where the OS supports them.
//!
//! # Finding the keyfile at unlock, and the leak that choice costs
//!
//! An unlock has to locate the file before it can derive anything, and the
//! canonical CLI surface has no `--keyfile` flag to carry it (U1's frozen
//! surface; adding one is a deliberate decision, not an implementation
//! detail). The path therefore comes from, in order:
//!
//! 1. an explicit argument (the in-process API, and what the tests use);
//! 2. the `ANTSEAL_KEYFILE` environment variable — **a path, never a
//!    secret**, which is exactly the rule `ANTSEAL_DIR` already follows,
//!    and is untouched by D41's rejection of env-carried *secrets* (that
//!    record's whole argument was `/proc/PID/environ` retaining secret
//!    bytes; a path retains nothing worth having);
//! 3. the path recorded in the vault header, if the vault recorded one.
//!
//! Recording the path in the header is a deliberate trade, stated plainly:
//! it means anyone who reaches the vault directory learns **where** the
//! keyfile is kept. That is a real disclosure and it buys two things. The
//! header is bound as AAD into every vault record, so an attacker cannot
//! silently *redirect* the lookup at a keyfile they control — editing the
//! recorded path breaks authentication for the whole vault. And the wrap
//! stays usable: a factor a user must re-declare on every single
//! invocation is a factor they will turn off.
//!
//! The recording is **optional**. A vault may carry mode 1 with no
//! recorded path, in which case the path must arrive out of band and
//! nothing in the vault directory says where the second factor lives.

use std::path::{Path, PathBuf};

use rand_core::TryCryptoRng;
use zeroize::Zeroize;

use super::kdf::VaultKey;
use crate::error::CliError;

/// Keyfile length: 32 bytes of CSPRNG output — a key, not a passphrase.
pub const KEYFILE_LEN: usize = 32;

/// The environment variable naming the keyfile (a path, never a secret).
pub const KEYFILE_ENV: &str = "ANTSEAL_KEYFILE";

/// HKDF `info` for the wrap. Versioned into the string: a future schedule
/// mints a new label and never reuses this one (the domain-separation
/// discipline `WALLET_SUBKEY_INFO` follows).
const WRAP_INFO: &[u8] = b"antseal-cli vault v1: keyfile wrap";

/// Bounded read for a keyfile: exactly [`KEYFILE_LEN`] bytes are
/// expected, and the cap keeps a mistargeted path (a 4 GiB video) from
/// being slurped before it is rejected.
const MAX_KEYFILE_READ_BYTES: usize = 1024;

/// The 32 keyfile bytes, under the same narrow scope as
/// [`WalletKeyHandle`](super::wallet::WalletKeyHandle): no `Clone`, no
/// `Display`, redacted `Debug`, wiped on drop.
pub struct KeyfileSecret([u8; KEYFILE_LEN]);

impl KeyfileSecret {
    /// Wrap exactly 32 secret bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEYFILE_LEN]) -> Self {
        KeyfileSecret(bytes)
    }
}

impl std::fmt::Debug for KeyfileSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyfileSecret(<redacted>)")
    }
}

impl Drop for KeyfileSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// What wrap a vault is being created with (D39's `--wrap` selector,
/// D50's registry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapChoice {
    /// Mode 0: passphrase only (the default; D39 says the offer defaults
    /// to declined).
    None,
    /// Mode 1: generate a keyfile at `path` and require it at every
    /// unlock. `record_path` decides whether the vault header remembers
    /// where it is — see the module docs on that trade.
    Keyfile {
        /// Where the generated keyfile is written.
        path: PathBuf,
        /// Record the path in the header (convenience) or not (nothing in
        /// the vault directory says where the second factor lives).
        record_path: bool,
    },
}

impl WrapChoice {
    /// The D50 wrap-mode id this choice writes into the header.
    #[must_use]
    pub const fn mode(&self) -> u8 {
        match self {
            WrapChoice::None => super::header::WRAP_MODE_NONE,
            WrapChoice::Keyfile { .. } => super::header::WRAP_MODE_KEYFILE,
        }
    }
}

/// Generate a keyfile and write it to `path`.
///
/// **Refuses to overwrite.** A keyfile that replaces an existing file
/// could be replacing another vault's only second factor, which would
/// brick that vault permanently — the same class of irreversibility D39
/// made the existing-vault refusal absolute for.
///
/// # Errors
///
/// [`CliError::Usage`] when the path already exists; [`CliError::Io`] for
/// a failed create/write; [`CliError::Internal`] if the OS CSPRNG fails.
pub fn generate<R: TryCryptoRng + ?Sized>(
    path: &Path,
    rng: &mut R,
) -> Result<KeyfileSecret, CliError> {
    if path.exists() {
        return Err(CliError::Usage {
            message: format!(
                "{} already exists — antseal will not overwrite it. If that file is another \
                 vault's keyfile, replacing it would make that vault permanently \
                 unopenable. Choose a different path",
                path.display()
            ),
        });
    }
    let mut bytes = [0u8; KEYFILE_LEN];
    rng.try_fill_bytes(&mut bytes)
        .map_err(|_| CliError::Internal {
            detail: "the OS CSPRNG failed while generating a vault keyfile".to_owned(),
        })?;

    let write = || -> std::io::Result<()> {
        use std::io::Write as _;

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            // Owner-only from the moment it exists: a 0644 window would
            // publish the second factor to every local account.
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()
    };
    if let Err(source) = write() {
        bytes.zeroize();
        return Err(CliError::Io {
            context: format!("writing the vault keyfile {}", path.display()),
            source,
        });
    }
    let secret = KeyfileSecret::from_bytes(bytes);
    bytes.zeroize();
    Ok(secret)
}

/// Read a keyfile back.
///
/// # Errors
///
/// [`CliError::VaultKeyfileMissing`] when the file is absent, unreadable,
/// or not exactly [`KEYFILE_LEN`] bytes — **one distinct class**, never
/// the generic vault-auth failure (U8 Accept). A user whose USB stick is
/// unplugged must be told that, not told their passphrase is wrong.
pub fn read_from(path: &Path) -> Result<KeyfileSecret, CliError> {
    let bytes = super::session::read_bounded(path, MAX_KEYFILE_READ_BYTES).map_err(|source| {
        CliError::VaultKeyfileMissing {
            path: path.to_path_buf(),
            detail: source.to_string(),
        }
    })?;
    let mut bytes = bytes;
    let arr: [u8; KEYFILE_LEN] = match bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let len = bytes.len();
            bytes.zeroize();
            return Err(CliError::VaultKeyfileMissing {
                path: path.to_path_buf(),
                detail: format!(
                    "expected exactly {KEYFILE_LEN} bytes, found {len} — this is not an \
                     antseal keyfile"
                ),
            });
        }
    };
    bytes.zeroize();
    Ok(KeyfileSecret::from_bytes(arr))
}

/// Where this unlock should look for the keyfile: explicit argument, then
/// [`KEYFILE_ENV`], then whatever the header recorded (module docs).
///
/// Returns `None` when none of the three supplies a path — the caller
/// turns that into the distinct missing-keyfile error, naming all three
/// channels.
#[must_use]
pub fn locate(explicit: Option<&Path>, recorded: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_path_buf());
    }
    if let Some(value) = std::env::var_os(KEYFILE_ENV)
        && !value.is_empty()
    {
        return Some(PathBuf::from(value));
    }
    recorded.map(Path::to_path_buf)
}

/// Combine the passphrase-derived key with the keyfile (module docs).
///
/// # Errors
///
/// [`CliError::Internal`] on HKDF-Expand failure — structurally
/// unreachable for a fixed 32-byte output, kept total rather than
/// panicking, and never degraded into a silent all-zero key.
pub fn combine(base: &VaultKey, keyfile: &KeyfileSecret) -> Result<VaultKey, CliError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(&keyfile.0), base.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(WRAP_INFO, &mut okm)
        .map_err(|_| CliError::Internal {
            detail: "HKDF-Expand failed for the fixed-length keyfile wrap".to_owned(),
        })?;
    let key = VaultKey::from_bytes(okm);
    okm.zeroize();
    Ok(key)
}

/// The placement guidance `init` prints when a keyfile wrap is chosen.
/// Docs own the long form (Q24); this is the minimum a user needs at the
/// moment the file is created.
///
/// **It names no command, deliberately (U84 / D151 §2 R7).** This text is
/// printed only to a keyfile user, and `vault export` refuses a
/// keyfile-wrapped vault ([`crate::vault::export`], the overturned-U8
/// section), so any sentence here about the export would be advice that
/// cannot be followed. The vault-level instruction is
/// [`crate::vault::bookkeeping::BACKUP_BY_HAND`], eleven lines below on
/// the same screen; this says only what is true of the **keyfile**.
#[must_use]
pub fn placement_guidance(path: &Path) -> Vec<String> {
    vec![
        format!("Keyfile written to {}.", path.display()),
        "  This file is now REQUIRED alongside your passphrase at every unlock. Lose it and \
         the vault is gone — exactly as if you had lost the passphrase."
            .to_owned(),
        "  Keep it on different media from the vault: a USB stick, a second machine, a \
         password manager's file attachment. Keeping it in your home directory beside \
         `~/.antseal/` protects against nothing, because anything that reaches one reaches \
         the other."
            .to_owned(),
        format!(
            "  Back it up separately too: a copy of the keyfile, on different media from the \
             vault, is the second half of this vault's backup. Override its location for a \
             single run with {KEYFILE_ENV}=<path>."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "antseal-keyfile-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::create_dir_all(&root).expect("mk dir");
            Self(root)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_generated_keyfile_is_32_bytes_owner_only_and_never_overwritten() {
        let dir = Dir::new("gen");
        let path = dir.0.join("vault.key");
        let secret = generate(&path, &mut ChaCha20Rng::from_seed([0x31; 32])).expect("generated");
        let bytes = std::fs::read(&path).expect("read back");
        assert_eq!(bytes.len(), KEYFILE_LEN);
        assert_eq!(&bytes[..], &secret.0[..]);
        assert_ne!(bytes, vec![0u8; KEYFILE_LEN], "not all zeroes");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "owner-only from creation");
        }

        // Refuses to overwrite: the file might be another vault's only
        // second factor.
        let err =
            generate(&path, &mut ChaCha20Rng::from_seed([0x32; 32])).expect_err("never overwrites");
        assert_eq!(err.class(), crate::error::ErrorClass::Usage);
        assert!(err.to_string().contains("already exists"), "{err}");
        // …and the original bytes are untouched.
        assert_eq!(std::fs::read(&path).expect("read"), bytes);
    }

    #[test]
    fn a_missing_or_wrong_sized_keyfile_is_its_own_class_not_an_auth_failure() {
        let dir = Dir::new("read");
        let missing = dir.0.join("nope.key");
        let err = read_from(&missing).expect_err("absent");
        assert_eq!(err.class(), crate::error::ErrorClass::VaultKeyfileMissing);
        assert_ne!(err.class(), crate::error::ErrorClass::VaultAuthFailure);
        assert!(err.to_string().contains("nope.key"), "{err}");

        let short = dir.0.join("short.key");
        std::fs::write(&short, b"too short").expect("write");
        let err = read_from(&short).expect_err("wrong length");
        assert_eq!(err.class(), crate::error::ErrorClass::VaultKeyfileMissing);
        assert!(err.to_string().contains("not an antseal keyfile"), "{err}");
    }

    #[test]
    fn the_wrap_binds_both_factors_and_changes_with_either() {
        let base = VaultKey::from_bytes([0x11; 32]);
        let other_base = VaultKey::from_bytes([0x12; 32]);
        let k1 = KeyfileSecret::from_bytes([0x21; 32]);
        let k2 = KeyfileSecret::from_bytes([0x22; 32]);

        let a = combine(&base, &k1).expect("combine");
        let b = combine(&base, &k1).expect("combine");
        assert_eq!(a.as_bytes(), b.as_bytes(), "deterministic");

        // Either factor changing changes the result…
        assert_ne!(
            a.as_bytes(),
            combine(&base, &k2).expect("combine").as_bytes()
        );
        assert_ne!(
            a.as_bytes(),
            combine(&other_base, &k1).expect("combine").as_bytes()
        );
        // …and the wrapped key is not the passphrase-derived key.
        assert_ne!(a.as_bytes(), base.as_bytes());
    }

    #[test]
    fn locate_prefers_the_explicit_path_then_the_env_then_the_recording() {
        let explicit = PathBuf::from("/explicit/k");
        let recorded = PathBuf::from("/recorded/k");
        assert_eq!(
            locate(Some(&explicit), Some(&recorded)),
            Some(explicit.clone())
        );
        // No explicit, no env (the harness never sets it): the recording.
        assert_eq!(locate(None, Some(&recorded)), Some(recorded));
        assert_eq!(locate(None, None), None);
    }

    /// The guidance echoes the caller's path and the env override. What it
    /// must not do — promise anything about `antseal vault export` — is
    /// asserted where the command can actually be driven
    /// (`tests/vault_keyfile.rs::the_backup_advice_matches_what_export_actually_does`).
    ///
    /// **What used to be here, and why it could not fail (U84).** This test
    /// asserted `text.contains("does NOT contain the keyfile")` — the copy
    /// compared to its own words. It was green *because* the sentence
    /// existed, while `vault export` refused the very vaults this text is
    /// printed for. Do not reintroduce a check whose expected value is the
    /// string under test; the wording is pinned by U78's golden and the
    /// claim is pinned by behaviour.
    #[test]
    fn the_placement_guidance_echoes_the_path_and_the_env_override() {
        let text = placement_guidance(Path::new("/media/usb/vault.key")).join("\n");
        assert!(text.contains("/media/usb/vault.key"), "{text}");
        assert!(text.contains(KEYFILE_ENV), "{text}");
        assert!(!text.contains("antseal vault export"), "{text}");
    }

    /// The secret types stay redacted (project rule 6 / U21).
    #[test]
    fn debug_never_prints_key_bytes() {
        let secret = KeyfileSecret::from_bytes([0xAB; KEYFILE_LEN]);
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "KeyfileSecret(<redacted>)");
        assert!(!rendered.contains("ab"), "{rendered}");
    }
}
