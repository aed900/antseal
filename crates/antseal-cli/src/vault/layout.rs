//! Vault directory resolution and the structural beside/inside partition
//! (U5; partition normative per D42 — see the module docs of
//! [`crate::vault`]).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Directory name under the home directory (single-constant rule, U1
/// Notes: a pre-release rename edits exactly this line).
pub const VAULT_DIR_NAME: &str = ".antseal";

/// Environment override for the vault directory (a path, never a
/// secret — D41 rejects env for secrets only). House precedent: env is
/// the sanctioned non-flag channel (`RUST_LOG`), keeping the canonical
/// CLI surface closed.
pub const ENV_VAULT_DIR: &str = "ANTSEAL_DIR";

/// The **exhaustive** beside-the-AEAD set (D42): these three files are
/// readable/writable with no passphrase, and nothing may ever be added
/// here that is secret or per-work. Adding a variant is a
/// decision-register event, not a refactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BesideFile {
    /// `config.toml` — operator preferences (U4). Never secrets, never
    /// per-work data.
    Config,
    /// `vault.header` — format version, KDF block, wrap mode
    /// ([`crate::vault::header`]).
    Header,
    /// `vault.lock` — the single-writer lockfile
    /// ([`crate::vault::lock`]); contains no data.
    Lockfile,
}

impl BesideFile {
    /// The exact on-disk file name.
    #[must_use]
    pub fn file_name(self) -> &'static str {
        match self {
            BesideFile::Config => "config.toml",
            BesideFile::Header => "vault.header",
            BesideFile::Lockfile => "vault.lock",
        }
    }
}

/// Resolution failure: no override and no home directory.
#[derive(Debug, thiserror::Error)]
pub enum LayoutError {
    /// Neither `ANTSEAL_DIR` nor a home directory is available.
    #[error(
        "cannot locate the vault directory: no home directory is known to the OS and \
         ANTSEAL_DIR is not set"
    )]
    NoHome,
}

/// The resolved vault directory and its typed paths.
///
/// `VaultLayout` computes paths only — it never creates, reads, or writes
/// anything (`init`/U11 creates; callers go through
/// [`crate::vault::fs`]/[`crate::vault::lock`] for mutation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultLayout {
    root: PathBuf,
}

impl VaultLayout {
    /// Layout rooted at an explicit directory (tests, future flags).
    #[must_use]
    pub fn at(root: PathBuf) -> Self {
        VaultLayout { root }
    }

    /// Resolve from the real process environment: `ANTSEAL_DIR` if set
    /// (used verbatim), else `<home>/.antseal`.
    ///
    /// # Errors
    ///
    /// [`LayoutError::NoHome`] when neither source yields a directory.
    pub fn resolve() -> Result<Self, LayoutError> {
        Self::resolve_from(
            std::env::var_os(ENV_VAULT_DIR).as_deref(),
            std::env::home_dir(),
        )
    }

    /// Pure resolution core (deterministically testable; edition 2024
    /// makes `set_var` unsafe, so tests inject instead of mutating the
    /// environment).
    ///
    /// # Errors
    ///
    /// [`LayoutError::NoHome`] when `env_override` is `None`/empty and
    /// `home` is `None`.
    pub fn resolve_from(
        env_override: Option<&OsStr>,
        home: Option<PathBuf>,
    ) -> Result<Self, LayoutError> {
        if let Some(dir) = env_override
            && !dir.is_empty()
        {
            return Ok(VaultLayout {
                root: PathBuf::from(dir),
            });
        }
        let home = home.ok_or(LayoutError::NoHome)?;
        Ok(VaultLayout {
            root: home.join(VAULT_DIR_NAME),
        })
    }

    /// The vault directory itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path of one of the three beside-the-AEAD files (the closed D42
    /// set).
    #[must_use]
    pub fn beside_path(&self, file: BesideFile) -> PathBuf {
        self.root.join(file.file_name())
    }

    /// The inside-the-AEAD area: every byte under this directory is
    /// ciphertext under the vault key (U6/U9). No plaintext writer may
    /// target it.
    #[must_use]
    pub fn store_root(&self) -> PathBuf {
        self.root.join("store")
    }

    /// Per-work record area under the store (record shapes owned by U9).
    #[must_use]
    pub fn works_dir(&self) -> PathBuf {
        self.store_root().join("works")
    }

    /// The vault key-check record (`store/check`, U6): the AEAD over a
    /// fixed public marker that makes wrong-passphrase and tampered-header
    /// detection immediate and uniform at unlock.
    #[must_use]
    pub fn check_record_path(&self) -> PathBuf {
        self.store_root().join("check")
    }

    /// The wallet record slot under the store (own sub-key, U10).
    #[must_use]
    pub fn wallet_record_path(&self) -> PathBuf {
        self.store_root().join("wallet")
    }
}
