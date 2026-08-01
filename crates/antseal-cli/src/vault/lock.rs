//! The single-writer vault lock (U5) — one of the three beside-the-AEAD
//! files (D42; it carries no data).
//!
//! # Protocol (unlink-free, kernel-arbitrated)
//!
//! [`VaultLock::acquire`] opens (creating if absent) `vault.lock` and
//! takes an **exclusive OS file lock** on it (`std::fs::File::try_lock`,
//! `flock`-backed on Linux). The lock, not the file's existence, is the
//! mutual exclusion:
//!
//! - **Stale-lock story:** the kernel releases the lock when the holding
//!   process exits *for any reason* (crash, `SIGKILL`, reboot), so a
//!   leftover `vault.lock` file from a dead process locks immediately —
//!   staleness cannot cause a false "held" verdict, and no heuristic pid
//!   liveness probe is needed. The pid written into the file is advisory
//!   only, for the error message.
//! - **Unlink-free:** the file is never deleted, by design. An
//!   unlink-and-recreate protocol has the classic race — holder A locks
//!   inode 1, B unlinks and recreates the path as inode 2, C locks
//!   inode 2, and two "holders" coexist. One immortal inode makes that
//!   impossible.
//! - Two handles in one process are two open file descriptions, so even
//!   a same-process double-acquire is refused (probed on the pinned
//!   toolchain).
//!
//! Release is `Drop` (explicit unlock + close); a leaked handle is
//! released by the kernel at process exit.

use std::fs::{self, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::error::CliError;

/// Failure to acquire the vault lock.
#[derive(Debug, Error)]
pub enum LockError {
    /// Another live process holds the lock (the kernel says so; the pid
    /// is advisory, read from the lockfile for the message).
    #[error("the vault lock at {} is held by another process{}", lock_path.display(),
        holder_pid.map(|p| format!(" (pid {p})")).unwrap_or_default())]
    Held {
        lock_path: PathBuf,
        holder_pid: Option<u32>,
    },

    /// The lockfile could not be opened/locked/written for ordinary I/O
    /// reasons.
    #[error("vault lock I/O failure at {}: {source}", lock_path.display())]
    Io {
        lock_path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl From<LockError> for CliError {
    fn from(err: LockError) -> Self {
        match err {
            LockError::Held {
                lock_path,
                holder_pid,
            } => CliError::VaultLockHeld {
                lock_path,
                holder_pid,
            },
            LockError::Io { lock_path, source } => CliError::Io {
                context: format!("acquiring the vault lock at {}", lock_path.display()),
                source,
            },
        }
    }
}

/// An exclusive hold on the vault. Keep it alive for the whole mutating
/// command; release is `Drop`.
#[derive(Debug)]
pub struct VaultLock {
    file: std::fs::File,
    path: PathBuf,
}

impl VaultLock {
    /// Acquire the single-writer lock, failing fast when held.
    ///
    /// # Errors
    ///
    /// [`LockError::Held`] when another process holds it;
    /// [`LockError::Io`] for ordinary I/O failure (including a missing
    /// vault directory — creating the directory is `init`'s job, not the
    /// lock's).
    pub fn acquire(lock_path: &Path) -> Result<Self, LockError> {
        let io_err = |source| LockError::Io {
            lock_path: lock_path.to_owned(),
            source,
        };
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .map_err(io_err)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(LockError::Held {
                    lock_path: lock_path.to_owned(),
                    holder_pid: read_advisory_pid(lock_path),
                });
            }
            Err(TryLockError::Error(source)) => return Err(io_err(source)),
        }
        // We hold the lock: record our pid (advisory, for messages).
        file.set_len(0).map_err(io_err)?;
        file.write_all(format!("{}\n", std::process::id()).as_bytes())
            .map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
        Ok(VaultLock {
            file,
            path: lock_path.to_owned(),
        })
    }

    /// The lockfile path this hold covers.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        // Best-effort explicit unlock; closing the file releases it
        // regardless, and the kernel releases it on process death.
        let _ = self.file.unlock();
    }
}

/// Advisory holder pid from the lockfile contents (never trusted for
/// liveness — the kernel's lock verdict is the truth).
fn read_advisory_pid(lock_path: &Path) -> Option<u32> {
    fs::read_to_string(lock_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}
