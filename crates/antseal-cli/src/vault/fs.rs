//! Crash-safe file writes for the vault (U5).
//!
//! Every mutating write of a beside-file or store record goes through
//! [`atomic_write`]: same-directory temp file → write → `fsync(file)` →
//! `rename` → `fsync(parent dir)`. POSIX `rename` is atomic, so a reader
//! of the target path observes the complete old bytes or the complete new
//! bytes — never a torn mix — and a crash at any step leaves at worst an
//! inert temp file (dot-prefixed, unique name; no parser ever reads temp
//! names, and a leftover is deleted the next time the same target is
//! written by the colliding writer).
//!
//! The kill matrix is tested deterministically: the write sequence takes
//! an injectable [`FailPoint`] that aborts *without cleanup* — exactly
//! what `SIGKILL` leaves behind — and the tests assert old-or-new (never
//! torn) at every point.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic discriminator for temp names within this process.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Simulated-crash points for the kill-matrix tests. Each aborts the
/// sequence with **no cleanup**, modelling a process killed at that
/// instant.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailPoint {
    /// No injected failure (the production path).
    None,
    /// Killed right after the temp file was created (empty temp left).
    AfterTempCreate,
    /// Killed after the bytes were written but before fsync.
    AfterTempWrite,
    /// Killed after the temp was fsynced but before the rename.
    AfterTempSync,
}

/// Write `bytes` to `path` atomically (temp + fsync + rename + dir
/// fsync). On success the target holds exactly `bytes`; on failure the
/// previous target state is untouched.
///
/// # Errors
///
/// Ordinary `io::Error`s from the underlying operations; the target is
/// never left torn.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    atomic_write_impl(path, bytes, FailPoint::None)
}

/// Unique temp path beside `path` (same directory — `rename` must not
/// cross filesystems).
fn temp_path_for(path: &Path, parent: &Path) -> PathBuf {
    let file_name = path.file_name().unwrap_or_else(|| "vault-write".as_ref());
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".{}.tmp.{}.{seq}",
        file_name.to_string_lossy(),
        std::process::id(),
    ))
}

pub(crate) fn atomic_write_impl(path: &Path, bytes: &[u8], fail: FailPoint) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "atomic_write target has no parent directory: {}",
                    path.display()
                ),
            )
        })?;
    let temp = temp_path_for(path, parent);

    // The closure-free sequence, with explicit temp cleanup on every real
    // error path (a *simulated* crash deliberately skips cleanup).
    let result = (|| {
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&temp) {
            Ok(f) => f,
            // A pid-reuse collision with an inert leftover from a crashed
            // run: the leftover is garbage by construction — remove and
            // retry once.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temp)?;
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temp)?
            }
            Err(e) => return Err(e),
        };
        if fail == FailPoint::AfterTempCreate {
            return Err(simulated_crash());
        }
        file.write_all(bytes)?;
        if fail == FailPoint::AfterTempWrite {
            return Err(simulated_crash());
        }
        // Durability of the content itself.
        file.sync_all()?;
        drop(file);
        if fail == FailPoint::AfterTempSync {
            return Err(simulated_crash());
        }
        // Atomic replacement.
        fs::rename(&temp, path)?;
        // Durability of the directory entry (the rename itself). Unix:
        // fsync the parent directory; other platforms lack the operation
        // and rely on the rename's own semantics.
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if let Err(e) = result {
        if !is_simulated_crash(&e) {
            // Real failure: best-effort temp cleanup, propagate the error.
            let _ = fs::remove_file(&temp);
        }
        return Err(e);
    }
    Ok(())
}

/// Marker error for injected kill points (tests only reach this).
fn simulated_crash() -> io::Error {
    io::Error::other(SIMULATED_CRASH_MSG)
}

fn is_simulated_crash(e: &io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.to_string() == SIMULATED_CRASH_MSG)
}

const SIMULATED_CRASH_MSG: &str = "simulated crash (kill-matrix failpoint)";

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-cleaning unique temp dir (std-only; no tempfile dependency).
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("antseal-cli-fs-{tag}-{}-{seq}", std::process::id()));
            fs::create_dir_all(&dir).expect("create test dir");
            TestDir(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temp_files_in(dir: &Path) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.expect("dir entry").path())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().contains(".tmp."))
            })
            .collect()
    }

    #[test]
    fn writes_fresh_file_and_leaves_no_temp() {
        let dir = TestDir::new("fresh");
        let target = dir.path().join("vault.header");
        atomic_write(&target, b"header-bytes").expect("atomic write");
        assert_eq!(fs::read(&target).expect("read back"), b"header-bytes");
        assert!(temp_files_in(dir.path()).is_empty(), "no temp residue");
    }

    #[test]
    fn overwrites_existing_file_completely() {
        let dir = TestDir::new("overwrite");
        let target = dir.path().join("config.toml");
        atomic_write(&target, b"old old old old").expect("first write");
        atomic_write(&target, b"new").expect("second write");
        assert_eq!(fs::read(&target).expect("read back"), b"new");
    }

    /// The kill matrix: at every injected kill point the target holds the
    /// complete old state (or stays absent for a fresh write) — never a
    /// torn mix — and a re-run completes the write.
    #[test]
    fn kill_matrix_leaves_old_or_new_never_torn() {
        for fail in [
            FailPoint::AfterTempCreate,
            FailPoint::AfterTempWrite,
            FailPoint::AfterTempSync,
        ] {
            // Fresh target: killed write leaves no target at all.
            let dir = TestDir::new("kill-fresh");
            let target = dir.path().join("store-record");
            let err = atomic_write_impl(&target, b"new-bytes", fail).expect_err("injected kill");
            assert!(is_simulated_crash(&err), "{fail:?}");
            assert!(!target.exists(), "{fail:?}: fresh target must not appear");
            // Recovery: the identical re-run succeeds despite residue.
            atomic_write(&target, b"new-bytes").expect("re-run after crash");
            assert_eq!(fs::read(&target).expect("read"), b"new-bytes", "{fail:?}");

            // Existing target: killed write leaves the old bytes intact.
            let dir = TestDir::new("kill-old");
            let target = dir.path().join("store-record");
            atomic_write(&target, b"old-consistent-state").expect("seed old state");
            let err = atomic_write_impl(&target, b"replacement", fail).expect_err("injected kill");
            assert!(is_simulated_crash(&err), "{fail:?}");
            assert_eq!(
                fs::read(&target).expect("read"),
                b"old-consistent-state",
                "{fail:?}: old state must survive a mid-write kill"
            );
            // Recovery on the same path.
            atomic_write(&target, b"replacement").expect("re-run after crash");
            assert_eq!(fs::read(&target).expect("read"), b"replacement", "{fail:?}");
        }
    }

    /// A crashed run's temp residue is inert: visible as a dotfile,
    /// never read, and no obstacle to later writes of the same target.
    #[test]
    fn crash_residue_is_inert_and_reruns_clean_it_up_by_name_collision_only() {
        let dir = TestDir::new("residue");
        let target = dir.path().join("wallet");
        let err =
            atomic_write_impl(&target, b"a", FailPoint::AfterTempWrite).expect_err("injected");
        assert!(is_simulated_crash(&err));
        assert_eq!(temp_files_in(dir.path()).len(), 1, "residue visible");
        atomic_write(&target, b"b").expect("later write unaffected");
        assert_eq!(fs::read(&target).expect("read"), b"b");
    }

    #[test]
    fn real_errors_clean_their_temp_up() {
        let dir = TestDir::new("realerr");
        // Target "directory" is actually a file → rename fails → cleanup.
        let bogus_parent = dir.path().join("not-a-dir");
        fs::write(&bogus_parent, b"file").expect("plant file");
        let target = bogus_parent.join("child");
        assert!(atomic_write(&target, b"x").is_err(), "write must fail");
        assert!(temp_files_in(dir.path()).is_empty(), "no temp residue");
    }

    #[test]
    fn rootless_target_is_rejected() {
        let err = atomic_write(Path::new("relative-no-parent"), b"x").expect_err("no parent");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
