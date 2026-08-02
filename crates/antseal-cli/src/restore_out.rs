//! `restore`'s CLI half (U20): where the recovered files go, what happens
//! when something is already there, and how the run reports itself.
//!
//! Everything here implements `docs/decisions/D48-restore-output-policy.md`
//! §1–§6. S14's engine supplies verified bytes and per-file verification
//! outcomes; this module decides paths, compares, writes, renders, and
//! chooses the exit class. **Restore never prompts** (D48 §5): the
//! per-file byte-aware policy replaces the interactive "overwrite? y/n"
//! convention entirely.
//!
//! # Convergent, never destructive
//!
//! The three target states are decided by bytes, not by timestamps or by
//! asking:
//!
//! | target | behaviour | status |
//! | --- | --- | --- |
//! | absent | temp file + atomic rename | `restored` |
//! | byte-identical to what we would write | left alone, not even touched | `already-restored` |
//! | different | left alone; per-file error | `refused-overwrite` |
//!
//! So a re-run after a partial failure completes what is missing,
//! confirms what is done, and exits 0 — while a differing file is never
//! silently replaced. The comparison bytes are **exactly what restore
//! would write**: the raw-mirror rendition wherever a mirror exists, never
//! the canonical bytes (D48 §3, S14's raw-mirror preference).
//!
//! # Defensive re-rooting (D48 §2)
//!
//! A recorded path is lexically cleaned, stripped of any absolute root,
//! refused if a `..` component survives, and only then joined under the
//! output directory. The vault is self-authored, but a hand-edited or
//! bit-rotted record must degrade into a clean error rather than a write
//! outside `-o`. Every target is computed **before any write**, so two
//! recorded paths colliding on one target abort the run while the
//! directory is still untouched — there is no half-ordering that is both
//! deterministic and safe.
//!
//! One consequence is worth stating out loud: because §2 strips the
//! absolute root, `-o /` reproduces the recorded absolute paths at their
//! original locations. That is the supported, explicit "put my files
//! back" flow, still protected per file by the table above. The default
//! output directory never does it.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use antseal_net::StorageBackend;

use crate::error::CliError;
use crate::pipeline::restore::{
    ByteSource, FailureKind, FileOutcome, ManifestSource, RestoreEngine, RestoreReport, hex32,
};
use crate::vault::store::WorkStore;

/// Directory-name prefix of the default output directory (D48 §1).
pub const OUTPUT_DIR_PREFIX: &str = "antseal-restore-";

/// The default output directory for a work: `./antseal-restore-<work-id>/`
/// under the invocation cwd, `<work-id>` in D29's printed form.
///
/// Work-scoped by construction, so the default is collision-free across
/// works and a re-run of the *same* work lands in the *same* directory —
/// which is exactly what D48 §3's idempotency wants.
#[must_use]
pub fn default_output_dir(work_id: &[u8; 32]) -> PathBuf {
    PathBuf::from(format!("{OUTPUT_DIR_PREFIX}{}", hex32(work_id)))
}

/// What happened to one file. The five D48 §3 rows, plus the two failure
/// classes a run can hit on its way there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileStatus {
    /// Written (temp + rename).
    Restored,
    /// Already present and byte-identical: confirmed, not rewritten.
    AlreadyRestored,
    /// Could not be obtained from the network or a verified local copy.
    FetchFailed,
    /// The write itself failed (permissions, full disk, a directory in
    /// the way).
    WriteError,
    /// Present and different: **not touched**.
    RefusedOverwrite,
    /// A vault record could not drive a safe restore for this file.
    MalformedRecord,
    /// The bytes did not open their manifest commitment: never written.
    VerificationFailed,
}

impl FileStatus {
    /// Stable kebab identifier (`--json`, and the human report's first
    /// column).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Restored => "restored",
            Self::AlreadyRestored => "already-restored",
            Self::FetchFailed => "fetch-failed",
            Self::WriteError => "write-error",
            Self::RefusedOverwrite => "refused-overwrite",
            Self::MalformedRecord => "malformed-record",
            Self::VerificationFailed => "verification-failed",
        }
    }

    /// Whether this row is a success (D48 §3: a run exits 0 iff every
    /// file is `restored` or `already-restored`).
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Restored | Self::AlreadyRestored)
    }

    /// D48 §6's severity rank — **the** reason this enum derives `Ord`
    /// in this declaration order.
    ///
    /// The decision fixes three rungs: verification-failed (an evidence
    /// problem) > refused-overwrite (a local conflict, user-fixable) >
    /// fetch/network (transient). Two rungs it does not name are placed
    /// by the same logic: `malformed-record` sits just under
    /// verification-failed (a record problem is no more transient than an
    /// evidence one, but it is about the vault rather than the sealed
    /// content), and `write-error` sits between refused-overwrite and
    /// fetch — a local, non-transient obstruction that is still the
    /// user's to clear.
    #[must_use]
    pub const fn severity(self) -> u8 {
        self as u8
    }
}

/// One file's row in the run report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReport {
    /// Manifest file id.
    pub file_id: u64,
    /// The path as the vault recorded it.
    pub recorded_path: String,
    /// Where it was (or would have been) written, after §2's re-rooting.
    pub target: PathBuf,
    /// What happened.
    pub status: FileStatus,
    /// Why, for the non-obvious rows. Never secret material.
    pub detail: Option<String>,
    /// Byte length of the verified content, when there was any.
    pub bytes: Option<u64>,
    /// Which rendition the bytes are (raw-mirror where one exists).
    pub source: Option<ByteSource>,
}

/// What one `restore` invocation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutput {
    /// The work restored.
    pub work_id: [u8; 32],
    /// The output directory (default or `-o`).
    pub output_dir: PathBuf,
    /// Where the manifest came from — the one line that says whether the
    /// run really exercised the network.
    pub manifest_source: ManifestSource,
    /// One row per file, in `file_id` order.
    pub files: Vec<FileReport>,
}

impl RestoreOutput {
    /// The most severe non-success status present, or `None` when every
    /// file succeeded (D48 §6).
    #[must_use]
    pub fn most_severe(&self) -> Option<FileStatus> {
        self.files
            .iter()
            .map(|f| f.status)
            .filter(|s| !s.is_success())
            .max()
    }

    /// How many rows carry each status.
    #[must_use]
    pub fn counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for status in [
            FileStatus::Restored,
            FileStatus::AlreadyRestored,
            FileStatus::RefusedOverwrite,
            FileStatus::VerificationFailed,
            FileStatus::FetchFailed,
            FileStatus::MalformedRecord,
            FileStatus::WriteError,
        ] {
            counts.insert(status.name(), 0);
        }
        for file in &self.files {
            *counts.entry(file.status.name()).or_insert(0) += 1;
        }
        counts
    }

    /// The run's error, if any: D48 §6's severity-ordered class, carrying
    /// the count of files in that class. `None` means exit 0.
    #[must_use]
    pub fn into_error(&self) -> Option<CliError> {
        let worst = self.most_severe()?;
        let affected: Vec<&FileReport> = self.files.iter().filter(|f| f.status == worst).collect();
        let count = affected.len();
        let detail = affected
            .iter()
            .map(|f| {
                f.detail.as_ref().map_or_else(
                    || f.recorded_path.clone(),
                    |d| format!("{}: {d}", f.recorded_path),
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        Some(match worst {
            FileStatus::VerificationFailed => CliError::RestoreVerificationFailed {
                failed_files: count,
                detail,
            },
            FileStatus::MalformedRecord => CliError::MalformedRestoreRecord { detail },
            FileStatus::RefusedOverwrite => CliError::RefusedOverwrite {
                refused_files: count,
            },
            FileStatus::WriteError => CliError::Io {
                context: format!("writing restored file(s): {detail}"),
                source: std::io::Error::other("restore write failed"),
            },
            FileStatus::FetchFailed => CliError::NetworkFailure { detail },
            FileStatus::Restored | FileStatus::AlreadyRestored => unreachable!("filtered above"),
        })
    }

    /// The `--json` result document (U3's envelope wraps it).
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "work_id": hex32(&self.work_id),
            "output_dir": self.output_dir.display().to_string(),
            "manifest_source": self.manifest_source.name(),
            "files": self.files.iter().map(|f| serde_json::json!({
                "file_id": f.file_id,
                "recorded_path": f.recorded_path,
                "target": f.target.display().to_string(),
                "status": f.status.name(),
                "detail": f.detail,
                "bytes": f.bytes,
                "source": f.source.map(ByteSource::name),
            })).collect::<Vec<_>>(),
            "counts": self.counts(),
        })
    }

    /// The human report, as lines.
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let mut out = Vec::new();
        let restored = self.files.iter().filter(|f| f.status.is_success()).count();
        out.push(format!(
            "Restored {restored} of {} file(s) into {}",
            self.files.len(),
            self.output_dir.display()
        ));
        for file in &self.files {
            let mut line = format!(
                "  {:<19} {} -> {}",
                file.status.name(),
                file.recorded_path,
                file.target.display()
            );
            if let Some(bytes) = file.bytes {
                let rendition = match file.source {
                    Some(ByteSource::RawMirror) => " — exact original bytes",
                    _ => "",
                };
                line.push_str(&format!(" ({bytes} bytes{rendition})"));
            }
            out.push(line);
            if let Some(detail) = &file.detail {
                out.push(format!("      {detail}"));
            }
        }
        if self
            .files
            .iter()
            .any(|f| f.status == FileStatus::RefusedOverwrite)
        {
            out.push(
                "Files that differ from the sealed content were left exactly as they were — \
                 move them aside and re-run to write the sealed versions."
                    .to_owned(),
            );
        }
        out
    }
}

/// Resolve, fetch, verify and write one work — the whole `restore`
/// command minus argument parsing and the backend's construction.
///
/// # Errors
///
/// The whole-run classes: an unknown work id, a manifest that cannot be
/// resolved, a recorded path that cannot be safely re-rooted, an
/// intra-work target collision, or a failure to create the output
/// directory. Per-file failures are **rows**, not errors — D48 §3's
/// convergent re-run needs a run to get as far as it can.
pub async fn run_restore<B: StorageBackend>(
    backend: &B,
    store: &WorkStore<'_>,
    work_id: &str,
    output: Option<&Path>,
) -> Result<RestoreOutput, CliError> {
    let engine = RestoreEngine::new(backend, store);
    let seal_id = engine.resolve_work_id(work_id)?;
    let report = engine.restore(&seal_id).await?;
    let dir = output.map_or_else(|| default_output_dir(&report.work_id), Path::to_path_buf);
    write_verified(&report, &dir)
}

/// Apply D48 §2–§4 to a finished [`RestoreReport`]: compute every target,
/// refuse unsafe or colliding ones **before** touching the disk, then
/// write each file under the byte-aware policy.
///
/// # Errors
///
/// [`CliError::MalformedRestoreRecord`] for an unsafe recorded path or an
/// intra-work collision (both pre-write); [`CliError::Io`] when the output
/// directory cannot be created.
pub fn write_verified(
    report: &RestoreReport,
    output_dir: &Path,
) -> Result<RestoreOutput, CliError> {
    // ── §2: every target computed before any write ──
    let mut targets: Vec<PathBuf> = Vec::with_capacity(report.files.len());
    let mut seen: BTreeMap<PathBuf, String> = BTreeMap::new();
    for outcome in &report.files {
        let recorded = outcome.recorded_path();
        let target = reroot(output_dir, recorded)?;
        if let Some(first) = seen.get(&target) {
            return Err(CliError::MalformedRestoreRecord {
                detail: format!(
                    "two recorded paths ({first} and {recorded}) both restore to {} — refusing \
                     to write either",
                    target.display()
                ),
            });
        }
        seen.insert(target.clone(), recorded.to_owned());
        targets.push(target);
    }

    std::fs::create_dir_all(output_dir).map_err(|source| CliError::Io {
        context: format!(
            "creating the restore output directory {}",
            output_dir.display()
        ),
        source,
    })?;

    let mut files = Vec::with_capacity(report.files.len());
    for (index, outcome) in report.files.iter().enumerate() {
        let target = targets[index].clone();
        files.push(match outcome {
            FileOutcome::Failed(failed) => FileReport {
                file_id: failed.file_id,
                recorded_path: failed.recorded_path.clone(),
                target,
                status: match failed.error.kind() {
                    FailureKind::Fetch => FileStatus::FetchFailed,
                    FailureKind::MalformedRecord => FileStatus::MalformedRecord,
                    FailureKind::Verification => FileStatus::VerificationFailed,
                },
                detail: Some(failed.error.to_string()),
                bytes: None,
                source: None,
            },
            FileOutcome::Verified(verified) => {
                let (status, detail) = place(&target, &verified.bytes, index);
                FileReport {
                    file_id: verified.file_id,
                    recorded_path: verified.recorded_path.clone(),
                    target,
                    status,
                    detail,
                    bytes: Some(verified.bytes.len() as u64),
                    source: Some(verified.source),
                }
            }
        });
    }

    Ok(RestoreOutput {
        work_id: report.work_id,
        output_dir: output_dir.to_path_buf(),
        manifest_source: report.manifest_source,
        files,
    })
}

/// D48 §2's defensive lexical re-rooting.
///
/// Lexically clean (`.` and `//` collapse via component iteration), drop
/// any absolute-root or platform prefix, **reject** a surviving `..` or an
/// empty result, then join under `output_dir`.
///
/// # Errors
///
/// [`CliError::MalformedRestoreRecord`] — the distinct class D48 §2 names.
pub fn reroot(output_dir: &Path, recorded: &str) -> Result<PathBuf, CliError> {
    let malformed = |why: &str| CliError::MalformedRestoreRecord {
        detail: format!("the recorded path {recorded:?} {why}"),
    };
    if recorded.is_empty() {
        return Err(malformed("is empty"));
    }
    let mut relative = PathBuf::new();
    for component in Path::new(recorded).components() {
        match component {
            // Absolute roots and Windows prefixes are stripped: §2's
            // prefix rule is what makes `-o /` the explicit in-place
            // flow and everything else contained.
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                return Err(malformed(
                    "escapes the output directory with a `..` component",
                ));
            }
            Component::Normal(part) => relative.push(part),
        }
    }
    if relative.as_os_str().is_empty() {
        return Err(malformed("names no file once cleaned"));
    }
    Ok(output_dir.join(relative))
}

/// The per-file byte-aware policy (D48 §3) plus the write discipline
/// (§4). `index` only seeds a unique temp name.
fn place(target: &Path, bytes: &[u8], index: usize) -> (FileStatus, Option<String>) {
    match std::fs::metadata(target) {
        Ok(meta) if meta.is_dir() => {
            return (
                FileStatus::RefusedOverwrite,
                Some("a directory already exists at this path; it was not touched".to_owned()),
            );
        }
        Ok(_) => match std::fs::read(target) {
            Ok(existing) if existing == bytes => {
                return (FileStatus::AlreadyRestored, None);
            }
            Ok(_) => {
                return (
                    FileStatus::RefusedOverwrite,
                    Some(
                        "a different file already exists here and was left exactly as it was"
                            .to_owned(),
                    ),
                );
            }
            Err(err) => {
                // Unreadable but present: refusing is the conservative
                // reading of "exists, differs" — we cannot prove it is
                // the same, so we do not replace it.
                return (
                    FileStatus::RefusedOverwrite,
                    Some(format!(
                        "a file exists here and could not be read to compare it ({err}); it was \
                         left untouched"
                    )),
                );
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return (
                FileStatus::WriteError,
                Some(format!("could not inspect the target path: {err}")),
            );
        }
    }

    // ── §4: temp file + atomic rename, so a killed restore never leaves
    //    a partial file at a final path ──
    let Some(parent) = target.parent() else {
        return (
            FileStatus::WriteError,
            Some("the target path has no parent directory".to_owned()),
        );
    };
    if let Err(err) = std::fs::create_dir_all(parent) {
        return (
            FileStatus::WriteError,
            Some(format!("could not create {}: {err}", parent.display())),
        );
    }
    // The temp sits in the target's own directory — inside the output
    // tree, and guaranteed to be on the same filesystem as the target, so
    // the rename is atomic rather than a copy.
    let temp = parent.join(format!(
        ".{OUTPUT_DIR_PREFIX}tmp-{}-{index}",
        std::process::id()
    ));
    if let Err(err) = std::fs::write(&temp, bytes) {
        let _ = std::fs::remove_file(&temp);
        return (
            FileStatus::WriteError,
            Some(format!("could not write the restored bytes: {err}")),
        );
    }
    if let Err(err) = std::fs::rename(&temp, target) {
        let _ = std::fs::remove_file(&temp);
        return (
            FileStatus::WriteError,
            Some(format!("could not place the restored file: {err}")),
        );
    }
    (FileStatus::Restored, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_directory_is_work_scoped() {
        let dir = default_output_dir(&[0xAB; 32]);
        assert_eq!(
            dir,
            PathBuf::from(format!("antseal-restore-{}", "ab".repeat(32)))
        );
    }

    #[test]
    fn rerooting_cleans_strips_and_contains() {
        let out = Path::new("/out");
        assert_eq!(
            reroot(out, "notes.txt").expect("plain"),
            PathBuf::from("/out/notes.txt")
        );
        assert_eq!(
            reroot(out, "./a//b/./c.txt").expect("cleaned"),
            PathBuf::from("/out/a/b/c.txt")
        );
        assert_eq!(
            reroot(out, "/etc/passwd").expect("root stripped"),
            PathBuf::from("/out/etc/passwd")
        );
    }

    #[test]
    fn rerooting_refuses_escapes_and_empties() {
        let out = Path::new("/out");
        for bad in [
            "../escape.txt",
            "a/../../escape.txt",
            "/../escape",
            "",
            ".",
            "./",
        ] {
            let err = reroot(out, bad).expect_err(bad);
            assert_eq!(
                err.class(),
                crate::error::ErrorClass::MalformedRestoreRecord,
                "{bad}"
            );
        }
    }

    /// D48 §6's rank, asserted as data rather than as prose.
    #[test]
    fn severity_follows_the_decision() {
        assert!(FileStatus::VerificationFailed > FileStatus::MalformedRecord);
        assert!(FileStatus::MalformedRecord > FileStatus::RefusedOverwrite);
        assert!(FileStatus::RefusedOverwrite > FileStatus::WriteError);
        assert!(FileStatus::WriteError > FileStatus::FetchFailed);
        assert!(FileStatus::Restored.is_success());
        assert!(FileStatus::AlreadyRestored.is_success());
        for failing in [
            FileStatus::FetchFailed,
            FileStatus::WriteError,
            FileStatus::RefusedOverwrite,
            FileStatus::MalformedRecord,
            FileStatus::VerificationFailed,
        ] {
            assert!(!failing.is_success(), "{}", failing.name());
        }
    }
}
