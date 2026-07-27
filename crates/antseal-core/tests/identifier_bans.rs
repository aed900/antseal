//! Repo-wide identifier bans (task F7).
//!
//! MVP-SPEC.md line 75 names two distinct digests and forbids collapsing
//! them into one: `work_id` = SHA-256 of the manifest **body**, and
//! `anchor_digest` = SHA-256 of the **full encoded manifest, signatures
//! included**. They answer different questions — "which work is this?" versus
//! "what did the timestamp authority attest?" — and a codebase that calls
//! either one `manifest_hash` has already lost the distinction that keeps
//! anchors bound to the bytes they were computed over.
//!
//! So the identifier is banned outright, and this test is the enforcement:
//! it greps the tracked Rust sources rather than trusting review.

use std::fs;
use std::path::{Path, PathBuf};

/// The workspace root (this crate sits at `crates/antseal-core`).
const WORKSPACE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// Identifiers no source file may contain, with the reason each is banned.
const BANNED: &[(&str, &str)] = &[(
    "manifest_hash",
    "MVP-SPEC.md line 75 bans it: use `work_id` (body) or `anchor_digest` \
     (full manifest incl. signatures) — the two are not interchangeable",
)];

#[test]
fn no_source_file_uses_a_banned_identifier() {
    let mut offenders = Vec::new();
    let mut scanned = 0usize;

    for path in rust_sources(&Path::new(WORKSPACE_ROOT).join("crates")) {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("{}: cannot read source: {err}", path.display()));
        scanned += 1;

        // This file necessarily contains the banned strings (it defines
        // them); skip itself so the guard is not its own violation.
        if path.ends_with("identifier_bans.rs") {
            continue;
        }

        for (identifier, reason) in BANNED {
            for (number, line) in text.lines().enumerate() {
                // A prose mention explaining the ban is allowed; a real
                // identifier use is not. The distinction is crude but
                // sufficient: bare-word mentions in doc comments are prose.
                if line.contains(identifier) && !line.trim_start().starts_with("//") {
                    offenders.push(format!(
                        "{}:{}: `{identifier}` — {reason}",
                        path.display(),
                        number + 1
                    ));
                }
            }
        }
    }

    assert!(
        scanned > 0,
        "the source sweep found no files — the walk is broken, not the code clean"
    );
    assert!(
        offenders.is_empty(),
        "banned identifiers found in {} scanned files:\n  {}",
        scanned,
        offenders.join("\n  ")
    );
}

/// Every `.rs` file under `dir`, recursively (skipping `target/`).
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(err) => panic!("{}: cannot read directory: {err}", current.display()),
        };
        for entry in entries {
            let path = entry
                .unwrap_or_else(|err| panic!("{}: cannot read entry: {err}", current.display()))
                .path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}
