//! The **freeze-manifest** format: model, parser and digest helper.
//!
//! One directive vocabulary, one parser, two consumers — the golden-vector
//! freeze (`vector_freeze.rs`, Q6) and the wire-registry freeze
//! (`format_freeze.rs`, Q50). Sharing it is not tidiness: a second
//! hand-written parser would be a second answer to "what does `#! status
//! frozen` mean", and the whole point of a freeze manifest is that the
//! answer is single. The tests-of-the-test for every malformed-construct
//! class live with the vector gate and cover this parser for both.
//!
//! A manifest is `sha256sum -c` compatible by design (`#` starts a comment
//! to GNU coreutils), so its digests can also be checked by a tool that
//! shares no code with antseal.
//!
//! What varies between consumers is only **which files may be frozen**,
//! carried as an [`EntryPolicy`]: the vector tree freezes `*.json` and
//! treats `README.md`, `*.py` generators and `INDEX.json` as auxiliaries;
//! the format registry freezes exactly its `.md` normative text and its
//! `.json` mirror.

#![allow(dead_code, reason = "each consumer uses a subset of the model")]

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

/// The manifest schema version this parser implements.
pub const MANIFEST_VERSION: u64 = 1;

/// Which files a given manifest is allowed to freeze.
///
/// The rule is a *policy*, not a constant, because the two consumers freeze
/// different things — but it is enforced identically for both, so a manifest
/// can never quietly reach outside its own domain.
pub struct EntryPolicy {
    /// Prefix a frozen entry's **file name** must carry, or `""` for none.
    /// The registry freeze uses it to admit `registry-v<n>.*` and nothing
    /// else, so a working document sitting in the same directory can never
    /// be frozen — otherwise editing a plan would read as a format event.
    pub required_name_prefix: &'static str,
    /// Path suffixes a frozen entry may have.
    pub allowed_suffixes: &'static [&'static str],
    /// Exact path names that are auxiliaries and must never be frozen.
    pub excluded_paths: &'static [&'static str],
    /// How the rejection message describes what this manifest freezes.
    pub subject: &'static str,
}

/// Lowercase-hex SHA-256, the form every manifest line carries.
#[must_use]
pub fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Freeze status of one format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Vectors may still be regenerated as a recorded, justified change.
    PreFreeze,
    /// Q14 has run: digests are permanent, additions only.
    Frozen,
}

/// A must-exist vector the version still owes.
#[derive(Debug, Clone)]
pub struct Pending {
    /// Stable slug naming the obligation.
    pub slug: String,
    /// Task id that must land it.
    pub task: String,
    /// What the vector must pin.
    pub what: String,
}

/// One frozen vector file.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Lowercase-hex SHA-256 of the file's exact bytes.
    pub digest: String,
    /// Path relative to the version directory, forward slashes.
    pub path: String,
}

/// A parsed `FROZEN.sha256`.
#[derive(Debug)]
pub struct Manifest {
    pub format_version: String,
    pub status: Status,
    pub freeze_gate: String,
    /// `kind name -> introducing task`.
    pub kinds: BTreeMap<String, String>,
    pub pending: Vec<Pending>,
    pub entries: Vec<Entry>,
}

/// Parse a manifest. Every malformed construct is an error — nothing is
/// tolerated, skipped, or defaulted.
#[expect(
    clippy::too_many_lines,
    reason = "one linear parser over one file format; splitting it would \
              scatter the directive vocabulary across helpers"
)]
pub fn parse_manifest(text: &str, origin: &str, policy: &EntryPolicy) -> Result<Manifest, String> {
    let mut manifest_version: Option<u64> = None;
    let mut format_version: Option<String> = None;
    let mut status: Option<Status> = None;
    let mut freeze_gate: Option<String> = None;
    let mut kinds: BTreeMap<String, String> = BTreeMap::new();
    let mut pending: Vec<Pending> = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();

    for (index, raw) in text.lines().enumerate() {
        let lineno = index + 1;
        let at = format!("{origin}:{lineno}");
        // Trailing whitespace would silently corrupt a path; reject it.
        if raw != raw.trim_end() {
            return Err(format!("{at}: trailing whitespace"));
        }
        if raw.is_empty() {
            continue;
        }
        if let Some(directive) = raw.strip_prefix("#!") {
            let directive = directive.trim();
            let (word, rest) = split_word(directive);
            match word {
                "manifest-version" => {
                    let value: u64 = rest
                        .parse()
                        .map_err(|_| format!("{at}: manifest-version must be an integer"))?;
                    set_once(&mut manifest_version, value, "manifest-version", &at)?;
                }
                "format-version" => {
                    require_nonempty(rest, "format-version", &at)?;
                    set_once(&mut format_version, rest.to_owned(), "format-version", &at)?;
                }
                "status" => {
                    let value = match rest {
                        "pre-freeze" => Status::PreFreeze,
                        "frozen" => Status::Frozen,
                        other => {
                            return Err(format!(
                                "{at}: status must be `pre-freeze` or `frozen`, got `{other}`"
                            ));
                        }
                    };
                    set_once(&mut status, value, "status", &at)?;
                }
                "freeze-gate" => {
                    require_nonempty(rest, "freeze-gate", &at)?;
                    set_once(&mut freeze_gate, rest.to_owned(), "freeze-gate", &at)?;
                }
                "kind" => {
                    let (name, since) = split_word(rest);
                    require_nonempty(name, "kind name", &at)?;
                    require_nonempty(since, "kind introducing task", &at)?;
                    if kinds.insert(name.to_owned(), since.to_owned()).is_some() {
                        return Err(format!("{at}: kind `{name}` declared twice"));
                    }
                }
                "pending" => {
                    let (slug, rest) = split_word(rest);
                    let (task, what) = split_word(rest);
                    require_nonempty(slug, "pending slug", &at)?;
                    require_nonempty(task, "pending owning task", &at)?;
                    require_nonempty(what, "pending description", &at)?;
                    if pending.iter().any(|p| p.slug == slug) {
                        return Err(format!("{at}: pending slug `{slug}` declared twice"));
                    }
                    pending.push(Pending {
                        slug: slug.to_owned(),
                        task: task.to_owned(),
                        what: what.to_owned(),
                    });
                }
                other => {
                    return Err(format!(
                        "{at}: unknown directive `#! {other}` — the vocabulary is \
                         manifest-version/format-version/status/freeze-gate/kind/pending \
                         (a typo must never be silently ignored)"
                    ));
                }
            }
            continue;
        }
        if raw.starts_with('#') {
            continue; // prose comment (also skipped by `sha256sum -c`)
        }
        entries.push(parse_entry(raw, &at, policy)?);
    }

    let manifest_version =
        manifest_version.ok_or_else(|| format!("{origin}: missing `#! manifest-version`"))?;
    if manifest_version != MANIFEST_VERSION {
        return Err(format!(
            "{origin}: manifest-version {manifest_version} is not the {MANIFEST_VERSION} this \
             checker implements"
        ));
    }
    let manifest = Manifest {
        format_version: format_version
            .ok_or_else(|| format!("{origin}: missing `#! format-version`"))?,
        status: status.ok_or_else(|| format!("{origin}: missing `#! status`"))?,
        freeze_gate: freeze_gate.ok_or_else(|| format!("{origin}: missing `#! freeze-gate`"))?,
        kinds,
        pending,
        entries,
    };
    if manifest.entries.is_empty() {
        return Err(format!(
            "{origin}: zero frozen entries — an empty freeze manifest asserts nothing and must \
             fail loudly"
        ));
    }
    if manifest.status == Status::Frozen && !manifest.pending.is_empty() {
        return Err(format!(
            "{origin}: status is `frozen` but {} `#! pending` must-exist vector(s) remain \
             ({}); the freeze gate requires zero pending",
            manifest.pending.len(),
            manifest
                .pending
                .iter()
                .map(|p| format!("{} ({})", p.slug, p.task))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(manifest)
}

/// One `<64-hex-digits><2 spaces><relative/path>` line, in the exact shape
/// `sha256sum` emits and consumes.
fn parse_entry(raw: &str, at: &str, policy: &EntryPolicy) -> Result<Entry, String> {
    let (digest, path) = raw
        .split_once("  ")
        .ok_or_else(|| format!("{at}: not a `<sha256>  <path>` line (needs two spaces)"))?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{at}: digest must be 64 hex digits, got `{digest}`"
        ));
    }
    if digest.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(format!("{at}: digest must be lowercase hex"));
    }
    if path.is_empty() {
        return Err(format!("{at}: empty path"));
    }
    // Path discipline: relative, forward slashes, no traversal. A manifest
    // is committed data; an absolute or `..` path would let it reach
    // outside the version directory it freezes.
    if path.starts_with('/')
        || path.contains('\\')
        || path.split('/').any(|c| c == ".." || c == ".")
    {
        return Err(format!(
            "{at}: path `{path}` must be relative to the version directory, forward-slashed, \
             with no `.`/`..` components"
        ));
    }
    let file_name = path.rsplit('/').next().unwrap_or(path);
    if !policy
        .allowed_suffixes
        .iter()
        .any(|suffix| path.ends_with(suffix))
        || !file_name.starts_with(policy.required_name_prefix)
        || policy.excluded_paths.contains(&path)
    {
        return Err(format!(
            "{at}: `{path}` is not part of {} — this manifest freezes `{}*` files ending in \
             {:?} and treats {:?} as auxiliaries by design",
            policy.subject,
            policy.required_name_prefix,
            policy.allowed_suffixes,
            policy.excluded_paths
        ));
    }
    Ok(Entry {
        digest: digest.to_owned(),
        path: path.to_owned(),
    })
}

fn split_word(text: &str) -> (&str, &str) {
    match text.split_once(char::is_whitespace) {
        Some((head, tail)) => (head, tail.trim_start()),
        None => (text, ""),
    }
}

fn require_nonempty(value: &str, what: &str, at: &str) -> Result<(), String> {
    if value.is_empty() {
        Err(format!("{at}: {what} is empty"))
    } else {
        Ok(())
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, what: &str, at: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{at}: `{what}` given twice"));
    }
    *slot = Some(value);
    Ok(())
}
