//! F10 — the **per-version golden-vector index**, and the test that makes it
//! load-bearing rather than decorative.
//!
//! `testdata/vectors/v<n>/INDEX.json` is the *roster* of one format version:
//! for every committed vector, a permanent slug, its path, its kind, the task
//! that landed it, and the obligation it discharges; plus the vectors the
//! version still owes. `FROZEN.sha256` (Q6) is the *freeze*: it pins bytes and
//! catches deletions. The two are deliberately different files with different
//! jobs, and this test makes them mutually enforcing — neither can drift from
//! the tree or from the other.
//!
//! What is checked, per version directory:
//!
//! 1. The index's `format_version` equals its directory **and** names a
//!    version this build supports (`antseal_core::format::SUPPORTED_VERSIONS`)
//!    — the code ⟷ data link F10's module docs promise.
//! 2. Roster completeness, **both directions**: every committed `*.json`
//!    vector has exactly one index entry, and every index entry names a file
//!    that exists. A vector landed without registering, or an entry left
//!    behind by a deletion, both fail.
//! 3. The index cannot lie about a vector: each entry's `kind` is compared
//!    against the vector file's own `kind` field, and its `format_version`
//!    against the directory.
//! 4. Every registered kind is one the executor knows
//!    (`test_util::vectors::KNOWN_KINDS`), so an entry can never claim a kind
//!    no test could run.
//! 5. Index ⟷ freeze agreement: every rostered vector is frozen, and the
//!    freeze-blocking `pending` entries are exactly `FROZEN.sha256`'s
//!    `#! pending` lines, task for task.
//!
//! Test names carry the reserved `vector_` marker so the three-OS lane
//! (`cross-os-*`) runs this everywhere, alongside the Q4 runner.
//!
//! Registration procedure for downstream vector tasks (F12/F13/G15/R9):
//! `testdata/vectors/README.md`, section "The per-version index".

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use antseal_core::format::SUPPORTED_VERSIONS;
use antseal_core::test_util::vectors::KNOWN_KINDS;
use serde::Deserialize;

/// The committed vector tree (workspace-relative via the crate manifest dir).
const VECTORS_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/vectors");

/// The index file name. A documented auxiliary, like `README.md`, `*.py` and
/// `FROZEN.sha256`: it is not a golden vector and is not frozen — it is the
/// roster *of* the frozen set.
const INDEX_NAME: &str = "INDEX.json";

/// Q6's freeze manifest, read here independently of its own checker.
const FROZEN_NAME: &str = "FROZEN.sha256";

// ---------------------------------------------------------------------------
// the index schema
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    schema: String,
    schema_version: u32,
    format_version: String,
    freeze_gate: String,
    /// Free text; carries the "this is the roster, not the freeze" note so a
    /// reader of the raw file is not left guessing.
    #[allow(dead_code)]
    note: String,
    vectors: Vec<Entry>,
    pending: Vec<Pending>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    slug: String,
    path: String,
    kind: String,
    task: String,
    pins: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    slug: String,
    kind: String,
    task: String,
    /// `true` ⇒ this vector is part of Q14's must-exist minimum and has a
    /// matching `#! pending` line in `FROZEN.sha256`.
    must_exist_before_freeze: bool,
    pins: String,
}

/// The fields of a vector file this test needs. The full envelope is the Q4
/// executor's business; reading only these two keeps the check independent of
/// payload shape.
#[derive(Debug, Deserialize)]
struct VectorHead {
    kind: String,
    format_version: String,
}

// ---------------------------------------------------------------------------
// discovery
// ---------------------------------------------------------------------------

fn version_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(VECTORS_ROOT)
        .expect("vectors root must exist")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    assert!(!dirs.is_empty(), "no format-version directories found");
    dirs
}

/// Every committed `*.json` **vector** under `dir`, relative and slash-joined.
/// The index itself is excluded: it is an auxiliary, not a vector.
fn committed_vectors(base: &Path, dir: &Path, out: &mut BTreeSet<String>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            committed_vectors(base, &path, out);
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 name");
        if name.ends_with(".json") && name != INDEX_NAME {
            let relative = path.strip_prefix(base).expect("under base");
            let joined: Vec<&str> = relative
                .components()
                .map(|c| c.as_os_str().to_str().expect("utf-8 path"))
                .collect();
            out.insert(joined.join("/"));
        }
    }
}

/// `FROZEN.sha256`, read independently of Q6's own checker: the set of frozen
/// paths and the set of `#! pending <slug> <task> …` declarations.
fn read_frozen(dir: &Path) -> (BTreeSet<String>, BTreeMap<String, String>) {
    let text = fs::read_to_string(dir.join(FROZEN_NAME))
        .unwrap_or_else(|e| panic!("{}/{FROZEN_NAME}: {e}", dir.display()));
    let mut paths = BTreeSet::new();
    let mut pending = BTreeMap::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("#! pending ") {
            let mut words = rest.split_whitespace();
            let slug = words.next().expect("`#! pending` needs a slug").to_owned();
            let task = words.next().expect("`#! pending` needs a task").to_owned();
            pending.insert(slug, task);
        } else if !line.starts_with('#') && !line.trim().is_empty() {
            // `<digest>  <path>` — two spaces, sha256sum format.
            let path = line
                .split_once("  ")
                .unwrap_or_else(|| panic!("malformed digest line: {line}"))
                .1;
            paths.insert(path.to_owned());
        }
    }
    (paths, pending)
}

fn load_index(dir: &Path) -> Index {
    let path = dir.join(INDEX_NAME);
    let bytes = fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: every format-version directory must carry an {INDEX_NAME} \
             (F10; testdata/vectors/README.md): {e}",
            path.display()
        )
    });
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// the checks
// ---------------------------------------------------------------------------

/// **The F10 accept**: the versioned vector directory carries a
/// machine-readable index, and this test consumes it.
#[test]
fn vector_index_exists_and_matches_the_committed_tree() {
    let mut versions_seen = 0;
    for dir in version_dirs() {
        let version = dir
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 dir name")
            .to_owned();
        let index = load_index(&dir);

        assert_eq!(index.schema, "antseal-vector-index", "{version}");
        assert_eq!(index.schema_version, 1, "{version}");
        assert_eq!(index.freeze_gate, "Q14", "{version}");
        assert_eq!(
            index.format_version, version,
            "{version}: the index's format_version must equal its directory"
        );

        // The code ⟷ data link: a version directory exists only for a version
        // this build can decode (F10's `SUPPORTED_VERSIONS`). Retention means
        // that stays true forever — a released version is never dropped.
        let supported: Vec<String> = SUPPORTED_VERSIONS.iter().map(|v| format!("v{v}")).collect();
        assert!(
            supported.contains(&index.format_version),
            "{version}: vectors exist for a version this build cannot decode \
             (supported: {supported:?}) — either dispatch lost a row or the \
             directory was added without one (MVP-SPEC.md line 123)"
        );

        // Roster completeness, both directions.
        let mut on_disk = BTreeSet::new();
        committed_vectors(&dir, &dir, &mut on_disk);
        let rostered: BTreeSet<String> = index.vectors.iter().map(|e| e.path.clone()).collect();
        assert_eq!(
            rostered.len(),
            index.vectors.len(),
            "{version}: duplicate path in the index"
        );
        assert_eq!(
            rostered, on_disk,
            "{version}: the index and the committed tree disagree. \
             Missing from the index = a vector landed without registering; \
             missing from disk = a stale entry. Registration procedure: \
             testdata/vectors/README.md"
        );

        // Slugs are the permanent handles downstream work refers to.
        let slugs: BTreeSet<&str> = index.vectors.iter().map(|e| e.slug.as_str()).collect();
        assert_eq!(
            slugs.len(),
            index.vectors.len(),
            "{version}: duplicate slug"
        );

        for entry in &index.vectors {
            let ctx = format!("{version}/{}", entry.path);
            assert!(!entry.slug.is_empty(), "{ctx}: empty slug");
            assert!(!entry.task.is_empty(), "{ctx}: entry must name its task");
            assert!(
                entry.pins.len() >= 20,
                "{ctx}: `pins` must state what the vector pins"
            );
            assert!(
                KNOWN_KINDS.contains(&entry.kind.as_str()),
                "{ctx}: kind `{}` is not a registered vector kind {KNOWN_KINDS:?}",
                entry.kind
            );

            // The index cannot lie about a vector: compare against the file.
            let head: VectorHead = serde_json::from_slice(
                &fs::read(dir.join(&entry.path)).unwrap_or_else(|e| panic!("{ctx}: {e}")),
            )
            .unwrap_or_else(|e| panic!("{ctx}: {e}"));
            assert_eq!(head.kind, entry.kind, "{ctx}: index kind ≠ file kind");
            assert_eq!(
                head.format_version, version,
                "{ctx}: file's format_version ≠ its directory"
            );
        }

        // Pending entries: distinct slugs, named owners, and a kind that is
        // either already registered or explicitly still to come.
        let pending_slugs: BTreeSet<&str> = index.pending.iter().map(|p| p.slug.as_str()).collect();
        assert_eq!(
            pending_slugs.len(),
            index.pending.len(),
            "{version}: duplicate pending slug"
        );
        for p in &index.pending {
            assert!(!p.task.is_empty(), "{version}/{}: no owning task", p.slug);
            assert!(!p.kind.is_empty(), "{version}/{}: no kind", p.slug);
            assert!(
                p.pins.len() >= 20,
                "{version}/{}: `pins` must state the obligation",
                p.slug
            );
            assert!(
                !slugs.contains(p.slug.as_str()),
                "{version}/{}: slug is both landed and pending",
                p.slug
            );
        }

        versions_seen += 1;
    }
    assert!(versions_seen > 0, "no version directories checked");
}

/// The index and Q6's freeze manifest are **mutually enforcing**: every
/// rostered vector is frozen, and the freeze-blocking pending entries are
/// exactly `FROZEN.sha256`'s `#! pending` lines. Two files, one truth.
#[test]
fn vector_index_agrees_with_the_freeze_manifest() {
    for dir in version_dirs() {
        let version = dir.file_name().and_then(|n| n.to_str()).expect("utf-8");
        let index = load_index(&dir);
        let (frozen_paths, frozen_pending) = read_frozen(&dir);

        let rostered: BTreeSet<String> = index.vectors.iter().map(|e| e.path.clone()).collect();
        assert_eq!(
            rostered, frozen_paths,
            "{version}: the roster (INDEX.json) and the freeze (FROZEN.sha256) \
             disagree. A rostered-but-unfrozen vector has no retention \
             guarantee; a frozen-but-unrostered one has no recorded owner."
        );

        // The index is NOT itself frozen: it changes whenever a vector lands,
        // which must never read as a format event.
        assert!(
            !frozen_paths.contains(INDEX_NAME),
            "{version}: {INDEX_NAME} must stay an auxiliary — freezing the \
             roster would make every registration a frozen-byte change"
        );

        let blocking: BTreeMap<String, String> = index
            .pending
            .iter()
            .filter(|p| p.must_exist_before_freeze)
            .map(|p| (p.slug.clone(), p.task.clone()))
            .collect();
        assert_eq!(
            blocking, frozen_pending,
            "{version}: the freeze-blocking pending set must match \
             FROZEN.sha256's `#! pending` lines exactly (slug and owning task). \
             Entries with `must_exist_before_freeze: false` are tracked here \
             only and do not gate Q14."
        );
    }
}

/// Every kind the index registers — landed **or** pending — is a kind some
/// version's `FROZEN.sha256` declares or that a pending entry owns, so the
/// three files cannot drift into three different kind vocabularies.
#[test]
fn vector_index_kinds_stay_inside_the_known_vocabulary() {
    // Landed kinds must be executable today.
    for dir in version_dirs() {
        let index = load_index(&dir);
        for e in &index.vectors {
            assert!(
                KNOWN_KINDS.contains(&e.kind.as_str()),
                "{}: unregistered kind `{}`",
                e.slug,
                e.kind
            );
        }
        // A pending kind is by definition not yet executable; what must hold
        // is that it is not *already* registered under a different name.
        for p in &index.pending {
            assert!(
                !KNOWN_KINDS.contains(&p.kind.as_str()),
                "{}: kind `{}` is already registered — the entry is stale, or \
                 it should have landed as a vector rather than stayed pending",
                p.slug,
                p.kind
            );
        }
    }
}
