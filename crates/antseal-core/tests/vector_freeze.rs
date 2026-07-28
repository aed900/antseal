//! Q6 — the golden-vector **freeze** and **must-exist** guard.
//!
//! The Q4 runner (`vector_runner.rs`) executes every vector file it finds.
//! That is a one-sided guarantee: a runner can only fail on files that
//! exist, so *deleting* a vector removes its coverage silently. This test
//! is the other side. Per format-version directory,
//! `testdata/vectors/v<n>/FROZEN.sha256` pins:
//!
//! 1. **the frozen bytes** — a SHA-256 per committed vector file, so a
//!    modification turns CI red (MVP-SPEC.md line 123, format stability);
//! 2. **the must-exist list** — the hash lines themselves. Every listed
//!    path must exist, so a deletion turns CI red; and every committed
//!    `*.json` must be listed, so a vector cannot sit outside the freeze;
//! 3. **the still-owed vectors** — `#! pending` directives naming the task
//!    that must land each one (empty-anchor bundle, unbalanced-n=6 fine
//!    tree). Q14's gate condition is zero pending.
//!
//! Retention is **per version, indefinite**: `v1/` is the unit of
//! retention, discovery is a directory walk, and a future `v2/` neither
//! disturbs nor releases `v1/`. Every future release runs all versions
//! (`testdata/README.md`, retention policy).
//!
//! What changes at Q14: `#! status pre-freeze` becomes `#! status frozen`.
//! Before that, a vector may still be regenerated as a recorded, justified
//! change (re-run `scripts/vector-freeze.sh --update` and review the digest
//! diff). After it, digests are permanent, `--update` refuses to modify or
//! drop an entry, and the only legal change is an addition — under a new
//! format version if the format itself moved.
//!
//! Auxiliaries (`README.md`, the `*.py` reference generators) are
//! deliberately **not** frozen: the generators are re-runnable cross-checks,
//! and the JSON they produced is what the format commits to.
//!
//! The manifest is `sha256sum -c` compatible, so CI also checks the digests
//! with a tool sharing no code with antseal (`scripts/vector-freeze.sh`,
//! lane `vector-freeze`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use antseal_core::test_util::vectors::KNOWN_KINDS;

/// The freeze-manifest format itself — model, directive parser and digest
/// helper — shared with `format_freeze.rs` (Q50) so `#! status frozen` has
/// exactly one meaning in this repo. The tests-of-the-test below cover the
/// parser for both consumers.
#[path = "freeze_manifest/mod.rs"]
mod freeze_manifest;

use freeze_manifest::{EntryPolicy, Pending, Status, hex_sha256, parse_manifest};

/// The committed vector tree (workspace-relative via the crate manifest
/// dir, so it holds on every OS and checkout location).
const VECTORS_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/vectors");

/// Per-version freeze manifest file name. Whitelisted as an auxiliary by
/// the Q4 discovery contract, so it never trips the runner.
const MANIFEST_NAME: &str = "FROZEN.sha256";

/// F10's per-version roster. An **auxiliary**, like `README.md` and the
/// `*.py` generators: it is the list *of* the frozen vectors, not one of them,
/// and it changes whenever a vector lands — freezing it would make every
/// registration read as a frozen-byte change. `tests/vector_index.rs` is what
/// holds it to the tree, and it cross-checks against this manifest.
const INDEX_NAME: &str = "INDEX.json";

/// Which files the vector freeze covers. Auxiliaries — `README.md`, the
/// `*.py` reference generators and `INDEX.json` — are deliberately outside
/// it: the generators are re-runnable cross-checks, and the JSON they
/// produced is what the format commits to.
const VECTOR_ENTRIES: EntryPolicy = EntryPolicy {
    required_name_prefix: "",
    allowed_suffixes: &[".json"],
    excluded_paths: &[INDEX_NAME],
    subject: "the golden-vector freeze",
};

/// **The must-exist vectors format v1 still owes**, pinned here as the
/// second layer over the `#! pending` directives — deleting a directive
/// would otherwise silently shrink the obligation.
///
/// Source: MVP-SPEC.md line 153 (manifest/bundle encode-decode incl.
/// **empty-anchor vectors**) and line 169 (the **unbalanced-`n`** n=6
/// fine-tree vector), which are also `tasks/Q.md` Q6's named dependencies
/// on F13 and G15. Editing this list means re-reading those spec lines.
/// **Empty as of 2026-07-28** — v1 owes nothing, which is Q14's gate
/// condition on this file. The three obligations and their discharges:
///
/// | slug | task | landed as |
/// | --- | --- | --- |
/// | `fine-tree-unbalanced-n6` | G15 | `fine-tree/fine-tree.json` |
/// | `manifest-encode-decode` | F12 | `manifest/manifest.json` |
/// | `bundle-empty-anchor` | F13 | `bundle/bundle.json` (case `empty-anchor-unanchored`) |
///
/// Each directive and its row here were deleted in the same commit as the
/// vector, which is the discharge procedure this constant's doc comment
/// describes. An empty list is not a licence to stop checking: a *new*
/// obligation added later must appear in both places again.
const EXPECTED_PENDING_V1: &[(&str, &str)] = &[];

// ---------------------------------------------------------------------------
// the checks
// ---------------------------------------------------------------------------

/// What one version directory's freeze looks like after checking.
#[derive(Debug)]
struct VersionReport {
    version: String,
    frozen: usize,
    status: Status,
    kinds: BTreeMap<String, String>,
    pending: Vec<Pending>,
}

/// Check every format-version directory under a `vectors/`-shaped tree.
///
/// Collects **all** violations rather than stopping at the first, so one
/// run tells a maintainer everything that is wrong.
fn check_tree(root: &Path) -> Result<Vec<VersionReport>, Vec<String>> {
    let mut failures = Vec::new();
    let mut reports = Vec::new();

    let versions = match version_dirs(root) {
        Ok(dirs) => dirs,
        Err(message) => return Err(vec![message]),
    };
    if versions.is_empty() {
        return Err(vec![format!(
            "{}: no format-version directories — vector retention is per version and at least \
             one must exist",
            root.display()
        )]);
    }
    for (version, dir) in versions {
        match check_version_dir(&dir, &version) {
            Ok(report) => reports.push(report),
            Err(mut errors) => failures.append(&mut errors),
        }
    }
    if failures.is_empty() {
        Ok(reports)
    } else {
        Err(failures)
    }
}

fn version_dirs(root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let mut dirs = Vec::new();
    for path in sorted_entries(root)? {
        if !path.is_dir() {
            continue; // top-level strays are the Q4 runner's failure to raise
        }
        let name = file_name(&path)?;
        if is_version_dirname(&name) {
            dirs.push((name, path));
        } else {
            return Err(format!(
                "{}: directories under vectors/ must be `v<integer>` format-version \
                 directories (discovery contract, testdata/vectors/README.md)",
                path.display()
            ));
        }
    }
    Ok(dirs)
}

fn check_version_dir(dir: &Path, version: &str) -> Result<VersionReport, Vec<String>> {
    let manifest_path = dir.join(MANIFEST_NAME);
    let text = match fs::read_to_string(&manifest_path) {
        Ok(text) => text,
        Err(err) => {
            return Err(vec![format!(
                "{}: cannot read the freeze manifest ({err}) — every format-version directory \
                 must carry one; without it the version's vectors are unfrozen and a deletion \
                 would pass unnoticed (Q6)",
                manifest_path.display()
            )]);
        }
    };
    let origin = manifest_path.display().to_string();
    let manifest = parse_manifest(&text, &origin, &VECTOR_ENTRIES).map_err(|e| vec![e])?;

    let mut failures = Vec::new();
    if manifest.format_version != version {
        failures.push(format!(
            "{origin}: declares format-version `{}` but sits in `{version}/` (misfiled manifest)",
            manifest.format_version
        ));
    }

    // Entries must be sorted and duplicate-free: the manifest is a diffable
    // inventory, and a duplicate path could pin two different digests.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for entry in &manifest.entries {
        if !seen.insert(entry.path.as_str()) {
            failures.push(format!("{origin}: `{}` listed twice", entry.path));
        }
        if previous.is_some_and(|prev| prev >= entry.path.as_str()) {
            failures.push(format!(
                "{origin}: `{}` is out of order — entries are byte-sorted by path so the \
                 manifest diffs cleanly (`scripts/vector-freeze.sh --update` sorts them)",
                entry.path
            ));
        }
        previous = Some(entry.path.as_str());
    }

    // Layer 1 — frozen bytes + must-exist: every listed file exists and
    // hashes to its pinned digest.
    for entry in &manifest.entries {
        let path = dir.join(&entry.path);
        match fs::read(&path) {
            Err(err) => failures.push(format!(
                "{origin}: frozen vector `{}` is MISSING ({err}) — vectors are retained \
                 indefinitely per format version; deleting one is never a legal change",
                entry.path
            )),
            Ok(bytes) => {
                let actual = hex_sha256(&bytes);
                if actual != entry.digest {
                    failures.push(format!(
                        "{origin}: frozen vector `{}` CHANGED\n      pinned {}\n      actual {}\n \
                         a byte change to a committed vector is a format event (regenerate + \
                         justify while `pre-freeze`; after Q14 it needs a new format version)",
                        entry.path, entry.digest, actual
                    ));
                }
            }
        }
    }

    // Layer 2 — nothing sits outside the freeze: every committed vector
    // file is listed. Additions are legal, but they land *in* the manifest.
    let mut committed = Vec::new();
    if let Err(message) = collect_json(dir, dir, &mut committed) {
        failures.push(message);
    }
    committed.sort();
    for path in &committed {
        if !seen.contains(path.as_str()) {
            let digest = fs::read(dir.join(path))
                .map(|bytes| hex_sha256(&bytes))
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            failures.push(format!(
                "{origin}: `{path}` is committed but UNFROZEN — every vector file is frozen the \
                 moment it lands. Append this line (or run `scripts/vector-freeze.sh --update`):\n\
                 \x20     {digest}  {path}"
            ));
        }
    }

    if failures.is_empty() {
        Ok(VersionReport {
            version: version.to_owned(),
            frozen: manifest.entries.len(),
            status: manifest.status,
            kinds: manifest.kinds,
            pending: manifest.pending,
        })
    } else {
        // Name the gate that flips this version to permanent, once, so the
        // failure text always says where the rule comes from.
        failures.push(format!(
            "{origin}: (freeze gate for this version: {}; status {:?})",
            manifest.freeze_gate, manifest.status
        ));
        Err(failures)
    }
}

/// Recursively collect committed `*.json` paths, relative to `base`.
fn collect_json(base: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), String> {
    for path in sorted_entries(dir)? {
        if path.is_dir() {
            collect_json(base, &path, out)?;
        } else if file_name(&path)?.ends_with(".json") && file_name(&path)? != INDEX_NAME {
            let relative = path
                .strip_prefix(base)
                .map_err(|_| format!("{}: not under the version directory", path.display()))?;
            let mut text = String::new();
            for (index, component) in relative.components().enumerate() {
                if index > 0 {
                    text.push('/');
                }
                text.push_str(
                    component
                        .as_os_str()
                        .to_str()
                        .ok_or_else(|| format!("{}: non-UTF-8 path", path.display()))?,
                );
            }
            out.push(text);
        }
    }
    Ok(())
}

fn sorted_entries(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let read = fs::read_dir(dir).map_err(|e| format!("{}: cannot read dir: {e}", dir.display()))?;
    let mut entries = Vec::new();
    for entry in read {
        let entry = entry.map_err(|e| format!("{}: dir entry error: {e}", dir.display()))?;
        entries.push(entry.path());
    }
    entries.sort();
    Ok(entries)
}

fn file_name(path: &Path) -> Result<String, String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .ok_or_else(|| format!("{}: non-UTF-8 file name in testdata", path.display()))
}

fn is_version_dirname(name: &str) -> bool {
    name.strip_prefix('v')
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

fn render(failures: &[String]) -> String {
    let mut out = format!("{} vector-freeze failure(s):\n", failures.len());
    for failure in failures {
        out.push_str("  - ");
        out.push_str(failure);
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------

fn committed_tree() -> Vec<VersionReport> {
    match check_tree(Path::new(VECTORS_ROOT)) {
        Ok(reports) => reports,
        Err(failures) => panic!("{}", render(&failures)),
    }
}

/// **The Q6 gate**: every committed vector of every retained format version
/// is frozen at its exact bytes, still present, and nothing sits outside
/// the freeze.
#[test]
fn vector_freeze_manifest_pins_every_committed_vector() {
    let reports = committed_tree();
    for report in &reports {
        println!(
            "vector freeze [{}]: {} frozen vector(s), status {:?}, {} kind(s), {} pending",
            report.version,
            report.frozen,
            report.status,
            report.kinds.len(),
            report.pending.len()
        );
    }
    assert!(!reports.is_empty(), "no format versions checked");
}

/// Every vector **kind** that freezes is recorded in a version manifest,
/// and no manifest invents one. The kind name and its payload shape are
/// what freeze at Q14 — the Q4 envelope itself is shared and carries its
/// own `schema_version`.
#[test]
fn vector_freeze_records_every_registered_kind() {
    let reports = committed_tree();
    let recorded: BTreeSet<&str> = reports
        .iter()
        .flat_map(|r| r.kinds.keys().map(String::as_str))
        .collect();
    let registered: BTreeSet<&str> = KNOWN_KINDS.iter().copied().collect();
    assert_eq!(
        recorded, registered,
        "the `#! kind` directives across all version manifests must equal \
         test_util::vectors::KNOWN_KINDS — a new kind is a framework change that freezes at \
         Q14 and must be recorded in the version it appears in"
    );
}

/// The `#! pending` must-exist obligations are exactly the ones format v1
/// still owes, each naming the task that must land it.
///
/// Pinned against [`EXPECTED_PENDING_V1`] so a directive cannot be quietly
/// deleted: the whole point of a must-exist list is that the absent
/// artifact is visible.
#[test]
fn vector_freeze_pending_must_exist_list_is_complete() {
    let reports = committed_tree();
    let v1 = reports
        .iter()
        .find(|r| r.version == "v1")
        .unwrap_or_else(|| panic!("format version v1 must exist"));
    let actual: Vec<(&str, &str)> = v1
        .pending
        .iter()
        .map(|p| (p.slug.as_str(), p.task.as_str()))
        .collect();
    assert_eq!(
        actual, EXPECTED_PENDING_V1,
        "the v1 must-exist obligations changed; landing one means deleting its `#! pending` \
         line AND its row here, in the same commit as the vector"
    );
    for p in &v1.pending {
        println!(
            "must-exist PENDING [v1] {} — owner {}: {}",
            p.slug, p.task, p.what
        );
    }
    // Q14's gate condition, stated where it is checked rather than only in
    // prose: the freeze may not be executed while obligations remain, and
    // `parse_manifest` refuses `status frozen` with a non-empty pending set.
    //
    // **Flipped at Q14, 2026-07-28.** This asserted `PreFreeze`
    // *unconditionally*, which was a snapshot of the then-current state rather
    // than the rule its own comment describes — so it fired on the freeze
    // itself, with the self-contradicting message "still owes 0 must-exist
    // vector(s); it cannot be `frozen`". Owing zero is precisely the condition
    // that permits freezing. Both directions are now asserted separately:
    if !v1.pending.is_empty() {
        assert_eq!(
            v1.status,
            Status::PreFreeze,
            "v1 still owes {} must-exist vector(s); it cannot be `frozen`",
            v1.pending.len()
        );
    }
    // …and the post-freeze state is pinned, so a silent un-freeze is a failure
    // rather than a return to a permissive mode. Editing this line is how a
    // v2-style re-open would have to announce itself.
    assert_eq!(
        v1.status,
        Status::Frozen,
        "v1 is `{:?}`; the format-v1 freeze (Q14) set it to `frozen` on 2026-07-28 \
         and nothing since may relax it — line 123 makes v1 verifiable forever",
        v1.status
    );
}

// ---------------------------------------------------------------------------
// tests-of-the-test: every failure class turns the gate red, and a legal
// addition stays green (tasks/Q.md Q6 accept)
// ---------------------------------------------------------------------------

/// A scratch `vectors/`-shaped tree under the cargo-provided tmp dir,
/// seeded with one version directory holding one frozen vector.
fn scratch_tree(test: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("vector_freeze")
        .join(test);
    if root.exists() {
        fs::remove_dir_all(&root).expect("scratch cleanup");
    }
    fs::create_dir_all(root.join("v1/group")).expect("scratch tree");
    fs::write(root.join("v1/group/a.json"), b"{\"a\":1}\n").expect("write vector");
    write_manifest(&root, MANIFEST_HEADER, &["group/a.json"]);
    root
}

const MANIFEST_HEADER: &str = "#! manifest-version 1\n\
     #! format-version v1\n\
     #! status pre-freeze\n\
     #! freeze-gate Q14\n\
     #! kind hkdf-labels C3\n\
     #! kind commitments C16\n\
     #! kind unit-aead C16\n\
     #! kind manifest-aead C16\n\
     #! kind signatures C16\n\
     #! kind sig-reject C15\n\
     #! kind fine-tree G15\n";

/// Rewrite `v1/FROZEN.sha256` with the given header and freshly computed
/// digests for the given relative paths.
fn write_manifest(root: &Path, header: &str, paths: &[&str]) {
    let mut text = header.to_owned();
    for path in paths {
        let bytes = fs::read(root.join("v1").join(path)).expect("read vector for hashing");
        text.push_str(&format!("{}  {path}\n", hex_sha256(&bytes)));
    }
    fs::write(root.join("v1").join(MANIFEST_NAME), text).expect("write manifest");
}

#[track_caller]
fn expect_red(root: &Path, needle: &str) {
    match check_tree(root) {
        Err(failures) => {
            let rendered = render(&failures);
            assert!(
                rendered.contains(needle),
                "failure must mention `{needle}`, got:\n{rendered}"
            );
        }
        Ok(_) => panic!("check_tree must fail (expected `{needle}`), but the tree passed"),
    }
}

#[track_caller]
fn expect_green(root: &Path) {
    if let Err(failures) = check_tree(root) {
        panic!("{}", render(&failures));
    }
}

/// The seeded scratch tree is valid — the positive control, without which
/// every red assertion below could be passing for the wrong reason.
#[test]
fn vector_freeze_scratch_baseline_is_green() {
    expect_green(&scratch_tree("baseline"));
}

/// **Q6 accept**: mutating a frozen vector turns CI red.
#[test]
fn vector_freeze_red_on_a_mutated_vector() {
    let root = scratch_tree("mutated");
    fs::write(root.join("v1/group/a.json"), b"{\"a\":2}\n").expect("mutate");
    expect_red(&root, "CHANGED");
}

/// **Q6 accept**: deleting a frozen vector turns CI red. This is the case
/// the Q4 runner structurally cannot catch.
#[test]
fn vector_freeze_red_on_a_deleted_vector() {
    let root = scratch_tree("deleted");
    fs::remove_file(root.join("v1/group/a.json")).expect("delete");
    expect_red(&root, "is MISSING");
}

/// **Q6 accept**: adding a vector stays green — the addition is a legal,
/// non-breaking change that appends a manifest line.
#[test]
fn vector_freeze_green_on_an_added_vector() {
    let root = scratch_tree("added");
    fs::write(root.join("v1/group/b.json"), b"{\"b\":1}\n").expect("write");
    write_manifest(&root, MANIFEST_HEADER, &["group/a.json", "group/b.json"]);
    expect_green(&root);
}

/// ...but an addition that skips the manifest is red, with the exact line
/// to append. A vector outside the freeze has no retention guarantee.
#[test]
fn vector_freeze_red_on_an_unfrozen_addition() {
    let root = scratch_tree("unfrozen_addition");
    fs::write(root.join("v1/group/b.json"), b"{\"b\":1}\n").expect("write");
    expect_red(&root, "is committed but UNFROZEN");
}

/// A version directory with no manifest is red: its vectors would be
/// unfrozen and deletable in silence.
#[test]
fn vector_freeze_red_on_a_version_directory_without_a_manifest() {
    let root = scratch_tree("no_manifest");
    fs::remove_file(root.join("v1").join(MANIFEST_NAME)).expect("remove manifest");
    expect_red(&root, "cannot read the freeze manifest");
}

/// Retention is per version: a *second* version directory is checked too,
/// and its own missing manifest is its own failure — `v1` being fine never
/// covers for `v2`.
#[test]
fn vector_freeze_checks_every_retained_version_independently() {
    let root = scratch_tree("multi_version");
    fs::create_dir_all(root.join("v2")).expect("v2");
    fs::write(root.join("v2/c.json"), b"{\"c\":1}\n").expect("write");
    expect_red(&root, "v2");
}

#[test]
fn vector_freeze_red_on_a_typo_in_a_directive() {
    let root = scratch_tree("typo_directive");
    let header = format!("{MANIFEST_HEADER}#! stauts frozen\n");
    write_manifest(&root, &header, &["group/a.json"]);
    expect_red(&root, "unknown directive");
}

#[test]
fn vector_freeze_red_on_a_misfiled_format_version() {
    let root = scratch_tree("misfiled_version");
    let header = MANIFEST_HEADER.replace("format-version v1", "format-version v2");
    write_manifest(&root, &header, &["group/a.json"]);
    expect_red(&root, "misfiled manifest");
}

#[test]
fn vector_freeze_red_on_a_malformed_digest_line() {
    let root = scratch_tree("malformed_digest");
    let text = format!("{MANIFEST_HEADER}deadbeef  group/a.json\n");
    fs::write(root.join("v1").join(MANIFEST_NAME), text).expect("write manifest");
    expect_red(&root, "64 hex digits");
}

#[test]
fn vector_freeze_red_on_a_path_escaping_the_version_directory() {
    let root = scratch_tree("path_traversal");
    let digest = hex_sha256(b"{\"a\":1}\n");
    let text = format!("{MANIFEST_HEADER}{digest}  ../v1/group/a.json\n");
    fs::write(root.join("v1").join(MANIFEST_NAME), text).expect("write manifest");
    expect_red(&root, "must be relative to the version directory");
}

#[test]
fn vector_freeze_red_on_duplicate_and_unsorted_entries() {
    let root = scratch_tree("duplicate_entry");
    write_manifest(&root, MANIFEST_HEADER, &["group/a.json", "group/a.json"]);
    expect_red(&root, "listed twice");
}

#[test]
fn vector_freeze_red_on_an_empty_manifest() {
    let root = scratch_tree("empty_manifest");
    fs::write(root.join("v1").join(MANIFEST_NAME), MANIFEST_HEADER).expect("write manifest");
    expect_red(&root, "zero frozen entries");
}

/// The Q14 gate condition, proven rather than described: declaring a
/// version `frozen` while it still owes a must-exist vector is red.
#[test]
fn vector_freeze_red_on_freezing_with_a_pending_obligation() {
    let root = scratch_tree("frozen_with_pending");
    let header = format!(
        "{}#! pending fine-tree-unbalanced-n6 G15 the n=6 opening\n",
        MANIFEST_HEADER.replace("status pre-freeze", "status frozen")
    );
    write_manifest(&root, &header, &["group/a.json"]);
    expect_red(&root, "requires zero pending");
}

/// A `#! pending` line without an owning task is red — an unowned
/// obligation is indistinguishable from a forgotten one.
#[test]
fn vector_freeze_red_on_a_pending_line_without_an_owner() {
    let root = scratch_tree("pending_no_owner");
    let header = format!("{MANIFEST_HEADER}#! pending fine-tree-unbalanced-n6\n");
    write_manifest(&root, &header, &["group/a.json"]);
    expect_red(&root, "pending owning task is empty");
}

/// Freezing an auxiliary is red: generators are re-runnable cross-checks,
/// not artifacts the format commits to.
#[test]
fn vector_freeze_red_on_freezing_a_generator() {
    let root = scratch_tree("frozen_generator");
    let digest = hex_sha256(b"print('x')\n");
    let text = format!("{MANIFEST_HEADER}{digest}  group/gen_vectors.py\n");
    fs::write(root.join("v1").join(MANIFEST_NAME), text).expect("write manifest");
    expect_red(&root, "is not part of the golden-vector freeze");
}
