//! Q4 — the native golden-vector runner.
//!
//! Discovers every committed vector by **walking `testdata/vectors/` — no
//! hardcoded file lists** — and executes each through the WASM-safe
//! parse/validate/execute path in `antseal_core::test_util::vectors`
//! (schema + discovery contract: `testdata/vectors/README.md`).
//!
//! Failure discipline (Q4 accept): a malformed vector file fails the run
//! loudly; an unclassifiable file under `vectors/` fails the run; zero
//! discovered vectors fails the run. Nothing is ever silently skipped.
//!
//! Test names carry the reserved `vector_` marker so the three-OS CI lane
//! (`cross-os-*`) runs this suite everywhere (CONTRIBUTING.md, "Cross-OS
//! suite naming"); CI lane `golden-vectors` runs it on the primary OS.
//!
//! Adding a vector file requires **no change here** — see the documented
//! add-a-vector procedure in `testdata/vectors/README.md`.

use std::fs;
use std::path::{Path, PathBuf};

use antseal_core::test_util::vectors::{VectorSummary, execute_vector_bytes};

/// The committed vector tree (path is workspace-relative via the crate
/// manifest dir, so it holds on every OS and checkout location).
const VECTORS_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/vectors");

/// One discovered-and-executed vector file.
struct Executed {
    path: PathBuf,
    summary: VectorSummary,
}

/// Walk a `vectors/` tree per the discovery contract; execute every vector.
///
/// Errors are `String`s carrying the offending path — the calling test
/// panics with them, which *is* the loud failure. Directory entries are
/// sorted so behavior (and first-failure reporting) is deterministic
/// across platforms.
fn run_tree(root: &Path) -> Result<Vec<Executed>, String> {
    let mut executed = Vec::new();
    for entry in sorted_entries(root)? {
        let name = entry_name(&entry)?;
        if entry.is_dir() {
            if !is_version_dirname(&name) {
                return Err(format!(
                    "{}: directories under vectors/ must be format-version directories \
                     (`v<integer>`); found `{name}` (discovery contract, testdata/vectors/README.md)",
                    entry.display()
                ));
            }
            walk_version_dir(&entry, &name, &mut executed)?;
        } else if name != "README.md" {
            return Err(format!(
                "{}: only README.md and v<integer>/ directories may sit directly under \
                 vectors/ (discovery contract, testdata/vectors/README.md)",
                entry.display()
            ));
        }
    }
    if executed.is_empty() {
        return Err(format!(
            "{}: zero vector files discovered — vector discovery is broken or the tree \
             is empty; both must fail loudly (Q4)",
            root.display()
        ));
    }
    Ok(executed)
}

/// Recurse a `v<n>/` directory: every regular file must classify as a
/// vector (`.json`, executed) or a documented auxiliary (`README.md`,
/// `*.py` generators, Q6's `FROZEN.sha256`); anything else is an error.
fn walk_version_dir(dir: &Path, version: &str, executed: &mut Vec<Executed>) -> Result<(), String> {
    for entry in sorted_entries(dir)? {
        if entry.is_dir() {
            walk_version_dir(&entry, version, executed)?;
            continue;
        }
        let name = entry_name(&entry)?;
        // F10's per-version roster is an auxiliary, not a vector: it carries
        // no `kind`/`inputs`/`expect` and is checked by `vector_index.rs`.
        // Listed before the `.json` arm so it is never executed as a vector.
        if name == "INDEX.json" {
            continue;
        }
        if name.ends_with(".json") {
            let bytes = fs::read(&entry)
                .map_err(|e| format!("{}: cannot read vector file: {e}", entry.display()))?;
            let summary = execute_vector_bytes(&bytes, version)
                .map_err(|e| format!("{}: {e}", entry.display()))?;
            executed.push(Executed {
                path: entry,
                summary,
            });
        } else if name == "README.md" || name == "FROZEN.sha256" || name.ends_with(".py") {
            // Documented auxiliaries (discovery contract).
        } else {
            return Err(format!(
                "{}: unclassifiable file under vectors/{version}/ — every file must be a \
                 vector (*.json) or a documented auxiliary (README.md, *.py, FROZEN.sha256, \
                 INDEX.json); nothing is silently skipped (Q4)",
                entry.display()
            ));
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

fn entry_name(path: &Path) -> Result<String, String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .ok_or_else(|| format!("{}: non-UTF-8 file name in testdata", path.display()))
}

fn is_version_dirname(name: &str) -> bool {
    name.strip_prefix('v')
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

// ---------------------------------------------------------------------------
// the runner
// ---------------------------------------------------------------------------

/// **The Q4 runner**: every committed vector of every format version is
/// discovered and executed; any malformed/unclassifiable/failing file —
/// or an empty discovery — fails this test.
#[test]
fn vector_runner_discovers_and_executes_every_committed_vector() {
    let executed = run_tree(Path::new(VECTORS_ROOT)).unwrap_or_else(|e| panic!("{e}"));
    assert!(!executed.is_empty(), "discovery returned an empty set");
    println!("golden-vector runner: {} vector file(s)", executed.len());
    for run in &executed {
        // The recomputed digest is the medium the Q5 native<->WASM bit-match
        // lane compares (crates/wasm-bitmatch); printing it here makes the
        // two lanes' logs directly comparable by eye.
        let digest: String = run
            .summary
            .recomputed_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        println!(
            "  OK [{}] {} — {} item(s), recomputed {}: {}",
            run.summary.kind,
            run.path.display(),
            run.summary.items,
            digest,
            run.summary.description
        );
    }
}

// ---------------------------------------------------------------------------
// tests-of-the-test: the runner fails loudly, never skips
// (execution-level tampering — wrong okm/info bytes, wrong W, dropped
// labels — is covered by the unit tamper tests in
// `antseal_core::test_util::vectors`; the cases below prove the
// *discovery* layer surfaces every failure class through `run_tree`.)
// ---------------------------------------------------------------------------

/// A scratch `vectors/`-shaped tree under the cargo-provided tmp dir.
fn scratch_tree(test: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("vector_runner")
        .join(test);
    // Stale state from a previous run must not leak between executions.
    if root.exists() {
        fs::remove_dir_all(&root).expect("scratch cleanup");
    }
    fs::create_dir_all(root.join("v1")).expect("scratch tree");
    root
}

fn expect_err(root: &Path, needle: &str) {
    match run_tree(root) {
        Err(message) => assert!(
            message.contains(needle),
            "error must mention `{needle}`, got: {message}"
        ),
        Ok(executed) => panic!(
            "run_tree must fail; instead executed {} vector(s)",
            executed.len()
        ),
    }
}

#[test]
fn vector_runner_fails_loudly_on_invalid_json() {
    let root = scratch_tree("invalid_json");
    fs::write(root.join("v1/broken.json"), b"{ this is not json").expect("write");
    expect_err(&root, "broken.json");
}

#[test]
fn vector_runner_fails_loudly_on_unknown_kind() {
    let root = scratch_tree("unknown_kind");
    let doc = serde_json::json!({
        "schema": "antseal-golden-vector",
        "schema_version": 1,
        "format_version": "v1",
        "kind": "not-a-registered-kind",
        "non_secret": "NON-SECRET scratch fixture",
        "description": "runner test-of-the-test",
        "inputs": {},
        "expect": {},
    });
    fs::write(
        root.join("v1/unknown-kind.json"),
        serde_json::to_vec(&doc).expect("serialize"),
    )
    .expect("write");
    expect_err(&root, "unknown vector kind");
}

#[test]
fn vector_runner_fails_loudly_on_misfiled_format_version() {
    let root = scratch_tree("misfiled_version");
    let doc = serde_json::json!({
        "schema": "antseal-golden-vector",
        "schema_version": 1,
        // Declares v2 but sits under v1/ — misfiled vectors must be caught.
        "format_version": "v2",
        "kind": "hkdf-labels",
        "non_secret": "NON-SECRET scratch fixture",
        "description": "runner test-of-the-test",
        "inputs": {},
        "expect": {},
    });
    fs::write(
        root.join("v1/misfiled.json"),
        serde_json::to_vec(&doc).expect("serialize"),
    )
    .expect("write");
    expect_err(&root, "misfiled");
}

#[test]
fn vector_runner_fails_loudly_on_unclassifiable_file() {
    let root = scratch_tree("unclassifiable");
    fs::write(root.join("v1/notes.txt"), b"stray file").expect("write");
    expect_err(&root, "unclassifiable");
}

#[test]
fn vector_runner_fails_loudly_on_stray_top_level_file() {
    let root = scratch_tree("stray_top_level");
    fs::write(root.join("stray.bin"), b"stray").expect("write");
    expect_err(&root, "stray.bin");
}

#[test]
fn vector_runner_fails_loudly_on_non_version_directory() {
    let root = scratch_tree("bad_version_dir");
    fs::create_dir_all(root.join("extras")).expect("mkdir");
    expect_err(&root, "format-version directories");
}

#[test]
fn vector_runner_fails_loudly_on_zero_vectors() {
    let root = scratch_tree("zero_vectors");
    fs::write(root.join("v1/README.md"), b"# aux only, no vectors\n").expect("write");
    expect_err(&root, "zero vector files");
}
