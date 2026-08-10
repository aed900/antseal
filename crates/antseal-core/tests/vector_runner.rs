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

/// Names the discovery walk must ignore rather than classify.
///
/// Q4/Q5 say nothing under `vectors/v<n>/` is SILENTLY skipped, and that rule
/// is unchanged: every `*.json` is still discovered, executed and counted, and
/// every file that is neither a vector, nor a documented auxiliary, nor on
/// this list is still a hard failure naming the path.
///
/// What this list adds is the distinction Q4/Q5 never had to draw, because in
/// 2026-07 nobody had yet run a Python import inside the vector tree: a file
/// the REPOSITORY ITSELF declares is not part of the tree is not an
/// unclassifiable vector, it is not a vector at all. `.gitignore` is where
/// that declaration lives, and `__pycache__/` has been in it since the wave-7
/// freeze — so before D116 the tree carried two rules that disagreed about
/// whether the same directory was expected, and the build-breaking one won.
///
/// Measured (D116 §1.5): a `.pyc` here failed `cargo check --workspace` with
/// exit 101, and so did `vector_runner`, which is CI's `golden-vectors`,
/// `cross-os` and `test` contexts. A vim swap file did the same, so editing
/// `crosscheck_cbor.py` bricked the workspace build for as long as the editor
/// was open.
///
/// `vector_freeze.rs`'s `collect_json` needs no such list because it filters
/// POSITIVELY for `.json` instead of asserting a closed classification, and is
/// green through all of the above — the tolerant shape was already in the tree.
///
/// This block is duplicated VERBATIM in `crates/wasm-bitmatch/build.rs` and
/// `crates/antseal-core/tests/vector_runner.rs` — a build script cannot import
/// a test module — and `bitmatch.rs` asserts the two texts are byte-identical
/// (D116 R8a). Edit both or neither.
const IGNORED_DIRS: &[&str] = &["__pycache__", ".idea", ".vscode"];
const IGNORED_SUFFIXES: &[&str] = &[".pyc", ".pyo", ".pyd", ".swp", ".swo"];
const IGNORED_NAMES: &[&str] = &[".DS_Store"];

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
        let name = entry_name(&entry)?;
        if entry.is_dir() {
            if IGNORED_DIRS.contains(&name.as_str()) {
                continue; // pruned, not recursed (D116 R7)
            }
            walk_version_dir(&entry, version, executed)?;
            continue;
        }
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
        } else if IGNORED_NAMES.contains(&name.as_str())
            || IGNORED_SUFFIXES.iter().any(|s| name.ends_with(s))
        {
            // D116 R7: AFTER the `*.json` arm and after `INDEX.json`, so an
            // ignorable rule can never swallow a vector.
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

// ---------------------------------------------------------------------------
// D116 R8(c) — tests-of-the-test for the ignorable classifier (Q140).
//
// The fatal arm above (`..._on_unclassifiable_file`, a stray `.txt`) is the
// R8(c) case that proves the closed classification SURVIVED this change: the
// walk still refuses a file it cannot name. The cases below prove the new
// arm only ever fires on what `.gitignore` already declares expected.
// ---------------------------------------------------------------------------

/// Seed a scratch tree with one REAL committed vector.
///
/// Without it every "green" case below would be vacuous in the worst way: an
/// empty tree fails the zero-vector rule, so a green run has to have actually
/// executed something. Using a committed vector rather than a synthetic one
/// also means these cases cannot drift away from what the executor accepts.
fn seed_valid_vector(root: &Path) {
    let source = Path::new(VECTORS_ROOT).join("v1/hkdf/hkdf-labels.json");
    let bytes = fs::read(&source)
        .unwrap_or_else(|e| panic!("cannot read seed vector {}: {e}", source.display()));
    fs::write(root.join("v1/seed.json"), bytes).expect("write seed vector");
}

/// `run_tree` must succeed and execute exactly `expected` vector(s).
fn expect_ok(root: &Path, expected: usize) {
    match run_tree(root) {
        Ok(executed) => assert_eq!(
            executed.len(),
            expected,
            "expected {expected} executed vector(s), got {}: {:?}",
            executed.len(),
            executed
                .iter()
                .map(|e| e.path.display().to_string())
                .collect::<Vec<_>>(),
        ),
        Err(message) => panic!("run_tree must succeed here; instead: {message}"),
    }
}

#[test]
fn vector_runner_ignores_pycache_bytecode() {
    let root = scratch_tree("ignore_pycache");
    seed_valid_vector(&root);
    fs::create_dir_all(root.join("v1/__pycache__")).expect("mkdir");
    fs::write(
        root.join("v1/__pycache__/gen.cpython-311.pyc"),
        b"\x00bytecode",
    )
    .expect("write");
    expect_ok(&root, 1);
}

#[test]
fn vector_runner_ignores_bytecode_outside_pycache() {
    // The suffix rule, not the directory rule: a `.pyc` can be written beside
    // the source when the interpreter is told to.
    let root = scratch_tree("ignore_loose_pyc");
    seed_valid_vector(&root);
    fs::write(root.join("v1/gen.pyc"), b"\x00bytecode").expect("write");
    expect_ok(&root, 1);
}

#[test]
fn vector_runner_ignores_editor_swap_files() {
    // Q140's widest consequence: this is a file vim creates merely by OPENING
    // `crosscheck_cbor.py`, and before D116 it failed the build until close.
    let root = scratch_tree("ignore_swap");
    seed_valid_vector(&root);
    fs::write(root.join("v1/.gen_vectors.py.swp"), b"swap").expect("write");
    expect_ok(&root, 1);
}

#[test]
fn vector_runner_prunes_ignored_directories_rather_than_walking_them() {
    // Pruning has a real, slightly surprising consequence, so it is pinned
    // rather than left to be rediscovered: a vector hidden inside an ignored
    // directory is INVISIBLE — not executed, not counted, not an error. That
    // is correct (the repository has declared the directory not part of the
    // tree) but it must be a decision, not an accident.
    let root = scratch_tree("prune_not_walk");
    seed_valid_vector(&root);
    fs::create_dir_all(root.join("v1/__pycache__")).expect("mkdir");
    fs::write(
        root.join("v1/__pycache__/hidden.json"),
        b"{ not even valid json",
    )
    .expect("write");
    expect_ok(&root, 1);
}

#[test]
fn vector_runner_still_fails_on_pycache_directly_under_vectors() {
    // `walk_root` is deliberately NOT relaxed (D116 R7): nothing imports a
    // module from `vectors/` itself, and loosening the top level would let a
    // whole stray tree in unnoticed.
    let root = scratch_tree("pycache_at_root");
    seed_valid_vector(&root);
    fs::create_dir_all(root.join("__pycache__")).expect("mkdir");
    expect_err(&root, "format-version directories");
}

// ---------------------------------------------------------------------------
// D116 R8(b) — `.gitignore` is the authority, and this test says so.
// ---------------------------------------------------------------------------

/// `.gitignore` patterns that must stay BUILD-BREAKING under `vectors/v<n>/`.
///
/// R8(b) allows a pattern to be excluded "with the reason". The line is drawn
/// by what the pattern is *for*, and `.gitignore` states both purposes itself:
///
/// - `__pycache__/`, `*.py[cod]`, `*.swp`, `.idea/`, `.vscode/`, `.DS_Store`
///   are there because a tool routinely PRODUCES them beside the files it
///   reads — and `.gitignore`'s own comment names `testdata/vectors/v1/` as a
///   place that happens. Those are ignorable; that is Q140.
/// - The patterns below are there because the file is DANGEROUS (`.gitignore`
///   opens with "no secret material may ever be committable by default") or is
///   devnet runtime state. Silently skipping a key-shaped file that turned up
///   inside the frozen vector tree is the opposite of what that rule wants —
///   it should be as loud as possible. They stay fatal on purpose.
///
/// `*wallet*.json` is excluded twice over: it ends in `.json`, and the
/// ignorable arm runs AFTER the `*.json` arm (D116 R7), so this walk sees a
/// vector regardless of what this list says.
const GITIGNORE_PATTERNS_DELIBERATELY_FATAL: &[&str] = &[
    "*.key",
    "*.pem",
    "wallets/",
    "*wallet*.json",
    ".secrets/",
    "devnet-data/",
    "*.devnet/",
    ".devnet/",
];

/// Expand a gitignore character class (`*.py[cod]` → `*.pyc`, `*.pyo`,
/// `*.pyd`). Any other glob metacharacter is left alone: this only has to
/// understand the patterns the file actually uses.
fn expand_classes(pattern: &str) -> Vec<String> {
    let Some(open) = pattern.find('[') else {
        return vec![pattern.to_owned()];
    };
    let Some(close) = pattern[open..].find(']').map(|i| open + i) else {
        return vec![pattern.to_owned()];
    };
    let mut out = Vec::new();
    for choice in pattern[open + 1..close].chars() {
        let expanded = format!("{}{choice}{}", &pattern[..open], &pattern[close + 1..]);
        out.extend(expand_classes(&expanded));
    }
    out
}

/// Every `.gitignore` pattern that can match a bare NAME under the vector
/// tree must be either ignorable here or deliberately, explicitly fatal.
///
/// This is the instrument that closes Q140's actual diagnosis. The bug was
/// never "`__pycache__` is missing from a list" — it was that the repository
/// held **two rules that disagreed** about whether a file was expected, and
/// the build-breaking one won silently. Adding the name to `IGNORED_DIRS`
/// fixes today's collision; this test is what makes the next one impossible
/// to introduce without saying so out loud.
///
/// One-directional by design: `IGNORED_*` may be a superset (it carries
/// `.swo` and `.pyd`, which `.gitignore` does not list), because being
/// tolerant of a file git would have tracked is not a build failure.
#[test]
fn vector_gitignore_expected_names_cannot_brick_the_build() {
    let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.gitignore"));
    let text =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    let mut uncovered = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        // Anchored (`/target`) and path-bearing (`fuzz/corpus/`) patterns
        // cannot match a bare name inside `vectors/v<n>/`, so they cannot
        // produce the Q140 collision.
        let interior = line.strip_suffix('/').unwrap_or(line);
        if interior.contains('/') {
            continue;
        }
        if GITIGNORE_PATTERNS_DELIBERATELY_FATAL.contains(&line) {
            continue;
        }
        let is_dir_pattern = line.ends_with('/');
        for candidate in expand_classes(interior) {
            let covered = if is_dir_pattern {
                IGNORED_DIRS.contains(&candidate.as_str())
            } else if let Some(suffix) = candidate.strip_prefix('*') {
                IGNORED_SUFFIXES.contains(&suffix)
            } else {
                IGNORED_NAMES.contains(&candidate.as_str())
                    || IGNORED_DIRS.contains(&candidate.as_str())
            };
            if !covered {
                uncovered.push(format!("`{line}` (as `{candidate}`)"));
            }
        }
    }

    assert!(
        uncovered.is_empty(),
        ".gitignore declares {} expected anywhere in the tree, but the vector discovery \
         walk would classify a matching file under testdata/vectors/v<n>/ as unclassifiable \
         and FAIL THE BUILD. Two rules that disagree about whether a file is expected is the \
         Q140 defect; add it to IGNORED_* (D116 R7) or exclude the pattern in \
         GITIGNORE_PATTERNS_DELIBERATELY_FATAL with the reason.",
        uncovered.join(", "),
    );
}
