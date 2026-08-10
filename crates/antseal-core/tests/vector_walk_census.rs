//! Q157 — **the census of directory walks over `testdata/vectors/` is
//! complete, and every site it names is real.**
//!
//! Q140's diagnosis was never "a name is missing from a list": it was that the
//! repository held **two rules that disagreed** about whether a file was part
//! of the vector tree, and the build-breaking one won silently. That failure
//! scales with the number of walks and nothing counted them. This file counts
//! them, and turns red when a new one appears unregistered.
//!
//! The census itself — the count, the class of each site, and the written
//! reason its rule is what it is — lives in `tests/vector_walk/mod.rs`, beside
//! the list the sites share. This file is only its enforcement.
//!
//! Test names carry the reserved `vector_` marker so the three-OS lane
//! (`cross-os-*`) runs them everywhere: the whole point is a rule that holds
//! on the machine where someone opens an editor in the vector tree.

use std::fs;
use std::path::{Path, PathBuf};

/// The census under test.
#[path = "vector_walk/mod.rs"]
mod vector_walk;

use vector_walk::{VECTOR_TREE_WALK_COUNT, VECTOR_TREE_WALKS, WalkClass};

/// Repository root, from this crate's manifest dir.
fn repo_root() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")).to_path_buf()
}

/// **The count, asserted as a literal.** Not redundant with
/// `VECTOR_TREE_WALKS.len()`: a literal is what makes adding a site a
/// deliberate edit to a number a reviewer can see in a diff, rather than a
/// silent `+1` inside a table. Q157's accept is exactly this — "the count of
/// walks is stated somewhere, so a fifth is added knowingly".
///
/// Measured 2026-08-10, when the row that commissioned this expected five.
#[test]
fn vector_walk_census_states_the_count() {
    assert_eq!(
        VECTOR_TREE_WALK_COUNT, 12,
        "the census now lists {} walk sites over testdata/vectors/, not 12. That is a \
         real change, not a typo: every site is a rule about what the tree contains, \
         and Q140 is what happens when two of them disagree. Update this literal, the \
         table in vector_walk/mod.rs and the count in testdata/vectors/README.md \
         together, and say in the commit which site was added and what class it is.",
        VECTOR_TREE_WALK_COUNT
    );
}

/// Every registered site names a file that exists and a function that is in
/// it. A census that drifts from the tree is worse than none: it reads as
/// coverage while covering nothing.
#[test]
fn vector_walk_census_names_only_real_sites() {
    let root = repo_root();
    let mut missing = Vec::new();
    for walk in VECTOR_TREE_WALKS {
        let path = root.join(walk.file);
        let Ok(text) = fs::read_to_string(&path) else {
            missing.push(format!("{}: file does not exist", walk.file));
            continue;
        };
        // Rust `fn name(`, Python `def name(`, shell `name()`.
        let found = text.contains(&format!("fn {}(", walk.function))
            || text.contains(&format!("def {}(", walk.function))
            || text.contains(&format!("\n{}()", walk.function));
        if !found {
            missing.push(format!(
                "{}: no `{}` in it any more",
                walk.file, walk.function
            ));
        }
        assert!(
            !walk.reason.is_empty(),
            "{} `{}`: a census row with no reason is the state Q157 was filed to end — \
             every walk either shares the whole list or says why it does not",
            walk.file,
            walk.function
        );
    }
    assert!(
        missing.is_empty(),
        "the walk census has drifted from the tree:\n  {}",
        missing.join("\n  ")
    );
}

/// Rust files that walk a directory tree **other** than `testdata/vectors/`
/// while mentioning it, with the tree each one actually walks.
///
/// Every one of these calls `read_dir` and contains the string
/// `testdata/vectors`, so the sweep below sees them; each is exempt because
/// its walk is rooted somewhere else entirely. Verified 2026-08-10 by reading
/// the root constant of each.
const NOT_WALKS_OF_THE_VECTOR_TREE: &[(&str, &str)] = &[
    (
        "crates/antseal-core/tests/codec_fuzz.rs",
        "testdata/fuzz-seeds (SEED_ROOT); names the vector tree only to say the freeze \
         covers that one and not this one",
    ),
    (
        "crates/antseal-core/tests/format_freeze.rs",
        "docs/format (FORMAT_DIR); the wire-registry freeze, which shares only the \
         freeze-manifest parser with the vector freeze",
    ),
    (
        "crates/antseal-core/tests/format_tamper_fixtures.rs",
        "testdata/tamper/format (FORMAT_DIR); names the vector tree to explain which \
         freeze does NOT cover its fixtures",
    ),
];

/// **The sweep.** Any Rust file that both names `testdata/vectors` and lists a
/// directory is either a registered walk site or an explicit exemption.
///
/// This is what makes a thirteenth site an act rather than an accident. Its
/// limit is stated rather than hidden: it sees **Rust** only, so census sites
/// 11 (`crosscheck_cbor.py`) and 12 (`vector-freeze.sh`) are held by
/// `vector_walk_census_names_only_real_sites` above and by nothing else — a
/// *new* walk in a shell script or a Python checker is not caught here. Eight
/// of the twelve are Rust, and the two `closed` sites — the only ones that can
/// fail a build — both are.
#[test]
fn vector_walk_census_covers_every_rust_walk_of_the_tree() {
    let root = repo_root();
    let registered: Vec<&str> = VECTOR_TREE_WALKS.iter().map(|w| w.file).collect();
    let mut scanned = 0usize;
    let mut exempted = 0usize;
    let mut unregistered = Vec::new();

    for path in rust_sources(&root.join("crates")) {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: cannot read: {e}", path.display()));
        scanned += 1;
        if !text.contains("testdata/vectors") || !text.contains("read_dir(") {
            continue;
        }
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string()
            .replace('\\', "/");
        // The census and its enforcement mention every walker by path; they
        // walk `crates/` looking for walkers, never the vector tree.
        if relative.ends_with("tests/vector_walk/mod.rs")
            || relative.ends_with("tests/vector_walk_census.rs")
        {
            continue;
        }
        if let Some((_, why)) = NOT_WALKS_OF_THE_VECTOR_TREE
            .iter()
            .find(|(file, _)| *file == relative)
        {
            assert!(!why.is_empty(), "{relative}: exemption with no reason");
            exempted += 1;
            continue;
        }
        if !registered.contains(&relative.as_str()) {
            unregistered.push(relative);
        }
    }

    assert!(
        scanned > 0,
        "the source sweep found no files — the sweep is broken, not the tree clean"
    );
    assert_eq!(
        exempted,
        NOT_WALKS_OF_THE_VECTOR_TREE.len(),
        "every exemption must match a file the sweep actually reaches — a stale entry \
         silently un-guards a real walk. Reached {exempted} of {}",
        NOT_WALKS_OF_THE_VECTOR_TREE.len()
    );
    assert!(
        unregistered.is_empty(),
        "these files walk a directory and name testdata/vectors, but are neither a \
         registered walk site nor an exemption:\n  {}\n\nA walk over the vector tree \
         has to declare its class in crates/antseal-core/tests/vector_walk/mod.rs — \
         `closed`, `positive` or `version-gate` — with the reason its rule is what it \
         is. Q140 is what an unregistered second rule costs: a git-ignored dropping \
         that fails the workspace build. If it walks some other tree, add it to \
         NOT_WALKS_OF_THE_VECTOR_TREE naming the root it really walks.",
        unregistered.join("\n  "),
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

/// The three classes are not decoration: a `positive` site must never become
/// `closed`, which is the one thing Q157's `Do` forbids outright. Pinning the
/// per-class counts is how a silent reclassification — the shape of the
/// wave-13 defect — shows up as a diff in a number.
#[test]
fn vector_walk_census_class_mix_is_pinned() {
    let count = |class: WalkClass| {
        VECTOR_TREE_WALKS
            .iter()
            .filter(|w| w.class == class)
            .count()
    };
    assert_eq!(
        (
            count(WalkClass::Closed),
            count(WalkClass::Positive),
            count(WalkClass::VersionGate)
        ),
        (2, 5, 5),
        "the class mix moved. Two `closed` sites is the whole exposure to Q140's \
         fatal — a file that classifies as nothing fails a build — and both are \
         supposed to be the vector-embedding and vector-executing walks. A `positive` \
         site turning `closed` is the wave-13 defect being reintroduced, and is \
         forbidden by Q157 in as many words."
    );
}
