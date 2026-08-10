//! **The census of directory walks over `testdata/vectors/`, and the one
//! ignorable-droppings list they share** (Q157, extending Q140/D116 R7).
//!
//! # Why this file exists
//!
//! Q140 found two walks over the committed vector tree carrying the *same*
//! closed classification rule, where a `__pycache__/` directory or a vim
//! `.swp` file failed the whole workspace build. Its fix put one list behind
//! both. Q157 measured the rest of the tree and found the list was not the
//! whole story: **there are twelve walk sites over this one directory**, in
//! three languages, and they did not agree about what the tree contains.
//!
//! The failure Q140 diagnosed is not "a name is missing from a list" — it is
//! **two rules disagreeing about whether a file is part of the tree, with the
//! build-breaking one winning silently**. That failure needs no closed
//! classification to happen; it needs only two walks and one dropping.
//!
//! # Counting rule
//!
//! A **walk site** is one function that enumerates directory entries under the
//! committed tree at `testdata/vectors/`. Functions are counted, not calls: a
//! root gate and the recursion it hands off to are two sites, because they
//! carry two rules. Shared primitives that only list one directory on behalf
//! of a caller (`sorted_entries`) are not sites — the rule lives in the
//! caller. A walk over a *copy* of the tree is not a site over the tree; the
//! two in `scripts/vector-freeze.sh --self-test` are noted below and excluded.
//!
//! # The census — **twelve sites**, measured 2026-08-10
//!
//! Machine-readable as [`VECTOR_TREE_WALKS`]; `tests/vector_walk_census.rs`
//! holds it to the tree, and fails if a thirteenth Rust site appears without
//! being registered here. Classes:
//!
//! - **closed** — every file must classify or the walk fails. Needs the whole
//!   list: the prune *and* the file arms.
//! - **positive** — selects `*.json` and ignores everything else. Needs the
//!   prune arm only, and **must never be converted to `closed`** (Q157): the
//!   positive filter is the shape that survived Q140.
//! - **version-gate** — lists the root and decides what is a `v<n>/`
//!   directory. Uses no list at all, deliberately (see below).
//!
//! | # | site | scope | class |
//! | --- | --- | --- | --- |
//! | 1 | `wasm-bitmatch/build.rs` `walk_root` | root | version-gate |
//! | 2 | `wasm-bitmatch/build.rs` `walk_version_dir` | `v<n>/`, recursive | closed |
//! | 3 | `antseal-core/tests/vector_runner.rs` `run_tree` | root | version-gate |
//! | 4 | `antseal-core/tests/vector_runner.rs` `walk_version_dir` | `v<n>/`, recursive | closed |
//! | 5 | `antseal-core/tests/vector_freeze.rs` `version_dirs` | root | version-gate |
//! | 6 | `antseal-core/tests/vector_freeze.rs` `collect_json` | `v<n>/`, recursive | positive |
//! | 7 | `antseal-core/tests/vector_index.rs` `version_dirs` | root | version-gate |
//! | 8 | `antseal-core/tests/vector_index.rs` `committed_vectors` | `v<n>/`, recursive | positive |
//! | 9 | `antseal-core/tests/cbor_span_agreement.rs` `committed_byte_strings` | whole tree, recursive | positive |
//! | 10 | `wasm-bitmatch/tests/bitmatch.rs` `walk_committed` | whole tree, recursive | positive |
//! | 11 | `testdata/vectors/v1/crosscheck_cbor.py` `discover` | `v<n>/`, recursive | positive |
//! | 12 | `scripts/vector-freeze.sh` `version_dirs` | root | version-gate |
//!
//! Not sites, and why: `scripts/vector-freeze.sh`'s two `find`s inside the
//! `--self-test` arms walk a scratch `cp -R` copy the script just made, not
//! the committed tree; `vector_index.rs`'s `read_frozen` parses
//! `FROZEN.sha256` and lists no directory at all (it is a second *parser of
//! the manifest*, which is **Q142**, not a walk).
//!
//! # What each class does with the list, and why the root uses none
//!
//! `IGNORED_DIRS` is a **prune**, and *every recursive site obeys it* —
//! including the positive ones. This is the Q157 fix and it is not cosmetic:
//! with `.vscode/settings.json` planted under `testdata/vectors/v1/` (a file
//! `.gitignore:49` declares expected), sites 1–4 pruned it and sites 6, 8, 9
//! and 10 did not, so **eight tests across four test targets failed** on a
//! git-ignored dropping — one of them advising a rebuild that could never
//! help, because the stale-table message cannot tell "the build is behind"
//! from "the two walks disagree". Measured 2026-08-10; that is Q140's exact
//! diagnosis, four sites wider than Q140 knew.
//!
//! `IGNORED_SUFFIXES`/`IGNORED_NAMES` are only meaningful where an unknown
//! *file* is fatal, so only the two `closed` sites carry them. A positive site
//! needs no such list: an unknown file is already ignored, which is why
//! `collect_json` was green through the whole of Q140. That tolerance is now
//! deliberate rather than accidental — it is written here, and it is what the
//! `Do` of Q157 forbids anyone to "fix".
//!
//! The three `version-gate` sites use no list on purpose. D116 R7 ruled that a
//! stray directory sitting **directly under `vectors/`** stays fatal: nothing
//! imports a module from there, and loosening the root would let a whole stray
//! tree in unnoticed. The Python checkers live in `v1/`, so that is where
//! `__pycache__/` actually appears. `scripts/vector-freeze.sh`'s gate is the
//! odd one out — `find -name 'v[0-9]*'` *skips* a stray root directory rather
//! than failing on it — which is safe only because sites 1, 3, 5 and 7 all
//! fail on it loudly; it is recorded here rather than changed, because a shell
//! script that hard-fails on a directory it was not asked about is a worse
//! trade than four Rust sites that already do.

#![allow(
    dead_code,
    reason = "each of the four consumers uses a different subset of this module"
)]

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
/// The two halves belong to different WALK CLASSES (census above, Q157).
/// `IGNORED_DIRS` is a prune every recursive walk over the tree obeys, because
/// a directory the repository declares absent has to be absent for all of them
/// or they disagree — measured, four of them did. `IGNORED_SUFFIXES` and
/// `IGNORED_NAMES` mean something only where an unknown file is fatal, which
/// is the two `closed` sites and nowhere else; a positive-filter walk needs no
/// such list and must not grow one.
///
/// This block is duplicated VERBATIM in `crates/wasm-bitmatch/build.rs` — a
/// build script cannot import a test module — and `bitmatch.rs` asserts the
/// two texts are byte-identical (D116 R8a). Edit both or neither.
pub const IGNORED_DIRS: &[&str] = &["__pycache__", ".idea", ".vscode"];
pub const IGNORED_SUFFIXES: &[&str] = &[".pyc", ".pyo", ".pyd", ".swp", ".swo"];
pub const IGNORED_NAMES: &[&str] = &[".DS_Store"];

/// A directory the repository declares is not part of the tree.
///
/// Every recursive walk prunes on this — closed and positive alike — so that
/// all of them see the same tree. Pruning (rather than descending and
/// ignoring) is what makes a `*.json` *inside* such a directory invisible
/// instead of a vector that landed unfrozen and unrostered.
pub fn is_ignored_dir(name: &str) -> bool {
    IGNORED_DIRS.contains(&name)
}

/// A file the repository declares is not part of the tree.
///
/// Only a `closed` site needs this: it is the arm that keeps a git-ignored
/// dropping from being reported as an unclassifiable vector. It must always
/// run **after** the `*.json` arm (D116 R7) so it can never swallow a vector.
pub fn is_ignorable_file(name: &str) -> bool {
    IGNORED_NAMES.contains(&name) || IGNORED_SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// What a walk site does with an unknown entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkClass {
    /// Unknown file ⇒ hard failure. Uses the prune arm and the file arms.
    Closed,
    /// Selects `*.json`; everything else is skipped. Prune arm only, and
    /// never to be tightened (Q157).
    Positive,
    /// Lists the tree root and decides what is a `v<n>/` directory. Uses no
    /// ignorable list at all: a stray directory at the root stays fatal
    /// (D116 R7).
    VersionGate,
}

/// One registered walk site over the committed vector tree.
#[derive(Debug, Clone, Copy)]
pub struct Walk {
    /// Repository-relative path, forward slashes on every OS.
    pub file: &'static str,
    /// The function that enumerates directory entries.
    pub function: &'static str,
    pub class: WalkClass,
    /// Why this site's rule is what it is — the "written reason" Q157's
    /// accept requires of any walk that does not share the whole list.
    pub reason: &'static str,
}

/// **The census.** Every walk site over `testdata/vectors/`, in the order the
/// module docs table them. `tests/vector_walk_census.rs` holds this to the
/// tree; adding a thirteenth Rust site without registering it here is red.
pub const VECTOR_TREE_WALKS: &[Walk] = &[
    Walk {
        file: "crates/wasm-bitmatch/build.rs",
        function: "walk_root",
        class: WalkClass::VersionGate,
        reason: "root gate; a stray directory directly under vectors/ stays fatal (D116 R7)",
    },
    Walk {
        file: "crates/wasm-bitmatch/build.rs",
        function: "walk_version_dir",
        class: WalkClass::Closed,
        reason: "embeds every vector at build time, so an unknown file must not be embedded \
                 silently; carries the verbatim copy of the list (a build script cannot import \
                 a test module)",
    },
    Walk {
        file: "crates/antseal-core/tests/vector_runner.rs",
        function: "run_tree",
        class: WalkClass::VersionGate,
        reason: "root gate; the Q4 runner is the site that raises a top-level stray for all of \
                 them (D116 R7)",
    },
    Walk {
        file: "crates/antseal-core/tests/vector_runner.rs",
        function: "walk_version_dir",
        class: WalkClass::Closed,
        reason: "Q4's 'nothing is silently skipped' is this site's whole job: an unclassifiable \
                 file is a vector that would not run",
    },
    Walk {
        file: "crates/antseal-core/tests/vector_freeze.rs",
        function: "version_dirs",
        class: WalkClass::VersionGate,
        reason: "root gate; retention is per version, so a misnamed version directory is a \
                 retention bug and fails here",
    },
    Walk {
        file: "crates/antseal-core/tests/vector_freeze.rs",
        function: "collect_json",
        class: WalkClass::Positive,
        reason: "answers 'is any committed vector outside the freeze?', which is a question \
                 about *.json only; an unknown file is the Q4 runner's business, not this \
                 site's",
    },
    Walk {
        file: "crates/antseal-core/tests/vector_index.rs",
        function: "version_dirs",
        class: WalkClass::VersionGate,
        reason: "root gate; every version directory must carry an INDEX.json roster",
    },
    Walk {
        file: "crates/antseal-core/tests/vector_index.rs",
        function: "committed_vectors",
        class: WalkClass::Positive,
        reason: "answers 'is every committed vector rostered?', a question about *.json only",
    },
    Walk {
        file: "crates/antseal-core/tests/cbor_span_agreement.rs",
        function: "committed_byte_strings",
        class: WalkClass::Positive,
        reason: "harvests *_bytes hex fields out of every committed vector; it PARSES each file \
                 it selects, so a dropping it selects is a panic rather than a skip — the \
                 sharpest reason a positive site still needs the prune arm",
    },
    Walk {
        file: "crates/wasm-bitmatch/tests/bitmatch.rs",
        function: "walk_committed",
        class: WalkClass::Positive,
        reason: "the independent cross-check of build.rs's discovery; it must see exactly the \
                 tree build.rs saw, so it prunes identically or the comparison reports a \
                 disagreement as a stale table",
    },
    Walk {
        file: "testdata/vectors/v1/crosscheck_cbor.py",
        function: "discover",
        class: WalkClass::Positive,
        reason: "D31's deliberately independent CBOR checker; restates the prune in Python \
                 because sharing code with the implementation it cross-checks is the one thing \
                 it must not do",
    },
    Walk {
        file: "scripts/vector-freeze.sh",
        function: "version_dirs",
        class: WalkClass::VersionGate,
        reason: "root gate in shell (`find -name 'v[0-9]*'`); tolerant where the four Rust \
                 gates are fatal, which is safe only because they are fatal — recorded, not \
                 changed",
    },
];

/// The count, stated as a number so a thirteenth site is added knowingly.
pub const VECTOR_TREE_WALK_COUNT: usize = VECTOR_TREE_WALKS.len();
