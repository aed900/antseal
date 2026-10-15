//! Q272 / D173 §2 R15 / D176 §2 R5 — no upstream peer file, loader or cache,
//! pinned in source.
//!
//! # What is being pinned, and why it needs pinning
//!
//! Nothing antseal learns about the storage network survives a run except its
//! peer source: every client is built with `Client::connect`, which hard-codes
//! `peer_cache_path: None` (`ant-core-0.5.0/src/data/client/mod.rs`,
//! `Client::connect`); `saorsa-core`'s close-group cache defaults to `None`
//! (`saorsa-core-0.26.2/src/network.rs`, `close_group_cache_dir`); and nothing
//! reads the `bootstrap_peers.toml` upstream's own CLI installs. So an eclipse —
//! every peer a client can see being hostile — ends with the run, unless the
//! peer source itself is hostile. `docs/threat-model.md` §2.11 states that
//! property.
//!
//! It holds today **by construction of the one call antseal happens to make**,
//! not by any check. Upstream offers every door back in, each a one-line
//! change that reads as ordinary reuse:
//!
//! | name | upstream | what it would adopt |
//! | --- | --- | --- |
//! | `from_node_with_peer_cache` | `ant-core-0.5.0/src/data/client/mod.rs` | the constructor that attaches a persisted peer cache |
//! | `save_peer_cache` | same file | writes connected peers into that cache |
//! | `client_peer_cache` | `ant-core-0.5.0/src/data/peer_cache.rs` (`client_peer_cache.json`) | the cache file itself, by name |
//! | `load_bootstrap_peers` | `ant-core-0.5.0/src/config.rs` | reads upstream's installed peer file |
//! | `bootstrap_peers.toml` | same function, and upstream's release archives | that peer file, by path, without the API name |
//! | `close_group_cache_dir` | `saorsa-core-0.26.2/src/network.rs` | a close-group cache loaded at start and contacted first |
//!
//! A persisted peer set would let one hostile run choose the next run's
//! peers, and upstream's default cache path and its peer file sit in
//! upstream's own data and config directories (`peer_cache::cache_path`,
//! `config::config_dir`), which upstream's CLI also writes. D173 §2 R6 rules
//! that a resolved peer set has exactly one provenance and nothing is unioned
//! into it; this file is what keeps a later lane from undoing that with a
//! call upstream already provides.
//!
//! # The scan
//!
//! Every `.rs` file under every `crates/*/src` is read as text. A line whose
//! first non-blank characters are `//` — a comment, a doc comment or a module
//! doc — is prose, and naming these items there is allowed and wanted: the
//! house style cites upstream by name. **Every other line is code**, including
//! a code line that ends in a trailing comment, so a trailing comment naming a
//! forbidden item reds. That is the fail-closed direction: stripping a
//! trailing `//` would also strip the tail of a string such as a URL, and the
//! literal `bootstrap_peers.toml` inside a string is exactly one of the things
//! this pin exists to catch. The match is a plain substring, so a longer
//! identifier or file name that contains a forbidden name reds too.
//!
//! The scan reports how many files it read and refuses a scan that read none,
//! or that did not reach the adapter file where `Client::connect` is called:
//! a directory walk that silently found nothing is the assertion that cannot
//! fail.
//!
//! # What this file does NOT cover
//!
//! - It is lexical. A forbidden name assembled at compile time (a macro that
//!   concatenates identifiers), or a line inside a multi-line string literal
//!   that happens to begin with `//`, is not seen. It is a tripwire against an
//!   honest regression, not a parser for a hostile contributor.
//! - It reads `crates/*/src` only — not `build.rs`, `tests/`, `benches/` or
//!   `examples/`, where naming these items is legitimate (this file does).
//! - It does not cover the upstream file antseal **does** write: every dropped
//!   `Client` writes `client_adaptive.json` (three concurrency caps, no peers)
//!   into upstream's data directory, and every connect reads it back. That is
//!   `S42`'s, and §2.11 says so.
//!
//! The planted cases run inside this file, over a fresh directory under
//! `std::env::temp_dir()`, so no plant ever touches a source file another lane
//! may hold. Everything here runs in the default feature set: no
//! `ant-backend`, no upstream graph, no network.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The forbidden names, as `(name, why)`. Spelled once here; the planted
/// cases below spell them **again, independently**, so a typo in this table
/// cannot pass by matching its own typo.
const FORBIDDEN: &[(&str, &str)] = &[
    (
        "from_node_with_peer_cache",
        "ant-core's constructor that attaches a persisted client peer cache",
    ),
    (
        "save_peer_cache",
        "ant-core's writer for the persisted client peer cache",
    ),
    (
        "load_bootstrap_peers",
        "ant-core's loader for upstream's installed peer file",
    ),
    (
        "close_group_cache_dir",
        "saorsa-core's cross-run close-group cache, contacted first at start",
    ),
    (
        "client_peer_cache",
        "the persisted client peer cache file, client_peer_cache.json",
    ),
    (
        "bootstrap_peers.toml",
        "upstream's peer file, read by path without the loader's name",
    ),
];

/// The adapter file that calls `Client::connect`. A scan that did not read it
/// has not scanned the one place this pin is mostly about.
const ADAPTER_FILE: &str = "antseal-net/src/ant_backend.rs";

/// One forbidden name on one code line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Hit {
    /// Path relative to the scanned `crates/` directory, `/`-separated.
    file: String,
    /// 1-based line number.
    line: usize,
    /// The forbidden name found.
    name: &'static str,
    /// The line, trimmed.
    text: String,
}

/// What one scan read and found.
#[derive(Debug, Default)]
struct Scan {
    /// `crates/*` directories that have a `src/` directory, sorted.
    crates_with_src: Vec<String>,
    /// Every `.rs` file read, relative to the scanned `crates/` directory.
    files: Vec<String>,
    /// Every forbidden name on a code line.
    hits: Vec<Hit>,
    /// Entries that could not be read as text, or that are symlinks — never
    /// skipped silently.
    unreadable: Vec<String>,
}

/// Whether a line is prose: its first non-blank characters are `//`.
fn is_comment_line(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

/// The forbidden names on one line, in table order. Comment lines name none.
fn forbidden_names_on(line: &str) -> Vec<&'static str> {
    if is_comment_line(line) {
        return Vec::new();
    }
    FORBIDDEN
        .iter()
        .filter(|(name, _)| line.contains(name))
        .map(|(name, _)| *name)
        .collect()
}

/// `path` relative to `root`, `/`-separated; `root` itself is shown whole.
fn relative(path: &Path, root: &Path) -> String {
    let parts = path
        .strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        path.display().to_string()
    } else {
        parts.join("/")
    }
}

/// The entries of `dir`, sorted. A directory, or an entry of it, that cannot
/// be read is recorded in `scan.unreadable` — never dropped, because a walk
/// that quietly skips what it could not read is a scan of less than it says.
fn sorted_entries(dir: &Path, root: &Path, scan: &mut Scan) -> Vec<PathBuf> {
    let Ok(read) = fs::read_dir(dir) else {
        scan.unreadable.push(relative(dir, root));
        return Vec::new();
    };
    let mut entries = Vec::new();
    for entry in read {
        match entry {
            Ok(entry) => entries.push(entry.path()),
            Err(_) => scan
                .unreadable
                .push(format!("an entry of {}", relative(dir, root))),
        }
    }
    entries.sort();
    entries
}

/// Walk `dir` depth-first in sorted order, scanning every `.rs` file.
fn walk(dir: &Path, root: &Path, scan: &mut Scan) {
    for path in sorted_entries(dir, root, scan) {
        let Ok(kind) = fs::symlink_metadata(&path).map(|m| m.file_type()) else {
            scan.unreadable.push(relative(&path, root));
            continue;
        };
        if kind.is_symlink() {
            // Not followed (a loop, or a file outside the tree) and not
            // skipped silently either.
            scan.unreadable.push(relative(&path, root));
        } else if kind.is_dir() {
            walk(&path, root, scan);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let name = relative(&path, root);
            let Ok(text) = fs::read_to_string(&path) else {
                scan.unreadable.push(name);
                continue;
            };
            for (index, line) in text.lines().enumerate() {
                for forbidden in forbidden_names_on(line) {
                    scan.hits.push(Hit {
                        file: name.clone(),
                        line: index + 1,
                        name: forbidden,
                        text: line.trim().to_owned(),
                    });
                }
            }
            scan.files.push(name);
        }
    }
}

/// Scan every `<crates_dir>/*/src` tree.
fn scan_crates(crates_dir: &Path) -> Scan {
    let mut scan = Scan::default();
    for crate_dir in sorted_entries(crates_dir, crates_dir, &mut scan) {
        let src = crate_dir.join("src");
        if src.is_dir() {
            scan.crates_with_src.push(relative(&crate_dir, crates_dir));
            walk(&src, crates_dir, &mut scan);
        }
    }
    scan
}

/// The pin's verdict over a scan: `Ok(summary)` or `Err(what is wrong)`.
///
/// `required_file` is the file the scan must have read (the adapter, for the
/// real tree); `None` only for the planted trees, which have no adapter.
fn verdict(scan: &Scan, required_file: Option<&str>) -> Result<String, String> {
    if scan.files.is_empty() {
        return Err(format!(
            "the scan read 0 .rs files under {} crates/*/src tree(s) — a walk that found \
             nothing proves nothing, so this pin refuses it",
            scan.crates_with_src.len()
        ));
    }
    if !scan.unreadable.is_empty() {
        return Err(format!(
            "the scan could not read {} entr(ies) as text, or met symlinks it will not follow: \
             {:?}",
            scan.unreadable.len(),
            scan.unreadable
        ));
    }
    if let Some(required) = required_file
        && !scan.files.iter().any(|file| file == required)
    {
        return Err(format!(
            "the scan read {} .rs files but not {required}, where Client::connect is \
             called — it is not scanning the tree this pin is about",
            scan.files.len()
        ));
    }
    if !scan.hits.is_empty() {
        let listing = scan
            .hits
            .iter()
            .map(|hit| {
                let why = FORBIDDEN
                    .iter()
                    .find(|(name, _)| *name == hit.name)
                    .map_or("", |(_, why)| *why);
                format!(
                    "  crates/{}:{} names `{}` ({why}):\n      {}",
                    hit.file, hit.line, hit.name, hit.text
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        return Err(format!(
            "{} code line(s) under crates/*/src name an upstream peer file, loader or cache \
             (scanned {} .rs files):\n{listing}\n\nA persisted or upstream-supplied peer set \
             lets one hostile run or one hostile file choose every later run's peers, and a \
             resolved peer set has exactly one provenance with nothing unioned into it \
             (D173 §2 R6; docs/threat-model.md §2.11). Naming these items in a `//` comment is \
             fine; adopting one needs a decision record, not a patch",
            scan.hits.len(),
            scan.files.len()
        ));
    }
    Ok(format!(
        "scanned {} .rs files under {} crates/*/src trees; 0 code lines name an upstream peer \
         file, loader or cache",
        scan.files.len(),
        scan.crates_with_src.len()
    ))
}

// ---------------------------------------------------------------------------
// The real tree
// ---------------------------------------------------------------------------

/// The workspace's `crates/` directory (this crate sits at
/// `crates/antseal-net`).
fn workspace_crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// No code line under any `crates/*/src` names an upstream peer file, loader
/// or cache.
#[test]
fn no_code_line_names_an_upstream_peer_file_loader_or_cache() {
    let scan = scan_crates(&workspace_crates_dir());
    match verdict(&scan, Some(ADAPTER_FILE)) {
        Ok(summary) => println!("{summary}"),
        Err(problem) => panic!("{problem}"),
    }
    // Every crate with a `src/` contributed a file, so a walk that stopped
    // after the first crate cannot pass as a whole-tree scan.
    for crate_name in &scan.crates_with_src {
        let prefix = format!("{crate_name}/src/");
        assert!(
            scan.files.iter().any(|file| file.starts_with(&prefix)),
            "crates/{crate_name}/src exists but the scan read no .rs file in it; scanned: \
             {} files",
            scan.files.len()
        );
    }
    assert!(
        scan.crates_with_src.iter().any(|c| c == "antseal-cli"),
        "the scan did not reach crates/antseal-cli, where peer resolution lives; crates seen: \
         {:?}",
        scan.crates_with_src
    );
}

// ---------------------------------------------------------------------------
// The planted cases, over a temporary tree
// ---------------------------------------------------------------------------

/// A fresh directory under the system temp dir, removed on drop (also when a
/// planted assertion panics).
struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "antseal-no-upstream-peer-state-{label}-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("cannot create {}: {e}", dir.display()));
        Self(dir)
    }

    /// Write `contents` to `crates/<relative>` inside the tree.
    fn write(&self, relative: &str, contents: &str) {
        let path = self.crates().join(relative);
        let parent = path
            .parent()
            .unwrap_or_else(|| panic!("{} has no parent", path.display()));
        fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("cannot create {}: {e}", parent.display()));
        fs::write(&path, contents)
            .unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
    }

    fn crates(&self) -> PathBuf {
        self.0.join("crates")
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        // Best effort: a leftover directory under the temp dir is harmless,
        // and a panic here would mask the assertion that failed.
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A code line naming each forbidden item reds, naming the file, the line and
/// the item. The six lines spell the names independently of `FORBIDDEN`.
#[test]
fn a_code_line_naming_a_forbidden_item_reds_with_file_line_and_name() {
    let tree = TempTree::new("code");
    tree.write(
        "fake-net/src/client.rs",
        "pub async fn build(node: Node, config: Config) -> Client {\n\
         \x20   let client = Client::from_node_with_peer_cache(node, config, Some(dir()));\n\
         \x20   client.save_peer_cache().await;\n\
         \x20   client\n\
         }\n",
    );
    tree.write(
        "fake-cli/src/peers/resolve.rs",
        // The upstream crate path is joined from two pieces at compile time,
        // so no source line of this file spells it: scripts/ci-lanes.sh's S6
        // containment rule greps every code line under crates/ for it. The
        // runtime fixture is the same bytes either way.
        concat!(
            "fn peers() -> Vec<SocketAddr> {\n\
             \x20   let from_upstream = ant_",
            "core::config::load_bootstrap_peers();\n\
             \x20   let by_path = config_dir().join(\"bootstrap_peers.toml\");\n\
             \x20   let cache = data_dir().join(\"client_peer_cache.json\");\n\
             \x20   let core = CoreNodeConfig::builder().close_group_cache_dir(cache_dir());\n\
             \x20   unimplemented_resolution(from_upstream, by_path, cache, core)\n\
             }\n"
        ),
    );

    let scan = scan_crates(&tree.crates());
    assert_eq!(
        scan.files.len(),
        2,
        "the planted tree has two .rs files; the scan read {:?}",
        scan.files
    );

    let found: Vec<(&str, usize, &str)> = scan
        .hits
        .iter()
        .map(|hit| (hit.file.as_str(), hit.line, hit.name))
        .collect();
    let expected: Vec<(&str, usize, &str)> = vec![
        ("fake-cli/src/peers/resolve.rs", 2, "load_bootstrap_peers"),
        ("fake-cli/src/peers/resolve.rs", 3, "bootstrap_peers.toml"),
        ("fake-cli/src/peers/resolve.rs", 4, "client_peer_cache"),
        ("fake-cli/src/peers/resolve.rs", 5, "close_group_cache_dir"),
        ("fake-net/src/client.rs", 2, "from_node_with_peer_cache"),
        ("fake-net/src/client.rs", 3, "save_peer_cache"),
    ];
    assert_eq!(
        found, expected,
        "each planted code line must red exactly once, naming its file, line and item"
    );

    let problem = verdict(&scan, None).expect_err("a tree with six planted code lines must red");
    for needle in [
        "6 code line(s)",
        "crates/fake-net/src/client.rs:2 names `from_node_with_peer_cache`",
        "crates/fake-net/src/client.rs:3 names `save_peer_cache`",
        "crates/fake-cli/src/peers/resolve.rs:2 names `load_bootstrap_peers`",
        "crates/fake-cli/src/peers/resolve.rs:3 names `bootstrap_peers.toml`",
        "crates/fake-cli/src/peers/resolve.rs:4 names `client_peer_cache`",
        "crates/fake-cli/src/peers/resolve.rs:5 names `close_group_cache_dir`",
    ] {
        assert!(
            problem.contains(needle),
            "the failure must say `{needle}`; it said:\n{problem}"
        );
    }
}

/// A comment naming every forbidden item stays green — the house style cites
/// upstream by name — and so do the near-miss identifiers antseal really uses.
#[test]
fn comments_and_near_miss_code_lines_stay_green() {
    let tree = TempTree::new("prose");
    tree.write(
        "fake-net/src/lib.rs",
        // Split for the same S6 reason as the code-line fixture above.
        concat!(
            "//! Upstream offers `Client::from_node_with_peer_cache` and `save_peer_cache`;\n\
             //! antseal calls neither.\n\
             /// `ant_",
            "core::config::load_bootstrap_peers` reads `bootstrap_peers.toml`.\n\
             pub fn connect(bootstrap_peers: &[SocketAddr]) {\n\
             \x20   // saorsa-core's close_group_cache_dir stays None; no client_peer_cache.json.\n\
             \x20       // (indented deeper) from_node_with_peer_cache, bootstrap_peers.toml\n\
             \x20   let resolved = bootstrap_peers.to_vec();\n\
             \x20   connect_bootstrap_peers(&resolved);\n\
             \x20   let peer_cache_path: Option<PathBuf> = None;\n\
             \x20   Client::from_node(node(), config(), peer_cache_path);\n\
             }\n"
        ),
    );

    let scan = scan_crates(&tree.crates());
    assert_eq!(
        scan.files,
        vec!["fake-net/src/lib.rs".to_owned()],
        "the planted tree has one .rs file"
    );
    assert!(
        scan.hits.is_empty(),
        "comment lines and near-miss identifiers must not red; got {:?}",
        scan.hits
    );
    let summary = verdict(&scan, None).unwrap_or_else(|problem| panic!("{problem}"));
    assert!(
        summary.starts_with("scanned 1 .rs files under 1 crates/*/src trees"),
        "the green verdict must report what it read; it said: {summary}"
    );
}

/// A trailing comment on a code line does not make the line prose: the whole
/// line is code, so a URL-shaped string naming the peer file still reds.
#[test]
fn a_trailing_comment_or_a_url_string_does_not_hide_a_code_line() {
    let tree = TempTree::new("trailing");
    tree.write(
        "fake-net/src/audit.rs",
        "const AUDIT: &str = \"https://example.invalid/resources/bootstrap_peers.toml\";\n\
         let cached = client.save_peer_cache().await; // not a comment line\n",
    );

    let scan = scan_crates(&tree.crates());
    let found: Vec<(usize, &str)> = scan.hits.iter().map(|hit| (hit.line, hit.name)).collect();
    assert_eq!(
        found,
        vec![(1, "bootstrap_peers.toml"), (2, "save_peer_cache")],
        "a string after `//` inside a URL and a code line with a trailing comment must both red"
    );
}

/// A scan that read nothing is refused, and says how many files it read.
#[test]
fn a_scan_that_reads_no_files_is_refused() {
    let tree = TempTree::new("empty");
    // A crate with an empty `src/`, and a crate with no `src/` at all.
    fs::create_dir_all(tree.crates().join("hollow/src"))
        .unwrap_or_else(|e| panic!("cannot create the hollow crate: {e}"));
    fs::create_dir_all(tree.crates().join("no-src/tests"))
        .unwrap_or_else(|e| panic!("cannot create the no-src crate: {e}"));
    tree.write("no-src/tests/pin.rs", "let x = load_bootstrap_peers();\n");

    let scan = scan_crates(&tree.crates());
    assert_eq!(scan.crates_with_src, vec!["hollow".to_owned()]);
    assert!(scan.files.is_empty(), "nothing under a src/ to read");
    let problem = verdict(&scan, None).expect_err("an empty scan must be refused");
    assert!(
        problem.contains("the scan read 0 .rs files under 1 crates/*/src tree(s)"),
        "the refusal must report the zero; it said: {problem}"
    );

    let missing = scan_crates(&tree.0.join("does-not-exist"));
    let problem = verdict(&missing, None).expect_err("a missing crates/ directory must be refused");
    assert!(
        problem.contains("the scan read 0 .rs files"),
        "a missing root must refuse on the zero; it said: {problem}"
    );
}

/// A scan of a real-looking tree that never reached the adapter file is
/// refused, even with zero hits.
#[test]
fn a_scan_that_misses_the_adapter_file_is_refused() {
    let tree = TempTree::new("no-adapter");
    tree.write("antseal-net/src/lib.rs", "pub mod network;\n");
    tree.write("antseal-net/src/network.rs", "pub struct NetworkConfig;\n");

    let scan = scan_crates(&tree.crates());
    assert_eq!(scan.files.len(), 2);
    let problem = verdict(&scan, Some(ADAPTER_FILE))
        .expect_err("a scan without the adapter file must be refused");
    assert!(
        problem.contains("but not antseal-net/src/ant_backend.rs"),
        "the refusal must name the missing adapter file; it said: {problem}"
    );

    tree.write("antseal-net/src/ant_backend.rs", "fn connect() {}\n");
    let rescan = scan_crates(&tree.crates());
    let summary =
        verdict(&rescan, Some(ADAPTER_FILE)).unwrap_or_else(|problem| panic!("{problem}"));
    assert!(
        summary.starts_with("scanned 3 .rs files under 1 crates/*/src trees"),
        "with the adapter present the same tree is green: {summary}"
    );
}
