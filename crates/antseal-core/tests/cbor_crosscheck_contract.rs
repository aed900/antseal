//! F14/F19 — the drift guard between the two implementations of the
//! diagnostic-sidecar rendering.
//!
//! The rendering table exists **twice as executable code** — in Rust
//! (`antseal_core::test_util::vectors_cbor_diag`) and in Python
//! (`testdata/vectors/v1/crosscheck_cbor.py`, the D12/D31 independent
//! cross-check) — and **three times as prose**
//! (`docs/testing/cbor-cross-check.md`, `testdata/vectors/README.md`, and the
//! Rust module docs).
//!
//! That redundancy is the whole point: a second implementation written from
//! the same table is what makes the cross-check evidence rather than a
//! round-trip. But five copies of one rule is a drift hazard, and the freeze
//! gate cannot rest on a promise that somebody will remember to edit all of
//! them. So the agreement is **tested**:
//!
//! - the two executable copies must agree on the numeric bound they enforce;
//! - the two prose copies of the table must be *identical*, row for row;
//! - all five must keep pointing at each other, so a reader who lands on any
//!   one of them finds the rest.
//!
//! This test deliberately does **not** run the Python checker. That is
//! `scripts/cross-check.sh` and the `cross-check` CI lane's job: shelling out
//! to an interpreter from `cargo test` would make the crate's test suite
//! depend on a dev tool that is, by design, not part of the build
//! (`docs/dependency-policy.md` §5).

use std::fs;
use std::path::PathBuf;

use antseal_core::test_util::vectors_cbor_diag::MAX_JSON_SAFE_INT;

/// Repo root, reached from the crate manifest dir so it holds on every OS
/// and in every checkout location (including agent worktrees).
fn repo_root() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

fn read(relative: &str) -> String {
    let path = repo_root().join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()))
}

/// The Python checker's copy of the bound must equal the Rust constant.
///
/// `MAX_JSON_SAFE_INT` is not a stylistic detail: it is the promise that no
/// pinned value in a sidecar can be silently rounded by a reader whose JSON
/// numbers are IEEE doubles. Two implementations enforcing *different* bounds
/// would leave a band of integers one accepts and the other refuses — and the
/// cross-check would disagree with itself rather than with the bytes.
#[test]
fn python_checker_enforces_the_same_json_safe_bound() {
    let source = read("testdata/vectors/v1/crosscheck_cbor.py");
    let line = source
        .lines()
        .find(|line| line.starts_with("MAX_JSON_SAFE_INT = "))
        .expect(
            "testdata/vectors/v1/crosscheck_cbor.py must declare MAX_JSON_SAFE_INT at module level",
        );
    let declared: u64 = line
        .trim_start_matches("MAX_JSON_SAFE_INT = ")
        .trim()
        .parse()
        .expect("MAX_JSON_SAFE_INT must be a plain integer literal so this test can read it");

    assert_eq!(
        declared, MAX_JSON_SAFE_INT,
        "testdata/vectors/v1/crosscheck_cbor.py declares MAX_JSON_SAFE_INT = {declared}, but \
         vectors_cbor_diag::MAX_JSON_SAFE_INT is {MAX_JSON_SAFE_INT}. The two implementations of \
         the rendering table must enforce the same bound (docs/testing/cbor-cross-check.md §3)"
    );
    assert_eq!(
        MAX_JSON_SAFE_INT,
        (1u64 << 53) - 1,
        "the bound is 2^53 - 1, the last integer an IEEE-754 double represents exactly"
    );
}

/// All three prose copies of the rendering table must state the same six rows.
///
/// The table is normative, so "the README says one thing and the contract doc
/// says another" is not a documentation nit — it is two different formats, and
/// the second implementation would be written from whichever copy its author
/// happened to open.
#[test]
fn the_rendering_table_is_stated_identically_everywhere() {
    /// Scrape the table rows, tolerating a `//!` doc-comment prefix so the
    /// Rust module's copy is compared on the same footing as the markdown.
    fn rows(text: &str, what: &str) -> Vec<String> {
        text.lines()
            .map(|line| line.trim().trim_start_matches("//!").trim())
            .filter(|line| line.contains("(major ") && line.starts_with('|'))
            .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .tap_non_empty(what)
    }

    let copies = [
        ("docs/testing/cbor-cross-check.md", "the contract doc"),
        ("testdata/vectors/README.md", "the vector README"),
        (
            "crates/antseal-core/src/test_util/vectors_cbor_diag.rs",
            "the Rust module docs",
        ),
    ]
    .map(|(path, what)| (path, rows(&read(path), what)));

    let (first_path, first) = &copies[0];
    assert_eq!(
        first.len(),
        6,
        "the rendering table has one row per CBOR major type the profile admits (0-5); \
         found {} in {first_path}",
        first.len()
    );
    for (path, table) in &copies[1..] {
        assert_eq!(
            first, table,
            "the rendering table in {first_path} and the copy in {path} have drifted. They are \
             one normative rule stated three times; a change to any of them is a change to the \
             format's diagnostic sidecar (docs/testing/cbor-cross-check.md §8)"
        );
    }
}

/// Every copy of the rule must name the others, so no reader lands on one
/// alone and edits it in isolation.
#[test]
fn the_five_copies_cross_reference_each_other() {
    const CONTRACT: &str = "docs/testing/cbor-cross-check.md";
    const README: &str = "testdata/vectors/README.md";
    const RUST: &str = "crates/antseal-core/src/test_util/vectors_cbor_diag.rs";
    const PYTHON: &str = "testdata/vectors/v1/crosscheck_cbor.py";

    // (source file, the paths it must mention, why)
    let edges: [(&str, &[&str]); 4] = [
        (CONTRACT, &[README, RUST, PYTHON]),
        (README, &[CONTRACT]),
        (RUST, &[CONTRACT, README, PYTHON]),
        (PYTHON, &[CONTRACT, RUST]),
    ];

    for (source, targets) in edges {
        let text = read(source);
        for target in targets {
            assert!(
                text.contains(target),
                "{source} must reference {target}: the rendering table lives in five places and \
                 they only stay in step if each one points at the rest \
                 (docs/testing/cbor-cross-check.md §8)"
            );
        }
    }
}

/// The dev-tool pin must be internally consistent and stay out of the crates.
#[test]
fn the_cbor2_pin_is_exact_and_dev_tool_only() {
    let pin = read("requirements-crosscheck.txt");

    // Exactly one pinned requirement, with `==`. A range would let a future
    // release substitute itself into the freeze gate's evidence silently.
    let requirements: Vec<&str> = pin
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && !line.is_empty() && !line.starts_with("--hash="))
        .collect();
    assert_eq!(
        requirements.len(),
        1,
        "requirements-crosscheck.txt must pin exactly one package; found {requirements:?}"
    );
    let version = requirements[0]
        .trim_end_matches(['\\', ' '])
        .strip_prefix("cbor2==")
        .expect("the pinned requirement is `cbor2==<version>` (D7 §D12 pins it exactly)")
        .to_owned();

    // The pip hashes and the pip-less bootstrap table describe the same
    // artifact set. If they drift, one install path silently stops being
    // pinned to what the other verifies.
    let hashes = pin
        .lines()
        .filter(|l| l.trim().starts_with("--hash=sha256:"))
        .count();
    let boot = pin.lines().filter(|l| l.starts_with("# boot ")).count();
    assert!(
        hashes > 0,
        "requirements-crosscheck.txt must carry --hash lines"
    );
    assert_eq!(
        hashes, boot,
        "requirements-crosscheck.txt has {hashes} --hash rows but {boot} `# boot` rows: pip and \
         the pip-less bootstrap must pin the same artifacts"
    );

    let checker = read("testdata/vectors/v1/crosscheck_cbor.py");
    assert!(
        checker.contains(&format!("CBOR2_VERSION = \"{version}\"")),
        "testdata/vectors/v1/crosscheck_cbor.py must expect exactly the version \
         requirements-crosscheck.txt pins ({version})"
    );

    // D31 §8: cbor2 DECODES only. If the checker ever calls `dumps`, the
    // encoding authority has quietly moved back to the library whose key
    // order is RFC 7049 length-first, and the caveat D31 retired returns.
    assert!(
        !checker.contains("cbor2.dumps"),
        "testdata/vectors/v1/crosscheck_cbor.py must not encode with cbor2: decision D31 makes \
         it a DECODE-only vehicle and the RFC 8949 §4.2.1 encoder ours. (The literal is banned \
         outright, prose included — paraphrase it if you need to discuss it.)"
    );

    // The independence claim is structural, not aspirational: no crate may
    // reach the cross-check implementation. If this ever fails, the artifact
    // has stopped being a second implementation and the freeze gate loses its
    // input (docs/testing/cbor-cross-check.md §6).
    for manifest in ["crates/antseal-core/Cargo.toml", "Cargo.toml"] {
        let text = read(manifest);
        for line in text.lines() {
            let code = line.split('#').next().unwrap_or_default();
            assert!(
                !code.contains("cbor2"),
                "{manifest} names cbor2 outside a comment: it is a DEV TOOL and must never enter \
                 a Rust dependency graph (docs/dependency-policy.md §5, decision D12)"
            );
        }
    }
}

/// Tiny helper so an empty scrape fails as an empty scrape, not as a
/// confusing equality assertion between two empty vectors.
trait TapNonEmpty {
    fn tap_non_empty(self, what: &str) -> Self;
}

impl TapNonEmpty for Vec<String> {
    fn tap_non_empty(self, what: &str) -> Self {
        assert!(
            !self.is_empty(),
            "no rendering-table rows were found in {what}: the scrape is broken, or the table \
             was removed"
        );
        self
    }
}
