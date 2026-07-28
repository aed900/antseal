//! F12 — the manifest golden-vector **generator and regenerator**.
//!
//! The Q4 runner (`vector_runner.rs`) executes the committed
//! `testdata/vectors/v1/manifest/manifest.json` like any other vector. This
//! file adds the two things a byte-level format freeze needs on top:
//!
//! 1. **Generation is in-repo and reproducible.** [`document`] builds the
//!    whole vector — envelope, `inputs` and `expect` — from a case table and
//!    R6's fixture constructor. Running the suite with
//!    `ANTSEAL_BLESS_VECTORS=1` rewrites the committed file from it, which is
//!    how the file was produced in the first place; without the variable the
//!    suite only ever *compares*.
//! 2. **Drift fails CI.** The committed document is diffed against a fresh
//!    generation, so any change to the codec, the registry, the fixture
//!    constants or R6's construction turns this red with the offending field
//!    named — rather than silently producing a manifest that no longer means
//!    what the vector says.
//!
//! Four independent regenerations therefore stand behind the committed
//! artifact:
//!
//! | who | independence |
//! | --- | --- |
//! | this test | the whole document, from `inputs` through the public API |
//! | the Q4 runner | decodes the committed bytes and re-encodes them |
//! | `crates/wasm-bitmatch` (Q5) | the same executor under `wasm32-unknown-unknown`, byte-compared |
//! | F14 | a second CBOR implementation (Python `cbor2`, decision D12) against the diagnostic sidecars |
//!
//! Test names carry the reserved `vector_` marker so the three `cross-os-*`
//! CI lanes run them everywhere (CONTRIBUTING.md, "Cross-OS suite naming") —
//! the document is pure hex, integers and ASCII, so it must regenerate
//! identically on Linux, macOS and Windows.

use std::fs;
use std::path::PathBuf;

use antseal_core::test_util::TEST_MASTER_SECRET_W;
use antseal_core::test_util::bundle_fixtures::{
    DEFAULT_SEED, FIXTURE_APP_VERSION, FIXTURE_CLAIMED_TIME, FIXTURE_SEAL_ID, Selection, WorkSpec,
    build, shapes,
};
use antseal_core::test_util::vectors::first_difference;
use antseal_core::test_util::vectors_manifest::{KIND, regenerate_expect};
use serde_json::{Value, json};

/// The committed document (workspace-relative via the crate manifest dir, so
/// it resolves on every OS and checkout location).
const VECTOR_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/manifest/manifest.json"
);

/// Top-level field order of a written vector file. Not a schema rule — the
/// envelope is a JSON object and order is immaterial to every consumer — but
/// a committed artifact that reorders itself on every regeneration would make
/// the freeze diff unreadable.
const FIELD_ORDER: [&str; 8] = [
    "schema",
    "schema_version",
    "format_version",
    "kind",
    "non_secret",
    "description",
    "inputs",
    "expect",
];

const NON_SECRET: &str = "NON-SECRET test fixture (project rule 6): every commitment, key, salt, \
     signature and fine-tree root below derives from the documented fixed test seed W = \
     0x00..0x1f (testdata/README.md) through R6's deterministic fixture constructor. The \
     seal_id, app_version, claimed_time and content addresses are published fixture \
     constants. Never real vault, wallet or author material.";

const DESCRIPTION: &str = "Manifest golden vectors (F12): canonical deterministic-CBOR manifest \
     envelope bytes, a two-layer diagnostic sidecar (the F14 independent-CBOR cross-check target), \
     and the work_id/anchor_digest each manifest hashes to — which is also where F7's deferred \
     committed-digest artifact lands. Cases cover a minimal single-file binary work under both \
     sig_policy shapes, a text file with a raw-mirror unit, a --no-fine-tree file carrying \
     unit_commit, an empty-file unit, and a multi-file multi-unit body (MVP-SPEC.md lines 73, 75, \
     98, 153, 167).";

// ---------------------------------------------------------------------------
// the case table
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn file(path: &str, kind: &str, raw: &[u8], fine_tree: bool, split: &[u64]) -> Value {
    json!({
        "path": path,
        "kind": kind,
        "raw": hex(raw),
        "fine_tree": fine_tree,
        "split": split,
    })
}

fn case(name: &str, title: &str, policy: &str, files: Vec<Value>) -> Value {
    json!({
        "name": name,
        "title": title,
        "policy": policy,
        "seed": DEFAULT_SEED,
        "files": files,
    })
}

/// The blob file `shapes::single_binary` seals.
fn blob64() -> Vec<u8> {
    (0u8..64).collect()
}

/// The split binary file of `shapes::multi_file`.
fn blob30() -> Vec<u8> {
    (0u8..30).collect()
}

fn cases() -> Vec<Value> {
    let minimal = || vec![file("data/blob.bin", "binary", &blob64(), true, &[])];
    vec![
        // The reference manifest: one binary file, one fine-tree-covered
        // unit, the default hybrid policy.
        case(
            "minimal-binary-hybrid",
            "single binary",
            "hybrid",
            minimal(),
        ),
        // The identical work under the Ed25519-only fallback (spec line 97):
        // a one-field diff against the case above.
        case(
            "minimal-binary-ed25519-only",
            "single binary",
            "ed25519-only",
            minimal(),
        ),
        // A CRLF source, so G7 emits the raw mirror as the file's last unit
        // (D23) and the file carries `canon_commit`.
        case(
            "text-with-raw-mirror",
            "single text with mirror",
            "ed25519-only",
            vec![file("notes/intro.md", "text", shapes::CRLF_TEXT, true, &[])],
        ),
        // `--no-fine-tree`: no `fine_root`, and the unit carries
        // `unit_commit` instead (spec lines 84, 94).
        case(
            "no-fine-tree-unit-commit",
            "no fine tree",
            "ed25519-only",
            vec![file(
                "archive/old.txt",
                "text",
                shapes::CANONICAL_TEXT,
                false,
                &[],
            )],
        ),
        // The empty file: `size` 0, `true_length` 0, exactly one unit, and
        // no fine tree — G4's rule, expressed by asking for one and having
        // the constructor decline (there is no leaf to hash).
        case(
            "empty-file-unit",
            "empty file",
            "ed25519-only",
            vec![file("data/empty.bin", "binary", b"", true, &[])],
        ),
        // The richest shape under the default policy: three files, a
        // `--split` tiling, a raw mirror and a `--no-fine-tree` file.
        case(
            "multi-file-multi-unit",
            "multi file",
            "hybrid",
            vec![
                file("notes/intro.md", "text", shapes::CRLF_TEXT, true, &[]),
                file("data/blob.bin", "binary", &blob30(), true, &[10, 10, 10]),
                file(
                    "archive/old.txt",
                    "text",
                    shapes::CANONICAL_TEXT,
                    false,
                    &[],
                ),
            ],
        ),
    ]
}

/// Which committed case reproduces which R6 named shape, under the policy the
/// case declares. This is the anti-drift tie: the vector describes its works
/// declaratively (so the frozen file does not name a Rust function), and this
/// pairing is what stops the two descriptions from parting company (R29).
fn shape_parity() -> Vec<(&'static str, WorkSpec)> {
    vec![
        ("minimal-binary-hybrid", shapes::single_binary()),
        (
            "minimal-binary-ed25519-only",
            shapes::single_binary().with_ed25519_only_policy(),
        ),
        (
            "text-with-raw-mirror",
            shapes::single_text_with_mirror().with_ed25519_only_policy(),
        ),
        (
            "no-fine-tree-unit-commit",
            shapes::no_fine_tree().with_ed25519_only_policy(),
        ),
        (
            "empty-file-unit",
            shapes::empty_file().with_ed25519_only_policy(),
        ),
        ("multi-file-multi-unit", shapes::multi_file()),
    ]
}

// ---------------------------------------------------------------------------
// generation
// ---------------------------------------------------------------------------

/// The whole vector document, generated from the case table.
fn document() -> Value {
    let mut doc = json!({
        "schema": "antseal-golden-vector",
        "schema_version": 1,
        "format_version": "v1",
        "kind": KIND,
        "non_secret": NON_SECRET,
        "description": DESCRIPTION,
        "inputs": {
            "w": hex(&TEST_MASTER_SECRET_W),
            "seal_id": hex(&FIXTURE_SEAL_ID),
            "app_version": FIXTURE_APP_VERSION,
            "claimed_time": FIXTURE_CLAIMED_TIME,
            "cases": cases(),
        },
        "expect": Value::Null,
    });
    let expect = regenerate_expect(&doc).unwrap_or_else(|e| panic!("generating `expect`: {e}"));
    doc["expect"] = expect;
    doc
}

/// Render a document with a stable top-level field order.
fn render(document: &Value) -> String {
    let mut out = String::from("{\n");
    for (index, key) in FIELD_ORDER.iter().enumerate() {
        let value = document
            .get(*key)
            .unwrap_or_else(|| panic!("generated document has no `{key}`"));
        let body = serde_json::to_string_pretty(value)
            .unwrap_or_else(|e| panic!("rendering `{key}`: {e}"))
            .replace('\n', "\n  ");
        out.push_str("  \"");
        out.push_str(key);
        out.push_str("\": ");
        out.push_str(&body);
        if index + 1 < FIELD_ORDER.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("}\n");
    out
}

fn committed_document() -> Value {
    let path = PathBuf::from(VECTOR_PATH);
    let bytes = fs::read(&path)
        .unwrap_or_else(|e| panic!("{}: the F12 vector must exist: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("{}: not valid JSON: {e}", path.display()))
}

/// `ANTSEAL_BLESS_VECTORS=1` rewrites the committed file from the generator.
///
/// Deliberately opt-in and loud: regenerating a frozen vector is a reviewed
/// event (`testdata/vectors/README.md`, "What changes at Q14"), never
/// something a test run does on its own.
fn blessing() -> bool {
    std::env::var_os("ANTSEAL_BLESS_VECTORS").is_some()
}

// ---------------------------------------------------------------------------
// the tests
// ---------------------------------------------------------------------------

/// **The F12 generator-diff test.** Regenerate the whole document and require
/// it to equal what is committed, field for field.
#[test]
fn vector_manifest_document_regenerates() {
    let generated = document();
    if blessing() {
        let path = PathBuf::from(VECTOR_PATH);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|e| panic!("creating {parent:?}: {e}"));
        }
        fs::write(&path, render(&generated))
            .unwrap_or_else(|e| panic!("{}: writing the vector: {e}", path.display()));
    }
    let committed = committed_document();
    assert!(
        generated == committed,
        "the committed manifest vector no longer matches what antseal-core computes.\n\
         First difference: {}\n\
         If this is a deliberate format change it is a FORMAT EVENT \
         (testdata/vectors/README.md): regenerate with \
         `ANTSEAL_BLESS_VECTORS=1 cargo test -p antseal-core vector_manifest`, re-run \
         `scripts/vector-freeze.sh --update`, and justify the digest diff in the commit.",
        first_difference("document", &generated, &committed)
    );
}

/// The declarative case descriptions really are R6's named shapes.
///
/// Without this, the vector's own `inputs` could drift from
/// `bundle_fixtures::shapes` — two descriptions of "the M0 works" that agree
/// today and quietly stop agreeing later (R29).
#[test]
fn vector_manifest_cases_reproduce_the_r6_named_shapes() {
    let committed = committed_document();
    let cases = committed["expect"]["cases"]
        .as_array()
        .expect("expect.cases is an array");
    for (name, spec) in shape_parity() {
        let case = cases
            .iter()
            .find(|c| c["name"] == json!(name))
            .unwrap_or_else(|| panic!("no committed case named `{name}`"));
        let built = build(&spec, &Selection::nothing(spec.files.len()));
        assert_eq!(
            case["manifest_bytes"],
            json!(hex(&built.manifest)),
            "case `{name}` no longer equals its bundle_fixtures::shapes counterpart"
        );
    }
}

/// A manifest is a function of the **work**, never of what a reveal shows.
///
/// The generator builds each case under `Selection::nothing`; this asserts
/// the committed bytes would have been identical under `--all`, so the vector
/// means "this work's manifest" and not "this work's manifest when nothing is
/// revealed".
#[test]
fn vector_manifest_bytes_are_selection_independent() {
    for (name, spec) in shape_parity() {
        let files = spec.files.len();
        let withheld = build(&spec, &Selection::nothing(files));
        let revealed = build(&spec, &Selection::all(files));
        assert_eq!(
            withheld.manifest, revealed.manifest,
            "case `{name}`: the manifest changed with the reveal selection"
        );
    }
}

/// The rendering is stable: writing a document twice produces identical
/// bytes, so a bless is a no-op diff whenever nothing changed.
#[test]
fn vector_manifest_rendering_is_deterministic() {
    let document = committed_document();
    assert_eq!(render(&document), render(&document));
    let reparsed: Value = serde_json::from_str(&render(&document)).expect("re-parses");
    assert_eq!(reparsed, document, "rendering must be lossless");
}
