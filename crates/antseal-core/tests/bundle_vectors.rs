//! F13 — the `.sealproof` golden-vector **generator and regenerator**.
//!
//! Same contract as F12's `manifest_vectors.rs`: [`document`] builds the whole
//! vector from a case table and R6's fixture constructor,
//! `ANTSEAL_BLESS_VECTORS=1` rewrites the committed file from it, and without
//! the variable the suite only ever **compares** — so any change to the codec,
//! the registry, the anchor placeholders or R6's assembly turns this red with
//! the offending field named.
//!
//! Test names carry the reserved `vector_` marker so the three `cross-os-*`
//! CI lanes run them everywhere (CONTRIBUTING.md, "Cross-OS suite naming").

use std::fs;
use std::path::PathBuf;

use antseal_core::test_util::TEST_MASTER_SECRET_W;
use antseal_core::test_util::bundle_fixtures::{
    DEFAULT_SEED, FIXTURE_APP_VERSION, FIXTURE_CLAIMED_TIME, FIXTURE_SEAL_ID, FileSelection,
    Selection, WorkSpec, build, shapes,
};
use antseal_core::test_util::vectors::first_difference;
use antseal_core::test_util::vectors_bundle::{KIND, regenerate_expect};
use serde_json::{Value, json};

const VECTOR_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/bundle/bundle.json"
);

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

const NON_SECRET: &str = "NON-SECRET test fixture (project rule 6): every key, salt, seed, \
     commitment, signature and disclosed proof node below derives from the documented fixed test \
     seed W = 0x00..0x1f (testdata/README.md) through R6's deterministic fixture constructor. All \
     anchor artifact bytes — .ots blobs, DER tokens, intermediate certificates, the 80-byte \
     Bitcoin header and the receipt payload — are self-labelling SCHEMA-OPAQUE PLACEHOLDERS, not \
     recorded attestations; A swaps in real recorded fixtures at M2 with no schema change. Never \
     real vault, wallet, author or on-chain material.";

const DESCRIPTION: &str = ".sealproof bundle golden vectors (F13): canonical deterministic-CBOR \
     bundle bytes, three-layer diagnostic sidecars (bundle -> embedded manifest envelope -> inner \
     body, the F14 independent-CBOR cross-check target), and the reveal structure each bundle \
     discloses. Cases cover the EMPTY-ANCHOR (UNANCHORED) bundle — the named M0 milestone \
     artifact — a whole-work reveal, a single covered-unit reveal with a leaf-exact sub-cover and \
     boundary paths, a non-covered unit reveal, a full-file reveal with a raw mirror and \
     file_salt/s_root, a bundle with every anchor kind and optional slot populated in both \
     receipt-included and receipt-excluded form, and a bundle that reveals nothing at all \
     (MVP-SPEC.md lines 73, 112-114, 153, 167).";

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

fn work(name: &str, title: &str, policy: &str, files: Vec<Value>) -> Value {
    json!({
        "name": name,
        "title": title,
        "policy": policy,
        "seed": DEFAULT_SEED,
        "files": files,
    })
}

fn case(name: &str, anchors: &str, selection: Vec<Value>, work: Value) -> Value {
    json!({
        "name": name,
        "anchors": anchors,
        "selection": selection,
        "work": work,
    })
}

fn units(indices: &[usize]) -> Value {
    json!({ "units": indices })
}

/// `shapes::single_binary`'s file, under the Ed25519-only policy.
fn single_binary_work() -> Value {
    work(
        "single-binary",
        "single binary",
        "ed25519-only",
        vec![file(
            "data/blob.bin",
            "binary",
            &(0u8..64).collect::<Vec<u8>>(),
            true,
            &[],
        )],
    )
}

/// `shapes::multi_file`'s three files, under a named policy.
fn multi_file_work(name: &str, policy: &str) -> Value {
    work(
        name,
        "multi file",
        policy,
        vec![
            file("notes/intro.md", "text", shapes::CRLF_TEXT, true, &[]),
            file(
                "data/blob.bin",
                "binary",
                &(0u8..30).collect::<Vec<u8>>(),
                true,
                &[10, 10, 10],
            ),
            file(
                "archive/old.txt",
                "text",
                shapes::CANONICAL_TEXT,
                false,
                &[],
            ),
        ],
    )
}

fn cases() -> Vec<Value> {
    vec![
        // ── the M0 milestone artifact ──────────────────────────────────
        // A bundle carrying no anchors at all. Perfectly valid: it proves
        // existence, integrity and authorship and simply carries no
        // independent time (MVP-SPEC.md line 153).
        case(
            "empty-anchor-unanchored",
            "empty",
            vec![json!("full")],
            single_binary_work(),
        ),
        // Every file of a three-file work fully revealed, under the default
        // hybrid policy — the canonical "a real seal's proof" artifact.
        case(
            "whole-work-reveal",
            "one-ots-two-tsa",
            vec![json!("full"), json!("full"), json!("full")],
            multi_file_work("multi-file-hybrid", "hybrid"),
        ),
        // One covered unit of the unbalanced n = 6 file: leaves [2, 4), so
        // the cover is a leaf-exact interior node and the boundary path is
        // genuinely non-empty (spec line 96).
        case(
            "covered-unit-partial-reveal",
            "empty",
            vec![units(&[1])],
            work(
                "unbalanced-n6",
                "unbalanced n6",
                "ed25519-only",
                vec![file(
                    "data/n6.bin",
                    "binary",
                    &[0, 1, 2, 3, 4, 5],
                    true,
                    &[2, 2, 2],
                )],
            ),
        ),
        // Only the `--no-fine-tree` file is shown, so its unit arrives as a
        // non-covered reveal carrying `unit_salt` instead of a cover.
        case(
            "noncovered-unit-reveal",
            "empty",
            vec![json!("untouched"), json!("untouched"), json!("full")],
            multi_file_work("multi-file", "ed25519-only"),
        ),
        // A full-file reveal of a mirrored text file: the covered canonical
        // unit, the non-covered raw mirror, and `file_salt` + `s_root`.
        case(
            "full-file-reveal-with-mirror",
            "empty",
            vec![json!("full")],
            work(
                "single-text-with-mirror",
                "single text with mirror",
                "ed25519-only",
                vec![file("notes/intro.md", "text", shapes::CRLF_TEXT, true, &[])],
            ),
        ),
        // Every anchor kind and every optional slot populated — the OTS
        // upgrade group, TSA intermediates and `source`, and the receipt.
        case(
            "every-anchor-kind-with-receipt",
            "every-kind",
            vec![json!("full"), units(&[1]), json!("untouched")],
            multi_file_work("multi-file-mixed", "ed25519-only"),
        ),
        // The receipt-excluded twin: identical in every other byte.
        case(
            "every-anchor-kind-no-receipt",
            "every-kind-no-receipt",
            vec![json!("full"), units(&[1]), json!("untouched")],
            multi_file_work("multi-file-mixed", "ed25519-only"),
        ),
        // The zero-revealed-unit bundle: proves the work exists and shows
        // none of it (an F8 representability requirement).
        case(
            "nothing-revealed",
            "empty",
            vec![json!("untouched"), json!("untouched"), json!("untouched")],
            multi_file_work("multi-file", "ed25519-only"),
        ),
    ]
}

/// Which committed case reproduces which R6 named shape, under which
/// selection — the anti-drift tie (R29).
fn shape_parity() -> Vec<(&'static str, WorkSpec, Selection)> {
    let mixed = Selection(vec![
        FileSelection::Full,
        FileSelection::Units(vec![1]),
        FileSelection::Untouched,
    ]);
    vec![
        (
            "empty-anchor-unanchored",
            shapes::single_binary().with_ed25519_only_policy(),
            Selection::all(1),
        ),
        (
            "whole-work-reveal",
            shapes::multi_file_anchored(),
            Selection::all(3),
        ),
        (
            "covered-unit-partial-reveal",
            shapes::unbalanced_n6().with_ed25519_only_policy(),
            Selection(vec![FileSelection::Units(vec![1])]),
        ),
        (
            "noncovered-unit-reveal",
            shapes::multi_file().with_ed25519_only_policy(),
            Selection(vec![
                FileSelection::Untouched,
                FileSelection::Untouched,
                FileSelection::Full,
            ]),
        ),
        (
            "full-file-reveal-with-mirror",
            shapes::single_text_with_mirror().with_ed25519_only_policy(),
            Selection::all(1),
        ),
        (
            "every-anchor-kind-with-receipt",
            shapes::multi_file_every_anchor_kind().with_ed25519_only_policy(),
            mixed.clone(),
        ),
        (
            "every-anchor-kind-no-receipt",
            shapes::multi_file_every_anchor_kind_no_receipt().with_ed25519_only_policy(),
            mixed,
        ),
        (
            "nothing-revealed",
            shapes::multi_file().with_ed25519_only_policy(),
            Selection::nothing(3),
        ),
    ]
}

// ---------------------------------------------------------------------------
// generation
// ---------------------------------------------------------------------------

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
        .unwrap_or_else(|e| panic!("{}: the F13 vector must exist: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("{}: not valid JSON: {e}", path.display()))
}

fn blessing() -> bool {
    std::env::var_os("ANTSEAL_BLESS_VECTORS").is_some()
}

// ---------------------------------------------------------------------------
// the tests
// ---------------------------------------------------------------------------

/// **The F13 generator-diff test.**
#[test]
fn vector_bundle_document_regenerates() {
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
        "the committed bundle vector no longer matches what antseal-core computes.\n\
         First difference: {}\n\
         If this is a deliberate format change it is a FORMAT EVENT \
         (testdata/vectors/README.md): regenerate with \
         `ANTSEAL_BLESS_VECTORS=1 cargo test -p antseal-core vector_bundle`, re-run \
         `scripts/vector-freeze.sh --update`, and justify the digest diff in the commit.\n\
         Swapping A's recorded M2 anchor fixtures in for the M0 placeholders is exactly \
         such a recorded regeneration — and needs no schema change.",
        first_difference("document", &generated, &committed)
    );
}

/// The declarative case descriptions really are R6's named shapes under the
/// stated selections.
#[test]
fn vector_bundle_cases_reproduce_the_r6_named_shapes() {
    let committed = committed_document();
    let cases = committed["expect"]["cases"]
        .as_array()
        .expect("expect.cases is an array");
    for (name, spec, selection) in shape_parity() {
        let case = cases
            .iter()
            .find(|c| c["name"] == json!(name))
            .unwrap_or_else(|| panic!("no committed case named `{name}`"));
        let built = build(&spec, &selection);
        assert_eq!(
            case["bundle_bytes"],
            json!(hex(&built.bytes)),
            "case `{name}` no longer equals its bundle_fixtures::shapes counterpart"
        );
    }
}

/// The **empty-anchor** case is what the must-exist slug promises: a bundle
/// with no OTS artifact, no TSA artifact and no receipt — and it decodes.
///
/// Stated here as well as in the executor because this is the one case whose
/// absence would silently retire an explicit M0 milestone bullet
/// (MVP-SPEC.md line 153; Q6's `bundle-empty-anchor` obligation).
#[test]
fn vector_bundle_carries_the_empty_anchor_milestone_case() {
    let committed = committed_document();
    let cases = committed["expect"]["cases"]
        .as_array()
        .expect("expect.cases is an array");
    let unanchored = cases
        .iter()
        .find(|c| c["name"] == json!("empty-anchor-unanchored"))
        .expect("the empty-anchor case must exist");
    assert_eq!(unanchored["decoded"]["ots_anchors"], json!([]));
    assert_eq!(unanchored["decoded"]["tsa_anchors"], json!([]));
    assert!(unanchored["decoded"]["receipt"].is_null());
    // …and it is not vacuous: the bundle really does carry evidence.
    assert!(
        !unanchored["decoded"]["revealed_unit_ids"]
            .as_array()
            .expect("revealed_unit_ids is an array")
            .is_empty(),
        "the unanchored bundle must still reveal something, or it pins nothing"
    );
}

/// The receipt pair differs in the receipt section and nothing else.
///
/// The two bundles are built from identical works under identical selections,
/// so any other difference would mean receipt presence had leaked into an
/// unrelated part of the encoding.
#[test]
fn vector_bundle_receipt_pair_differs_only_in_the_receipt() {
    let committed = committed_document();
    let cases = committed["expect"]["cases"]
        .as_array()
        .expect("expect.cases is an array");
    let find = |name: &str| {
        cases
            .iter()
            .find(|c| c["name"] == json!(name))
            .unwrap_or_else(|| panic!("no committed case named `{name}`"))
            .clone()
    };
    let mut with = find("every-anchor-kind-with-receipt");
    let mut without = find("every-anchor-kind-no-receipt");
    assert!(!with["decoded"]["receipt"].is_null());
    assert!(without["decoded"]["receipt"].is_null());
    for case in [&mut with, &mut without] {
        case["decoded"]["receipt"] = Value::Null;
        case["name"] = Value::Null;
        // The bytes and their sidecar necessarily differ by the section.
        case["bundle_bytes"] = Value::Null;
        case["diagnostic"] = Value::Null;
    }
    assert_eq!(
        with, without,
        "the receipt-included and receipt-excluded bundles differ somewhere other \
         than the receipt section"
    );
}

/// Rendering is stable and lossless, so a bless is a no-op diff whenever
/// nothing changed.
#[test]
fn vector_bundle_rendering_is_deterministic() {
    let document = committed_document();
    assert_eq!(render(&document), render(&document));
    let reparsed: Value = serde_json::from_str(&render(&document)).expect("re-parses");
    assert_eq!(reparsed, document, "rendering must be lossless");
}
