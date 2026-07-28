//! G21 — the content-model golden-vector **regenerator** and emitter.
//!
//! The Q4 runner (`vector_runner.rs`) executes the committed
//! `testdata/vectors/v1/content-model/content-model.json` like any other
//! vector, and the Q5 lane (`scripts/wasm-bitmatch.sh`) executes it again
//! under `wasm32-unknown-unknown` and byte-compares the recomputed digest.
//! This file adds the two things only the native side can do:
//!
//! 1. **Regenerate and diff** — rebuild the whole `expect` object from the
//!    file's own `inputs`, through `assemble_content_model`, and diff it
//!    against what is committed. Any change to the assembly's output — a
//!    different split boundary, a renumbered unit, a moved mirror, a changed
//!    `fine_root` — turns this red with the offending field named.
//! 2. **Emit** — `emit_content_model_vector_document` (ignored by default)
//!    writes the document. It is the *only* sanctioned way to regenerate the
//!    file:
//!
//!    ```text
//!    cargo test -p antseal-core --features test-util --test content_model_vectors \
//!        -- --ignored emit_content_model_vector_document
//!    ./scripts/vector-freeze.sh --update      # then justify the digest diff
//!    ```
//!
//! # Why this vector exists at all
//!
//! G14's golden fixture is committed as **Rust constants**
//! (`content::fixtures`), which the wasm32 `--lib` lane runs — but the Q5
//! bit-match compares committed vector *files*, so the assembly's derived
//! values sat outside it. This is that file. The executor additionally ties
//! the committed case back to `golden_inputs()`/`golden_model()` in both
//! directions, so the file and the Rust fixture cannot drift apart.
//!
//! Test names carry the reserved `vector_` marker so the three `cross-os-*`
//! CI lanes run them everywhere (CONTRIBUTING.md, "Cross-OS suite naming") —
//! the document is hex, integers and booleans, so it must regenerate
//! identically on Linux, macOS and Windows.

use std::fs;
use std::path::PathBuf;

use antseal_core::test_util::vectors_content_model::{
    FORCED_TEXT_CASE, GOLDEN_CASE, KIND, build_inputs, regenerate_expect,
};
use antseal_core::test_util::vectors_fine_tree::first_difference;

/// The committed document (workspace-relative via the crate manifest dir, so
/// it resolves on every OS and checkout location).
const VECTOR_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/content-model/content-model.json"
);

const NON_SECRET: &str = "NON-SECRET test fixture (project rule 6): every value below derives from \
     the documented fixed test seed W = bytes 0x00..0x1f (testdata/README.md) \
     through `content::fixtures::SyntheticFineSeeds`, the deliberately \
     test-only s_root supplier whose domain label appears verbatim in \
     `inputs.fine_seed_label` and which is NOT C's HKDF(W, \"fine-seed\", \
     file_id) — so no committed value here is reachable from any production \
     key schedule. File bytes are synthetic literals. Never real vault \
     material.";

const DESCRIPTION: &str = "Content-model golden vectors (G21): the seal-side assembly's DERIVED \
     values for two whole works — per-file descriptor fields, canonical \
     rendition, synthetic s_root and fine_root, and per-unit work-global id, \
     kind, byte range, true_length, fine-tree coverage and unit_commit \
     obligation. The first case is byte-identical to G14's Rust fixture \
     `content::fixtures::golden_inputs()`, which the executor asserts in both \
     directions; the second covers the --force-text branch on bytes that are \
     not valid UTF-8. No range-proof bytes are pinned, so decision D83's \
     cover encoding cannot move this document (MVP-SPEC.md lines 76, 78, 83, \
     85, 92, 94, 98, 153, 169).";

fn committed_document() -> serde_json::Value {
    let path = PathBuf::from(VECTOR_PATH);
    let bytes = fs::read(&path)
        .unwrap_or_else(|e| panic!("{}: the G21 vector must exist: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("{}: not valid JSON: {e}", path.display()))
}

/// **The G21 generator-diff test.** Regenerate `expect` from `inputs` and
/// require it to equal the committed bytes' meaning, field for field.
#[test]
fn vector_content_model_document_regenerates() {
    let document = committed_document();
    let recomputed = regenerate_expect(&document).unwrap_or_else(|e| panic!("regeneration: {e}"));
    let committed = document
        .get("expect")
        .unwrap_or_else(|| panic!("the vector has no `expect` object"));
    assert!(
        &recomputed == committed,
        "the committed content-model vector no longer matches what antseal-core assembles.\n\
         First difference: {}\n\
         If this is a deliberate assembly change it is a FORMAT EVENT \
         (testdata/vectors/README.md): re-emit with `cargo test -p antseal-core \
         --features test-util --test content_model_vectors -- --ignored \
         emit_content_model_vector_document`, re-run `scripts/vector-freeze.sh --update`, \
         and justify the digest diff in the commit.",
        first_difference("expect", &recomputed, committed)
    );
}

/// The emitter's inputs and the committed file agree — so a case added to one
/// and forgotten in the other is caught, rather than surviving until the next
/// regeneration silently rewrites the file.
#[test]
fn vector_content_model_emitter_inputs_match_the_committed_document() {
    let document = committed_document();
    assert_eq!(
        document.get("inputs"),
        Some(&build_inputs()),
        "the emitter's case list and the committed `inputs` have diverged; \
         re-emit the document or fix the list"
    );
}

/// The document really is the G21 one: the right kind, the golden case that
/// ties it to G14's Rust fixture, and the `--force-text` case that covers the
/// branch those four golden files leave untouched.
#[test]
fn vector_content_model_document_covers_the_mandated_cases() {
    let document = committed_document();
    assert_eq!(
        document.get("kind").and_then(serde_json::Value::as_str),
        Some(KIND)
    );

    let names: Vec<&str> = document
        .pointer("/inputs/cases")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("inputs.cases must be an array"))
        .iter()
        .filter_map(|case| case.get("name").and_then(serde_json::Value::as_str))
        .collect();
    assert!(
        names.contains(&GOLDEN_CASE),
        "the G14 tie case is mandatory; found {names:?}"
    );
    assert!(
        names.contains(&FORCED_TEXT_CASE),
        "the --force-text case is mandatory; found {names:?}"
    );

    // The golden case's four files, with the derived values that make it the
    // fixture G14 documents: 41 raw bytes canonicalizing to 34 (every CR LF
    // loses its CR), three --split paragraphs plus a mirror, a binary file, a
    // --no-fine-tree file and an empty file — seven work-global units.
    let cases = document
        .pointer("/expect/cases")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("expect.cases must be an array"));
    let golden = cases
        .iter()
        .find(|case| case.get("name").and_then(serde_json::Value::as_str) == Some(GOLDEN_CASE))
        .unwrap_or_else(|| panic!("the golden case must exist in `expect`"));
    let number = |field: &str| golden.get(field).and_then(serde_json::Value::as_u64);
    assert_eq!(number("file_count"), Some(4));
    assert_eq!(number("unit_count"), Some(7));

    let files = golden
        .get("files")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("the golden case must carry files"));
    assert_eq!(
        files[0].get("raw_len").and_then(serde_json::Value::as_u64),
        Some(41)
    );
    assert_eq!(
        files[0].get("size").and_then(serde_json::Value::as_u64),
        Some(34)
    );
    assert_eq!(
        files[0].get("kind").and_then(serde_json::Value::as_str),
        Some("text")
    );
    assert_eq!(
        files[3].get("size").and_then(serde_json::Value::as_u64),
        Some(0),
        "file 3 is the empty file (MVP-SPEC.md line 78)"
    );
    assert_eq!(
        files[3].get("fine_root"),
        Some(&serde_json::Value::Null),
        "an empty file has no fine tree"
    );

    // Work-global ids: dense from 0 across all four files, never restarting
    // (MVP-SPEC.md line 76). Asserted here on the committed bytes, not only
    // inside the executor.
    let units = golden
        .get("units")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("the golden case must carry units"));
    let ids: Vec<u64> = units
        .iter()
        .filter_map(|unit| unit.get("unit_id").and_then(serde_json::Value::as_u64))
        .collect();
    assert_eq!(ids, (0..7).collect::<Vec<u64>>());

    // The sole-commitment rule (MVP-SPEC.md line 94), read off the file:
    // `unit_commit_required` is exactly the negation of `covered`.
    for unit in units {
        let flag = |field: &str| unit.get(field).and_then(serde_json::Value::as_bool);
        assert_eq!(
            flag("unit_commit_required").map(|required| !required),
            flag("covered"),
            "unit {:?} breaks unit_commit-iff-not-covered",
            unit.get("unit_id")
        );
    }
}

/// The regenerator refuses a document of another kind rather than silently
/// producing something — a test-of-the-test for the one public entry point
/// other tasks may call.
#[test]
fn vector_content_model_regenerator_rejects_a_foreign_document() {
    let foreign = serde_json::json!({"kind": "fine-tree", "inputs": {}});
    let error = regenerate_expect(&foreign).expect_err("a foreign document must not regenerate");
    assert!(error.to_string().contains(KIND), "{error}");
}

/// Regenerate the committed document. **Ignored by default**: it writes into
/// `testdata/`, which is a deliberate act with a freeze consequence, never a
/// side effect of running the suite. See this file's module docs.
#[test]
#[ignore = "writes testdata/; run deliberately when the content model changes"]
fn emit_content_model_vector_document() {
    let inputs = build_inputs();
    let document = serde_json::json!({"kind": KIND, "inputs": inputs.clone()});
    let expect = regenerate_expect(&document).unwrap_or_else(|e| panic!("recomputation: {e}"));

    // The envelope's eight keys are written in their documented order; every
    // nested object is `serde_json`'s own ordering.
    let sub = |value: &serde_json::Value| {
        serde_json::to_string_pretty(value)
            .unwrap_or_else(|e| panic!("serialize: {e}"))
            .replace('\n', "\n  ")
    };
    let string = |value: &str| {
        serde_json::to_string(value).unwrap_or_else(|e| panic!("serialize string: {e}"))
    };
    let body = format!(
        "{{\n  \"schema\": \"antseal-golden-vector\",\n  \"schema_version\": 1,\n  \
         \"format_version\": \"v1\",\n  \"kind\": {},\n  \"non_secret\": {},\n  \
         \"description\": {},\n  \"inputs\": {},\n  \"expect\": {}\n}}\n",
        string(KIND),
        string(&squash(NON_SECRET)),
        string(&squash(DESCRIPTION)),
        sub(&inputs),
        sub(&expect),
    );

    let path = PathBuf::from(VECTOR_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| panic!("{}: {e}", parent.display()));
    }
    fs::write(&path, body.as_bytes()).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    println!(
        "wrote {} — now run ./scripts/vector-freeze.sh --update",
        path.display()
    );
}

/// Collapse the source-literal line wrapping of the long prose constants into
/// single spaces, so the emitted JSON string is one clean sentence run.
fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
