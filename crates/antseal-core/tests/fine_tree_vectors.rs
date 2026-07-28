//! G15 — the fine-tree golden-vector **regenerator**.
//!
//! The Q4 runner (`vector_runner.rs`) executes the committed
//! `testdata/vectors/v1/fine-tree/fine-tree.json` like any other vector.
//! This file adds the thing G15 asks for on top: *"a generator test that
//! regenerates and diffs, so drift fails CI"*. It rebuilds the whole `expect`
//! object from the file's own `inputs` through antseal-core's public API and
//! diffs it against what is committed, so **any** construction or indexing
//! change — a bit-order flip, a different RFC 6962 split, a renumbered node
//! address, a dropped level — turns this red with the offending field named.
//!
//! Three independent regenerations therefore stand behind the one committed
//! artifact:
//!
//! | who | independence |
//! | --- | --- |
//! | this test | antseal-core's public API, whole-document |
//! | `testdata/vectors/v1/fine-tree/gen_vectors.py` | a second implementation, Python stdlib only, shares no code |
//! | `crates/wasm-bitmatch` (Q5) | the same executor under `wasm32-unknown-unknown`, byte-compared |
//!
//! Test names carry the reserved `vector_` marker so the three `cross-os-*`
//! CI lanes run them everywhere (CONTRIBUTING.md, "Cross-OS suite naming") —
//! the document is pure hex and integers, so it must regenerate identically
//! on Linux, macOS and Windows.

use std::fs;
use std::path::PathBuf;

use antseal_core::test_util::vectors::first_difference;
use antseal_core::test_util::vectors_fine_tree::{KIND, S_ROOT_LABEL, regenerate_expect};

/// The committed document (workspace-relative via the crate manifest dir, so
/// it resolves on every OS and checkout location).
const VECTOR_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/fine-tree/fine-tree.json"
);

fn committed_document() -> serde_json::Value {
    let path = PathBuf::from(VECTOR_PATH);
    let bytes = fs::read(&path)
        .unwrap_or_else(|e| panic!("{}: the G15 vector must exist: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("{}: not valid JSON: {e}", path.display()))
}

/// **The G15 generator-diff test.** Regenerate `expect` from `inputs` and
/// require it to equal the committed bytes' meaning, field for field.
#[test]
fn vector_fine_tree_document_regenerates() {
    let document = committed_document();
    let recomputed = regenerate_expect(&document).unwrap_or_else(|e| panic!("regeneration: {e}"));
    let committed = document
        .get("expect")
        .unwrap_or_else(|| panic!("the vector has no `expect` object"));
    assert!(
        &recomputed == committed,
        "the committed fine-tree vector no longer matches what antseal-core computes.\n\
         First difference: {}\n\
         If this is a deliberate construction change it is a FORMAT EVENT \
         (testdata/vectors/README.md): regenerate with \
         `python3 testdata/vectors/v1/fine-tree/gen_vectors.py > \
         testdata/vectors/v1/fine-tree/fine-tree.json`, re-run \
         `scripts/vector-freeze.sh --update`, and justify the digest diff in \
         the commit.",
        first_difference("expect", &recomputed, committed)
    );
}

/// The document really is the G15 one: the right kind, the documented
/// synthetic-seed label, and the four cases the task enumerates — including
/// the unbalanced `n = 6` case whose slug Q6's must-exist list names.
#[test]
fn vector_fine_tree_document_covers_the_mandated_cases() {
    let document = committed_document();
    assert_eq!(
        document.get("kind").and_then(serde_json::Value::as_str),
        Some(KIND)
    );
    assert_eq!(
        document
            .pointer("/inputs/s_root_label")
            .and_then(serde_json::Value::as_str),
        Some(S_ROOT_LABEL),
        "the synthetic s_root must be the documented alternate_test_secret derivation"
    );

    let cases = document
        .pointer("/expect/cases")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("expect.cases must be an array"));
    let sizes: Vec<u64> = cases
        .iter()
        .filter_map(|case| case.get("n").and_then(serde_json::Value::as_u64))
        .collect();
    // The mandated set: the unbalanced n = 6 vector (MVP-SPEC.md line 169),
    // n = 1 (root == leaf), n = 0 (no tree), and one n just past a power of
    // two exercising unused GGM slots.
    assert!(sizes.contains(&6), "the unbalanced n = 6 case is mandatory");
    assert!(sizes.contains(&1), "n = 1 (root == leaf) is mandatory");
    assert!(sizes.contains(&0), "n = 0 (no tree) is mandatory");
    assert!(
        sizes.iter().any(|&n| n == 5 || n == 9),
        "one n just past a power of two is mandatory; found {sizes:?}"
    );

    let n6 = cases
        .iter()
        .find(|case| case.get("n").and_then(serde_json::Value::as_u64) == Some(6))
        .unwrap_or_else(|| panic!("the n = 6 case must exist"));
    // Every intermediate is pinned, not just the root: 12 used grid nodes at
    // d = 3 with n = 6, six salts, eleven RFC 6962 content-tree nodes.
    let len = |field: &str| {
        n6.get(field)
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len)
    };
    assert_eq!(len("ggm_nodes"), 12, "all used GGM node seeds");
    assert_eq!(len("salts"), 6, "every salt_i — the MSB-first pin");
    assert_eq!(
        len("merkle_nodes"),
        11,
        "every RFC 6962 node, level by level"
    );
    assert!(
        n6.get("fine_root")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|root| root.len() == 64)
    );

    // The three spec-named openings plus the two-node interior one.
    let openings = n6
        .get("openings")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("the n = 6 case must carry openings"));
    let spans: Vec<(u64, u64)> = openings
        .iter()
        .filter_map(|opening| {
            Some((
                opening.get("start")?.as_u64()?,
                opening.get("length")?.as_u64()?,
            ))
        })
        .collect();
    for required in [(2, 1), (4, 2), (0, 6)] {
        assert!(
            spans.contains(&required),
            "reveal {required:?} is mandated at n = 6; found {spans:?}"
        );
    }
    // The full reveal is the only one that may release s_root (spec line 96).
    for opening in openings {
        let releases = opening
            .get("releases_s_root")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let full = opening.get("start").and_then(serde_json::Value::as_u64) == Some(0)
            && opening.get("length").and_then(serde_json::Value::as_u64) == Some(6);
        assert_eq!(releases, full, "s_root is released iff the range is [0, n)");
    }
}

/// The regenerator refuses a document of another kind rather than silently
/// producing something — a test-of-the-test for the one public entry point
/// other tasks may call.
#[test]
fn vector_fine_tree_regenerator_rejects_a_foreign_document() {
    let foreign = serde_json::json!({"kind": "hkdf-labels", "inputs": {}});
    let error = regenerate_expect(&foreign)
        .err()
        .unwrap_or_else(|| panic!("a foreign document must not regenerate"));
    assert!(error.to_string().contains("fine-tree"), "{error}");
}
