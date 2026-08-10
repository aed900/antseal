//! **F25 accept, clause 1, over the committed artifacts**: the span cursor
//! ([`antseal_core::test_util::cbor_span`]) agrees with `check_canonical` on
//! **every committed golden vector**.
//!
//! The in-crate half of the property runs over documents the fixture builders
//! produce in memory (`cbor_span`'s own tests). This half runs over the bytes
//! that are actually *in the repository*, which is the population F25's accept
//! clause names — and it discovers them rather than listing them, so a vector
//! added by a later task is covered on the day it lands.
//!
//! # What counts as a golden CBOR document
//!
//! Every `*_bytes` string field anywhere in `testdata/vectors/`, unhexed, that
//! `check_canonical` **accepts**. The filter is the decoder's own verdict
//! rather than a hand-kept file list, so:
//!
//! - `manifest/manifest.json:manifest_bytes` and `bundle/bundle.json:bundle_bytes`
//!   are covered (canonical CBOR documents);
//! - `crypto/unit-aead.json:unit_bytes` and friends are skipped (AEAD
//!   ciphertext is not CBOR and `check_canonical` says so);
//! - anything future that *is* CBOR is picked up automatically.
//!
//! A non-vacuity floor is asserted at the end, so "the filter accidentally
//! matched nothing" cannot read as a pass.
//!
//! Test names deliberately avoid the reserved `corpus_`/`vector_` markers
//! (CONTRIBUTING.md, "Cross-OS suite naming"): this is a property of a test
//! utility, not a golden-vector execution lane.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use antseal_core::codec::decode::check_canonical;
use antseal_core::test_util::cbor_span::{ItemSpan, all_item_spans, item_span, span_of_next_item};
use serde_json::Value;

/// The census of every walk over `testdata/vectors/` and the one prune list
/// they share (Q140/D116 R7, Q157). This file holds census site 9.
#[path = "vector_walk/mod.rs"]
mod vector_walk;

/// The committed vector tree (workspace-relative via the crate manifest dir).
const VECTORS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/vectors");

/// Below this many canonical documents the sweep is not testing anything: v1
/// commits 8 bundle cases and 8 manifest cases today.
const MINIMUM_DOCUMENTS: usize = 12;

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.is_empty() {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

/// Every `*_bytes` hex field in one JSON document, with a readable label.
fn byte_fields(path: &Path, value: &Value, trail: &str, out: &mut Vec<(String, Vec<u8>)>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if let Value::String(text) = child
                    && key.ends_with("_bytes")
                    && let Some(bytes) = unhex(text)
                {
                    out.push((format!("{}{trail}/{key}", path.display()), bytes));
                }
                byte_fields(path, child, &format!("{trail}/{key}"), out);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                byte_fields(path, child, &format!("{trail}[{index}]"), out);
            }
        }
        _ => {}
    }
}

/// Every committed vector document, as `(label, bytes)`.
///
/// **Census site 9, class `positive`** (`vector_walk/mod.rs`, Q157). It
/// selects `*.json` and ignores everything else, and that stays — but it is
/// the site where a positive filter is *least* forgiving, because it does not
/// merely list what it selects, it **parses** it. A file it should never have
/// seen is a panic, not a skip. Measured 2026-08-10: a git-ignored
/// `.vscode/settings.json` planted under `v1/` (JSON with comments, as VS Code
/// writes it) failed all three tests in this file with "does not parse", while
/// the Q4 runner had already pruned the same directory. Hence the shared
/// prune below: the sites see one tree, or they disagree about it.
fn committed_byte_strings() -> Vec<(String, Vec<u8>)> {
    committed_byte_strings_under(Path::new(VECTORS_DIR))
}

/// The walk itself, parameterised on the root so the tests-of-the-test can
/// point it at a scratch tree.
fn committed_byte_strings_under(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut walk = vec![root.to_path_buf()];
    while let Some(dir) = walk.pop() {
        let entries =
            fs::read_dir(&dir).unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|e| panic!("cannot read a directory entry: {e}"));
            let path = entry.path();
            if path.is_dir() {
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(vector_walk::is_ignored_dir)
                {
                    continue; // pruned, not recursed (D116 R7, Q157)
                }
                walk.push(path);
            } else if path.extension().is_some_and(|e| e == "json") {
                let text = fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
                let document: Value = serde_json::from_str(&text)
                    .unwrap_or_else(|e| panic!("{} does not parse: {e}", path.display()));
                byte_fields(&path, &document, "", &mut out);
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Only the ones that are canonical CBOR documents.
fn canonical_documents() -> Vec<(String, Vec<u8>)> {
    committed_byte_strings()
        .into_iter()
        .filter(|(_, bytes)| check_canonical(bytes).is_ok())
        .collect()
}

/// **F25 accept, clause 1.** For every committed golden vector that is a
/// canonical CBOR document, and for *every item inside it*: the cursor's span
/// is exactly the byte range `check_canonical` accepts as one complete
/// document, and re-splicing that range unchanged reproduces the input byte
/// for byte.
#[test]
fn the_span_cursor_agrees_with_check_canonical_on_every_committed_vector() {
    let documents = canonical_documents();
    assert!(
        documents.len() >= MINIMUM_DOCUMENTS,
        "only {} canonical committed documents found — the discovery filter is broken, and a \
         sweep over nothing is not a passing test",
        documents.len()
    );

    let mut items_checked = 0usize;
    for (label, bytes) in &documents {
        let spans =
            all_item_spans(bytes).unwrap_or_else(|| panic!("{label}: the cursor refused the item"));
        assert_eq!(spans[0].start, 0, "{label}: the outermost span is anchored");
        assert_eq!(
            spans[0].end,
            bytes.len(),
            "{label}: the outermost span is the whole document"
        );
        for span in &spans {
            let item = bytes
                .get(span.start..span.end)
                .unwrap_or_else(|| panic!("{label}: span {span:?} out of range"));
            assert_eq!(
                check_canonical(item),
                Ok(()),
                "{label}: the item the cursor reports at {span:?} is not a canonical document"
            );

            // Walk it and re-splice it unchanged: byte-for-byte identity.
            let mut rebuilt = Vec::with_capacity(bytes.len());
            rebuilt.extend_from_slice(bytes.get(..span.start).expect("prefix"));
            rebuilt.extend_from_slice(item);
            rebuilt.extend_from_slice(bytes.get(span.end..).expect("suffix"));
            assert_eq!(
                &rebuilt, bytes,
                "{label}: re-splicing {span:?} unchanged did not reproduce the input"
            );

            // The two entry points agree, and the head/payload split is exact.
            assert_eq!(span_of_next_item(bytes, span.start), Some(span.range()));
            assert_eq!(item_span(bytes, span.start), Some(*span));
            assert!(
                span.start <= span.head_end && span.head_end <= span.end,
                "{label}: {span:?} has an inconsistent head split"
            );
            items_checked += 1;
        }
    }
    assert!(
        items_checked > 500,
        "only {items_checked} items swept across {} documents",
        documents.len()
    );
}

/// Spans nest properly: two spans of one document are either disjoint or one
/// strictly contains the other. A cursor that reported overlapping-but-not-
/// nested extents would still pass the round-trip above while being useless
/// for addressing — this is the property that makes `(path, mutation)` mean
/// something.
#[test]
fn spans_of_one_document_form_a_tree() {
    for (label, bytes) in canonical_documents() {
        let spans: Vec<ItemSpan> =
            all_item_spans(&bytes).unwrap_or_else(|| panic!("{label}: enumeration"));
        for (i, a) in spans.iter().enumerate() {
            for b in spans.iter().skip(i + 1) {
                let disjoint = a.end <= b.start || b.end <= a.start;
                let a_contains_b = a.start <= b.start && b.end <= a.end;
                let b_contains_a = b.start <= a.start && a.end <= b.end;
                assert!(
                    disjoint || a_contains_b || b_contains_a,
                    "{label}: {a:?} and {b:?} overlap without nesting"
                );
            }
        }
        // Every span is unique as a range *within its nesting level*; the whole
        // set may legitimately repeat a range only when a container and its
        // single child would coincide, which canonical CBOR never produces
        // (a container's head is at least one byte).
        let ranges: BTreeSet<(usize, usize)> = spans.iter().map(|s| s.range()).collect();
        assert_eq!(
            ranges.len(),
            spans.len(),
            "{label}: two items share a byte range"
        );
    }
}

/// The discovery filter is doing real work in both directions: it accepted the
/// manifest and bundle documents, and it rejected the AEAD ciphertext fields
/// that are not CBOR at all.
#[test]
fn the_discovery_filter_selects_cbor_and_rejects_ciphertext() {
    let all = committed_byte_strings();
    let canonical = canonical_documents();
    assert!(
        canonical.len() < all.len(),
        "nothing was filtered out — the sweep would be claiming ciphertext is CBOR"
    );
    assert!(
        canonical
            .iter()
            .any(|(label, _)| label.contains("bundle_bytes")),
        "no bundle vector was picked up"
    );
    assert!(
        canonical
            .iter()
            .any(|(label, _)| label.contains("manifest_bytes")),
        "no manifest vector was picked up"
    );
}

// ---------------------------------------------------------------------------
// Q157 — census site 9 is the site where a stray file is a PANIC, not a skip:
// this walk parses everything it selects. These pin that the droppings the
// repository declares expected never reach the parser.
// ---------------------------------------------------------------------------

/// A scratch tree with one document carrying one `*_bytes` field.
fn scratch_tree(test: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("cbor_span_agreement")
        .join(test);
    if root.exists() {
        fs::remove_dir_all(&root).expect("scratch cleanup");
    }
    fs::create_dir_all(root.join("v1/group")).expect("scratch tree");
    fs::write(root.join("v1/group/a.json"), br#"{"manifest_bytes":"a0"}"#).expect("write");
    root
}

/// The walk harvests the real document and nothing else.
fn expect_only_the_vector(root: &Path) {
    let found = committed_byte_strings_under(root);
    assert_eq!(
        found.len(),
        1,
        "expected exactly the one seeded document, got {:?}",
        found.iter().map(|(l, _)| l).collect::<Vec<_>>()
    );
}

#[test]
fn vector_span_walk_ignores_pycache_bytecode() {
    let root = scratch_tree("ignore_pycache");
    fs::create_dir_all(root.join("v1/__pycache__")).expect("mkdir");
    fs::write(root.join("v1/__pycache__/g.cpython-311.pyc"), b"\x00b").expect("write");
    expect_only_the_vector(&root);
}

#[test]
fn vector_span_walk_ignores_editor_swap_files() {
    let root = scratch_tree("ignore_swap");
    fs::write(root.join("v1/.gen_vectors.py.swp"), b"").expect("write");
    expect_only_the_vector(&root);
}

/// **The case Q157 fixed.** Before the prune, a git-ignored
/// `.vscode/settings.json` — JSON *with comments*, which is how VS Code writes
/// it and which `serde_json` rejects — panicked all three tests in this file
/// with "does not parse", naming a file no one had committed. Measured
/// 2026-08-10 against the live tree.
#[test]
fn vector_span_walk_ignores_json_inside_an_ignored_directory() {
    let root = scratch_tree("ignore_json_in_ignored_dir");
    fs::create_dir_all(root.join("v1/.vscode")).expect("mkdir");
    fs::write(
        root.join("v1/.vscode/settings.json"),
        b"{\n  // not a vector, and not even JSON\n}\n",
    )
    .expect("write");
    expect_only_the_vector(&root);
}
