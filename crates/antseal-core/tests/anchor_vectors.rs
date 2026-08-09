//! A22 — the `anchor` golden-vector **regenerator** and emitter.
//!
//! The Q4 runner (`vector_runner.rs`) executes the committed
//! `testdata/vectors/v1/anchor/anchor.json` like any other vector, and the Q5
//! lane (`scripts/wasm-bitmatch.sh`) executes it again under
//! `wasm32-unknown-unknown` and byte-compares. This file adds the two things
//! only the native side can do, on R9's pattern:
//!
//! 1. **Regenerate and diff** — rebuild the whole `expect` object from the
//!    file's own `inputs`, through the public anchor evaluators, and diff it
//!    against what is committed, naming the offending field.
//! 2. **Emit** — `emit_anchor_vector_document` (ignored by default) writes the
//!    document. It is the *only* sanctioned way to produce `expect`, which is
//!    what D101 §7.3 and D103 §3.2 mean by *"`expect` comes from the Rust
//!    executor's own `build_expect`"*:
//!
//!    ```text
//!    cargo test -p antseal-core --features test-util --test anchor_vectors \
//!        -- --ignored emit_anchor_vector_document
//!    ./scripts/vector-freeze.sh --update
//!    ```
//!
//!    `inputs` is **not** produced here: it is the derivation record's, and
//!    `testdata/vectors/v1/anchor/gen_vectors.py --check` re-derives it from
//!    `testdata/anchors/` on the cross-check lane. This emitter reads the
//!    committed `inputs` verbatim and only rewrites `expect`, so the two
//!    halves keep their separate owners.
//!
//! Deliberately **no** Python cross-implementation of `expect`: there is no
//! second RFC 3161 chain validator or `.ots` evaluator, and writing one would
//! pin the same judgement twice rather than check it (D101 §7.3). The
//! cross-check that *does* exist is `antseal-anchor`'s
//! `the_three_way_splice_reaches_the_committed_vector_digest`, which runs the
//! shipped `merge_upgrade` over the same archive bytes to the same SHA-256
//! the vector carries (D103 RULING 2a).
//!
//! Test names carry the reserved `vector_` marker so the three `cross-os-*`
//! CI lanes run them everywhere (CONTRIBUTING.md, "Cross-OS suite naming").

use std::fs;

use antseal_core::test_util::vectors::first_difference;
use antseal_core::test_util::vectors_anchor::{KIND, build_expect_from_json};

/// The committed document (workspace-relative via the crate manifest dir, so
/// it resolves on every OS and checkout location).
const VECTOR_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/anchor/anchor.json"
);

fn committed() -> serde_json::Value {
    let bytes = fs::read(VECTOR_PATH).expect("the committed anchor vector is readable");
    serde_json::from_slice(&bytes).expect("the committed anchor vector is JSON")
}

/// Rebuild `expect` from the committed `inputs` and diff. Any change to what
/// the anchor evaluators compute for a pinned artifact turns this red with
/// the offending field named — before `vector_runner` reports the same thing
/// less legibly, and before the wasm32 lane reports it as a digest mismatch.
#[test]
fn vector_anchor_expect_regenerates_from_its_own_inputs() {
    let document = committed();
    assert_eq!(
        document["kind"], KIND,
        "the document is not an `anchor` vector"
    );
    let rebuilt =
        build_expect_from_json(document["inputs"].clone()).expect("the committed inputs execute");
    assert!(
        rebuilt == document["expect"],
        "the anchor vector's `expect` no longer matches what the evaluators compute: {}",
        first_difference("expect", &rebuilt, &document["expect"])
    );
}

/// Write the document. Ignored by default — a golden vector is regenerated
/// deliberately, never as a side effect of running the suite.
#[test]
#[ignore = "regenerates a committed golden vector; run explicitly"]
fn emit_anchor_vector_document() {
    let document = committed();
    let inputs = document["inputs"].clone();
    let expect = build_expect_from_json(inputs.clone()).expect("the committed inputs execute");

    // R9's convention, shared with `report` and mirrored byte-for-byte by
    // `gen_vectors.py::render`: the eight envelope keys in their documented
    // order, every nested object in `serde_json`'s own alphabetical ordering.
    let sub = |value: &serde_json::Value| {
        serde_json::to_string_pretty(value)
            .expect("serializable")
            .replace('\n', "\n  ")
    };
    let string = |value: &serde_json::Value| value.to_string();
    let body = format!(
        "{{\n  \"schema\": \"antseal-golden-vector\",\n  \"schema_version\": 1,\n  \
         \"format_version\": \"v1\",\n  \"kind\": {},\n  \"non_secret\": {},\n  \
         \"description\": {},\n  \"inputs\": {},\n  \"expect\": {}\n}}\n",
        string(&document["kind"]),
        string(&document["non_secret"]),
        string(&document["description"]),
        sub(&inputs),
        sub(&expect),
    );

    fs::write(VECTOR_PATH, body).expect("the committed anchor vector is writable");
    eprintln!(
        "wrote {VECTOR_PATH} — now run ./scripts/vector-freeze.sh --update, and \
         testdata/vectors/v1/anchor/gen_vectors.py --check"
    );
}
