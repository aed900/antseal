//! Native guards for the Q5 bit-match harness.
//!
//! The lane itself (`scripts/wasm-bitmatch.sh`) proves native and wasm32
//! agree. These tests protect the *other* half of the contract — that the
//! thing being compared is complete, deterministic, and total — so a green
//! lane can never be green over nothing or over a stale table.
//!
//! Test names deliberately avoid the reserved `vector_`/`corpus_` markers
//! (CONTRIBUTING.md, "Cross-OS suite naming"): those names *are* membership
//! in the golden-vector and UTF-8-corpus suites, which this crate is not.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use wasm_bitmatch::{
    EMBEDDED_BYTES_BY_VERSION, EMBEDDED_VECTORS, EmbeddedVector, MAX_EMBEDDED_BYTES_PER_VERSION,
    transcript, transcript_bytes, transcript_for,
};

/// `testdata/vectors/`, resolved from this crate's manifest so it holds on
/// every OS and checkout location.
fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("testdata")
        .join("vectors")
}

/// Every `*.json` **vector** under the tree, as repo-relative forward-slash
/// paths. F10's per-version `INDEX.json` roster is excluded: it is a
/// documented auxiliary, not a vector, and carries no `kind`/`inputs`/`expect`
/// for the executor to run (`testdata/vectors/README.md`). This walk is the
/// independent cross-check of `build.rs`'s, so the exclusion has to be stated
/// in both — that is the point of having two.
fn walk_committed(dir: &Path, out: &mut BTreeSet<String>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("dir entry error under {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            walk_committed(&path, out);
        } else if path.file_name().is_some_and(|n| n == "INDEX.json") {
            // auxiliary — see above
        } else if path.extension().is_some_and(|ext| ext == "json") {
            let text = path.display().to_string().replace('\\', "/");
            let at = text
                .find("testdata/vectors/")
                .unwrap_or_else(|| panic!("{text}: not under testdata/vectors/"));
            out.insert(text[at..].to_owned());
        }
    }
}

/// The embedded table must be exactly the committed tree. Catches a stale
/// build (the `cargo::rerun-if-changed` watch failing) and any drift between
/// the harness's `build.rs` discovery and the Q4 runner's discovery — both
/// implement the contract in `testdata/vectors/README.md`.
#[test]
fn bitmatch_embedded_table_equals_the_committed_tree() {
    let mut committed = BTreeSet::new();
    walk_committed(&vectors_root(), &mut committed);
    let embedded: BTreeSet<String> = EMBEDDED_VECTORS.iter().map(|v| v.path.to_owned()).collect();

    assert!(
        !committed.is_empty(),
        "no committed vectors found under {} — discovery is broken",
        vectors_root().display()
    );
    assert_eq!(
        embedded,
        committed,
        "the embedded vector table is stale: rebuild `wasm-bitmatch` (build.rs watches \
         testdata/vectors/). Only in the embedded set: {:?}; only on disk: {:?}",
        embedded.difference(&committed).collect::<Vec<_>>(),
        committed.difference(&embedded).collect::<Vec<_>>(),
    );
}

/// Each embedded vector's bytes must be the file's bytes, and its declared
/// format version must be the directory it sits in.
#[test]
fn bitmatch_embedded_bytes_are_the_committed_bytes() {
    let root = vectors_root();
    for vector in EMBEDDED_VECTORS {
        let relative = vector
            .path
            .strip_prefix("testdata/vectors/")
            .unwrap_or_else(|| panic!("{}: unexpected embedded path shape", vector.path));
        let on_disk = fs::read(root.join(relative))
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", vector.path));
        assert_eq!(
            on_disk, vector.bytes,
            "{}: embedded bytes differ from the committed file",
            vector.path
        );
        assert!(
            relative.starts_with(&format!("{}/", vector.format_version)),
            "{}: embedded format_version `{}` does not match its directory",
            vector.path,
            vector.format_version
        );
    }
}

/// The transcript is the byte contract: it must be a pure function of the
/// inputs.
#[test]
fn bitmatch_transcript_is_deterministic() {
    assert_eq!(
        transcript_bytes(),
        transcript_bytes(),
        "the transcript must be byte-identical across runs"
    );
}

/// A bit-match over zero vectors, or over vectors that did not execute,
/// would be vacuous. The lane checks this too; asserting it here makes it a
/// `cargo test --workspace` failure as well.
#[test]
fn bitmatch_transcript_is_non_vacuous() {
    let run = transcript();
    assert!(run.vector_count >= 1, "the transcript covers no vectors");
    assert_eq!(run.vector_count as usize, run.entries.len());
    for entry in &run.entries {
        assert_eq!(
            entry.status, "executed",
            "{}: vector did not execute natively: {:?}",
            entry.path, entry.error
        );
        assert!(
            entry
                .recomputed_digest
                .as_ref()
                .is_some_and(|d| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit())),
            "{}: missing or malformed recomputed digest",
            entry.path
        );
    }
}

/// Entries are ordered by `path` regardless of the input order, so the
/// transcript cannot depend on how the table happened to be generated.
#[test]
fn bitmatch_transcript_sorts_entries_by_path() {
    let forward = transcript_for(EMBEDDED_VECTORS);
    let mut reversed: Vec<EmbeddedVector> = EMBEDDED_VECTORS.to_vec();
    reversed.reverse();
    let backward = transcript_for(&reversed);
    assert_eq!(
        forward
            .entries
            .iter()
            .map(|e| e.path.clone())
            .collect::<Vec<_>>(),
        backward
            .entries
            .iter()
            .map(|e| e.path.clone())
            .collect::<Vec<_>>(),
        "entry order must not depend on input order"
    );
    let paths: Vec<&String> = forward.entries.iter().map(|e| &e.path).collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted, "entries must be sorted by path");
}

/// Totality: a malformed vector is *recorded*, never panicked on. Without
/// this, a wasm-only failure would trap instead of producing a diffable byte
/// difference (and adversarial-input practice would be violated).
#[test]
fn bitmatch_records_malformed_vectors_instead_of_panicking() {
    let broken = [
        EmbeddedVector {
            format_version: "v1",
            path: "testdata/vectors/v1/synthetic/not-json.json",
            bytes: b"{ this is not json",
        },
        EmbeddedVector {
            format_version: "v1",
            path: "testdata/vectors/v1/synthetic/empty.json",
            bytes: b"",
        },
    ];
    let run = transcript_for(&broken);
    assert_eq!(run.vector_count, 2);
    for entry in &run.entries {
        assert_eq!(entry.status, "failed", "{}", entry.path);
        assert!(
            entry.error.as_ref().is_some_and(|e| !e.is_empty()),
            "{}: a failed entry must carry its error text",
            entry.path
        );
        assert!(entry.recomputed_digest.is_none());
    }
    // And the failure path is still deterministic bytes.
    assert_eq!(
        serde_json::to_vec(&transcript_for(&broken)).expect("serializes"),
        serde_json::to_vec(&run).expect("serializes"),
    );
}

/// D29 rules the transcript must satisfy for the byte comparison to be
/// meaningful: valid compact UTF-8 JSON, no floats anywhere, no whitespace
/// padding.
#[test]
fn bitmatch_transcript_obeys_the_d29_serialization_rules() {
    let bytes = transcript_bytes();
    let text = core::str::from_utf8(&bytes).expect("transcript must be UTF-8");

    // Compact encoding: no structural whitespace. Checked OUTSIDE string
    // literals — vector descriptions legitimately contain spaces.
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        if *byte == b'"' {
            in_string = true;
        } else {
            assert!(
                !byte.is_ascii_whitespace(),
                "structural whitespace at byte {index} — the transcript must be compact \
                 (D29 rule 5), not pretty-printed"
            );
        }
    }
    assert!(!in_string, "unterminated string literal in the transcript");
    assert!(text.starts_with('{') && text.ends_with('}'));

    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("transcript must be JSON");
    fn assert_no_floats(value: &serde_json::Value, at: &str) {
        match value {
            serde_json::Value::Number(number) => assert!(
                number.is_i64() || number.is_u64(),
                "{at}: floats are banned in the transcript (D29 rule 3)"
            ),
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    assert_no_floats(item, &format!("{at}[{index}]"));
                }
            }
            serde_json::Value::Object(fields) => {
                for (key, item) in fields {
                    assert_no_floats(item, &format!("{at}.{key}"));
                }
            }
            _ => {}
        }
    }
    assert_no_floats(&value, "$");

    // Rule 4: no conditional presence — every entry carries every field.
    let entries = value["entries"].as_array().expect("entries is an array");
    for entry in entries {
        for field in [
            "path",
            "format_version",
            "bytes",
            "status",
            "kind",
            "description",
            "items",
            "recomputed_digest",
            "error",
        ] {
            assert!(
                entry.get(field).is_some(),
                "entry is missing `{field}` — absent values must serialize as null, never be omitted"
            );
        }
    }
}

/// D87: the embedded-vector budget is enforced, not documented.
///
/// `build.rs` is the authoritative leg — it panics, so the crate cannot
/// build at all. This is the second, *testable* leg: it recomputes the
/// per-version totals from the linked table (so the generated
/// `EMBEDDED_BYTES_BY_VERSION` cannot drift from the bytes actually
/// embedded) and prints the utilisation, so a reviewer sees the tree
/// approaching the ceiling instead of discovering it as a red build.
#[test]
fn bitmatch_embedded_bytes_stay_under_the_per_version_ceiling() {
    let mut recomputed: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    for vector in EMBEDDED_VECTORS {
        *recomputed.entry(vector.format_version).or_default() += vector.bytes.len() as u64;
    }

    let declared: std::collections::BTreeMap<&str, u64> =
        EMBEDDED_BYTES_BY_VERSION.iter().copied().collect();
    assert_eq!(
        recomputed, declared,
        "the generated per-version byte totals disagree with the embedded bytes"
    );

    for (version, total) in &recomputed {
        let pct = (*total as f64) * 100.0 / (MAX_EMBEDDED_BYTES_PER_VERSION as f64);
        println!("D87: {version} embeds {total} B — {pct:.1}% of the per-version ceiling");
        assert!(
            *total <= MAX_EMBEDDED_BYTES_PER_VERSION,
            "{version}: {total} B embedded, over the D87 ceiling of \
             {MAX_EMBEDDED_BYTES_PER_VERSION} B (see build.rs and D87 §2.1)"
        );
    }
    assert!(!recomputed.is_empty(), "no format versions embedded");
}

// ─────────────────────────────────────────────────────────────────────────────
// Q53 / Q14 normative row N3, site 3 — TRANSCRIPT_VERSION stays 0 (R32)
// ─────────────────────────────────────────────────────────────────────────────

/// **The negative clause of the coupled-edit row, made executable.**
///
/// Q14 row N3 lists three sites that move together when the report byte format
/// versions, and its third is deliberately a **NEGATIVE**: `TRANSCRIPT_VERSION`
/// must *not* move. R32 established why on evidence — the transcript versions
/// an envelope that carries no report field, is written to `target/`, and sits
/// in no `FROZEN.sha256` — so `0` is this schema's first version, not a
/// placeholder waiting on Q14.
///
/// The row says the gate confirms this *"by `grep`, not by memory"*, and until
/// Q53 that was literally true: no Rust test named the numeral, and the only
/// runtime comparison was `scripts/wasm-bitmatch.mjs`'s — which checks the two
/// against *each other*, so bumping **both** would have passed the lane and
/// silently broken the negative clause.
///
/// So this asserts the value, not the agreement, at both sites:
///
/// - the Rust constant, by reference, so it cannot be satisfied by a stale copy;
/// - the runner's literal, by scrape, because it lives in JavaScript.
///
/// **If you are here because this test is red:** the fix is almost never to
/// update the number. Re-read the rule on `TRANSCRIPT_VERSION` in
/// `crates/wasm-bitmatch/src/lib.rs` — the version moves when a transcript
/// *field* is added, removed, renamed or reordered, and never for a change in
/// what the fields contain. If a field really did change, bump both sites and
/// amend R32's record and Q14 row N3 in the same commit.
#[test]
fn transcript_version_is_still_zero_at_both_sites() {
    assert_eq!(
        wasm_bitmatch::TRANSCRIPT_VERSION,
        0,
        "wasm_bitmatch::TRANSCRIPT_VERSION moved off 0. Q14 row N3's third site is a \
         NEGATIVE clause: the report byte format freezing at v1 does NOT move this."
    );

    let runner = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join("wasm-bitmatch.mjs");
    let source = fs::read_to_string(&runner)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", runner.display()));

    let declarations: Vec<&str> = source
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("const EXPECTED_TRANSCRIPT_VERSION"))
        .collect();
    assert_eq!(
        declarations.len(),
        1,
        "expected exactly one `const EXPECTED_TRANSCRIPT_VERSION` declaration in \
         scripts/wasm-bitmatch.mjs, found {}: {declarations:?}",
        declarations.len()
    );
    assert_eq!(
        declarations[0], "const EXPECTED_TRANSCRIPT_VERSION = 0;",
        "the wasm-bitmatch runner's expected transcript version no longer reads 0. \
         The runner compares itself against the module's exported version at lane \
         runtime, so moving BOTH keeps that lane green — which is exactly the hole \
         this assertion closes."
    );
}

/// The two discovery walks must carry the **same** ignorable-file rule, and
/// this is what stops them drifting apart again (D116 R8a, Q140).
///
/// `bitmatch_embedded_table_equals_the_committed_tree` above **cannot** catch
/// this class, which is why the check has to be a separate one: that test
/// compares the *result sets* of two walks that both **succeeded**, and a
/// `build.rs` panic happens strictly before any test in this crate runs. A
/// divergence that bricks the build is invisible to a test that needs the
/// build to have worked. So this reads the two sources as **text**.
///
/// A build script cannot import a test module, so the block is duplicated on
/// purpose; the duplication is only safe while something asserts the copies
/// are identical. Same technique as `cbor_crosscheck_contract.rs` on the
/// Python checker and `wasm-bitmatch.sh --trigger-self-test` arm 4 across two
/// shell scripts.
#[test]
fn bitmatch_ignorable_file_rule_is_identical_in_both_walkers() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let build_rs = manifest.join("build.rs");
    let runner = manifest
        .join("..")
        .join("antseal-core")
        .join("tests")
        .join("vector_runner.rs");

    let left = ignorable_block(&build_rs);
    let right = ignorable_block(&runner);

    assert_eq!(
        left,
        right,
        "the D116 R7 ignorable-file block has diverged between {} and {}. These two \
         walks impose the SAME closed classification on testdata/vectors/, and when \
         they disagree the stricter one fails the build (Q140). Edit both or neither.",
        build_rs.display(),
        runner.display(),
    );
}

/// The shared block, verbatim: its doc comment through the last of the three
/// `const IGNORED_*` declarations.
fn ignorable_block(path: &Path) -> String {
    const START: &str = "/// Names the discovery walk must ignore rather than classify.";
    const END: &str = "const IGNORED_NAMES:";

    let text =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let start = text.find(START).unwrap_or_else(|| {
        panic!(
            "{}: the D116 R7 ignorable-file block is missing (looked for `{START}`). It is \
             what keeps a git-ignored file from failing the build; do not delete it.",
            path.display()
        )
    });
    let rest = &text[start..];
    let end = rest.find(END).unwrap_or_else(|| {
        panic!(
            "{}: found the R7 doc comment but no `{END}` declaration after it",
            path.display()
        )
    });
    let end = rest[end..]
        .find('\n')
        .map_or(rest.len(), |offset| end + offset);
    rest[..end].to_owned()
}
