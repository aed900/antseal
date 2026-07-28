//! R9 — the verification-report golden-vector **regenerator** and emitter.
//!
//! The Q4 runner (`vector_runner.rs`) executes the committed
//! `testdata/vectors/v1/report/verification-reports.json` like any other
//! vector, and the Q5 lane (`scripts/wasm-bitmatch.sh`) executes it again
//! under `wasm32-unknown-unknown` and byte-compares. This file adds the two
//! things only the native side can do:
//!
//! 1. **Regenerate and diff** — rebuild the whole `expect` object from the
//!    file's own `inputs`, through R6's constructor and `verify_bundle`, and
//!    diff it against what is committed. Any change to the pipeline's output
//!    for any M0 shape turns this red with the offending field named.
//! 2. **Emit** — `emit_report_vector_document` (ignored by default) writes
//!    the document. It is the *only* sanctioned way to regenerate the file:
//!
//!    ```text
//!    cargo test -p antseal-core --features test-util --test report_vectors \
//!        -- --ignored emit_report_vector_document
//!    ./scripts/vector-freeze.sh --update      # then justify the digest diff
//!    ```
//!
//! Two independent regenerations therefore stand behind the one committed
//! artifact — this test (native, whole-document) and `crates/wasm-bitmatch`
//! (the same executor under wasm32, byte-compared). Unlike G15's kind there
//! is deliberately **no** Python cross-implementation: reproducing a report
//! means reproducing the whole evidence pipeline, and a second pipeline
//! would be a second product, not a cross-check. What stands in for it is
//! the *input* side — the bundles these reports describe are built from
//! commitments, AEAD, HKDF and fine-tree material that the `commitments`,
//! `unit-aead`, `signatures` and `fine-tree` vectors already pin against
//! independent implementations.
//!
//! Test names carry the reserved `vector_` marker so the three `cross-os-*`
//! CI lanes run them everywhere (CONTRIBUTING.md, "Cross-OS suite naming").

use std::fs;
use std::path::PathBuf;

use antseal_core::test_util::vectors_report::{KIND, REQUIRED_SHAPES, build_inputs};
use antseal_core::test_util::{vectors::first_difference, vectors_report};
use antseal_core::verify::REPORT_VERSION;

/// The committed document (workspace-relative via the crate manifest dir, so
/// it resolves on every OS and checkout location).
const VECTOR_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/report/verification-reports.json"
);

/// Every case the committed document carries, in file order: an R6
/// `shapes::catalogue()` handle plus the sentence saying what it pins.
///
/// This list is **generation-time input only** — the committed file carries
/// its own copy under `inputs.cases`, and every check reads that copy. So
/// adding a shape to R6's catalogue never breaks the frozen vector; only
/// changing what an already-pinned shape *means* does, which is precisely the
/// drift a golden vector exists to catch.
const CASES: &[(&str, &str)] = &[
    (
        "single-text-with-mirror/full",
        "raw-mirror full reveal: the mirror rides along with a whole-file text reveal (MVP-SPEC.md line 92)",
    ),
    (
        "single-text-with-mirror/full-no-mirror",
        "full text reveal with the raw mirror withheld — still a full reveal, mirrors being exempt by kind",
    ),
    (
        "single-text-with-mirror/untouched",
        "a bundle that proves the work exists and shows none of it: one committed placeholder, no touched files",
    ),
    (
        "single-binary/full",
        "binary file: offsets are raw-byte offsets, no canonical rendition and no mirror (MVP-SPEC.md line 83)",
    ),
    (
        "split-multi-unit/partial",
        "partial reveal with a leaf-exact cover: one --split unit of three, the middle one",
    ),
    (
        "split-multi-unit/partial-two-of-three",
        "partial reveal spanning two disjoint covers, so the blackout block sits between two revealed spans",
    ),
    (
        "split-multi-unit/full-via-enumerated-units",
        "full reveal derived from an enumerated unit list rather than declared (D28 rider 1)",
    ),
    (
        "split-multi-unit/all",
        "--all over a --split file: every normal unit plus the raw mirror",
    ),
    (
        "no-fine-tree/full",
        "--no-fine-tree file: one whole-file unit bound by unit_commit, no fine_root (MVP-SPEC.md lines 84, 94)",
    ),
    (
        "raw-mirror-sources/all",
        "the other two raw-mirror sources — a BOM-bearing and an NFD-bearing text file — revealed together",
    ),
    (
        "empty-file/full",
        "empty file: size 0, one empty unit, no fine tree (MVP-SPEC.md line 153; G4)",
    ),
    (
        "empty-file/untouched",
        "empty file as a committed placeholder: the size-only rendering at size 0 (MVP-SPEC.md line 121)",
    ),
    (
        "one-byte-file/full",
        "one-byte file: the smallest non-empty tiling domain (MVP-SPEC.md line 153)",
    ),
    (
        "unbalanced-n6/all",
        "full reveal at unbalanced n = 6, which releases s_root and rebuilds the whole fine tree",
    ),
    (
        "unbalanced-n6/unit-0",
        "per-unit reveal at unbalanced n = 6, leaves {0,1}: MSB-first GGM indexing through the pipeline (MVP-SPEC.md lines 96, 169)",
    ),
    (
        "unbalanced-n6/unit-1",
        "per-unit reveal at unbalanced n = 6, leaves {2,3}: MSB-first GGM indexing through the pipeline (MVP-SPEC.md lines 96, 169)",
    ),
    (
        "unbalanced-n6/unit-2",
        "per-unit reveal at unbalanced n = 6, leaves {4,5}: MSB-first GGM indexing through the pipeline (MVP-SPEC.md lines 96, 169)",
    ),
    (
        "multi-file/mixed",
        "multi-file work with an unrevealed committed-placeholder file, and the EMPTY-ANCHOR (UNANCHORED) bundle (MVP-SPEC.md lines 121, 153)",
    ),
    (
        "multi-file/all",
        "the same multi-file work fully revealed, so nothing renders as a placeholder",
    ),
    (
        "multi-file-anchored/mixed",
        "the populated anchor section: one OTS and two TSA artifacts, each an absent M0 slot (MVP-SPEC.md line 153)",
    ),
    (
        "ed25519-only-policy/full",
        "the Ed25519-only sig_policy fallback, so the signature-scheme datum has both of its named shapes pinned (MVP-SPEC.md line 97)",
    ),
];

const NON_SECRET: &str = "NON-SECRET test fixture (project rule 6): every bundle below is built by \
     R6's constructor from the documented fixed test seed W = bytes 0x00..0x1f \
     (testdata/README.md) under the fixed fixture seal_id, RNG seed and \
     app_version pinned in `inputs`. Reports carry only public statement data \
     — ids, sizes, spans, states — and the executor re-derives every k_u, \
     unit_salt, path_salt, file_salt and s_root of each work and requires none \
     of them to appear in the pinned bytes. Never real vault material.";

const DESCRIPTION: &str = "Verification-report golden vectors (R9): every M0 shape's canonical bundle \
     mapped to the byte-exact serialized VerificationReport that `verify_bundle` \
     produces for it — full text reveal, partial reveal with leaf-exact covers, \
     per-unit reveal at unbalanced n = 6 (MSB-first GGM indexing through the \
     pipeline), binary file, --no-fine-tree file, raw-mirror full reveal, empty \
     file, one-byte file, multi-file with an unrevealed committed-placeholder \
     file, and the empty-anchor (UNANCHORED) bundle. `report_json` is the D29 \
     compact-JSON encoding and is the medium the native<->WASM bit-match lane \
     compares (MVP-SPEC.md lines 153, 167, 169).";

fn committed_document() -> serde_json::Value {
    let path = PathBuf::from(VECTOR_PATH);
    let bytes = fs::read(&path)
        .unwrap_or_else(|e| panic!("{}: the R9 vector must exist: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("{}: not valid JSON: {e}", path.display()))
}

/// **The R9 generator-diff test.** Regenerate `expect` from `inputs` and
/// require it to equal the committed bytes' meaning, field for field.
#[test]
fn vector_report_document_regenerates() {
    let document = committed_document();
    let recomputed = vectors_report::regenerate_expect(&document)
        .unwrap_or_else(|e| panic!("regeneration: {e}"));
    let committed = document
        .get("expect")
        .unwrap_or_else(|| panic!("the vector has no `expect` object"));
    assert!(
        &recomputed == committed,
        "the committed verification-report vector no longer matches what antseal-core \
         computes.\n\
         First difference: {}\n\
         If this is a deliberate change to the report byte format it is a FORMAT EVENT \
         (docs/decisions/D29-report-byte-format.md, testdata/vectors/README.md): \
         re-emit with `cargo test -p antseal-core --features test-util --test \
         report_vectors -- --ignored emit_report_vector_document`, re-run \
         `scripts/vector-freeze.sh --update`, and justify the digest diff in the commit.",
        first_difference("expect", &recomputed, committed)
    );
}

/// The document really is the R9 one, and really does carry the M0 shapes the
/// milestone enumerates — asserted here against the committed file's own case
/// list, not merely inside the executor.
#[test]
fn vector_report_document_covers_the_mandated_m0_shapes() {
    let document = committed_document();
    assert_eq!(
        document.get("kind").and_then(serde_json::Value::as_str),
        Some(KIND)
    );

    let shapes: Vec<&str> = document
        .pointer("/inputs/cases")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("inputs.cases must be an array"))
        .iter()
        .filter_map(|case| case.get("shape").and_then(serde_json::Value::as_str))
        .collect();
    for (shape, row) in REQUIRED_SHAPES {
        assert!(
            shapes.contains(shape),
            "the M0 shape \"{row}\" (`{shape}`) is mandatory; found {shapes:?}"
        );
    }

    // Every case pins its report byte-exactly, and the object form is the
    // same bytes — the two are what the whole file exists to carry.
    let cases = document
        .pointer("/expect/cases")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("expect.cases must be an array"));
    assert_eq!(cases.len(), shapes.len(), "one expectation per input case");
    for case in cases {
        let shape = case
            .get("shape")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<unnamed>");
        let hex = case
            .get("report_json")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("`{shape}` pins no report_json"));
        let len = case
            .get("report_len")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("`{shape}` pins no report_len"));
        assert_eq!(
            hex.len() as u64,
            len * 2,
            "`{shape}`: report_json must be exactly report_len bytes of hex"
        );
        let bytes = decode_hex(hex);
        let decoded: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("`{shape}`: report_json is not valid JSON: {e}"));
        assert_eq!(
            Some(&decoded),
            case.get("report"),
            "`{shape}`: the object form must be the pinned bytes, decoded"
        );
        // D29 rule 8: the report carries its own format version, first field
        // — and it is the version this build produces. Derived from the
        // constant rather than hard-coded, so a bump that forgets the
        // re-emit fails here naming both halves of the edit (R32).
        let prefix = format!(r#"{{"report_version":{REPORT_VERSION}"#);
        assert!(
            bytes.starts_with(prefix.as_bytes()),
            "`{shape}`: pinned bytes must begin `{prefix}` — report_version is the first \
             serialized field (D29 rule 8) and must be REPORT_VERSION ({REPORT_VERSION}). \
             Bumping the constant re-emits the document: \
             `cargo test -p antseal-core --features test-util --test report_vectors \
             -- --ignored emit_report_vector_document`, then `scripts/vector-freeze.sh --update`"
        );
    }
}

/// The regenerator refuses a document of another kind rather than silently
/// producing something — a test-of-the-test for the one public entry point
/// other tasks may call.
#[test]
fn vector_report_regenerator_rejects_a_foreign_document() {
    let foreign = serde_json::json!({"kind": "fine-tree", "inputs": {}});
    let error = vectors_report::regenerate_expect(&foreign)
        .expect_err("a foreign document must not regenerate");
    assert!(error.to_string().contains("report"), "{error}");
}

/// The emitter's [`CASES`] list and the committed file agree — so a case
/// added to one and forgotten in the other is caught, rather than surviving
/// until the next regeneration silently rewrites the file.
#[test]
fn vector_report_emitter_case_list_matches_the_committed_document() {
    let document = committed_document();
    let committed: Vec<(String, String)> = document
        .pointer("/inputs/cases")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("inputs.cases must be an array"))
        .iter()
        .map(|case| {
            let field = |name: &str| {
                case.get(name)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            (field("shape"), field("pins"))
        })
        .collect();
    let expected: Vec<(String, String)> = CASES
        .iter()
        .map(|(shape, pins)| ((*shape).to_owned(), (*pins).to_owned()))
        .collect();
    assert_eq!(
        committed, expected,
        "the emitter's CASES list and the committed inputs.cases have diverged; \
         re-emit the document or fix the list"
    );
}

/// Regenerate the committed document. **Ignored by default**: it writes into
/// `testdata/`, which is a deliberate act with a freeze consequence, never a
/// side effect of running the suite. See this file's module docs.
#[test]
#[ignore = "writes testdata/; run deliberately when the report byte format changes"]
fn emit_report_vector_document() {
    let inputs = build_inputs(CASES);
    let document = serde_json::json!({"kind": KIND, "inputs": inputs.clone()});
    let expect = vectors_report::regenerate_expect(&document)
        .unwrap_or_else(|e| panic!("recomputation: {e}"));

    // The envelope's eight keys are written in their documented order; every
    // nested object is `serde_json`'s own (alphabetical) ordering, which is
    // exactly why the human-readable `report` object is NOT the field-order
    // pin — `report_json` is (see the format doc).
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
        "wrote {} ({} case(s)) — now run ./scripts/vector-freeze.sh --update",
        path.display(),
        CASES.len()
    );
}

/// Collapse the source-literal line wrapping of the long prose constants into
/// single spaces, so the emitted JSON string is one clean sentence run.
fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Decode canonical lowercase hex; panics on malformed input, which in a test
/// reading a committed file is the correct loud failure.
fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex");
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .unwrap_or_else(|e| panic!("bad hex at offset {i}: {e}"))
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Q53 / Q14 normative row N4 — the decode layer is never a report field (D86)
// ─────────────────────────────────────────────────────────────────────────────

/// **D86, permanent.** `ManifestError::layer()` / `SealProofError::layer()` are
/// *failure context*, not a report field, and never will be: a
/// `VerificationReport` exists only for a bundle that **passed** (D27 §4), and
/// `layer` is already the report's word for two other things — the evidence
/// layer and the storage-linkage layer (MVP-SPEC.md lines 118/119). Minting a
/// third meaning would freeze an ambiguity into a format that cannot be
/// changed without a version event.
///
/// Q14 row N4 ticks this by `grep -c '"layer"' … → 0`. A count computed by
/// hand at gate time is evidence exactly once; this is the same count, run on
/// every build, in **three** places rather than one:
///
/// 1. the committed document as a whole — the literal grep the row names;
/// 2. each of the 21 byte-pinned `report_json` strings, so a `layer` buried in
///    a report but absent from the surrounding envelope could not hide;
/// 3. the **regenerated** reports, which is the only one of the three that is
///    about the live `VerificationReport` type rather than about frozen bytes.
///    Without it, adding a `layer` field would be caught by the vector diff
///    (loudly, but as "the bytes changed") and by nothing that says why.
#[test]
fn vector_report_never_carries_a_decode_layer() {
    let document = committed_document();

    // (1) The row's own grep.
    let text = fs::read_to_string(PathBuf::from(VECTOR_PATH))
        .unwrap_or_else(|e| panic!("{VECTOR_PATH}: {e}"));
    assert_eq!(
        text.matches("layer").count(),
        0,
        "the committed report vector document now contains the substring `layer`. \
         D86 is permanent: the decode layer is failure context and is not a report \
         field. If a NEW field legitimately needs that word, it is named \
         `decode_layer` and only in U30's `--json` FAILURE envelope (D65, M3) — \
         which is not this document."
    );

    // (2) Each byte-pinned report string on its own.
    let cases = document
        .get("expect")
        .and_then(|expect| expect.get("cases"))
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("the R9 vector has no `expect.cases` array"));
    assert!(
        !cases.is_empty(),
        "no cases in the committed document — this check would be vacuous"
    );
    for case in cases {
        let shape = case
            .get("shape")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?");
        let json = case
            .get("report_json")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("case {shape:?} has no `report_json` string"));
        assert!(
            !json.contains("layer"),
            "the pinned report bytes for shape {shape:?} contain `layer`"
        );
    }

    // (3) The live type, not the frozen bytes.
    let recomputed = vectors_report::regenerate_expect(&document)
        .unwrap_or_else(|e| panic!("regeneration: {e}"));
    let rendered = serde_json::to_string(&recomputed)
        .unwrap_or_else(|e| panic!("cannot re-serialize the regenerated expect: {e}"));
    assert!(
        !rendered.contains("layer"),
        "a freshly computed VerificationReport now serializes a `layer` somewhere. \
         The committed vector has not caught up yet, so the failing artifact is the \
         TYPE, not the bytes: D27 §4 makes the report exist only for a bundle that \
         passed, so there is no decode layer to report. See D86 and Q14 row N4."
    );
}
