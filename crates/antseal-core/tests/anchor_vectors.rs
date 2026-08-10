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

use antseal_core::anchor::ots::{
    MAX_OTS_ATTESTATION_PAYLOAD_BYTES, MAX_OTS_ATTESTATIONS, MAX_OTS_BRANCH_WIDTH, MAX_OTS_DEPTH,
    MAX_OTS_OPERAND_BYTES, MAX_OTS_OPS, MAX_OTS_VALUE_BYTES, OtsAttestation, OtsShape,
    merkle_root_of, parse_ots_measured,
};
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

/// Lowercase hex → bytes, for the vector's own `*_hex` fields.
///
/// Local rather than borrowed from `test_util`: this file reads the committed
/// document directly, and a decoder shared with the executor would let one bug
/// hide itself in both halves of a comparison.
fn hex_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "hex has an odd length");
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex digit pair"))
        .collect()
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

/// The 3 808-byte spliced artifact's **shape**, measured by the parser that
/// enforces the limits (**A63** Accept row 1, **A48(a)**'s input).
///
/// A63's Accept asks that the assembled artifact *"round-trips through
/// `parse_ots` and its attestation set matches what the response bodies
/// name"*. Nothing asserted that as a **shape** until this row: the vector
/// runner asserts the artifact's *verdicts*, and the `antseal-anchor` splice
/// test asserts its *SHA-256*, but neither states what the DAG measures — and
/// the F4 registry's `measured against` cells are exactly those measurements.
/// So this is also the pin that stops those cells being prose: `parse_ots`
/// itself, over the bytes the frozen vector carries, is the only producer the
/// registry's own rule admits (§5, *"produced by the parser itself"*).
///
/// Deliberately an **integration** test rather than a `--lib` one: the bytes
/// live in `testdata/vectors/v1/anchor/anchor.json`, per D103 RULING 3a there
/// is no file copy of them, and `include_str!`-ing a 40 KB JSON document into
/// the `wasm32-core-tests` lane to reach three of its fields would trade a
/// real cost for no coverage — the wasm32 lane already re-executes this exact
/// artifact end to end and byte-compares (`scripts/wasm-bitmatch.sh`).
#[test]
fn vector_anchor_upgraded_artifact_has_the_shape_the_f4_registry_records() {
    let document = committed();
    let inputs = &document["inputs"];

    let digest_hex = inputs["anchor_digest"].as_str().expect("a hex digest");
    let digest: [u8; 32] = hex_bytes(digest_hex)
        .try_into()
        .expect("the anchor digest is 32 bytes");

    // Cases 4, 5 and 6 (0-based 3..=5) carry the identical spliced artifact;
    // asserting that here is what makes measuring one of them a statement
    // about all three.
    let artifacts: Vec<Vec<u8>> = (3..=5)
        .map(|i| hex_bytes(inputs["cases"][i]["artifact_hex"].as_str().expect("hex")))
        .collect();
    assert!(
        artifacts.windows(2).all(|w| w[0] == w[1]),
        "cases 4..6 no longer carry one artifact; the measurement below speaks for one of them"
    );
    let artifact = &artifacts[0];
    assert_eq!(artifact.len(), 3_808, "the spliced artifact's size");

    let (parsed, shape) =
        parse_ots_measured(artifact, &digest).expect("the spliced artifact parses");

    assert_eq!(
        shape,
        OtsShape {
            ops: 244,
            max_depth: 85,
            max_width: 3,
            attestations: 6,
            // **Smaller than the borrowed `LARGE_TEST` fixture's 174 and 210**,
            // which is why A48 could not simply re-point those two registry
            // rows: this artifact's operands are 32-byte merkle siblings and a
            // 44-byte calendar commitment, where `LARGE_TEST` carries a real
            // fat coinbase-transaction prefix. The binding measurement for
            // those two limits is still the mainnet proof, and §5 says so.
            max_operand_bytes: 89,
            max_value_bytes: 125,
            max_attestation_payload_bytes: 46,
        }
    );

    // The margin discipline `ots/tests.rs` states for the committed fixtures,
    // applied to the artifact a verifier actually parses. This is the premise
    // D104's KEEP-1 024 ruling rests on (`MAX_OTS_DEPTH >= 8 x` the deepest
    // real artifact = 680), asserted here rather than quoted there.
    assert!(shape.ops <= MAX_OTS_OPS / 8);
    assert!(shape.max_depth <= MAX_OTS_DEPTH / 8);
    assert!(shape.max_width <= MAX_OTS_BRANCH_WIDTH / 8);
    assert!(shape.attestations <= MAX_OTS_ATTESTATIONS / 8);
    assert!(shape.max_operand_bytes <= MAX_OTS_OPERAND_BYTES / 8);
    assert!(shape.max_value_bytes <= MAX_OTS_VALUE_BYTES / 8);
    assert!(shape.max_attestation_payload_bytes <= MAX_OTS_ATTESTATION_PAYLOAD_BYTES / 8);

    // A63 Accept row 1's second half: the attestation set is the one the six
    // committed response bodies name — three calendars still pending in their
    // own branches, three Bitcoin branches at the three heights
    // `upgraded/PROVENANCE.md` records, and nothing else.
    let mut pending: Vec<&str> = Vec::new();
    let mut bitcoin: Vec<u64> = Vec::new();
    for attestation in &parsed.attestations {
        match attestation {
            OtsAttestation::Pending { uri, commitment } => {
                assert!(commitment.is_some(), "{uri} has an indeterminate value");
                pending.push(uri);
            }
            OtsAttestation::Bitcoin {
                height,
                merkle_root,
            } => {
                assert!(merkle_root.is_some(), "block {height} has no derived root");
                bitcoin.push(*height);
            }
            OtsAttestation::UnknownType { tag, .. } => {
                panic!("an unknown attestation type {tag:?} in a fixture we assembled")
            }
        }
    }
    pending.sort_unstable();
    bitcoin.sort_unstable();
    assert_eq!(
        pending,
        [
            "https://alice.btc.calendar.opentimestamps.org",
            "https://bob.btc.calendar.opentimestamps.org",
            "https://btc.calendar.catallaxy.com",
        ]
    );
    assert_eq!(bitcoin, [960_767, 960_768, 960_771]);
}

// ── A48(b): the empirical merkle-root byte-order pin ─────────────────────

/// The mainnet headers A25 fetched on 2026-08-07, both endpoints.
///
/// `include_str!` rather than `fs::read`, matching `replay.rs`'s rule: a moved
/// fixture is a **compile error**, not a test that silently stops covering
/// anything. 160 lowercase hex characters each — the 80-byte header — with
/// url/http/bytes/sha256/utc per file in `CAPTURE.log`.
const FETCHED_HEADERS: &[(u64, &str, &str)] = &[
    (
        960_767,
        include_str!(
            "../../../testdata/anchors/A25-upgrade-headers/esplora-blockstream-header-960767.txt"
        ),
        include_str!(
            "../../../testdata/anchors/A25-upgrade-headers/esplora-mempool-header-960767.txt"
        ),
    ),
    (
        960_768,
        include_str!(
            "../../../testdata/anchors/A25-upgrade-headers/esplora-blockstream-header-960768.txt"
        ),
        include_str!(
            "../../../testdata/anchors/A25-upgrade-headers/esplora-mempool-header-960768.txt"
        ),
    ),
    (
        960_771,
        include_str!(
            "../../../testdata/anchors/A25-upgrade-headers/esplora-blockstream-header-960771.txt"
        ),
        include_str!(
            "../../../testdata/anchors/A25-upgrade-headers/esplora-mempool-header-960771.txt"
        ),
    ),
];

/// **A48(b).** The ops-derived merkle root equals a *fetched* mainnet header's
/// bytes `36..68`, with no reversal, at all three heights this project's own
/// upgraded `.ots` attests.
///
/// This is the pin A12's `Do` asked for and A12 could not land: what `header.rs`
/// ships is the **structural** read at 36..68 with no reversal, guarded by the
/// synthetic mutation test `a_byte_reversed_merkle_root_does_not_match`. That
/// test proves the implementation does not reverse; it cannot prove the
/// *convention* is right, because both sides of its comparison are values the
/// test itself chose. Here neither side is chosen: the left is derived by
/// executing a real calendar's op chain, the right is 32 bytes of a block
/// header two independent endpoints served.
///
/// **Why the reversal arm is not decoration.** A verifier that reversed one
/// side would still pass every synthetic test in the tree, because a synthetic
/// fixture reverses with it. It cannot pass this one: Bitcoin's merkle
/// algorithm is not reversal-symmetric, so a reversed root is a root no honest
/// artifact derives, and the assertion below says so at every height.
#[test]
fn vector_anchor_ops_derive_the_fetched_mainnet_headers_merkle_root() {
    let document = committed();
    let inputs = &document["inputs"];
    let digest: [u8; 32] = hex_bytes(inputs["anchor_digest"].as_str().expect("hex"))
        .try_into()
        .expect("32 bytes");
    let artifact = hex_bytes(inputs["cases"][3]["artifact_hex"].as_str().expect("hex"));
    let parsed = parse_ots_measured(&artifact, &digest)
        .expect("the spliced artifact parses")
        .0;

    let mut checked = 0_usize;
    for (height, blockstream, mempool) in FETCHED_HEADERS {
        // Two independent endpoints, byte-identical. An unsigned header is
        // trusted only because two of them agree (A49's must-agree rule), so
        // the agreement is asserted rather than assumed.
        assert_eq!(
            blockstream.trim(),
            mempool.trim(),
            "the two committed captures for block {height} disagree"
        );
        let header: [u8; 80] = hex_bytes(blockstream.trim())
            .try_into()
            .expect("a committed header is 80 bytes");
        let field = merkle_root_of(&header);

        let derived = parsed
            .attestations
            .iter()
            .find_map(|a| match a {
                OtsAttestation::Bitcoin {
                    height: h,
                    merkle_root: Some(root),
                } if h == height => Some(root.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no Bitcoin attestation derives a value at block {height}"));

        assert_eq!(
            derived.as_slice(),
            field.as_slice(),
            "block {height}: the ops-derived root is not the header's merkle-root field"
        );

        // The mutation arm, over the same real bytes: reverse the header's
        // field and the match must vanish. A 32-byte value that matched both
        // orders would be a palindrome and would pin nothing, so that is
        // excluded first rather than assumed.
        let mut reversed = field;
        reversed.reverse();
        assert_ne!(field, reversed, "block {height}'s root is a palindrome");
        assert_ne!(
            derived.as_slice(),
            reversed.as_slice(),
            "block {height}: a reversed merkle root still matched — the byte-order \
             convention this test exists to pin is not being applied"
        );
        checked += 1;
    }
    assert_eq!(checked, 3, "all three attested heights are pinned");
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
