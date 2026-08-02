//! A11/A12's suite: the four measured aborts that condemned
//! `opentimestamps =0.2.0`, one reachable witness per (b)-class limit, the
//! frozen check order, and the shape of every committed fixture.
//!
//! Every adversarial input is **built here from named parts** rather than
//! committed as an opaque blob, so that a reader can see what makes it
//! hostile. The four D58 regression inputs are reconstructed to the byte
//! counts D58 measured — 80, 102, 87 and 90 — and each test asserts that
//! count, so a builder change that quietly makes the witness a different
//! shape is caught.

use super::*;
use crate::bundle::schema::OtsUpgrade;
use crate::codec::caps::MAX_OTS_BYTES;

// ── builders ─────────────────────────────────────────────────────────────

/// The container magic, restated here **independently of the parser's copy**
/// so that a mutation of `parse::MAGIC` cannot silently move every fixture
/// with it.
const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

const PENDING_TAG: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const BITCOIN_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

/// Little-endian base-128, minimal form.
fn varuint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value % 128) as u8;
        value /= 128;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// `magic ‖ version ‖ digest-type ‖ digest ‖ body` — the 65-byte header plus
/// a timestamp body.
fn container(digest: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(65 + body.len());
    out.extend_from_slice(MAGIC);
    out.push(0x01);
    out.push(0x08);
    out.extend_from_slice(digest);
    out.extend_from_slice(body);
    out
}

/// A digest that is not any fixture's, for negative cases.
fn digest_of(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn attestation(tag: [u8; 8], payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00];
    out.extend_from_slice(&tag);
    out.extend_from_slice(&varuint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

/// A pending attestation whose payload is a varbytes URI.
fn pending(uri: &str) -> Vec<u8> {
    let mut payload = varuint(uri.len() as u64);
    payload.extend_from_slice(uri.as_bytes());
    attestation(PENDING_TAG, &payload)
}

/// A Bitcoin attestation whose payload is a varuint height.
fn bitcoin(height: u64) -> Vec<u8> {
    attestation(BITCOIN_TAG, &varuint(height))
}

/// `0xf0` append with an operand.
fn append(operand: &[u8]) -> Vec<u8> {
    let mut out = vec![0xf0];
    out.extend_from_slice(&varuint(operand.len() as u64));
    out.extend_from_slice(operand);
    out
}

/// Splice `n` children under one node: `ff c0 ff c1 … c_{n-1}`.
fn fork(children: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, child) in children.iter().enumerate() {
        if i + 1 < children.len() {
            out.push(0xff);
        }
        out.extend_from_slice(child);
    }
    out
}

fn code_of(result: &Result<OtsArtifact, OtsError>) -> &'static str {
    match result {
        Ok(_) => "<accepted>",
        Err(error) => error.code(),
    }
}

// ── the committed fixtures ───────────────────────────────────────────────

/// D58 §11, row 1. Red if the fixture stops parsing, or if the fork/`0xff`
/// handling drops or duplicates a branch.
#[test]
fn merged_pending_ots_parses_and_yields_three_pending_attestations() {
    for (bytes, digest, size) in [(MERGED_A, DIGEST_A, 664_usize), (MERGED_B, DIGEST_B, 629)] {
        assert_eq!(bytes.len(), size, "fixture size changed");
        let artifact = parse_ots(bytes, &digest).expect("the merged fixture must parse");
        assert_eq!(artifact.attestations.len(), 3, "one branch per calendar");

        let uris: Vec<&str> = artifact
            .attestations
            .iter()
            .map(|attestation| match attestation {
                OtsAttestation::Pending { uri, .. } => uri.as_str(),
                other => panic!("expected a pending attestation, got {other:?}"),
            })
            .collect();
        assert_eq!(
            uris,
            [
                "https://alice.btc.calendar.opentimestamps.org",
                "https://bob.btc.calendar.opentimestamps.org",
                "https://btc.calendar.catallaxy.com",
            ],
            "branch order is the merge order D58 §7.3 fixes"
        );
    }
}

/// D58 §11, row 2 — and the strongest evidence in the suite, because the
/// other party computed the same value from its own records.
///
/// This is the commitment D58 §7.4 put in a live `GET
/// https://bob.btc.calendar.opentimestamps.org/timestamp/<hex>`: the calendar
/// answered `404` + 42 bytes of *"Pending confirmation in Bitcoin
/// blockchain"* for it, and `404` + 9 bytes of *"Not found"* for a
/// one-byte perturbation of it. If op execution changes, A14 polls the wrong
/// URL and gets `Not found` — which D58 §7.4 rules a **hard error**, not a
/// re-poll.
#[test]
fn pending_commitment_matches_recorded_value() {
    const A_BOB: &str = "6a6f9805da7f14a96bcb07a45dc11eabc6ec73a21edc256fc1e4a109dc32556f\
                         003873210b8c9c8c453329b8";

    let artifact = parse_ots(MERGED_A, &DIGEST_A).expect("parses");
    let OtsAttestation::Pending {
        commitment: Some(commitment),
        uri,
    } = &artifact.attestations[1]
    else {
        panic!("branch 1 must be bob's, with a determinate commitment");
    };
    assert_eq!(uri, "https://bob.btc.calendar.opentimestamps.org");
    assert_eq!(commitment.len(), 44, "measured 44 B for all six captures");
    assert_eq!(hex(commitment), A_BOB);
}

/// A Bitcoin attestation's payload is a varuint height, recovered exactly —
/// including across the boundaries where the encoding grows a byte, which is
/// where D58 §4's weaker instance lives (`len = 1` around a 3-byte height).
#[test]
fn bitcoin_heights_survive_the_varuint_boundaries() {
    let digest = digest_of(0x42);
    for height in [
        0_u64,
        1,
        127,
        128,
        16_383,
        16_384,
        449_397,
        449_399,
        u64::from(u32::MAX),
    ] {
        let artifact = parse_ots(&container(&digest, &bitcoin(height)), &digest).expect("parses");
        assert_eq!(
            artifact.attestations,
            vec![OtsAttestation::Bitcoin {
                height,
                merkle_root: Some(digest.to_vec()),
            }],
            "height {height}"
        );
    }
}

/// D58 §11, row 3. Red if the Bitcoin attestation payload parse regresses,
/// or if the derived root at that node changes.
#[test]
fn upgraded_ots_yields_bitcoin_height_and_merkle_root() {
    let artifact = parse_ots(UPGRADED_LARGE_TEST, &DIGEST_LARGE_TEST).expect("parses");
    assert_eq!(artifact.attestations.len(), 4, "2 pending + 2 bitcoin");

    let bitcoin: Vec<(u64, String)> = artifact
        .attestations
        .iter()
        .filter_map(|attestation| match attestation {
            OtsAttestation::Bitcoin {
                height,
                merkle_root: Some(root),
            } => Some((*height, hex(root))),
            _ => None,
        })
        .collect();
    assert_eq!(
        bitcoin,
        vec![
            (
                449_399,
                "1a1da26714e8ef3b140c5f461ee52ea6fb5d8ca8e02d73370b5b416265eb1f5e".to_owned()
            ),
            (
                449_397,
                "7c17a8a0d6bc1da3604ecd442fc38869983290dcbc4876bdf0fcf133791ff218".to_owned()
            ),
        ]
    );
}

/// The F4 registry's provenance cells, measured by the parser that enforces
/// the limits — so a re-measurement (A25) is a call, not a rewrite.
#[test]
fn the_committed_fixtures_have_the_shape_the_f4_registry_records() {
    let (_, merged) = parse_ots_measured(MERGED_A, &DIGEST_A).expect("parses");
    assert_eq!(
        merged,
        OtsShape {
            ops: 34,
            max_depth: 12,
            max_width: 3,
            attestations: 3,
            max_operand_bytes: 32,
            max_value_bytes: 64,
            max_attestation_payload_bytes: 46,
        }
    );

    let (_, upgraded) =
        parse_ots_measured(UPGRADED_LARGE_TEST, &DIGEST_LARGE_TEST).expect("parses");
    assert_eq!(
        upgraded,
        OtsShape {
            ops: 100,
            // D58 §9.5's cell says 69; under §9.3's own normative depth
            // definition it is 67. The registry records the correction.
            max_depth: 67,
            max_width: 2,
            attestations: 4,
            max_operand_bytes: 174,
            max_value_bytes: 210,
            max_attestation_payload_bytes: 46,
        }
    );

    // Every measured quantity is far under its cap; that is what the F4
    // margins claim, asserted rather than trusted.
    for shape in [merged, upgraded] {
        assert!(shape.ops <= MAX_OTS_OPS / 8);
        assert!(shape.max_depth <= MAX_OTS_DEPTH / 8);
        assert!(shape.max_width <= MAX_OTS_BRANCH_WIDTH / 8);
        assert!(shape.attestations <= MAX_OTS_ATTESTATIONS / 8);
        assert!(shape.max_operand_bytes <= MAX_OTS_OPERAND_BYTES / 8);
        assert!(shape.max_value_bytes <= MAX_OTS_VALUE_BYTES / 8);
        assert!(shape.max_attestation_payload_bytes <= MAX_OTS_ATTESTATION_PAYLOAD_BYTES / 8);
    }
}

// ── the digest-commitment check (D58 §11 row 4 = D56 §9's row) ────────────

/// **One test in two documents.** D58 §11's
/// `ots_stamping_a_different_digest_is_rejected` pins the *position* (step 5,
/// before the walk); D56 §9's
/// `a_wrong_digest_ots_is_invalid_regardless_of_its_attestations` makes the
/// stronger statement (it beats a genuine, online-confirmable Bitcoin
/// attestation). D91 §6.4 records that they are the same input, so this
/// asserts both — which is what D91 §11.7 asks for.
///
/// Red when step 5 is removed or moved after the walk. **The worst reachable
/// defect in the file**: a `.ots` for someone else's seal, carrying a real
/// Bitcoin attestation, would otherwise render `proven`.
#[test]
fn ots_stamping_a_different_digest_is_rejected() {
    // (a) the position — one flipped bit in the merged fixture's start
    //     digest, everything else untouched.
    let mut flipped = DIGEST_A;
    flipped[0] ^= 0x01;
    let result = parse_ots(MERGED_A, &flipped);
    assert_eq!(
        code_of(&result),
        "anchor-ots-digest-mismatch",
        "step 5 must fire, and no other code (A21 row 1)"
    );

    // (b) the strength — a *real upgraded* proof, whose Bitcoin attestations
    //     are genuine and online-confirmable, offered for the wrong seal.
    let result = parse_ots(UPGRADED_LARGE_TEST, &DIGEST_A);
    assert_eq!(code_of(&result), "anchor-ots-digest-mismatch");

    // (c) the amplification argument, made observable: rejection does not
    //     depend on the body being well-formed at all, so a wrong-digest
    //     `.ots` costs one 32-byte comparison.
    let junk = container(&digest_of(0x11), &[0xff; 4096]);
    assert_eq!(
        code_of(&parse_ots(&junk, &digest_of(0x22))),
        "anchor-ots-digest-mismatch"
    );

    // …and D58's losing spelling is never what comes out.
    assert_ne!(
        code_of(&parse_ots(MERGED_A, &flipped)),
        "ots-ops-do-not-commit-anchor-digest"
    );
}

// ── the four measured aborts ─────────────────────────────────────────────

/// **D58 §3.1 — 80 bytes, uncatchable `SIGABRT`.**
///
/// An unknown 8-byte attestation tag with the length varint
/// `ff ff ff ff ff 0f` = 549 755 813 887. The rejected crate ran
/// `vec![0; len]` *before reading a byte*: `memory allocation of 549755813887
/// bytes failed`, exit 134. That is `handle_alloc_error`, **not** a panic, so
/// `catch_unwind` cannot intercept it and in WASM it is a module trap — which
/// is why this test would not merely fail against the crate, it would kill
/// the test process.
#[test]
fn unknown_attestation_with_huge_declared_length_is_rejected_not_aborted() {
    let digest = digest_of(0x42);
    let mut body = vec![0x00];
    body.extend_from_slice(&[0xde; 8]); // an unknown attestation type
    body.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x0f]);
    let bytes = container(&digest, &body);

    assert_eq!(bytes.len(), 80, "D58 §3.1's input is exactly 80 bytes");
    let result = parse_ots(&bytes, &digest);
    assert_eq!(
        code_of(&result),
        "anchor-ots-attestation-payload-too-long",
        "the payload cap must fire before anything is allocated"
    );
    assert_eq!(
        result,
        Err(OtsError::AttestationPayloadTooLong {
            limit: MAX_OTS_ATTESTATION_PAYLOAD_BYTES,
            declared: 549_755_813_887,
        })
    );
}

/// **D58 §3.2 — 102 bytes, a second uncatchable `SIGABRT`.**
///
/// 24 `0xf3` hexlify ops. The rejected crate capped the *operand* and not the
/// *running value*, and hexlify takes no operand and doubles: `32 · 2²⁴ =
/// 536 870 912`, exactly the failed allocation. At 36 ops it asks for 2 TiB.
///
/// **Here the chain cannot grow the value for a second, independent reason**,
/// and this is a correction to D58 §11, which asks for
/// `anchor-ots-value-too-long` from this input: §9.4 makes hexlify a
/// *registered-but-unimplemented* op, so it is skipped structurally and the
/// value never grows at all. The file parses, allocates nothing, and yields
/// one attestation whose commitment is `None`. The value cap still exists and
/// still fires — on `append`, which is the only implemented op that can grow
/// a value — and `appends_past_the_value_cap_are_rejected` witnesses that
/// half.
#[test]
fn hexlify_chain_cannot_grow_the_running_value() {
    let digest = digest_of(0x42);
    for (ops, expect_len) in [(20_usize, 98_usize), (24, 102), (36, 114)] {
        let mut body = vec![0xf3; ops];
        body.extend_from_slice(&attestation([0xde; 8], b"abc"));
        let bytes = container(&digest, &body);
        assert_eq!(bytes.len(), expect_len, "{ops} hexlify ops");

        let (artifact, shape) = parse_ots_measured(&bytes, &digest)
            .expect("an unimplemented op is not an error (D58 §9.4)");
        assert_eq!(
            shape.max_value_bytes, 32,
            "the running value never grew past the start digest"
        );
        assert_eq!(shape.ops as usize, ops);
        assert_eq!(
            artifact.attestations,
            vec![OtsAttestation::UnknownType {
                tag: [0xde; 8],
                payload_len: 3,
            }]
        );
    }
}

/// The other half of D58 §3.2: the value cap itself, on the only op that can
/// reach it.
#[test]
fn appends_past_the_value_cap_are_rejected() {
    let digest = digest_of(0x42);
    let operand = vec![0xab; MAX_OTS_OPERAND_BYTES as usize];
    let mut body = append(&operand);
    body.extend_from_slice(&append(&operand)); // 32 → 16 416 → 32 800
    body.extend_from_slice(&pending("https://example.invalid"));
    let bytes = container(&digest, &body);

    assert!(bytes.len() < MAX_OTS_BYTES as usize);
    assert_eq!(
        parse_ots(&bytes, &digest),
        Err(OtsError::ValueTooLong {
            limit: MAX_OTS_VALUE_BYTES,
            would_be: 32_800,
        }),
        "each operand is exactly at the operand cap and passes; the value \
         cap fires on the second append (D58 §9.3)"
    );
}

/// **D58 §3.3 — 87 bytes, a build-profile-dependent verdict.**
///
/// Thirteen continuation bytes take the rejected crate's unbounded `shift`
/// past 63. In debug it panics (`attempt to shift left with overflow`,
/// exit 101); in **release** the shift is masked, the length silently becomes
/// `0`, the file *parses successfully* as an unknown attestation with an
/// empty payload, and re-serialises to different bytes. The same
/// `.sealproof` therefore yields *"the verifier crashed"* from a test build
/// and *"valid artifact, one unknown attestation"* from the shipped one.
#[test]
fn thirteen_byte_varint_is_rejected() {
    let digest = digest_of(0x42);
    let mut body = vec![0x00];
    body.extend_from_slice(&[0xde; 8]);
    body.extend_from_slice(&[0x80; 12]);
    body.push(0x00);
    let bytes = container(&digest, &body);

    assert_eq!(bytes.len(), 87, "D58 §3.3's input is exactly 87 bytes");
    assert_eq!(
        code_of(&parse_ots(&bytes, &digest)),
        "anchor-ots-varint-too-long",
        "a masked-shift regression that 'succeeds' fails here"
    );
}

/// The structural half of D58 §3.3's claim, and it exists because the unit
/// test above **cannot** carry it.
///
/// `.github/workflows/ci.yml` is `cargo test --workspace --locked` and there
/// is no release test lane anywhere in CI or in `scripts/local-gate.sh`, so a
/// test asserting *"the same answer in debug and release"* would only ever
/// run in debug and could never fail on the release half — the un-failable
/// test this project keeps finding. The cross-profile property is instead
/// guaranteed by construction (a bounded varuint reader has no shift that can
/// overflow) and witnessed here: **no shift by a runtime value anywhere under
/// `anchor/ots/`**, that being the only construct whose behaviour differs
/// between profiles.
///
/// Deliberately stronger than its name: it rejects *every* binary shift in
/// the library region, constant shifts included, because telling the two
/// apart needs a parser and there are none to keep.
#[test]
fn ots_module_contains_no_runtime_shift() {
    // Needles built at runtime so this file does not contain its own.
    let shl = format!("{0}{0}", '<');
    let shr = format!("{0}{0}", '>');
    let forbidden = [
        format!(" {shl} "),
        format!(" {shr} "),
        format!("{shl}="),
        format!("{shr}="),
        "wrapping_shl".to_owned(),
        "wrapping_shr".to_owned(),
        "checked_shl".to_owned(),
        "checked_shr".to_owned(),
        "overflowing_shl".to_owned(),
        "overflowing_shr".to_owned(),
        "unbounded_shl".to_owned(),
        "unbounded_shr".to_owned(),
    ];

    // Every file of the module. `include_str!` keeps this runnable on
    // `wasm32-unknown-unknown`, which has no filesystem (P14) — and adding a
    // file without adding it here is caught by the count assertion.
    let sources: [(&str, &str); 6] = [
        ("mod.rs", include_str!("mod.rs")),
        ("error.rs", include_str!("error.rs")),
        ("exec.rs", include_str!("exec.rs")),
        ("header.rs", include_str!("header.rs")),
        ("limits.rs", include_str!("limits.rs")),
        ("parse.rs", include_str!("parse.rs")),
    ];

    for (name, source) in sources {
        // Library region only: a test may legitimately shift while building
        // a witness, and a test's behaviour is not the shipped parser's.
        let library_region = source.split("#[cfg(test)]").next().unwrap_or("");
        for needle in &forbidden {
            assert!(
                !library_region.contains(needle.as_str()),
                "anchor/ots/{name} contains {needle:?} — the varuint reader \
                 accumulates by multiplication precisely so that no shift \
                 exists to behave differently in release (D58 §3.3)"
            );
        }
    }
}

/// **D58 §4 — 90 bytes, two implementations, identical bytes, different
/// attestation sets.** The finding that would matter even if every abort were
/// fixed.
///
/// A Bitcoin attestation declares a 9-byte payload and writes 1. The rejected
/// crate reads the declared length and then **ignores it**, parsing the
/// height from the *outer* stream, so it reports `bitcoin(height=1)` **and**
/// `pending(uri="ab")`; `python-opentimestamps` sub-slices, caps at 8192, and
/// asserts EOF, so it reports one Bitcoin attestation with a 9-byte payload.
/// A sealer who can show one attestation to one verifier and a different one
/// to another has a capability antseal exists to deny.
#[test]
fn attestation_payload_length_is_authoritative() {
    let digest = digest_of(0x42);

    // Branch 1: a Bitcoin attestation declaring **9** payload bytes and
    // writing **1**. The eight bytes its sub-slice therefore swallows are the
    // opening of branch 2 — which is exactly what a length-ignoring parser
    // hands back as a second attestation.
    let mut lying = vec![0x00];
    lying.extend_from_slice(&BITCOIN_TAG);
    lying.push(0x09); // declared payload length
    lying.push(0x01); // height = 1, the only byte it means to write

    // Branch 2, which only a length-ignoring parser ever reaches: the tail
    // of that pending attestation.
    let mut tail = vec![0x00];
    tail.extend_from_slice(&PENDING_TAG);
    tail.push(0x03);
    tail.push(0x02);
    tail.extend_from_slice(b"ab");

    let mut body = vec![0xff];
    body.extend_from_slice(&lying);
    body.extend_from_slice(&tail);
    let bytes = container(&digest, &body);

    assert_eq!(bytes.len(), 90, "D58 §4's input is exactly 90 bytes");

    let result = parse_ots(&bytes, &digest);
    assert_eq!(
        code_of(&result),
        "anchor-ots-attestation-payload-not-consumed",
        "the sub-slice must be exhausted by the payload's own parse"
    );
    assert_eq!(
        result,
        Err(OtsError::AttestationPayloadNotConsumed {
            defect: PayloadDefect::Leftover,
        })
    );
    // And, said the other way, because "different attestation sets" is the
    // property and not the code: this input never yields two attestations.
    assert!(result.is_err(), "must not report two attestations");
}

/// D58 §4's weaker instance, visible without an exploit: fed `len = 1`
/// around a 3-byte height varuint, the rejected crate reported
/// `height = 16384` and re-serialised with `len = 3`, so its own round-trip
/// was not byte-preserving on inputs a conformant parser rejects outright.
#[test]
fn a_bitcoin_height_reaching_outside_its_declared_payload_is_rejected() {
    let digest = digest_of(0x42);
    let mut body = vec![0x00];
    body.extend_from_slice(&BITCOIN_TAG);
    body.push(0x01); // declared payload: 1 byte
    body.extend_from_slice(&[0x80, 0x80, 0x01]); // a 3-byte varuint = 16 384
    let bytes = container(&digest, &body);

    assert_eq!(
        parse_ots(&bytes, &digest),
        Err(OtsError::AttestationPayloadNotConsumed {
            defect: PayloadDefect::ShortRead,
        }),
        "the height's own varuint ran past the 1 byte it was given"
    );
}

// ── unknown ops, unimplemented ops, unknown attestation types ─────────────

/// D58 §11's `unimplemented_ops_yield_indeterminate_values_not_errors`.
///
/// Two branches, one clean and one behind each unimplemented op in turn.
/// Both attestations must appear: the first with `Some(commitment)`, the
/// second with `None`. Red if the whole parse errors (over-strict), **and**
/// red if the second reports a value — which would be a fabricated
/// commitment.
#[test]
fn unimplemented_ops_yield_indeterminate_values_not_errors() {
    let digest = digest_of(0x42);
    for op in [0x02_u8, 0x03, 0x67, 0xf2, 0xf3] {
        let clean = pending("https://alice.btc.calendar.opentimestamps.org");
        let mut shadowed = vec![op];
        shadowed.extend_from_slice(&pending("https://bob.btc.calendar.opentimestamps.org"));
        let bytes = container(&digest, &fork(&[clean, shadowed]));

        let artifact = parse_ots(&bytes, &digest)
            .unwrap_or_else(|error| panic!("op 0x{op:02x} must not error: {error}"));
        assert_eq!(artifact.attestations.len(), 2, "op 0x{op:02x}");

        let OtsAttestation::Pending {
            commitment: Some(first),
            ..
        } = &artifact.attestations[0]
        else {
            panic!("the clean sibling must keep its value (op 0x{op:02x})");
        };
        assert_eq!(first.as_slice(), digest.as_slice());

        assert!(
            matches!(
                &artifact.attestations[1],
                OtsAttestation::Pending {
                    commitment: None,
                    ..
                }
            ),
            "op 0x{op:02x} must leave its subtree indeterminate, not fabricate a value"
        );
    }
}

/// The other half of D58 §12.2's correction: an op tag carries **no length**,
/// so an unregistered one cannot be skipped and fails the artifact.
#[test]
fn an_unregistered_op_tag_is_a_parse_error() {
    let digest = digest_of(0x42);
    for tag in [0x01_u8, 0x07, 0x09, 0x66, 0x68, 0xef, 0xf4, 0xfe] {
        let mut body = vec![tag];
        body.extend_from_slice(&pending("https://example.invalid"));
        let bytes = container(&digest, &body);
        assert_eq!(
            parse_ots(&bytes, &digest),
            Err(OtsError::UnknownOp { tag }),
            "0x{tag:02x}"
        );
    }
}

/// A fork marker is never followed by another: the byte after `0xff` is read
/// as a child tag, exactly as the reference implementation does. So `ff ff`
/// is an unregistered op, not a nested fork.
#[test]
fn a_fork_marker_followed_by_a_fork_marker_is_an_unknown_op() {
    let digest = digest_of(0x42);
    let bytes = container(&digest, &[0xff, 0xff, 0x00]);
    assert_eq!(
        parse_ots(&bytes, &digest),
        Err(OtsError::UnknownOp { tag: 0xff })
    );
}

/// D58 §11's `unknown_attestation_type_is_carried_not_dropped`.
///
/// It must appear with its tag and payload length; its payload bytes must
/// **not** be retained; siblings must be unaffected. This is what keeps
/// `internally-consistent-only` reachable for OTS (D56 rule O9).
#[test]
fn unknown_attestation_type_is_carried_not_dropped() {
    let digest = digest_of(0x42);
    let unknown_tag = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let secret = b"a-litecoin-calendar-uri-we-do-not-parse";
    let bytes = container(
        &digest,
        &fork(&[
            pending("https://alice.btc.calendar.opentimestamps.org"),
            attestation(unknown_tag, secret),
        ]),
    );

    let artifact = parse_ots(&bytes, &digest).expect("an unknown type is not an error");
    assert_eq!(artifact.attestations.len(), 2);
    assert!(matches!(
        &artifact.attestations[0],
        OtsAttestation::Pending {
            commitment: Some(_),
            ..
        }
    ));
    assert_eq!(
        artifact.attestations[1],
        OtsAttestation::UnknownType {
            tag: unknown_tag,
            payload_len: secret.len() as u32,
        }
    );

    // The payload bytes are deliberately not retained (D58 §10.2). Asserted
    // over the whole rendered artifact, so a future field cannot smuggle
    // them back in.
    let rendered = format!("{artifact:?}");
    assert!(
        !rendered.contains("litecoin"),
        "an unknown attestation's payload must not be carried"
    );
}

/// An `.ots` whose **every** attestation is of a type this verifier cannot
/// evaluate still parses. It is D56 rule O9's input, and A18 renders it
/// `internally-consistent-only`; treating it as a parse error here would make
/// that state unreachable for OTS and A18's exhaustive-reachability Accept
/// undischargeable.
#[test]
fn an_all_unknown_attestation_ots_parses_rather_than_erroring() {
    let digest = digest_of(0x42);
    let bytes = container(
        &digest,
        &fork(&[
            attestation([0xaa; 8], b"one"),
            attestation([0xbb; 8], b"two"),
        ]),
    );
    let artifact = parse_ots(&bytes, &digest).expect("well-formed, just not evaluable");
    assert_eq!(artifact.attestations.len(), 2);
    assert!(
        artifact
            .attestations
            .iter()
            .all(|a| matches!(a, OtsAttestation::UnknownType { .. }))
    );
}

/// D56 §5 leaves it open whether A11 rejects a zero-attestation `.ots`, and
/// says either is safe. **The shape is unrepresentable**, so the choice never
/// becomes load-bearing: a node's last child is an attestation or an op, and
/// an op pushes a node that needs children of its own, so termination is only
/// ever an attestation.
#[test]
fn a_zero_attestation_ots_is_unrepresentable() {
    let digest = digest_of(0x42);
    for body in [
        vec![],                 // no children at all
        vec![0x08],             // an op with no subtree
        vec![0xff, 0x08],       // a fork whose child never terminates
        vec![0xf0, 0x01, 0xaa], // an append with no subtree
    ] {
        let bytes = container(&digest, &body);
        assert_eq!(
            code_of(&parse_ots(&bytes, &digest)),
            "anchor-ots-truncated",
            "body {body:02x?} must be truncated, never an empty artifact"
        );
    }
}

// ── the container header ─────────────────────────────────────────────────

#[test]
fn container_header_rejections_are_each_their_own_code() {
    let digest = digest_of(0x42);
    let good = container(&digest, &pending("https://example.invalid"));

    // Step 1 — magic. Anything shorter than 31 bytes is not an .ots at all.
    for bad in [vec![], vec![0x00], MAGIC[..30].to_vec(), {
        let mut m = good.clone();
        m[3] ^= 0x01;
        m
    }] {
        assert_eq!(code_of(&parse_ots(&bad, &digest)), "anchor-ots-bad-magic");
    }

    // Step 2 — version.
    let mut wrong_version = good.clone();
    wrong_version[31] = 0x02;
    assert_eq!(
        parse_ots(&wrong_version, &digest),
        Err(OtsError::UnsupportedVersion { version: 2 })
    );

    // Step 3 — digest type.
    let mut wrong_type = good.clone();
    wrong_type[32] = 0x02;
    assert_eq!(
        parse_ots(&wrong_type, &digest),
        Err(OtsError::UnsupportedDigestType { tag: 0x02 })
    );

    // Step 4 — the digest must be present.
    assert_eq!(
        code_of(&parse_ots(&good[..50], &digest)),
        "anchor-ots-truncated"
    );

    // Step 7 — and the file ends exactly where the DAG does.
    let mut trailing = good.clone();
    trailing.push(0x00);
    assert_eq!(
        parse_ots(&trailing, &digest),
        Err(OtsError::TrailingBytes { extra: 1 })
    );
    assert!(parse_ots(&good, &digest).is_ok());
}

/// Step 3 fires before step 5, so a file with an unsupported digest type is
/// never reported as a digest *mismatch* — the two are one header field
/// apart and D91 §7.2 keeps them separable on purpose.
#[test]
fn an_unsupported_digest_type_beats_a_digest_mismatch() {
    let mut bytes = container(&digest_of(0x42), &pending("https://example.invalid"));
    bytes[32] = 0x03; // SHA-1's tag in the OTS digest-type registry
    assert_eq!(
        parse_ots(&bytes, &digest_of(0x99)),
        Err(OtsError::UnsupportedDigestType { tag: 0x03 })
    );
}

// ── one reachable witness per limit, each returning its own code ──────────

/// Build the cheapest witness D58 §9.3 gives for each limit.
fn limit_witnesses(digest: &[u8; 32]) -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let att = pending("ab"); // 13 bytes: 00 + tag + len + varbytes

    // MAX_OTS_OPS — 5 branches of 820 `0x08` each = 4 100 ops. NOT 4 097 in
    // one chain: that has depth 4 097 and trips `too-deep` first.
    let ops = {
        let branch = |_| {
            let mut b = vec![0x08_u8; 820];
            b.extend_from_slice(&att);
            b
        };
        let branches: Vec<Vec<u8>> = (0..5).map(branch).collect();
        container(digest, &fork(&branches))
    };

    // MAX_OTS_DEPTH — 1 025 ops in one chain; 1 025 < 4 096 so the op count
    // does not fire.
    let depth = {
        let mut body = vec![0x08_u8; 1_025];
        body.extend_from_slice(&att);
        container(digest, &body)
    };

    // MAX_OTS_BRANCH_WIDTH — 65 sibling attestations. 65 < 256, 0 ops.
    let width = {
        let branches: Vec<Vec<u8>> = (0..65).map(|_| att.clone()).collect();
        container(digest, &fork(&branches))
    };

    // MAX_OTS_ATTESTATIONS — 64 root branches each forking into 5 = 320. NOT
    // 257 siblings: that is width 257 and trips `branch-too-wide` first.
    let attestations = {
        let subtree: Vec<Vec<u8>> = (0..5).map(|_| att.clone()).collect();
        let inner = fork(&subtree);
        let branches: Vec<Vec<u8>> = (0..64)
            .map(|_| {
                let mut b = vec![0x08_u8];
                b.extend_from_slice(&inner);
                b
            })
            .collect();
        container(digest, &fork(&branches))
    };

    // MAX_OTS_OPERAND_BYTES — one operand at cap + 1. Checked before the
    // value length, so this and not `value-too-long`.
    let operand = {
        let mut body = append(&vec![0xab; MAX_OTS_OPERAND_BYTES as usize + 1]);
        body.extend_from_slice(&att);
        container(digest, &body)
    };

    // MAX_OTS_VALUE_BYTES — two operands each exactly *at* the operand cap.
    let value = {
        let full = vec![0xab; MAX_OTS_OPERAND_BYTES as usize];
        let mut body = append(&full);
        body.extend_from_slice(&append(&full));
        body.extend_from_slice(&att);
        container(digest, &body)
    };

    // MAX_OTS_ATTESTATION_PAYLOAD_BYTES — one payload at cap + 1, on an
    // unknown tag so nothing else can object to its content.
    let payload = {
        let big = vec![0x5a; MAX_OTS_ATTESTATION_PAYLOAD_BYTES as usize + 1];
        container(digest, &attestation([0xde; 8], &big))
    };

    vec![
        ("MAX_OTS_OPS", "anchor-ots-too-many-ops", ops),
        ("MAX_OTS_DEPTH", "anchor-ots-too-deep", depth),
        ("MAX_OTS_BRANCH_WIDTH", "anchor-ots-branch-too-wide", width),
        (
            "MAX_OTS_ATTESTATIONS",
            "anchor-ots-too-many-attestations",
            attestations,
        ),
        (
            "MAX_OTS_OPERAND_BYTES",
            "anchor-ots-operand-too-long",
            operand,
        ),
        ("MAX_OTS_VALUE_BYTES", "anchor-ots-value-too-long", value),
        (
            "MAX_OTS_ATTESTATION_PAYLOAD_BYTES",
            "anchor-ots-attestation-payload-too-long",
            payload,
        ),
    ]
}

/// D58 §11's `every_ots_limit_has_a_reachable_witness_under_max_ots_bytes`.
///
/// Two claims, and **the second is the one that matters**: each witness is
/// under `MAX_OTS_BYTES` (so the rejection test is not shadowed by the byte
/// cap and can actually fail), *and* each returns **its own** code — because
/// two of the seven natural witnesses trip a different limit first (D58 §9.3)
/// and would otherwise silently test the wrong thing.
#[test]
fn every_ots_limit_has_a_reachable_witness_under_max_ots_bytes() {
    let digest = digest_of(0x42);
    let witnesses = limit_witnesses(&digest);
    assert_eq!(witnesses.len(), 7, "one witness per (b) limit");

    for (limit, expected, bytes) in &witnesses {
        assert!(
            (bytes.len() as u64) < MAX_OTS_BYTES,
            "{limit}'s witness is {} B, at or over MAX_OTS_BYTES — its \
             rejection test could never fail",
            bytes.len()
        );
        assert_eq!(
            code_of(&parse_ots(bytes, &digest)),
            *expected,
            "{limit}'s witness must return its own code"
        );
    }

    // Each code appears exactly once across the seven, so no two witnesses
    // are secretly the same test.
    let mut codes: Vec<&str> = witnesses.iter().map(|(_, code, _)| *code).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), 7);
}

/// D58 §11's `check_order_is_the_frozen_one`.
///
/// Constructs artifacts violating **two** rules at once and pins which wins.
/// Without this, §9.3's witnesses are correct only by accident.
#[test]
fn check_order_is_the_frozen_one() {
    let digest = digest_of(0x42);
    let att = pending("ab");

    // b before c — a 4 097-op single chain is over both MAX_OTS_OPS and
    // MAX_OTS_DEPTH. Depth wins. This is the pair D58 §9.3 names, and it is
    // why the ops witness had to be split across five branches.
    let mut chain = vec![0x08_u8; 4_097];
    chain.extend_from_slice(&att);
    assert_eq!(
        code_of(&parse_ots(&container(&digest, &chain), &digest)),
        "anchor-ots-too-deep"
    );

    // d before e — an operand over the operand cap would also carry the
    // value over its own; the operand cap fires.
    let mut both = append(&vec![0xab; MAX_OTS_VALUE_BYTES as usize + 1]);
    both.extend_from_slice(&att);
    assert_eq!(
        code_of(&parse_ots(&container(&digest, &both), &digest)),
        "anchor-ots-operand-too-long"
    );

    // g before h — the 257th attestation is rejected on the count, before
    // its (over-long) payload is even looked at.
    // The over-long payload has to sit *inside* the last subtree rather than
    // beside it at the root, because 65 root children would be over the width
    // cap and rule f would claim the input first.
    let big = vec![0x5a; MAX_OTS_ATTESTATION_PAYLOAD_BYTES as usize + 1];
    let mut branches: Vec<Vec<u8>> = (0..64)
        .map(|_| {
            let mut b = vec![0x08_u8];
            b.extend_from_slice(&fork(&(0..5).map(|_| att.clone()).collect::<Vec<_>>()));
            b
        })
        .collect();
    branches[63] = {
        let mut b = vec![0x08_u8];
        b.extend_from_slice(&fork(&[
            att.clone(),
            att.clone(),
            att.clone(),
            att.clone(),
            attestation([0xde; 8], &big),
        ]));
        b
    };
    assert_eq!(
        code_of(&parse_ots(&container(&digest, &fork(&branches)), &digest)),
        "anchor-ots-too-many-attestations",
        "the count is checked before the payload length"
    );

    // Step 5 before step 6 — a wrong digest beats every limit in the file.
    let mut over_limit = vec![0x08_u8; 4_097];
    over_limit.extend_from_slice(&att);
    assert_eq!(
        code_of(&parse_ots(
            &container(&digest, &over_limit),
            &digest_of(0x99)
        )),
        "anchor-ots-digest-mismatch"
    );

    // f at the child's start — an over-wide node is rejected before its
    // 65th child's own content is read. Recorded because D58 §10.3's
    // letters put d/e before f, and this input is the only place the two
    // readings differ.
    let mut wide: Vec<Vec<u8>> = (0..64).map(|_| att.clone()).collect();
    wide.push(append(&vec![0xab; MAX_OTS_OPERAND_BYTES as usize + 1]));
    assert_eq!(
        code_of(&parse_ots(&container(&digest, &fork(&wide)), &digest)),
        "anchor-ots-branch-too-wide"
    );
}

/// The limits are `<=`, not `<`: a file exactly *at* every cap parses.
///
/// Without this the rejection tests above would pass against an
/// implementation that is off by one in the strict direction, which would
/// reject honest artifacts.
#[test]
fn an_artifact_exactly_at_the_caps_is_accepted() {
    let digest = digest_of(0x42);

    let mut at_depth = vec![0x08_u8; MAX_OTS_DEPTH as usize];
    at_depth.extend_from_slice(&pending("ab"));
    let (_, shape) =
        parse_ots_measured(&container(&digest, &at_depth), &digest).expect("depth at the cap");
    assert_eq!(shape.max_depth, MAX_OTS_DEPTH);

    let at_width: Vec<Vec<u8>> = (0..MAX_OTS_BRANCH_WIDTH).map(|_| pending("ab")).collect();
    let (_, shape) = parse_ots_measured(&container(&digest, &fork(&at_width)), &digest)
        .expect("width at the cap");
    assert_eq!(shape.max_width, MAX_OTS_BRANCH_WIDTH);
    assert_eq!(shape.attestations, MAX_OTS_BRANCH_WIDTH);

    let at_operand = {
        let mut body = append(&vec![0xab; MAX_OTS_OPERAND_BYTES as usize]);
        body.extend_from_slice(&pending("ab"));
        body
    };
    let (_, shape) =
        parse_ots_measured(&container(&digest, &at_operand), &digest).expect("operand at the cap");
    assert_eq!(shape.max_operand_bytes, MAX_OTS_OPERAND_BYTES);

    let at_payload = attestation(
        [0xde; 8],
        &vec![0x5a; MAX_OTS_ATTESTATION_PAYLOAD_BYTES as usize],
    );
    let (_, shape) =
        parse_ots_measured(&container(&digest, &at_payload), &digest).expect("payload at the cap");
    assert_eq!(
        shape.max_attestation_payload_bytes,
        MAX_OTS_ATTESTATION_PAYLOAD_BYTES
    );
}

/// D58 §11's `parser_is_iterative_at_max_depth`.
///
/// A `MAX_OTS_DEPTH` chain parsed on a **256 KiB** thread stack. Measured by
/// D58 §3.5, the rejected crate's recursive descent needed 163 840 B for a
/// *255*-op chain in release and 1 048 576 B in debug; at 1 024 a recursive
/// implementation aborts here, and on wasm32 it would trap rather than
/// return an error.
///
/// Native-only because `wasm32-unknown-unknown` has no threads. The property
/// it witnesses is platform-independent, and the wasm32 lane runs every other
/// test in this file.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn parser_is_iterative_at_max_depth() {
    let digest = digest_of(0x42);
    let mut body = vec![0x08_u8; MAX_OTS_DEPTH as usize];
    body.extend_from_slice(&pending("https://alice.btc.calendar.opentimestamps.org"));
    let bytes = container(&digest, &body);

    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .name("ots-depth".to_owned())
        .spawn(move || {
            let (artifact, shape) = parse_ots_measured(&bytes, &digest).expect("parses at cap");
            (artifact.attestations.len(), shape.max_depth, shape.ops)
        })
        .expect("spawn");
    assert_eq!(handle.join().expect("no stack overflow"), (1, 1_024, 1_024));
}

// ── A12, over the real upgraded proof ────────────────────────────────────

/// A12's `Do`, end to end on a real mainnet proof: the ops-derived root at
/// the Bitcoin attestation for height 449 399 must equal the merkle-root
/// field of a header recording that height.
#[test]
fn a_header_committed_by_the_ops_is_attested_and_a_mutated_one_is_not() {
    let artifact = parse_ots(UPGRADED_LARGE_TEST, &DIGEST_LARGE_TEST).expect("parses");
    let OtsAttestation::Bitcoin {
        height,
        merkle_root: Some(root),
    } = &artifact.attestations[1]
    else {
        panic!("attestation 1 is the Bitcoin one for block 449399");
    };
    assert_eq!(*height, 449_399);

    let mut header = [0xaa_u8; 80];
    header[36..68].copy_from_slice(root);

    let upgrade = OtsUpgrade::new(*height, header, 0);
    assert_eq!(
        check_embedded_header(&artifact, &upgrade),
        EmbeddedHeader::Committed
    );

    // One flipped bit in the merkle-root field, and the same artifact no
    // longer commits it — D56 rule O8.
    let mut tampered = header;
    tampered[36] ^= 0x01;
    assert_eq!(
        check_embedded_header(&artifact, &OtsUpgrade::new(*height, tampered, 0)),
        EmbeddedHeader::Uncommitted
    );

    // A real root at the *other* attested height is not this height's.
    assert_eq!(
        check_embedded_header(&artifact, &OtsUpgrade::new(449_397, header, 0)),
        EmbeddedHeader::Uncommitted
    );

    // …and the proof does commit 449 397's own root, so the check is not
    // simply rejecting everything.
    let OtsAttestation::Bitcoin {
        merkle_root: Some(other),
        ..
    } = &artifact.attestations[3]
    else {
        panic!("attestation 3 is the Bitcoin one for block 449397");
    };
    let mut other_header = [0xaa_u8; 80];
    other_header[36..68].copy_from_slice(other);
    assert_eq!(
        check_embedded_header(&artifact, &OtsUpgrade::new(449_397, other_header, 0)),
        EmbeddedHeader::Committed
    );
}

// ── determinism ──────────────────────────────────────────────────────────

/// Same bytes, same answer — every time, and on every fixture, including the
/// rejections. The property `scripts/wasm-bitmatch.sh` checks across targets,
/// asserted here across runs.
#[test]
fn parsing_is_deterministic() {
    let digest = digest_of(0x42);
    let mut inputs: Vec<(Vec<u8>, [u8; 32])> = vec![
        (MERGED_A.to_vec(), DIGEST_A),
        (MERGED_B.to_vec(), DIGEST_B),
        (UPGRADED_LARGE_TEST.to_vec(), DIGEST_LARGE_TEST),
    ];
    for (_, _, bytes) in limit_witnesses(&digest) {
        inputs.push((bytes, digest));
    }

    for (bytes, expect) in &inputs {
        let first = parse_ots(bytes, expect);
        for _ in 0..3 {
            assert_eq!(parse_ots(bytes, expect), first);
        }
    }
}

/// No input of any shape may panic. A cheap structural sweep over the
/// committed fixtures: every prefix, and every single-byte mutation at a
/// stride, must return a value rather than unwind. A23's fuzz target is the
/// real instrument; this is the part that runs on every commit and on wasm32.
#[test]
fn no_prefix_or_mutation_of_a_real_fixture_panics() {
    for (bytes, digest) in [
        (MERGED_A, DIGEST_A),
        (MERGED_B, DIGEST_B),
        (UPGRADED_LARGE_TEST, DIGEST_LARGE_TEST),
    ] {
        for cut in (0..bytes.len()).step_by(7) {
            let _ = parse_ots(&bytes[..cut], &digest);
        }
        for at in (0..bytes.len()).step_by(11) {
            let mut mutated = bytes.to_vec();
            mutated[at] ^= 0xff;
            let _ = parse_ots(&mutated, &digest);
            let mut appended = bytes.to_vec();
            appended.push(mutated[at]);
            let _ = parse_ots(&appended, &digest);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
