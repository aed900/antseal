//! Golden-vector kind **`storage-address`** (task S4): the D32 storage
//! address rule — `address = BLAKE3-256(blob bytes)` — pinned over the S4
//! size ladder, with the cap+1 case committed as a **rejection**.
//!
//! Spec basis: pre-quote ciphertext address computation at seal time
//! (MVP-SPEC.md line 34) and the offline storage-linkage recomputation the
//! M3 verifier performs (line 119), both resolved by D32/D35 to BLAKE3-256
//! of the ciphertext bytes (`compute_address`,
//! `ant-protocol-2.3.0/src/data_types.rs:10-12`) — never `self_encryption`.
//!
//! # What the document pins
//!
//! - the address of the official-pattern input (`byte[i] = i % 251`) at
//!   every ladder length: 0, 272 (smallest padded-unit ciphertext), 65 552
//!   (mid; 65 chunks, so the BLAKE3 tree layer is on the hook), 4 194 047
//!   (max unit plaintext, D32 decision 3), 4 194 064 (max plaintext-derived
//!   ciphertext), 4 194 304 (= [`MAX_CHUNK_SIZE`], the cap edge);
//! - that cap + 1 is a **typed rejection** ([`ExceedsChunkCap`]) — no v1
//!   address exists for over-cap content (D32 decision 5), so the vector
//!   commits the *error*, not a hash;
//! - the [`MAX_CHUNK_SIZE`] constant itself (`expect.max_chunk_size`).
//!
//! Inputs are **generative** (a documented pattern + a length), not literal
//! bytes: the ladder's 4 MiB rungs would otherwise put ~25 MiB of hex into
//! a committed file and blow D87's 2 MiB embedded-bytes budget for the
//! whole version directory. The pattern is the official BLAKE3 test-vector
//! input (`i % 251`), so every case is independently checkable against any
//! third-party BLAKE3 tool. Independent reference generator (pure-Python
//! BLAKE3 from the spec): `testdata/vectors/v1/storage/gen_vectors.py`.
//!
//! The executor recomputes the **whole** `expect` object from `inputs`
//! through [`compute_storage_address`] and compares it as one value, then
//! asserts the structural coverage a value comparison cannot state: the
//! ladder must include 272, the exact cap edge, and at least one over-cap
//! rejection, and every case's outcome side must match its length side.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::vectors::{
    RECOMPUTED_DIGEST_DOMAIN, VectorError, VectorSummary, first_difference, hex, prefix_len,
};
use crate::storage::{ExceedsChunkCap, MAX_CHUNK_SIZE, compute_storage_address};

/// The registered kind string.
pub const KIND: &str = "storage-address";

/// The one documented input pattern: `byte[i] = i % 251` (the official
/// BLAKE3 test-vector input pattern, so committed cases are checkable
/// against any independent BLAKE3 implementation).
const PATTERN_I_MOD_251: &str = "i-mod-251";

/// The rejection marker committed for over-cap cases. A vector-file label
/// (compared verbatim), deliberately spelled like the [`ExceedsChunkCap`]
/// type it stands for; it is not an error-code-contract code.
const REJECTED_EXCEEDS_CHUNK_CAP: &str = "exceeds-chunk-cap";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    pattern: String,
    cases: Vec<CaseInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseInput {
    name: String,
    len: u64,
}

/// Execute a `storage-address` vector (module docs; S4 accept).
pub fn execute(
    inputs: serde_json::Value,
    expect: serde_json::Value,
    description: String,
) -> Result<VectorSummary, VectorError> {
    let payload_err = |problem: String| VectorError::Payload {
        kind: KIND,
        problem,
    };
    let check_err = |check: &'static str, problem: String| VectorError::Check {
        kind: KIND,
        check,
        problem,
    };

    let inputs: Inputs =
        serde_json::from_value(inputs).map_err(|e| payload_err(format!("inputs: {e}")))?;

    if inputs.pattern != PATTERN_I_MOD_251 {
        return Err(check_err(
            "pattern",
            format!(
                "inputs.pattern is `{}`; the only documented pattern is `{PATTERN_I_MOD_251}`",
                inputs.pattern
            ),
        ));
    }
    for (index, case) in inputs.cases.iter().enumerate() {
        if inputs.cases[..index].iter().any(|c| c.name == case.name) {
            return Err(check_err(
                "case-names-unique",
                format!("case name `{}` appears more than once", case.name),
            ));
        }
    }

    // 1. The whole `expect` object, recomputed from `inputs` through the
    //    public API and compared as one value.
    let recomputed = build_expect(&inputs, &check_err)?;
    if recomputed != expect {
        return Err(check_err(
            "document",
            first_difference("expect", &recomputed, &expect),
        ));
    }

    // 2. Structural ladder coverage a value comparison cannot state
    //    (S4 accept): the smallest padded-unit ciphertext shape, the exact
    //    cap edge, and the committed cap+1 rejection must all be present —
    //    a regenerated document that quietly dropped a rung must fail.
    let lens: Vec<u64> = inputs.cases.iter().map(|c| c.len).collect();
    let cap = MAX_CHUNK_SIZE as u64;
    for (required, why) in [
        (
            272,
            "the smallest padded-unit ciphertext (256 + 16-byte tag)",
        ),
        (cap, "the exact MAX_CHUNK_SIZE cap edge"),
        (cap + 1, "the committed cap+1 rejection"),
    ] {
        if !lens.contains(&required) {
            return Err(check_err(
                "ladder-coverage",
                format!("no case with len {required} — the ladder must include {why}"),
            ));
        }
    }

    // 3. Q5 bit-match: SHA-256 over the serialization of the recomputed
    //    value, so every recomputed address (and every rejection outcome)
    //    is compared native↔wasm32 byte-for-byte.
    let serialized = serde_json::to_vec(&recomputed)
        .map_err(|e| check_err("digest-serialization", e.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(RECOMPUTED_DIGEST_DOMAIN);
    digest.update(KIND.as_bytes());
    digest.update([0x00]);
    digest.update(prefix_len(serialized.len()));
    digest.update(&serialized);

    Ok(VectorSummary {
        kind: KIND,
        description,
        items: inputs.cases.len(),
        recomputed_digest: digest.finalize().into(),
    })
}

/// Recompute the entire `expect` object from `inputs` through
/// [`compute_storage_address`].
fn build_expect(
    inputs: &Inputs,
    check_err: &impl Fn(&'static str, String) -> VectorError,
) -> Result<serde_json::Value, VectorError> {
    let mut cases = Vec::with_capacity(inputs.cases.len());
    for case in &inputs.cases {
        let len = usize::try_from(case.len).map_err(|_| {
            check_err(
                "case-len",
                format!("case `{}`: len {} does not fit usize", case.name, case.len),
            )
        })?;
        let bytes = pattern_bytes(len);
        let outcome = match compute_storage_address(&bytes) {
            Ok(address) => {
                serde_json::json!({
                    "name": case.name,
                    "len": case.len,
                    "address": hex(address.as_bytes()),
                })
            }
            Err(ExceedsChunkCap { len: rejected_len }) => {
                // The function's own consistency: it must reject exactly
                // the over-cap lengths, at the length it was handed.
                if rejected_len != len || len <= MAX_CHUNK_SIZE {
                    return Err(check_err(
                        "rejection-consistency",
                        format!(
                            "case `{}`: rejected len {rejected_len} disagrees with input len \
                             {len} or the cap {MAX_CHUNK_SIZE}",
                            case.name
                        ),
                    ));
                }
                serde_json::json!({
                    "name": case.name,
                    "len": case.len,
                    "rejected": REJECTED_EXCEEDS_CHUNK_CAP,
                })
            }
        };
        cases.push(outcome);
    }
    Ok(serde_json::json!({
        "max_chunk_size": MAX_CHUNK_SIZE,
        "cases": cases,
    }))
}

/// The official BLAKE3 test-vector input pattern: `byte[i] = i % 251`.
fn pattern_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}
