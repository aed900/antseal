//! C3 — the M0 HKDF golden tests (MVP-SPEC.md line 153) and the committed
//! golden-vector verification (`testdata/vectors/v1/hkdf/`).
//!
//! Exercises only the public API of `antseal_core::crypto::hkdf`; the
//! structural-injectivity property test over arbitrary labels lives next to
//! the crate-private encoder in `src/crypto/hkdf.rs`.
//!
//! Q2/Q4 migration note: the committed vectors moved from
//! `testdata/vectors/hkdf/hkdf-sha256-v1.txt` (bespoke line format, parsed
//! by this file) into the per-format-version layout as
//! `testdata/vectors/v1/hkdf/hkdf-labels.json` (Q4 envelope schema) — a
//! pre-Q6, pre-freeze move with byte-identical derivation values. Parsing
//! and execution now live in `antseal_core::test_util::vectors` (shared
//! with the Q4 runner and, later, the Q5 WASM bit-match lane); this file
//! remains the C3 accept anchor pinning that *this exact committed file*
//! verifies against the public derivation API.

use antseal_core::crypto::hkdf::Label;
use antseal_core::test_util::vectors::execute_vector_bytes;

/// The committed C3 golden-vector file. Its fixture master secret is the
/// documented fixed NON-SECRET test seed
/// (`antseal_core::test_util::TEST_MASTER_SECRET_W`, bytes 0x00..0x1f) —
/// enforced by the `hkdf-labels` executor (project rule 6: never a real
/// secret).
const VECTOR_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/hkdf/hkdf-labels.json"
);

/// **The M0 golden test** mandated by MVP-SPEC.md line 153: *"a golden test
/// asserting all registered HKDF infos are pairwise distinct"*.
///
/// Enumerates every registered label crossed with the representative id set
/// {0, 1, max-real, sentinel} (max-real = `u64::MAX - 1`, the largest id a
/// real unit/file table could carry — one below the sentinel) and asserts
/// all encoded info byte strings are pairwise distinct. Distinct infos ⇒
/// independent PRF outputs ⇒ keys and salts of different roles never
/// collide (spec line 77).
#[test]
fn m0_golden_all_registered_hkdf_infos_pairwise_distinct() {
    use antseal_core::crypto::hkdf::SENTINEL_ID;

    let representative_ids: [u64; 4] = [0, 1, u64::MAX - 1, SENTINEL_ID];
    let mut infos: Vec<(String, Vec<u8>)> = Vec::new();
    for label in Label::ALL {
        for id in representative_ids {
            infos.push((
                format!("({}, {id:#x})", label.as_str()),
                label.info_bytes(id),
            ));
        }
    }
    assert_eq!(infos.len(), Label::ALL.len() * representative_ids.len());
    for i in 0..infos.len() {
        for j in (i + 1)..infos.len() {
            assert_ne!(
                infos[i].1, infos[j].1,
                "HKDF infos must be pairwise distinct: {} vs {} encode identically",
                infos[i].0, infos[j].0
            );
        }
    }
}

/// C3 accept: the committed golden vectors — produced by the independent
/// Python reference implementation in `testdata/vectors/v1/hkdf/` — verify
/// against this crate's public derivation API: full label-registry
/// coverage, info bytes, output lengths, and output bytes (all executed by
/// the shared `hkdf-labels` vector executor, which also enforces the
/// NON-SECRET fixture conventions).
///
/// The `vector_` name prefix opts this test into the cross-OS CI lane
/// (Q1 convention, CONTRIBUTING.md): committed-vector byte stability must
/// hold on linux, macOS, and windows. The generic Q4 runner
/// (`tests/vector_runner.rs`) also discovers and executes this file; this
/// test additionally pins its exact path and kind as the C3 acceptance
/// anchor.
#[test]
fn vector_committed_hkdf_golden_file_verifies() {
    let bytes =
        std::fs::read(VECTOR_FILE).unwrap_or_else(|e| panic!("cannot read {VECTOR_FILE}: {e}"));
    let summary =
        execute_vector_bytes(&bytes, "v1").unwrap_or_else(|e| panic!("{VECTOR_FILE}: {e}"));
    assert_eq!(summary.kind, "hkdf-labels");
    assert_eq!(
        summary.items,
        Label::ALL.len(),
        "exactly one vector per registered label"
    );
}
