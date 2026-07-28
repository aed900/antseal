//! C16 — the **independent cross-check vehicle for ML-DSA-65**.
//!
//! Regenerates the ML-DSA-65 half of `testdata/vectors/v1/crypto/signatures.json`
//! from `fips204 =0.4.6` — the *other* ML-DSA implementation (integritychain),
//! not the `ml-dsa =0.1.1` (RustCrypto) crate that antseal-core consumes and
//! that the vector is executed against. Two independently written FIPS 204
//! implementations producing the same bytes is the cross-check.
//!
//! # Why this lives here and not in antseal-core
//!
//! `fips204` is pinned in the root `[workspace.dependencies]` as a
//! **declaration-only fallback** (decision D14) — normally consumed by no
//! crate. This probe crate is standalone (empty `[workspace]` table, own
//! committed `Cargo.lock`) and already depends on both implementations, so
//! the cross-check runs here without pulling `fips204` into the root
//! lockfile or into antseal-core's audited dependency graph.
//!
//! # Why a second Rust crate, and what that is and is not worth
//!
//! It is a genuinely independent *implementation*: different authors,
//! different codebase, written separately from FIPS 204. It is **not**
//! cross-*language* independence the way the Python reference is for the
//! other surfaces, and it shares this machine's toolchain and target. There
//! is no Python ML-DSA in this toolchain, and NIST's ACVP known-answer files
//! are far too large to commit; the honest statement is that ML-DSA's
//! cross-check is one tier weaker than HKDF's, the commitments' and the
//! AEADs'. Choosing the permanent vehicle is **decision D31**, which this
//! artifact feeds and does not pre-empt.
//!
//! # Determinism is what makes this possible
//!
//! Decision D15 selected FIPS 204 **deterministic** signing (`rnd = 0^32`).
//! `ml-dsa`'s `sign_deterministic` and `fips204`'s
//! `try_sign_with_seed(&[0u8; 32], ..)` are the same mode, so signature
//! *bytes* — not merely verifiability — are comparable across
//! implementations. Under hedged signing this test could only have checked
//! that each implementation verifies the other's signature.
//!
//! # Run
//!
//! ```sh
//! cd probes/sig-probe
//! cargo test --test c16_mldsa_vector -- --nocapture
//! ```
//!
//! With the committed vector present this **asserts** agreement. Print mode
//! (`--nocapture`) also emits the `mldsa65-fips204.json` payload that
//! `testdata/vectors/v1/crypto/gen_vectors.py signatures` consumes, for the
//! initial generation.
//!
//! Fixtures here are NON-SECRET: the seed is
//! `HKDF(W, "sig-mldsa65", sentinel)` for the documented fixed test seed
//! `W = 00 01 .. 1f` (`testdata/README.md`), i.e. the value already
//! committed in `testdata/vectors/v1/hkdf/hkdf-labels.json`.

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

/// xi = HKDF(W, "sig-mldsa65", sentinel), copied from the committed C3 HKDF
/// golden vector (`testdata/vectors/v1/hkdf/hkdf-labels.json`, label
/// `sig-mldsa65`). Transcribing it keeps this crate free of an HKDF
/// dependency — and the value is cross-checked there by its own independent
/// Python implementation, so the chain from `W` is covered.
const SEED_HEX: &str = "7a3862bbaa81fbd09103d08c48b1ffe54afdf20fb0562f20d26803c9d111f590";

/// The frozen signature context (MVP-SPEC.md line 97), passed as FIPS 204's
/// `ctx` parameter.
const CONTEXT: &[u8] = b"antseal-manifest-v1";

/// The C16 fixture body — must match `SIG_BODY` in
/// `testdata/vectors/v1/crypto/gen_vectors.py`.
const BODY: &[u8] = b"antseal C16 crypto golden-vector manifest body\n";

/// The committed vector this cross-check validates.
const VECTOR_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/crypto/signatures.json"
);

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex must be even-length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Produce the ML-DSA-65 public key and deterministic signature from
/// `fips204`, for the C16 fixture seed / context / body.
fn fips204_outputs() -> (Vec<u8>, Vec<u8>) {
    let seed: [u8; 32] = unhex(SEED_HEX).try_into().expect("32-byte seed");
    let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
    // rnd = 0^32 is the FIPS 204 deterministic variant (decision D15).
    let sig = sk
        .try_sign_with_seed(&[0u8; 32], BODY, CONTEXT)
        .expect("ctx is well under the 255-byte FIPS 204 limit");
    // Sanity: the implementation verifies its own output under this ctx,
    // and rejects it under a different one (context binding is real).
    assert!(pk.verify(BODY, &sig, CONTEXT), "fips204 self-verify");
    assert!(
        !pk.verify(BODY, &sig, b"antseal-manifest-v2"),
        "fips204 must reject a wrong ctx"
    );
    (pk.into_bytes().to_vec(), sig.to_vec())
}

/// **The C16 ML-DSA cross-check**: `fips204` reproduces, byte for byte, the
/// ML-DSA-65 public key and signature committed in `signatures.json` — which
/// antseal-core executes against `ml-dsa`. Agreement between the two
/// implementations is what makes the committed bytes a cross-check rather
/// than a self-check.
#[test]
fn fips204_reproduces_the_committed_mldsa_vector() {
    let (pk, sig) = fips204_outputs();
    assert_eq!(pk.len(), 1952, "ML-DSA-65 public key length (FIPS 204 Table 2)");
    assert_eq!(sig.len(), 3309, "ML-DSA-65 signature length (FIPS 204 Table 2)");

    // Print the generator payload (consumed by gen_vectors.py on first
    // generation; harmless afterwards).
    println!(
        "{{\n  \"seed\": \"{SEED_HEX}\",\n  \"context\": \"{}\",\n  \"body\": \"{}\",\n  \
         \"public_key\": \"{}\",\n  \"signature\": \"{}\"\n}}",
        hex(CONTEXT),
        hex(BODY),
        hex(&pk),
        hex(&sig),
    );

    let committed = match std::fs::read_to_string(VECTOR_FILE) {
        Ok(text) => text,
        Err(e) => panic!(
            "cannot read {VECTOR_FILE}: {e}\n\
             (generate it first — see testdata/vectors/v1/crypto/README.md)"
        ),
    };

    // Minimal field extraction: this crate deliberately has no serde
    // dependency, and the committed file is generated with a stable
    // `json.dumps(indent=2)` layout.
    let field = |name: &str| -> String {
        let needle = format!("\"{name}\": \"");
        let start = committed
            .find(&needle)
            .unwrap_or_else(|| panic!("{VECTOR_FILE}: no `{name}` field"))
            + needle.len();
        let rest = &committed[start..];
        let end = rest.find('"').expect("unterminated JSON string");
        rest[..end].to_owned()
    };

    // `public_key` and `signature` appear for both algorithms; the ML-DSA
    // ones are identifiable by length (1952 / 3309 bytes = 3904 / 6618 hex
    // characters), which also guards against comparing the Ed25519 halves
    // by accident.
    let mldsa_pk = committed
        .match_indices("\"public_key\": \"")
        .map(|(i, m)| {
            let rest = &committed[i + m.len()..];
            rest[..rest.find('"').expect("unterminated")].to_owned()
        })
        .find(|value| value.len() == 1952 * 2)
        .expect("no 1952-byte public_key in the committed vector");
    let mldsa_sig = committed
        .match_indices("\"signature\": \"")
        .map(|(i, m)| {
            let rest = &committed[i + m.len()..];
            rest[..rest.find('"').expect("unterminated")].to_owned()
        })
        .find(|value| value.len() == 3309 * 2)
        .expect("no 3309-byte signature in the committed vector");

    assert_eq!(
        field("body"),
        hex(BODY),
        "the committed vector's body differs from this test's BODY"
    );
    assert_eq!(
        field("context"),
        hex(CONTEXT),
        "the committed vector's context differs from the frozen SIG_CONTEXT"
    );
    assert_eq!(
        mldsa_pk,
        hex(&pk),
        "fips204 and the committed ML-DSA-65 public key disagree"
    );
    assert_eq!(
        mldsa_sig,
        hex(&sig),
        "fips204 and the committed ML-DSA-65 signature disagree"
    );
}
