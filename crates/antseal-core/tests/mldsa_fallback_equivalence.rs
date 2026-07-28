//! `ml-dsa` ↔ `fips204` byte-identity — **T2, and NOT the independent cross-check**.
//!
//! # Read this before citing this file
//!
//! Decision D31 §1 grades cross-check vehicles into three tiers:
//!
//! - **T0** — an external oracle (NIST ACVP, RFC known-answer tests). The only
//!   tier that catches a **shared misreading of the specification**.
//! - **T1** — an independent re-implementation, written from the spec in
//!   another language. Catches implementation bugs, blind to a shared
//!   misreading.
//! - **T2** — two implementations inside one ecosystem. Blind to both.
//!
//! `ml-dsa =0.1.1` and `fips204 =0.4.6` are both Rust, both implement FIPS 204,
//! and both come from the same small post-quantum-Rust community. Agreement
//! between them is **T2**. It cannot detect a shared misreading of FIPS 204 —
//! the dominant risk for a 2024 standard with a non-trivial `ctx` /
//! `Sign_internal` split — so **this file is not evidence of independence and
//! must never be counted toward it**.
//!
//! The independent cross-check for ML-DSA-65 is `tests/acvp_ml_dsa.rs`: NIST's
//! own vectors, tier T0. That is what Q11, Q14 and MVP-SPEC.md line 5 mean.
//!
//! # So why does this exist
//!
//! Because D14 designates `fips204` as the **byte-identical fallback** if
//! `ml-dsa` has to be swapped out. That claim needs checking, and an
//! `ml-dsa`↔`fips204` byte-equality test is exactly the check it needs. It is
//! simply a different claim from the one line 5 mandates. Two checks, two
//! purposes, neither substituting for the other (D31 §4a).
//!
//! # `fips204` has not shipped
//!
//! It is a **dev-dependency** of `antseal-core`, consumed only here. A
//! `[dev-dependencies]` edge is not a consumed runtime dependency: `fips204`
//! stays out of `cargo tree -p antseal-core -e normal`, so D14's
//! "pinned-unconsumed" property holds and the `core-dep-graph` lane is
//! unperturbed. **Nothing about this file means the fallback was activated.**
//! D14's 2026-07-28 addendum records the move from declaration-only to
//! dev-dependency.
//!
//! # What is compared
//!
//! The two operations D14's fallback trigger would have to reproduce
//! bit-for-bit, driven through each crate's own public API, at the consumption
//! shape each decision fixes:
//!
//! | operation | `ml-dsa` (D14 primary, C13 shape) | `fips204` (D14 fallback shape) |
//! | --- | --- | --- |
//! | keygen from ξ | `SigningKey::<MlDsa65>::from_seed` | `ml_dsa_65::KG::keygen_from_seed` |
//! | deterministic sign | `sign_deterministic(body, ctx)` | `try_sign_with_seed(&[0; 32], body, ctx)` |
//!
//! `fips204`'s `try_sign_with_seed` with an all-zero seed is FIPS 204's
//! deterministic variant (`rnd = 0³²`) — the same thing `ml-dsa`'s
//! `sign_deterministic` does, and D15's mode.
//!
//! Cross-verification is asserted in both directions too: each crate must
//! accept the other's signature. Byte-equality alone would not notice two
//! implementations that agreed on a wrong-but-consistent encoding, and this is
//! cheap.

#![cfg(not(target_arch = "wasm32"))]

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use ml_dsa::{B32, EncodedVerifyingKey, Keypair, MlDsa65, Signature, SigningKey, VerifyingKey};

/// The frozen author-signature context (MVP-SPEC.md line 97).
const SIG_CONTEXT: &[u8] = antseal_core::crypto::SIG_CONTEXT;

/// FIPS 204 Table 2 sizes for ML-DSA-65.
const PUBLIC_KEY_LEN: usize = 1952;
const SIGNATURE_LEN: usize = 3309;

/// NON-SECRET fixture seeds (project rule 6). Deterministic, documented, and
/// never real key material: a counting seed, an all-zero seed, and an all-ones
/// seed, so a keygen that ignored ξ entirely could not pass.
fn fixture_seeds() -> Vec<[u8; 32]> {
    let mut counting = [0u8; 32];
    for (i, byte) in counting.iter_mut().enumerate() {
        *byte = u8::try_from(i).expect("32 < 256");
    }
    vec![counting, [0x00; 32], [0xff; 32]]
}

/// NON-SECRET fixture bodies: empty, short, and long enough to cross a SHAKE
/// block boundary.
fn fixture_bodies() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b"antseal fallback equivalence".to_vec(),
        vec![0x5a; 1024],
    ]
}

/// Keygen from the same ξ produces byte-identical public keys in both crates.
#[test]
fn mldsa_fallback_keygen_is_byte_identical_t2() {
    for seed in fixture_seeds() {
        let primary = SigningKey::<MlDsa65>::from_seed(
            <&B32>::try_from(seed.as_slice()).expect("32-byte seed"),
        );
        let primary_pk = primary.verifying_key().encode();

        let (fallback_pk, _fallback_sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
        let fallback_pk = fallback_pk.into_bytes();

        assert_eq!(primary_pk.len(), PUBLIC_KEY_LEN);
        assert_eq!(
            primary_pk.as_slice(),
            fallback_pk.as_slice(),
            "ml-dsa and fips204 disagree on the ML-DSA-65 public key for seed {}: \
             D14's fallback claim is that these are byte-identical",
            hex(&seed),
        );
    }
}

/// Deterministic signing over the frozen context produces byte-identical
/// signatures, and each crate accepts the other's.
#[test]
fn mldsa_fallback_deterministic_sign_is_byte_identical_t2() {
    for seed in fixture_seeds() {
        let primary = SigningKey::<MlDsa65>::from_seed(
            <&B32>::try_from(seed.as_slice()).expect("32-byte seed"),
        );
        let (fallback_pk, fallback_sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
        // `into_bytes` consumes, so encode once outside the body loop.
        let fallback_pk_bytes = fallback_pk.clone().into_bytes();
        let primary_vk = VerifyingKey::<MlDsa65>::decode(
            <&EncodedVerifyingKey<MlDsa65>>::try_from(fallback_pk_bytes.as_slice())
                .expect("fips204 public keys are 1952 bytes"),
        );

        for body in fixture_bodies() {
            // ml-dsa: exactly `sig_mldsa::sign_with_context`'s call.
            let primary_sig = primary
                .expanded_key()
                .sign_deterministic(&body, SIG_CONTEXT)
                .expect("the frozen context is 19 bytes, far below FIPS 204's 255")
                .encode();

            // fips204: D14's documented fallback call. An all-zero seed is
            // FIPS 204's deterministic variant, rnd = 0^32 (D15).
            let fallback_sig = fallback_sk
                .try_sign_with_seed(&[0u8; 32], &body, SIG_CONTEXT)
                .expect("deterministic signing over a 19-byte context cannot fail");

            assert_eq!(primary_sig.len(), SIGNATURE_LEN);
            assert_eq!(
                primary_sig.as_slice(),
                fallback_sig.as_slice(),
                "ml-dsa and fips204 disagree on the deterministic ML-DSA-65 \
                 signature (seed {}, {}-byte body): D14's fallback claim is that \
                 these are byte-identical",
                hex(&seed),
                body.len(),
            );

            // Byte-equality would not notice two implementations agreeing on a
            // wrong-but-consistent encoding. Cross-verify both ways.
            assert!(
                fallback_pk.verify(&body, &fallback_sig, SIG_CONTEXT),
                "fips204 rejects its own signature"
            );
            let decoded = Signature::<MlDsa65>::try_from(fallback_sig.as_slice())
                .expect("fips204 emits canonical signatures");
            assert!(
                primary_vk.verify_with_context(&body, SIG_CONTEXT, &decoded),
                "ml-dsa rejects a fips204 signature over the same body and context"
            );
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
