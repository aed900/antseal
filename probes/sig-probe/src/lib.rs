//! C11 signature-crate probe core (tasks/C.md C11; MVP-SPEC.md line 97).
//!
//! Everything here is deterministic: fixed fixture seeds (NOT secrets — they
//! are probe fixtures, deliberately recognizable counting patterns), the
//! frozen context string, deterministic keygen and deterministic signing.
//! The same two artifacts are produced natively (tests/) and on
//! wasm32-unknown-unknown (run-wasm.mjs), and must match bit-for-bit:
//!
//! - [`selfcheck`]: a bitmask of behavioral invariants (canonical-rejection
//!   behavior, ctx binding, strict-verification semantics, cross-crate and
//!   cross-version byte equality). Expected value: [`EXPECTED_SELFCHECK`].
//! - [`build_transcript`]: the concatenated deterministic byte outputs
//!   (public keys + signatures) of all four crate candidates.
//!
//! Offsets and rejection conditions cite the vendored pinned sources
//! (`ml-dsa-0.1.1/src/…`, `fips204-0.4.6/src/…`, `ed25519-dalek-{2.2.0,3.0.0}/src/…`)
//! and FIPS 204 / RFC 8032. See docs/research/C11-signature-probe.md for the
//! full findings.

use ml_dsa::{B32, Keypair, MlDsa65, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey};

use fips204::ml_dsa_65 as f204;
use fips204::traits::{KeyGen, SerDes, Signer as _, Verifier as _};

use ed25519_dalek_2 as d2;
use ed25519_dalek_3 as d3;

/// The frozen antseal signature context string (MVP-SPEC.md line 97).
pub const CTX: &[u8] = b"antseal-manifest-v1";
/// A wrong context of the same length (context-binding negative probe).
pub const WRONG_CTX: &[u8] = b"antseal-manifest-v2";
/// Fixed probe body ("manifest body bytes" stand-in).
pub const BODY: &[u8] = b"antseal C11 signature-crate probe body\n";

const fn seq32(start: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        a[i] = start + i as u8;
        i += 1;
    }
    a
}

/// Fixture ML-DSA seed xi (FIPS 204 Algorithm 6 input). Not a secret.
pub const SEED_MLDSA: [u8; 32] = seq32(0x00);
/// Fixture Ed25519 seed. Not a secret.
pub const SEED_ED25519: [u8; 32] = seq32(0x20);

/// ML-DSA-65 encoded sizes (FIPS 204 Table 2; asserted in the probes).
pub const MLDSA65_PK_LEN: usize = 1952;
pub const MLDSA65_SIG_LEN: usize = 3309;

/// ML-DSA-65 signature byte layout (FIPS 204 Algorithm 26 sigEncode):
/// `c_tilde(48) ‖ z(5·256·20 bits = 3200) ‖ hint indices(ω = 55) ‖ hint cuts(k = 6)`.
pub const OFF_Z: usize = 48;
pub const OFF_HINT_IDX: usize = 3248;
pub const OFF_HINT_CUTS: usize = 3303;
pub const OMEGA_65: usize = 55;

/// Expected [`selfcheck`] bitmask: all 27 invariants hold.
pub const EXPECTED_SELFCHECK: u32 = (1 << 27) - 1;

/// Ed25519 message pre-image per MVP-SPEC.md line 97 / tasks C12:
/// `ctx ‖ 0x00 ‖ body`.
pub fn ed25519_message() -> Vec<u8> {
    let mut m = Vec::with_capacity(CTX.len() + 1 + BODY.len());
    m.extend_from_slice(CTX);
    m.push(0x00);
    m.extend_from_slice(BODY);
    m
}

/// Group order L of the Ed25519 basepoint, little-endian
/// (RFC 8032 §5.1: L = 2^252 + 27742317777372353535851937790883648493).
pub const ED25519_L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// `s + L` over little-endian 32-byte scalars (no reduction). For canonical
/// `s < L` the sum stays < 2^253, so it fits 32 bytes and is exactly the
/// classic RFC 8032 "S out of range" maul: same value mod L, non-canonical
/// encoding.
pub fn add_l(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = s[i] as u16 + ED25519_L_LE[i] as u16 + carry;
        out[i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    debug_assert_eq!(carry, 0, "canonical s + L must fit in 32 bytes");
    out
}

/// Compressed encoding of the Edwards identity point (y = 1): a small-order
/// (order-1) group element, the simplest "small-order R / small-order A"
/// probe input.
pub const ED25519_IDENTITY: [u8; 32] = {
    let mut a = [0u8; 32];
    a[0] = 1;
    a
};

/// Non-canonical field encoding: little-endian p = 2^255 - 19 (≡ 0 mod p).
/// RFC 8032 decoding requires rejecting y ≥ p; ZIP-215 accepts it.
pub const ED25519_NONCANONICAL_Y: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

// ---------------------------------------------------------------------------
// ML-DSA (RustCrypto ml-dsa =0.1.1) probes
// ---------------------------------------------------------------------------

fn mldsa_keys() -> (MlDsaSigningKey<MlDsa65>, ml_dsa::VerifyingKey<MlDsa65>) {
    let sk = MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(SEED_MLDSA));
    let vk = sk.verifying_key();
    (sk, vk)
}

/// Deterministic pk and signature bytes from the fixture seed/body/ctx.
///
/// Signing mode: `ExpandedSigningKey::sign_deterministic` — the FIPS 204
/// Algorithm 2 deterministic variant (rnd = 32 zero bytes,
/// ml-dsa-0.1.1/src/signing.rs:435-447).
pub fn mldsa_outputs() -> (Vec<u8>, Vec<u8>) {
    let (sk, vk) = mldsa_keys();
    let sig = sk
        .expanded_key()
        .sign_deterministic(BODY, CTX)
        .expect("ctx is 19 bytes < 256");
    (vk.encode().to_vec(), sig.encode().to_vec())
}

fn mldsa_bits() -> u32 {
    let mut bits = 0u32;
    let (sk, vk) = mldsa_keys();
    let esk = sk.expanded_key();
    let sig = esk.sign_deterministic(BODY, CTX).expect("ctx < 256");
    let enc = sig.encode();
    assert_eq!(enc.len(), MLDSA65_SIG_LEN);
    assert_eq!(vk.encode().len(), MLDSA65_PK_LEN);

    // bit 0: FIPS 204 Algorithm 3 verify with ctx succeeds.
    if vk.verify_with_context(BODY, CTX, &sig) {
        bits |= 1 << 0;
    }
    // bit 1: same signature under a different ctx fails (ctx binding).
    if !vk.verify_with_context(BODY, WRONG_CTX, &sig) {
        bits |= 1 << 1;
    }
    // bit 2: same signature under the empty ctx fails.
    if !vk.verify_with_context(BODY, &[], &sig) {
        bits |= 1 << 2;
    }
    // bit 3: deterministic signing — a second call yields identical bytes.
    let sig2 = esk.sign_deterministic(BODY, CTX).expect("ctx < 256");
    if sig2.encode() == enc {
        bits |= 1 << 3;
    }

    // Canonical-rejection probes at decode (Algorithm 27 sigDecode +
    // Algorithm 21 HintBitUnpack semantics, ml-dsa-0.1.1/src/hint.rs:128-161
    // and src/lib.rs:115-127).

    // bit 4: duplicate hint indices within one polynomial segment → decode ⊥
    // (strict `<` at hint.rs:149; the CVE-2026-24850 regression guard).
    let mut t = enc.clone();
    for b in &mut t[OFF_HINT_IDX..] {
        *b = 0;
    }
    t[OFF_HINT_IDX] = 5;
    t[OFF_HINT_IDX + 1] = 5;
    for b in &mut t[OFF_HINT_CUTS..] {
        *b = 2;
    }
    if MlDsaSignature::<MlDsa65>::decode(&t).is_none() {
        bits |= 1 << 4;
    }

    // bit 5: hint count above ω (cut byte 56 > ω = 55) → decode ⊥
    // (max_cut > indices.len() at hint.rs:137).
    let mut t = enc.clone();
    for b in &mut t[OFF_HINT_IDX..] {
        *b = 0;
    }
    for b in &mut t[OFF_HINT_CUTS..] {
        *b = (OMEGA_65 + 1) as u8;
    }
    if MlDsaSignature::<MlDsa65>::decode(&t).is_none() {
        bits |= 1 << 5;
    }

    // bit 6: nonzero index byte beyond the last cut (padding must be zero)
    // → decode ⊥ (hint.rs:138).
    let mut t = enc.clone();
    for b in &mut t[OFF_HINT_IDX..] {
        *b = 0;
    }
    t[OFF_HINT_IDX] = 9; // cuts all zero, so this is padding
    if MlDsaSignature::<MlDsa65>::decode(&t).is_none() {
        bits |= 1 << 6;
    }

    // bit 7: decreasing cumulative cuts → decode ⊥ (hint.rs:136).
    let mut t = enc.clone();
    for b in &mut t[OFF_HINT_IDX..] {
        *b = 0;
    }
    let cuts = [2u8, 1, 2, 2, 2, 2];
    t[OFF_HINT_CUTS..].copy_from_slice(&cuts);
    if MlDsaSignature::<MlDsa65>::decode(&t).is_none() {
        bits |= 1 << 7;
    }

    // bit 8: z coefficient forced to γ1 (20-bit field = 0 decodes to the
    // range-endpoint value γ1 = 2^19, so ‖z‖∞ = γ1 ≥ γ1 − β) → decode ⊥
    // (infinity-norm bound at ml-dsa-0.1.1/src/lib.rs:122-124).
    let mut t = enc.clone();
    t[OFF_Z] = 0;
    t[OFF_Z + 1] = 0;
    t[OFF_Z + 2] &= 0xf0;
    if MlDsaSignature::<MlDsa65>::decode(&t).is_none() {
        bits |= 1 << 8;
    }

    // bit 9: a well-formed but wrong signature (c_tilde bit flip) DECODES
    // fine and fails only at verify — the decode/verify layering C13's
    // distinct errors (NonCanonicalSignature vs SignatureInvalid) build on.
    let mut t = enc.clone();
    t[0] ^= 0x01;
    match MlDsaSignature::<MlDsa65>::decode(&t) {
        Some(s) if !vk.verify_with_context(BODY, CTX, &s) => bits |= 1 << 9,
        _ => {}
    }

    bits
}

// ---------------------------------------------------------------------------
// fips204 =0.4.6 probes
// ---------------------------------------------------------------------------

/// Deterministic pk and signature bytes from the same fixture seed/body/ctx.
///
/// `try_sign_with_seed(&[0; 32], …)` drives the signing RNG with 32 zero
/// bytes (fips204-0.4.6/src/traits.rs:229,311-324), which is exactly the
/// FIPS 204 Algorithm 2 deterministic variant (rnd = 0^32) — byte-compatible
/// with ml-dsa's `sign_deterministic`.
pub fn fips204_outputs() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = f204::KG::keygen_from_seed(&SEED_MLDSA);
    let sig = sk
        .try_sign_with_seed(&[0u8; 32], BODY, CTX)
        .expect("ctx < 256");
    (pk.into_bytes().to_vec(), sig.to_vec())
}

fn fips204_bits(mldsa_pk: &[u8], mldsa_sig: &[u8]) -> u32 {
    let mut bits = 0u32;
    let (pk, sk) = f204::KG::keygen_from_seed(&SEED_MLDSA);
    let sig = sk
        .try_sign_with_seed(&[0u8; 32], BODY, CTX)
        .expect("ctx < 256");

    // bit 10: verify with ctx succeeds.
    if pk.verify(BODY, &sig, CTX) {
        bits |= 1 << 10;
    }
    // bit 11: wrong ctx fails.
    if !pk.verify(BODY, &sig, WRONG_CTX) {
        bits |= 1 << 11;
    }
    // bit 12: KeyGen cross-implementation check — fips204 pk bytes equal
    // ml-dsa pk bytes for the same seed xi.
    let pk_bytes = pk.into_bytes();
    if pk_bytes.as_slice() == mldsa_pk {
        bits |= 1 << 12;
    }
    // bit 13: deterministic-sign cross-implementation check — identical
    // signature bytes.
    if sig.as_slice() == mldsa_sig {
        bits |= 1 << 13;
    }
    // bit 14: duplicate hint indices → verify() == false. fips204 folds
    // decode failure (sig_decode → Err, fips204-0.4.6/src/ml_dsa.rs:367-372)
    // and verification failure into one bool — no distinct-error surface.
    let mut t = sig;
    for b in &mut t[OFF_HINT_IDX..] {
        *b = 0;
    }
    t[OFF_HINT_IDX] = 5;
    t[OFF_HINT_IDX + 1] = 5;
    for b in &mut t[OFF_HINT_CUTS..] {
        *b = 2;
    }
    let (pk2, _) = f204::KG::keygen_from_seed(&SEED_MLDSA);
    if !pk2.verify(BODY, &t, CTX) {
        bits |= 1 << 14;
    }

    bits
}

// ---------------------------------------------------------------------------
// ed25519-dalek 2.2.0 vs 3.0.0 probes
// ---------------------------------------------------------------------------

/// Deterministic pk and signature bytes (RFC 8032 Ed25519 is deterministic)
/// over `ctx ‖ 0x00 ‖ body` for dalek 2.2.0.
pub fn d2_outputs() -> (Vec<u8>, Vec<u8>) {
    use d2::Signer as _;
    let sk = d2::SigningKey::from_bytes(&SEED_ED25519);
    let sig = sk.sign(&ed25519_message());
    (
        sk.verifying_key().to_bytes().to_vec(),
        sig.to_bytes().to_vec(),
    )
}

/// Same for dalek 3.0.0.
pub fn d3_outputs() -> (Vec<u8>, Vec<u8>) {
    use d3::Signer as _;
    let sk = d3::SigningKey::from_bytes(&SEED_ED25519);
    let sig = sk.sign(&ed25519_message());
    (
        sk.verifying_key().to_bytes().to_vec(),
        sig.to_bytes().to_vec(),
    )
}

/// The shared shape of the per-version dalek probes, instantiated for both
/// pinned versions via the macro below (the two crates export identical
/// item names but distinct types, so this cannot be a generic fn).
macro_rules! dalek_bits {
    ($name:ident, $dalek:ident, $base:expr) => {
        fn $name() -> u32 {
            use $dalek::{Signer as _, Verifier as _};
            let mut bits = 0u32;
            let msg = ed25519_message();
            let sk = $dalek::SigningKey::from_bytes(&SEED_ED25519);
            let vk = sk.verifying_key();
            let sig = sk.sign(&msg);

            // base+0: verify_strict accepts the honest signature.
            if vk.verify_strict(&msg, &sig).is_ok() {
                bits |= 1 << ($base);
            }

            // base+1: the S ≥ L maul (s' = s + L; same value mod L).
            // `Signature::from_bytes` is infallible — the maul MUST parse —
            // and BOTH `verify` and `verify_strict` must reject it
            // (check_scalar via Scalar::from_canonical_bytes in every
            // verification path, src/signature.rs:89-96 in both versions).
            let sig_bytes = sig.to_bytes();
            let mut mauled = sig_bytes;
            let mut s = [0u8; 32];
            s.copy_from_slice(&sig_bytes[32..]);
            mauled[32..].copy_from_slice(&add_l(&s));
            let mauled_sig = $dalek::Signature::from_bytes(&mauled); // parse-time: accepted
            if vk.verify(&msg, &mauled_sig).is_err() && vk.verify_strict(&msg, &mauled_sig).is_err()
            {
                bits |= 1 << ($base + 1);
            }

            // base+2: small-order R (identity point) → verify_strict rejects
            // (is_small_order check, src/verifying.rs verify_strict).
            let mut small_r = [0u8; 64];
            small_r[..32].copy_from_slice(&ED25519_IDENTITY);
            // s = 0 is canonical, so rejection is attributable to R.
            let small_r_sig = $dalek::Signature::from_bytes(&small_r);
            if vk.verify_strict(&msg, &small_r_sig).is_err() {
                bits |= 1 << ($base + 2);
            }

            // base+3: small-order A — parses fine (ZIP-215), flagged weak,
            // and verify_strict rejects anything under it.
            match $dalek::VerifyingKey::from_bytes(&ED25519_IDENTITY) {
                Ok(weak_vk) => {
                    if weak_vk.is_weak() && weak_vk.verify_strict(&msg, &sig).is_err() {
                        bits |= 1 << ($base + 3);
                    }
                }
                Err(_) => {}
            }

            // base+4: NON-CANONICAL A (y-encoding = p ≡ 0 mod p) is ACCEPTED
            // at parse time and keeps its non-canonical byte identity —
            // documented ZIP-215 behavior (src/verifying.rs from_bytes doc:
            // "RFC 8032 / NIST point validation criteria are currently
            // unsupported", curve25519-dalek#626). This is the gap C12's
            // pre-validation layer must close (decompress→recompress
            // byte-compare).
            match $dalek::VerifyingKey::from_bytes(&ED25519_NONCANONICAL_Y) {
                Ok(nc) if nc.to_bytes() == ED25519_NONCANONICAL_Y => {
                    bits |= 1 << ($base + 4);
                }
                _ => {}
            }

            bits
        }
    };
}

dalek_bits!(d2_bits, ed25519_dalek_2, 15);
dalek_bits!(d3_bits, ed25519_dalek_3, 20);

// ---------------------------------------------------------------------------
// Zeroize integration: compile-time assertions that the pinned versions
// implement ZeroizeOnDrop for their secret-key types (with the probe's
// feature selection). A pin bump that silently loses this fails to compile.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn assert_zeroize_on_drop() {
    fn is_zod<T: zeroize::ZeroizeOnDrop>() {}
    is_zod::<MlDsaSigningKey<MlDsa65>>(); // ml-dsa-0.1.1/src/signing.rs:231
    is_zod::<ml_dsa::ExpandedSigningKey<MlDsa65>>(); // src/signing.rs:662
    is_zod::<d2::SigningKey>(); // ed25519-dalek-2.2.0/src/signing.rs
    is_zod::<d3::SigningKey>(); // ed25519-dalek-3.0.0/src/signing.rs:726
}

// ---------------------------------------------------------------------------
// Combined artifacts
// ---------------------------------------------------------------------------

/// All behavioral invariants as a bitmask; must equal [`EXPECTED_SELFCHECK`]
/// natively AND on wasm32.
pub fn selfcheck() -> u32 {
    let mut bits = mldsa_bits();
    let (mldsa_pk, mldsa_sig) = mldsa_outputs();
    bits |= fips204_bits(&mldsa_pk, &mldsa_sig);
    bits |= d2_bits();
    bits |= d3_bits();

    let (d2_pk, d2_sig) = d2_outputs();
    let (d3_pk, d3_sig) = d3_outputs();
    // bit 25: RFC 8032 determinism across the two pinned dalek versions —
    // identical signature bytes for the same seed and message.
    if d2_sig == d3_sig {
        bits |= 1 << 25;
    }
    // bit 26: identical public keys across the two versions.
    if d2_pk == d3_pk {
        bits |= 1 << 26;
    }
    bits
}

/// Concatenated deterministic outputs of all candidates:
/// `mldsa_pk(1952) ‖ mldsa_sig(3309) ‖ fips204_pk(1952) ‖ fips204_sig(3309) ‖
///  d2_pk(32) ‖ d2_sig(64) ‖ d3_pk(32) ‖ d3_sig(64)` — 10714 bytes total.
/// The native golden SHA-256 of this buffer is pinned in tests/transcript.rs;
/// the wasm run must reproduce it byte-for-byte.
pub fn build_transcript() -> Vec<u8> {
    let mut out = Vec::with_capacity(10714);
    let (pk, sig) = mldsa_outputs();
    out.extend_from_slice(&pk);
    out.extend_from_slice(&sig);
    let (pk, sig) = fips204_outputs();
    out.extend_from_slice(&pk);
    out.extend_from_slice(&sig);
    let (pk, sig) = d2_outputs();
    out.extend_from_slice(&pk);
    out.extend_from_slice(&sig);
    let (pk, sig) = d3_outputs();
    out.extend_from_slice(&pk);
    out.extend_from_slice(&sig);
    assert_eq!(out.len(), 10714);
    out
}

// ---------------------------------------------------------------------------
// wasm32 exports (no wasm-bindgen: the module is pure computation with zero
// imports, so a plain `WebAssembly.instantiate(bytes, {})` in Node can run
// it — see run-wasm.mjs). All safe code: the pointer hands out the address
// of a leaked, immutable buffer.
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

static RESULT: OnceLock<(u32, Vec<u8>)> = OnceLock::new();

fn computed() -> &'static (u32, Vec<u8>) {
    RESULT.get_or_init(|| (selfcheck(), build_transcript()))
}

/// Run every probe; returns the selfcheck bitmask (expect
/// [`EXPECTED_SELFCHECK`]).
#[no_mangle]
pub extern "C" fn probe_selfcheck() -> u32 {
    computed().0
}

/// Transcript length in bytes (call after `probe_selfcheck`).
#[no_mangle]
pub extern "C" fn probe_out_len() -> u32 {
    computed().1.len() as u32
}

/// Pointer to the transcript bytes inside wasm linear memory.
#[no_mangle]
pub extern "C" fn probe_out_ptr() -> *const u8 {
    computed().1.as_ptr()
}
