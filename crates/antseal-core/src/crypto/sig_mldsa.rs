//! ML-DSA-65 half of the hybrid author signature: FIPS 204 keys expanded from
//! a `W`-derived seed ξ, **deterministic** signing, and canonical-strict
//! verification with the FIPS 204 `ctx` parameter (tasks/C.md C13;
//! MVP-SPEC.md lines 97, 104, 183).
//!
//! ```text
//! xi  = HKDF(W, "sig-mldsa65", sentinel)          (C2; 32 B)
//! key = FIPS 204 Algorithm 6 ML-DSA.KeyGen_internal(xi)
//! sig = FIPS 204 Algorithm 2 ML-DSA.Sign(body, ctx), deterministic variant
//! ```
//!
//! # Context binding is native here (spec line 97)
//!
//! Unlike Ed25519, ML-DSA has a context parameter in the standard, so the
//! frozen [`SIG_CONTEXT`] is passed as FIPS 204's `ctx` rather than folded
//! into the message. The standard absorbs `M′ = 0x00 ‖ len(ctx) ‖ ctx ‖ M`
//! before hashing, which is the same domain separation the Ed25519 half
//! builds by hand — so both signatures over one body are bound to the same
//! context, by each algorithm's own rules.
//!
//! **Never use the crate's `Signer`/`Verifier` trait impls**: they sign and
//! verify with the *empty* context (C11 report §2.2). Every path here calls
//! `sign_deterministic` / `verify_with_context` explicitly.
//!
//! # Deterministic signing (decision D15)
//!
//! v1 signs with the FIPS 204 deterministic variant (`rnd = 0³²`) — the
//! pinned crate's non-RNG path. Consequences, all deliberate: signature
//! bytes are reproducible, so C16 can pin them as golden vectors; they are
//! *cross-implementation* reproducible (the C11 probe produced byte-identical
//! output from `fips204`), so the pinned-unconsumed fallback swap would be
//! byte-invisible; and the signing path needs no RNG on any target.
//! Verification is mode-agnostic — nothing in the format records which
//! variant produced a signature, so a future version may switch to hedged
//! signing without a format bump.
//!
//! # Canonical-strict verification without a pre-validation layer
//!
//! Spec line 97 requires rejecting *any* non-canonical or out-of-range
//! signature encoding. The C11 probe established (report §2.3, with source
//! citations and standing regression bits) that the pinned `ml-dsa =0.1.1`
//! already enforces the **complete** FIPS 204 canonical-encoding rule inside
//! `Signature::decode` (Algorithm 27 `sigDecode`):
//!
//! | rejected at decode | rule |
//! | --- | --- |
//! | `‖z‖∞ ≥ γ1 − β` | the norm bound, checked eagerly at decode |
//! | duplicate hint indices in a segment | strict `<` ordering — this is the CVE-2026-24850 fix |
//! | hint count above ω (= 55) | Algorithm 21 step 4 |
//! | nonzero index bytes after the last cut | the zero-padding rule, Algorithm 21 steps 16–18 |
//! | decreasing cumulative cuts | Algorithm 21 step 4 |
//! | wrong length | the exact-size `EncodedSignature` conversion |
//!
//! and that there are **no other encoding degrees of freedom**: `c_tilde` is
//! 48 opaque hash bytes (all values legal, equality-checked during verify)
//! and the 20-bit `z` packing is a bijection onto `[−γ1+1, γ1]`. So C13 adds
//! **no pre-validation layer** (D14) — that would duplicate the crate's
//! checks and risk diverging from them. The layering falls out instead:
//!
//! - `decode` fails ⇒ [`CryptoError::NonCanonicalSignature`];
//! - `decode` succeeds and `verify_with_context` returns false ⇒
//!   [`CryptoError::SignatureInvalid`].
//!
//! The reject tests below re-run the probe's mutations through *this* API, so
//! the two error classes — and the crate's canonical rejection itself — are
//! guarded here, not only in the probe. If the `fips204` fallback is ever
//! activated (D14's trigger), its bool-only API folds both classes together
//! and a pre-validation layer becomes mandatory (C11 report §3/§9).
//!
//! # Advisory posture (spec line 183)
//!
//! `ml-dsa` is pre-1.0 and unaudited; three 2026 advisories are assessed in
//! `docs/decisions/D14-mldsa-crate.md` and all are patched in the pinned
//! 0.1.1. Two of them are exactly the kind of regression the decode tests
//! below stand guard over (repeated hint indices; the `UseHint` off-by-two).
//! Advisory tracking must cover GHSA/osv.dev as well as RUSTSEC — only one of
//! the three ever received a RUSTSEC id.

use ml_dsa::{
    B32, EncodedVerifyingKey, Keypair as _, MlDsa65, Signature as MlDsaSignature,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};

use super::SIG_CONTEXT;
use super::error::{CryptoError, SigAlg};
use super::hkdf::derive_sig_mldsa65_seed;
use super::material::{MasterSecretRef, Seed32};

/// Byte length of an ML-DSA-65 public key (FIPS 204 Table 2; F's schema,
/// registry §4: 1952 B).
pub const PUBLIC_KEY_LEN: usize = 1952;

/// Byte length of an ML-DSA-65 signature (FIPS 204 Table 2; F's schema,
/// registry §4: 3309 B).
pub const SIGNATURE_LEN: usize = 3309;

/// FIPS 204 Algorithm 26 `sigEncode` layout for ML-DSA-65, as byte offsets
/// into the 3309-byte encoding:
/// `c_tilde(48) ‖ z(5·256·20 bits = 3200) ‖ hint indices(ω = 55) ‖ hint cuts(k = 6)`.
///
/// Public because C15's reject-vector suite constructs its mutations at these
/// offsets; nothing in the verification path indexes the encoding by hand
/// (the crate's decoder owns that).
pub const OFFSET_Z: usize = 48;
/// Start of the ω hint-index bytes (see [`OFFSET_Z`]).
pub const OFFSET_HINT_INDICES: usize = 3248;
/// Start of the k hint cumulative-cut bytes (see [`OFFSET_Z`]).
pub const OFFSET_HINT_CUTS: usize = 3303;
/// ω for ML-DSA-65: the maximum total number of hint bits (FIPS 204 Table 2).
pub const OMEGA: usize = 55;

/// Shorthand for this module's algorithm tag in error payloads.
const ALG: SigAlg = SigAlg::MlDsa65;

/// The frozen context is far below FIPS 204's 255-byte ctx limit, so the
/// signing call's ctx-length error is statically unreachable.
const _: () = assert!(SIG_CONTEXT.len() <= 255);

/// An ML-DSA-65 public key as carried in the manifest body's `pubkeys` map
/// (spec line 98) — **public** wire bytes, plain value semantics.
///
/// Construction is deliberately infallible, as for the Ed25519 half: every
/// 1952-byte string is a well-formed encoded key (FIPS 204 Algorithm 23
/// `pkDecode` is a bijection — `rho` is 32 opaque bytes and the `t1` packing
/// covers every 10-bit pattern), so there is nothing to reject at parse time.
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsa65PublicKey([u8; PUBLIC_KEY_LEN]);

/// An ML-DSA-65 signature as carried in the manifest envelope's `signatures`
/// map (spec line 97) — **public** wire bytes, plain value semantics.
///
/// Unlike the key, a same-length signature can still be non-canonical
/// (hint/`z` rules); that is decided in [`verify`], not here.
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsa65Signature([u8; SIGNATURE_LEN]);

macro_rules! wire_value {
    ($name:ident, $len:expr) => {
        impl $name {
            /// Length in bytes.
            pub const LEN: usize = $len;

            /// Construct from exactly-sized bytes (F's decode path).
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw bytes (F's encode path).
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Consume into the raw bytes.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; $len] {
                self.0
            }

            /// Length-checked construction from a bundle-supplied slice.
            ///
            /// Defense in depth behind F's strict decode layer, which already
            /// enforces the exact bstr length. A wrong length is reported as
            /// [`CryptoError::NonCanonicalSignature`] — matching the pinned
            /// crate, whose own decode folds wrong-length into the same
            /// "not a canonical encoding" outcome — rather than widening C4's
            /// frozen taxonomy with a length variant.
            ///
            /// # Errors
            ///
            #[doc = concat!("[`CryptoError::NonCanonicalSignature`] when `bytes.len() != ", stringify!($len), "`.")]
            pub fn try_from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
                match <[u8; $len]>::try_from(bytes) {
                    Ok(array) => Ok(Self::from_bytes(array)),
                    Err(_) => Err(CryptoError::NonCanonicalSignature { alg: ALG }),
                }
            }
        }

        impl core::fmt::Debug for $name {
            /// Abbreviated hex: these are kilobyte-scale **public** values, so
            /// there is nothing to redact, but a full rendering would be
            /// unreadable in a verifier diagnostic. Shows the length and the
            /// first and last 8 bytes.
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}({} B: ", stringify!($name), $len)?;
                for byte in &self.0[..8] {
                    write!(f, "{byte:02x}")?;
                }
                f.write_str("..")?;
                for byte in &self.0[$len - 8..] {
                    write!(f, "{byte:02x}")?;
                }
                f.write_str(")")
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = CryptoError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                Self::try_from_slice(bytes)
            }
        }
    };
}

wire_value!(MlDsa65PublicKey, PUBLIC_KEY_LEN);
wire_value!(MlDsa65Signature, SIGNATURE_LEN);

/// Expand the FIPS 204 signing key from `W`.
///
/// ξ never leaves this function: [`Seed32`] is `ZeroizeOnDrop`, and the
/// borrowed view handed to the crate is zero-copy (no transient array on the
/// stack to forget about). The crate's own copies — `SigningKey`'s seed and
/// `ExpandedSigningKey`'s `rho`/`K`/`tr`/`s1`/`s2`/`t0` — are zeroized on
/// their drop by the non-default `zeroize` feature the workspace pin enables
/// (compile-asserted in the tests).
fn signing_key(w: MasterSecretRef<'_>) -> MlDsaSigningKey<MlDsa65> {
    let xi: Seed32 = derive_sig_mldsa65_seed(w);
    // Static impossibility: `Seed32::LEN` (32) is exactly `B32`'s length.
    let seed = <&B32>::try_from(xi.as_bytes().as_slice())
        .expect("Seed32::LEN equals the FIPS 204 seed length");
    MlDsaSigningKey::<MlDsa65>::from_seed(seed)
}

/// The author's ML-DSA-65 public key for this work (spec line 97). Per-work
/// by construction: ξ derives from that work's `W`.
#[must_use]
pub fn public_key(w: MasterSecretRef<'_>) -> MlDsa65PublicKey {
    encode_public_key(&signing_key(w).verifying_key())
}

fn encode_public_key(vk: &MlDsaVerifyingKey<MlDsa65>) -> MlDsa65PublicKey {
    let encoded = vk.encode();
    MlDsa65PublicKey(
        <[u8; PUBLIC_KEY_LEN]>::try_from(encoded.as_slice())
            .expect("FIPS 204 Table 2 fixes the ML-DSA-65 public key at 1952 bytes"),
    )
}

/// Sign with an explicit context. Private: the public entry point always
/// binds [`SIG_CONTEXT`], so no caller can mint a signature under another
/// context. Tests use it to build the wrong-ctx negative case.
fn sign_with_context(w: MasterSecretRef<'_>, body: &[u8], ctx: &[u8]) -> MlDsa65Signature {
    debug_assert!(ctx.len() <= 255, "FIPS 204 caps ctx at 255 bytes");
    let signature = signing_key(w)
        .expanded_key()
        // FIPS 204 Algorithm 2, deterministic variant (rnd = 0^32) — D15.
        .sign_deterministic(body, ctx)
        .expect("the frozen context is 19 bytes, far below the FIPS 204 limit of 255");
    MlDsa65Signature(
        <[u8; SIGNATURE_LEN]>::try_from(signature.encode().as_slice())
            .expect("FIPS 204 Table 2 fixes the ML-DSA-65 signature at 3309 bytes"),
    )
}

/// Sign the manifest body bytes: FIPS 204 ML-DSA-65, deterministic variant,
/// with `ctx = "antseal-manifest-v1"` (spec line 97; decision D15).
#[must_use]
pub fn sign(w: MasterSecretRef<'_>, body: &[u8]) -> MlDsa65Signature {
    sign_with_context(w, body, SIG_CONTEXT)
}

/// Verify under an explicit context (see [`sign_with_context`]).
fn verify_with_context(
    pk: &MlDsa65PublicKey,
    body: &[u8],
    ctx: &[u8],
    sig: &MlDsa65Signature,
) -> Result<(), CryptoError> {
    // Canonical-encoding gate: Algorithm 27 sigDecode enforces the complete
    // FIPS 204 rule (module docs), so a decode failure IS the non-canonical
    // verdict — no separate pre-validation layer exists or is needed.
    let decoded = MlDsaSignature::<MlDsa65>::try_from(sig.0.as_slice())
        .map_err(|_| CryptoError::NonCanonicalSignature { alg: ALG })?;

    // Static impossibility: the wire type is exactly 1952 bytes.
    let encoded_key = <&EncodedVerifyingKey<MlDsa65>>::try_from(pk.0.as_slice())
        .expect("MlDsa65PublicKey is exactly the FIPS 204 encoded-key length");
    let verifying_key = MlDsaVerifyingKey::<MlDsa65>::decode(encoded_key);

    if verifying_key.verify_with_context(body, ctx, &decoded) {
        Ok(())
    } else {
        Err(CryptoError::SignatureInvalid { alg: ALG })
    }
}

/// Canonical-strict verification of an author signature over the manifest
/// body bytes with the frozen FIPS 204 context (spec line 97).
///
/// # Errors
///
/// - [`CryptoError::NonCanonicalSignature`] — the signature encoding is not
///   canonical: hint-count/ordering/padding violations, `z` out of range, or
///   the wrong length (module docs).
/// - [`CryptoError::SignatureInvalid`] — a canonical encoding that does not
///   verify: wrong key, wrong body, or a signature made under a different
///   context.
pub fn verify(
    pk: &MlDsa65PublicKey,
    body: &[u8],
    sig: &MlDsa65Signature,
) -> Result<(), CryptoError> {
    verify_with_context(pk, body, SIG_CONTEXT, sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::OnceLock;
    use zeroize::ZeroizeOnDrop;

    /// Fixed, public, NON-SECRET fixture `W` (project rule 6) — the seed
    /// `testdata/vectors/v1/hkdf/hkdf-labels.json` derives from.
    const TEST_W: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    const OTHER_W: [u8; 32] = [0xEEu8; 32];

    /// Stand-in for F's canonical CBOR body bytes (the same fixture the
    /// Ed25519 half uses, so C14 can sign one body with both algorithms).
    const BODY: &[u8] = b"antseal manifest body bytes (fixture)\n";

    fn w() -> MasterSecretRef<'static> {
        MasterSecretRef::from_bytes(&TEST_W)
    }

    fn other_w() -> MasterSecretRef<'static> {
        MasterSecretRef::from_bytes(&OTHER_W)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// ML-DSA keygen/signing is expensive in a debug build, so the fixture
    /// pair is computed once per test binary.
    fn fixture() -> &'static (MlDsa65PublicKey, MlDsa65Signature) {
        static FIXTURE: OnceLock<(MlDsa65PublicKey, MlDsa65Signature)> = OnceLock::new();
        FIXTURE.get_or_init(|| (public_key(w()), sign(w(), BODY)))
    }

    /// C13 accept: round-trip sign/verify over a fixed body with the frozen
    /// ctx, and the sizes F's schema pins.
    #[test]
    fn round_trip_with_context() {
        let (pk, sig) = fixture();
        assert_eq!(PUBLIC_KEY_LEN, 1952);
        assert_eq!(SIGNATURE_LEN, 3309);
        assert_eq!(pk.as_bytes().len(), PUBLIC_KEY_LEN);
        assert_eq!(sig.as_bytes().len(), SIGNATURE_LEN);
        // The sigEncode layout constants add up to the pinned length.
        assert_eq!(OFFSET_Z, 48);
        assert_eq!(OFFSET_HINT_INDICES, OFFSET_Z + 5 * 256 * 20 / 8);
        assert_eq!(OFFSET_HINT_CUTS, OFFSET_HINT_INDICES + OMEGA);
        assert_eq!(SIGNATURE_LEN, OFFSET_HINT_CUTS + 6);

        assert_eq!(verify(pk, BODY, sig), Ok(()));
    }

    /// C13 accept: keygen from a fixed ξ is deterministic, and signing is too
    /// (D15's deterministic variant) — the property C16's golden vectors and
    /// Q11's cross-check rest on.
    #[test]
    fn keygen_and_signing_are_deterministic() {
        let (pk, sig) = fixture();
        assert_eq!(&public_key(w()), pk, "keygen from a fixed xi is stable");
        assert_eq!(&sign(w(), BODY), sig, "deterministic signing (rnd = 0^32)");
        // A different W gives a different key and signature.
        assert_ne!(&public_key(other_w()), pk);
        assert_ne!(&sign(other_w(), BODY), sig);
    }

    /// C13 accept: committed KAT for the fixture ξ. Full 1952/3309-byte
    /// literals would drown the source, so the known answers are pinned as
    /// SHA-256 digests plus the exact ξ they expand from and byte-level
    /// anchors — any drift in the derivation, the keygen, the signing mode,
    /// or the context moves these.
    ///
    /// These digests pin *antseal's own derivation chain*
    /// (`W → HKDF ξ → keygen → deterministic sign over BODY`), so they are a
    /// drift detector rather than independent evidence. The independence
    /// comes from [`matches_the_c11_probe_transcript_golden`] below, which
    /// reproduces an artifact already cross-checked against a second ML-DSA
    /// implementation (`fips204`) and executed on wasm32.
    ///
    /// (C16 lifts these into `testdata/vectors/v1/` as a registered vector
    /// kind; the framework extension belongs to that task, not this one.)
    #[test]
    fn fixed_xi_keygen_and_signature_kat() {
        let (pk, sig) = fixture();

        // The exact xi, cross-checked with C3's committed HKDF vector
        // (label "sig-mldsa65", sentinel id).
        let xi = derive_sig_mldsa65_seed(w());
        assert_eq!(
            hex(xi.as_bytes()),
            "7a3862bbaa81fbd09103d08c48b1ffe54afdf20fb0562f20d26803c9d111f590"
        );

        assert_eq!(
            hex(&Sha256::digest(pk.as_bytes())),
            "b4fba752cc5f75643ddbc1a99e56a796bdcbcd830e3cad4a0dfbd11a37a0c3b0"
        );
        assert_eq!(
            hex(&Sha256::digest(sig.as_bytes())),
            "8eca4584820063c48edaf84eccede6cdf842adb912f6d4ce4d21d4b80633ec9d"
        );
    }

    /// C13 accept (independent cross-check): reconstruct the **C11 probe
    /// transcript** from this crate's own implementation and match its
    /// committed SHA-256 golden.
    ///
    /// The probe (`probes/sig-probe`, report §5) concatenated
    /// `mldsa_pk ‖ mldsa_sig ‖ fips204_pk ‖ fips204_sig ‖ d2_pk ‖ d2_sig ‖
    /// d3_pk ‖ d3_sig` over fixed fixture seeds, the frozen ctx and the
    /// Ed25519 `ctx ‖ 0x00 ‖ body` pre-image, and pinned the digest of the
    /// 10714-byte result — natively *and* on wasm32, byte-identically. Probe
    /// bits 12/13 proved the `fips204` halves equal the `ml-dsa` halves, and
    /// bits 25/26 that the two dalek majors agree, so the whole transcript is
    /// reproducible from the two crates antseal actually consumes.
    ///
    /// Matching that digest here means our keygen, our deterministic signing
    /// mode, our ctx handling and our encodings agree byte-for-byte with an
    /// artifact that was independently cross-checked against a second ML-DSA
    /// implementation — the strongest known-answer material available for
    /// this parameter set without shipping ACVP JSON.
    #[test]
    fn matches_the_c11_probe_transcript_golden() {
        const fn seq32(start: u8) -> [u8; 32] {
            let mut a = [0u8; 32];
            let mut i = 0;
            while i < 32 {
                a[i] = start + i as u8;
                i += 1;
            }
            a
        }
        const PROBE_BODY: &[u8] = b"antseal C11 signature-crate probe body\n";
        let probe_xi = seq32(0x00);
        let probe_ed_seed = seq32(0x20);

        // ML-DSA half, from the probe's xi (NOT the HKDF path — the probe
        // seeded the crate directly).
        let seed = <&B32>::try_from(probe_xi.as_slice()).expect("32 bytes");
        let sk = MlDsaSigningKey::<MlDsa65>::from_seed(seed);
        let mldsa_pk = encode_public_key(&sk.verifying_key());
        let mldsa_sig = MlDsa65Signature(
            <[u8; SIGNATURE_LEN]>::try_from(
                sk.expanded_key()
                    .sign_deterministic(PROBE_BODY, SIG_CONTEXT)
                    .expect("ctx < 256")
                    .encode()
                    .as_slice(),
            )
            .expect("3309 bytes"),
        );

        // Ed25519 half, over C12's pre-image construction.
        let ed_key = ed25519_dalek::SigningKey::from_bytes(&probe_ed_seed);
        let ed_message = crate::crypto::sig_ed25519::signing_message(PROBE_BODY);
        let ed_pk = ed_key.verifying_key().to_bytes();
        let ed_sig = ed25519_dalek::Signer::sign(&ed_key, &ed_message).to_bytes();

        let mut transcript = Vec::with_capacity(10714);
        for _ in 0..2 {
            // ml-dsa and fips204 halves are byte-identical (probe bit 12/13).
            transcript.extend_from_slice(mldsa_pk.as_bytes());
            transcript.extend_from_slice(mldsa_sig.as_bytes());
        }
        for _ in 0..2 {
            // dalek 2.2.0 and 3.0.0 halves are byte-identical (bits 25/26).
            transcript.extend_from_slice(&ed_pk);
            transcript.extend_from_slice(&ed_sig);
        }
        assert_eq!(transcript.len(), 10714);
        assert_eq!(
            hex(&Sha256::digest(&transcript)),
            "92354c8d75efdc6dfd26cea301243e35ba0776753c61127846b77c8a3cffa298",
            "C11 probe transcript golden (docs/research/C11-signature-probe.md §5)"
        );
    }

    /// C13 accept: wrong-ctx verification fails. Covers a same-length ctx, a
    /// different-length ctx, and the empty ctx — the last being what the
    /// crate's `Signer`/`Verifier` trait impls would silently use.
    #[test]
    fn wrong_context_fails() {
        let (pk, sig) = fixture();
        for wrong_ctx in [&b"antseal-manifest-v2"[..], b"antseal-manifest-v10", b""] {
            assert_eq!(
                verify_with_context(pk, BODY, wrong_ctx, sig).expect_err("must fail"),
                CryptoError::SignatureInvalid {
                    alg: SigAlg::MlDsa65
                }
            );
        }
        // …and a signature made under a wrong ctx fails the frozen-ctx path.
        let sig_wrong_ctx = sign_with_context(w(), BODY, b"antseal-manifest-v2");
        assert_eq!(
            verify(pk, BODY, &sig_wrong_ctx).expect_err("must fail"),
            CryptoError::SignatureInvalid {
                alg: SigAlg::MlDsa65
            }
        );
        // Sanity: it does verify under the ctx it was made with, so the
        // failure above is attributable to the context alone.
        assert_eq!(
            verify_with_context(pk, BODY, b"antseal-manifest-v2", &sig_wrong_ctx),
            Ok(())
        );
    }

    /// C13 accept: wrong key / wrong body → `SignatureInvalid`, distinct from
    /// the non-canonical class (tamper matrix, spec line 168).
    #[test]
    fn wrong_key_or_body_is_invalid() {
        let (pk, sig) = fixture();

        let other_sig = sign(other_w(), BODY);
        let invalid = verify(pk, BODY, &other_sig).expect_err("must fail");
        assert_eq!(
            invalid,
            CryptoError::SignatureInvalid {
                alg: SigAlg::MlDsa65
            }
        );

        let mut other_body = BODY.to_vec();
        other_body[0] ^= 0x01;
        assert_eq!(
            verify(pk, &other_body, sig).expect_err("must fail"),
            CryptoError::SignatureInvalid {
                alg: SigAlg::MlDsa65
            }
        );

        let non_canonical = CryptoError::NonCanonicalSignature {
            alg: SigAlg::MlDsa65,
        };
        assert_ne!(
            core::mem::discriminant(&invalid),
            core::mem::discriminant(&non_canonical)
        );
        assert_eq!(invalid.code(), "crypto-signature-invalid-ml-dsa-65");
        assert_eq!(
            non_canonical.code(),
            "crypto-non-canonical-signature-ml-dsa-65"
        );
    }

    /// C13 accept: every non-canonical encoding class rejects as
    /// `NonCanonicalSignature`, while a bit-mutated-but-decodable signature
    /// rejects as `SignatureInvalid` — the layering the two distinct verdicts
    /// rest on. These mirror C11 probe bits 4–9 through the public API, so
    /// the crate's canonical rejection is guarded in this crate's own suite
    /// (in particular the strict hint ordering, whose regression was
    /// CVE-2026-24850).
    #[test]
    fn non_canonical_encodings_reject_distinctly() {
        let (pk, sig) = fixture();
        let good = *sig.as_bytes();

        let mut cases: Vec<(&str, [u8; SIGNATURE_LEN])> = Vec::new();

        // Duplicate hint indices within one polynomial segment.
        let mut t = good;
        t[OFFSET_HINT_INDICES..].fill(0);
        t[OFFSET_HINT_INDICES] = 5;
        t[OFFSET_HINT_INDICES + 1] = 5;
        t[OFFSET_HINT_CUTS..].fill(2);
        cases.push(("duplicate hint indices", t));

        // Hint count above omega (cut byte 56 > 55).
        let mut t = good;
        t[OFFSET_HINT_INDICES..].fill(0);
        let over = u8::try_from(OMEGA + 1).expect("56 fits in u8");
        t[OFFSET_HINT_CUTS..].fill(over);
        cases.push(("hint count above omega", t));

        // Nonzero index byte beyond the last cut (zero-padding rule).
        let mut t = good;
        t[OFFSET_HINT_INDICES..].fill(0);
        t[OFFSET_HINT_INDICES] = 9;
        cases.push(("nonzero hint padding", t));

        // Decreasing cumulative cuts.
        let mut t = good;
        t[OFFSET_HINT_INDICES..].fill(0);
        t[OFFSET_HINT_CUTS..].copy_from_slice(&[2u8, 1, 2, 2, 2, 2]);
        cases.push(("decreasing hint cuts", t));

        // z coefficient forced to gamma1 (the 20-bit field 0 decodes to the
        // range endpoint), so ‖z‖∞ >= gamma1 − beta.
        let mut t = good;
        t[OFFSET_Z] = 0;
        t[OFFSET_Z + 1] = 0;
        t[OFFSET_Z + 2] &= 0xf0;
        cases.push(("z out of range", t));

        for (name, bytes) in cases {
            let mutated = MlDsa65Signature::from_bytes(bytes);
            assert_eq!(
                verify(pk, BODY, &mutated).expect_err("must fail"),
                CryptoError::NonCanonicalSignature {
                    alg: SigAlg::MlDsa65
                },
                "{name} must be rejected as non-canonical"
            );
        }

        // A bit-flipped c_tilde DECODES fine (48 opaque hash bytes, all
        // values legal) and fails only at verification.
        let mut decodable = good;
        decodable[0] ^= 0x01;
        assert_eq!(
            verify(pk, BODY, &MlDsa65Signature::from_bytes(decodable)).expect_err("must fail"),
            CryptoError::SignatureInvalid {
                alg: SigAlg::MlDsa65
            },
            "a decodable mutation is invalid, not non-canonical"
        );
        // A flip inside z stays in range here but breaks verification too.
        let mut z_flip = good;
        z_flip[OFFSET_Z + 100] ^= 0x01;
        assert!(verify(pk, BODY, &MlDsa65Signature::from_bytes(z_flip)).is_err());

        // All-zero and all-0xFF signatures reject cleanly (no panic).
        assert_eq!(
            verify(
                pk,
                BODY,
                &MlDsa65Signature::from_bytes([0xFFu8; SIGNATURE_LEN])
            )
            .expect_err("must fail"),
            CryptoError::NonCanonicalSignature {
                alg: SigAlg::MlDsa65
            }
        );
        assert!(
            verify(
                pk,
                BODY,
                &MlDsa65Signature::from_bytes([0u8; SIGNATURE_LEN])
            )
            .is_err()
        );
    }

    /// C13 accept: ξ is zeroized after expansion — `Seed32` wipes on drop and
    /// the crate's key types are `ZeroizeOnDrop` under the non-default
    /// `zeroize` feature (compile-asserted, so a pin bump that lost the
    /// feature fails to build).
    #[test]
    fn xi_and_key_material_zeroize_on_drop() {
        const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        const _: () = {
            assert_zeroize_on_drop::<Seed32>();
            assert_zeroize_on_drop::<MlDsaSigningKey<MlDsa65>>();
            assert_zeroize_on_drop::<ml_dsa::ExpandedSigningKey<MlDsa65>>();
        };

        let mut xi = derive_sig_mldsa65_seed(w());
        zeroize::Zeroize::zeroize(&mut xi);
        assert_eq!(xi.as_bytes(), &[0u8; 32]);
    }

    /// Wire values: lengths, abbreviated hex `Debug`, and the length-checked
    /// slice constructors (defensive parsing — wrong lengths reject, never
    /// panic).
    #[test]
    fn wire_value_lengths_and_slice_constructors() {
        let (pk, sig) = fixture();
        assert_eq!(MlDsa65PublicKey::LEN, PUBLIC_KEY_LEN);
        assert_eq!(MlDsa65Signature::LEN, SIGNATURE_LEN);
        assert_eq!(
            &MlDsa65PublicKey::try_from_slice(pk.as_bytes()).expect("exact length"),
            pk
        );
        assert_eq!(
            &MlDsa65Signature::try_from_slice(sig.as_bytes()).expect("exact length"),
            sig
        );
        for bad_len in [0usize, 1951, 1953, 3308, 3310] {
            let bytes = vec![0u8; bad_len];
            assert_eq!(
                MlDsa65PublicKey::try_from_slice(&bytes).expect_err("must reject"),
                CryptoError::NonCanonicalSignature {
                    alg: SigAlg::MlDsa65
                }
            );
            assert_eq!(
                MlDsa65Signature::try_from_slice(&bytes).expect_err("must reject"),
                CryptoError::NonCanonicalSignature {
                    alg: SigAlg::MlDsa65
                }
            );
        }

        let rendered = format!("{sig:?}");
        assert!(rendered.starts_with("MlDsa65Signature(3309 B: "));
        assert!(rendered.contains(&hex(&sig.as_bytes()[..8])));
        assert!(rendered.contains(&hex(&sig.as_bytes()[SIGNATURE_LEN - 8..])));
        assert!(
            rendered.len() < 64,
            "Debug must stay abbreviated: {}",
            rendered.len()
        );
        assert!(format!("{pk:?}").starts_with("MlDsa65PublicKey(1952 B: "));
    }
}
