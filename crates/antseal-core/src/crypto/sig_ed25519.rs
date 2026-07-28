//! Ed25519 half of the hybrid author signature: deterministic keys derived
//! from `W`, the frozen context prefix, and **strict/canonical** verification
//! with distinct error attribution (tasks/C.md C12; MVP-SPEC.md lines 97,
//! 104).
//!
//! ```text
//! seed    = HKDF(W, "sig-ed25519", sentinel)      (C2; 32 B)
//! key     = RFC 8032 Ed25519 keygen from that seed
//! message = ctx ‖ 0x00 ‖ body                     (ctx = SIG_CONTEXT)
//! ```
//!
//! # Why the pre-image carries the context (spec line 97)
//!
//! Plain Ed25519 has no context parameter, so the domain separator is folded
//! into the signed bytes: [`signing_message`] builds
//! `"antseal-manifest-v1" ‖ 0x00 ‖ body`. The `0x00` separator makes the
//! encoding unambiguous — the context is a fixed, `0x00`-free ASCII string,
//! so no other `(ctx′, body′)` pair can produce the same pre-image, and an
//! antseal signature can never be replayed as a signature over some other
//! protocol's message (nor the reverse).
//!
//! # Strict verification is a conformance requirement (spec line 97)
//!
//! Every verifier — CLI, WASM page, third party — must reach the same verdict
//! on the same frozen bundle, so [`verify`] implements RFC 8032
//! `verify_strict` semantics **plus an explicit pre-validation layer**
//! (decision D16, evidence in `docs/research/C11-signature-probe.md` §9). The
//! layer exists because the pinned crate cannot give us the distinction the
//! tamper matrix needs (spec line 168) and, in one case, does not perform the
//! check at all:
//!
//! | check | pinned `ed25519-dalek =3.0.0` | why we still pre-check |
//! | --- | --- | --- |
//! | `S < L` | rejected — but only *inside* `verify`/`verify_strict`, behind an opaque `signature::Error`; `Signature::from_bytes` is infallible by type | to emit [`CryptoError::NonCanonicalSignature`] distinctly from [`CryptoError::SignatureInvalid`] |
//! | canonical `R` encoding | rejected implicitly (`verify_strict` recompresses R and byte-compares) — again opaque | same, plus attribution |
//! | small-order `R`/`A` | rejected by `verify_strict` (`is_small_order`) | same |
//! | canonical `A` encoding | **NOT checked** — `VerifyingKey::from_bytes` is ZIP-215 and documents that "RFC 8032 / NIST point validation criteria are currently unsupported" (curve25519-dalek#626); probe bits 19/24 show a non-canonical `A` is accepted and keeps its byte identity | this is a real conformance gap, closed here |
//!
//! ## The two error classes
//!
//! - [`CryptoError::NonCanonicalSignature`] — the *encoding* is not a
//!   well-formed, canonical Ed25519 signature/key under RFC 8032 (mauled
//!   `S ≥ L`, non-canonical or off-curve `R`/`A`, small-order `R`/`A`,
//!   wrong length). Ed25519 is malleable and only EUF-CMA, not SUF-CMA:
//!   without these rejections a third party could re-encode someone else's
//!   valid signature and produce a *different* byte string that still
//!   verifies. Since `anchor_digest` covers the signatures, that would let an
//!   observer mint a fresh, differently-anchored copy of a work.
//! - [`CryptoError::SignatureInvalid`] — the encoding is impeccable but the
//!   signature does not verify over these bytes under this key (wrong key,
//!   wrong body, wrong context, forgery attempt).
//!
//! ## Canonical point encodings without decompressing by hand
//!
//! [`point_encoding_is_canonical`] implements the "decompress → recompress →
//! byte-compare" rule *arithmetically*, which is exactly equivalent and needs
//! no curve library: a 32-byte compressed Edwards point is `LE(y) ‖ sign(x)`
//! (sign in the top bit of the last byte), and recompression emits `y mod p`
//! with the low bit of the recovered `x`. So the byte-compare can only fail
//! when
//!
//! 1. the encoded `y ≥ p` (`y mod p` differs from what was written), or
//! 2. the sign bit is set while `x = 0` — recompression would emit sign 0.
//!    On Ed25519, `x = 0 ⟺ y² = 1 ⟺ y ∈ {1, p−1}` (substituting `x = 0`
//!    into `−x² + y² = 1 + d·x²y²`, and conversely because `d ≠ −1`).
//!
//! Both are checked below. Whether the point is *on the curve* at all is then
//! settled by dalek's decompression, and small-order membership by its
//! `is_small_order` test — applied to `R` as well as to `A`, by wrapping the
//! `R` bytes in a `VerifyingKey`. That is not a key: `VerifyingKey` is simply
//! the crate's only public wrapper around a validated, decompressed Edwards
//! point, and reusing it keeps a single decompression implementation for both
//! group elements.

use ed25519_dalek::{Signature as DalekSignature, Signer as _, SigningKey, VerifyingKey};

use super::SIG_CONTEXT;
use super::error::{CryptoError, SigAlg};
use super::hkdf::derive_sig_ed25519_seed;
use super::material::{MasterSecretRef, Seed32};

/// Byte length of an Ed25519 public key (F's schema, registry §4: 32 B).
pub const PUBLIC_KEY_LEN: usize = 32;

/// Byte length of an Ed25519 signature (F's schema, registry §4: 64 B).
pub const SIGNATURE_LEN: usize = 64;

/// The separator between the context and the body in the signed pre-image
/// (spec line 97: `ctx ‖ 0x00 ‖ body`).
///
/// Written in decimal deliberately: hex-form `u8` constants in `0x00..=0x06`
/// are reserved to the hash domain-tag registry ([`super::domain`]), and this
/// zero byte is a signature-pre-image separator, not a domain tag — the two
/// namespaces never meet (C1's grep-enforced convention).
pub const CONTEXT_SEPARATOR: u8 = 0;

/// Order `L` of the Ed25519 basepoint, little-endian
/// (RFC 8032 §5.1: `L = 2^252 + 27742317777372353535851937790883648493`).
/// The canonical-`S` bound: RFC 8032 requires `0 ≤ S < L`.
const L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Field modulus `p = 2^255 − 19`, little-endian (RFC 8032 §5.1). The
/// canonical-`y` bound for a compressed point encoding.
const P_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// The two `y` values with `x = 0` (module docs), little-endian: `y = 1` (the
/// identity) and `y = p − 1` (the order-2 point).
const Y_ONE_LE: [u8; 32] = {
    let mut y = [0u8; 32];
    y[0] = 1;
    y
};
const Y_P_MINUS_ONE_LE: [u8; 32] = {
    let mut y = P_LE;
    y[0] = 0xec;
    y
};

/// Shorthand for this module's algorithm tag in error payloads.
const ALG: SigAlg = SigAlg::Ed25519;

/// An Ed25519 public key as carried in the manifest body's `pubkeys` map
/// (spec line 98) — **public** wire bytes, plain value semantics.
///
/// Construction is deliberately infallible: validity is a *verification-time*
/// property ([`verify`] runs the canonicality and small-order checks), so a
/// decoded manifest can be inspected and rendered before any verdict exists,
/// and a malformed key surfaces as a signature verdict rather than as a parse
/// surprise.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519PublicKey([u8; PUBLIC_KEY_LEN]);

/// An Ed25519 signature as carried in the manifest envelope's `signatures`
/// map (spec line 97) — **public** wire bytes, plain value semantics.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519Signature([u8; SIGNATURE_LEN]);

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
            /// Defense in depth: F's strict decode layer already enforces the
            /// exact bstr length, so a wrong length should be unreachable
            /// here. When it does happen it is reported as
            /// [`CryptoError::NonCanonicalSignature`] — a byte string of the
            /// wrong length is not a canonical encoding of anything — rather
            /// than by widening C4's frozen taxonomy with a length variant no
            /// tamper-matrix row would reach.
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
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                // Public wire value: hex rendering is fine and useful for
                // verifier diagnostics (nothing secret to redact).
                f.write_str(concat!(stringify!($name), "("))?;
                for byte in &self.0 {
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

wire_value!(Ed25519PublicKey, PUBLIC_KEY_LEN);
wire_value!(Ed25519Signature, SIGNATURE_LEN);

impl Ed25519Signature {
    /// The `R` half (bytes 0..32) — a compressed Edwards point.
    #[must_use]
    pub fn r_bytes(&self) -> &[u8; 32] {
        let (r, _) = self.0.split_at(32);
        r.try_into().expect("a 64-byte signature splits into 32+32")
    }

    /// The `S` half (bytes 32..64) — a scalar, canonical iff `S < L`.
    #[must_use]
    pub fn s_bytes(&self) -> &[u8; 32] {
        let (_, s) = self.0.split_at(32);
        s.try_into().expect("a 64-byte signature splits into 32+32")
    }
}

/// The signed pre-image `ctx ‖ 0x00 ‖ body` (spec line 97). Public so F's
/// schema docs, the golden vectors, and third-party verifiers can pin the
/// exact construction.
#[must_use]
pub fn signing_message(body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIG_CONTEXT.len() + 1 + body.len());
    message.extend_from_slice(SIG_CONTEXT);
    message.push(CONTEXT_SEPARATOR);
    message.extend_from_slice(body);
    message
}

/// Build the signing key from `W`. The derived [`Seed32`] wipes when this
/// function returns (`ZeroizeOnDrop`), and the returned `SigningKey` — which
/// holds dalek's own copy of the seed — wipes on *its* drop (the crate's
/// `zeroize` feature, enabled in the workspace pin).
fn signing_key(w: MasterSecretRef<'_>) -> SigningKey {
    let seed: Seed32 = derive_sig_ed25519_seed(w);
    SigningKey::from_bytes(seed.as_bytes())
}

/// The author's Ed25519 public key for this work, `A` (spec line 97). Keys
/// are per-work by construction: the seed derives from that work's `W`.
#[must_use]
pub fn public_key(w: MasterSecretRef<'_>) -> Ed25519PublicKey {
    Ed25519PublicKey(signing_key(w).verifying_key().to_bytes())
}

/// Sign an explicit message. Private: every public entry point signs the
/// context-prefixed pre-image, so no caller can accidentally produce a
/// context-free signature. Tests use it to build exactly that negative case.
fn sign_message(w: MasterSecretRef<'_>, message: &[u8]) -> Ed25519Signature {
    Ed25519Signature(signing_key(w).sign(message).to_bytes())
}

/// Sign the manifest body bytes: RFC 8032 Ed25519 over
/// `ctx ‖ 0x00 ‖ body` (spec line 97).
///
/// Deterministic by construction (RFC 8032 derives the nonce from the key and
/// the message), so no RNG is involved and C16's golden vectors pin exact
/// signature bytes.
#[must_use]
pub fn sign(w: MasterSecretRef<'_>, body: &[u8]) -> Ed25519Signature {
    sign_message(w, &signing_message(body))
}

/// Little-endian comparison `a < b` over equal-length byte scalars.
fn lt_le(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// RFC 8032's canonical-scalar rule for the `S` half: `S < L`.
///
/// Public so C15's reject-vector suite and third-party verifiers can pin the
/// exact bound this implementation applies.
#[must_use]
pub fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    lt_le(s, &L_LE)
}

/// Canonicality of a compressed Edwards point encoding — the arithmetic
/// equivalent of decompress → recompress → byte-compare (module docs).
///
/// Says nothing about whether the point is on the curve or small-order; those
/// are separate checks in [`verify`].
#[must_use]
pub fn point_encoding_is_canonical(bytes: &[u8; 32]) -> bool {
    let mut y = *bytes;
    let sign_bit_set = y[31] & 0x80 != 0;
    y[31] &= 0x7f;

    // 1. y must be reduced mod p.
    if !lt_le(&y, &P_LE) {
        return false;
    }
    // 2. "negative zero": sign bit set on one of the two points with x = 0.
    if sign_bit_set && (y == Y_ONE_LE || y == Y_P_MINUS_ONE_LE) {
        return false;
    }
    true
}

/// Pre-validate a compressed group element (`A` or `R`): canonical encoding,
/// on the curve, and not small-order. Every failure is
/// [`CryptoError::NonCanonicalSignature`] — a malformed group element is an
/// encoding fault, never "the signature was wrong".
fn prevalidate_point(bytes: &[u8; 32]) -> Result<VerifyingKey, CryptoError> {
    let non_canonical = CryptoError::NonCanonicalSignature { alg: ALG };
    if !point_encoding_is_canonical(bytes) {
        return Err(non_canonical);
    }
    // Decompression settles on-curve membership (dalek returns Err on a
    // non-square); ZIP-215 means it does NOT re-check the encoding, which is
    // why the canonicality test above runs first.
    let point = VerifyingKey::from_bytes(bytes).map_err(|_| non_canonical)?;
    if point.is_weak() {
        // Small order: with a small-order A almost every message "verifies";
        // a small-order R is the classic malleability handle. RFC 8032 strict
        // verification rejects both.
        return Err(non_canonical);
    }
    Ok(point)
}

/// Strictly verify a signature over an explicit message. Private for the same
/// reason as [`sign_message`]: the public surface always binds the context.
fn verify_message(
    pk: &Ed25519PublicKey,
    message: &[u8],
    sig: &Ed25519Signature,
) -> Result<(), CryptoError> {
    // Pre-validation layer (D16) — every branch below is an *encoding*
    // rejection, reported distinctly from a verification failure.
    let verifying_key = prevalidate_point(&pk.0)?;
    prevalidate_point(sig.r_bytes())?;
    if !scalar_is_canonical(sig.s_bytes()) {
        return Err(CryptoError::NonCanonicalSignature { alg: ALG });
    }

    // RFC 8032 strict verification (cofactorless, canonical-R byte compare,
    // small-order rejection). Reaching this point means the encoding is
    // canonical, so an error here is genuinely "this signature does not
    // verify over these bytes".
    let dalek_sig = DalekSignature::from_bytes(&sig.0);
    verifying_key
        .verify_strict(message, &dalek_sig)
        .map_err(|_| CryptoError::SignatureInvalid { alg: ALG })
}

/// Strictly verify an author signature over the manifest body bytes
/// (spec line 97): pre-validation layer, then RFC 8032 `verify_strict` over
/// `ctx ‖ 0x00 ‖ body`.
///
/// # Errors
///
/// - [`CryptoError::NonCanonicalSignature`] — non-canonical `S ≥ L`,
///   non-canonical/off-curve/small-order `R` or `A` (module docs).
/// - [`CryptoError::SignatureInvalid`] — canonical encoding that does not
///   verify: wrong key, wrong body, or a signature made under a different
///   context.
pub fn verify(
    pk: &Ed25519PublicKey,
    body: &[u8],
    sig: &Ed25519Signature,
) -> Result<(), CryptoError> {
    verify_message(pk, &signing_message(body), sig)
}

/// Context-explicit signing for the **C15 reject-vector suite** — available
/// only under `cfg(test)` / the `test-util` feature, never in a production
/// build (the [`crate::crypto::unit_aead::mis_encrypt`] precedent).
///
/// The public [`sign`] deliberately admits no context parameter: every
/// signature this crate can produce binds [`SIG_CONTEXT`]. Authoring the
/// *negative* vectors — a signature that is perfectly valid under some other
/// context, or one made with no context prefix at all — therefore needs an
/// explicit escape hatch, and it lives here so no production path can reach
/// it.
#[cfg(any(test, feature = "test-vectors"))]
pub mod test_signing {
    use super::{CONTEXT_SEPARATOR, Ed25519Signature, MasterSecretRef, sign_message};

    /// Sign `ctx ‖ 0x00 ‖ body` under an **explicit** context. With
    /// `ctx = SIG_CONTEXT` this is byte-identical to [`super::sign`]; with
    /// any other value it produces the wrong-ctx reject vectors of
    /// MVP-SPEC.md line 97.
    #[must_use]
    pub fn sign_with_context(w: MasterSecretRef<'_>, ctx: &[u8], body: &[u8]) -> Ed25519Signature {
        let mut message = Vec::with_capacity(ctx.len() + 1 + body.len());
        message.extend_from_slice(ctx);
        message.push(CONTEXT_SEPARATOR);
        message.extend_from_slice(body);
        sign_message(w, &message)
    }

    /// Sign `message` with **no context construction at all** — the
    /// "signature made without the prefix" reject vector (spec line 97).
    #[must_use]
    pub fn sign_raw_message(w: MasterSecretRef<'_>, message: &[u8]) -> Ed25519Signature {
        sign_message(w, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::ZeroizeOnDrop;

    /// Fixed, public, NON-SECRET fixture `W` (project rule 6) — the same seed
    /// `testdata/vectors/v1/hkdf/hkdf-labels.json` derives from.
    const TEST_W: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    const OTHER_W: [u8; 32] = [0xEEu8; 32];

    /// Stand-in for F's canonical CBOR body bytes.
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

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "hex must be even-length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn unhex32(s: &str) -> [u8; 32] {
        unhex(s).try_into().expect("32-byte hex")
    }

    fn unhex64(s: &str) -> [u8; 64] {
        unhex(s).try_into().expect("64-byte hex")
    }

    /// `s + L` over little-endian 32-byte scalars, no reduction: for a
    /// canonical `s < L` the sum stays below `2^253`, so it fits in 32 bytes
    /// and is exactly the classic RFC 8032 "S out of range" maul — the same
    /// value mod L, a non-canonical encoding (C11 probe bits 16/21).
    fn add_l(s: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(s[i]) + u16::from(L_LE[i]) + carry;
            out[i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0, "canonical s + L must fit in 32 bytes");
        out
    }

    /// The constants are anchored to their RFC 8032 §5.1 *definitions*, not
    /// merely transcribed: `L = 2^252 + 27742317777372353535851937790883648493`
    /// and `p = 2^255 − 19`.
    #[test]
    fn curve_constants_match_their_rfc_definitions() {
        // L: the low 128 bits are the decimal addend; bit 252 is the 2^252
        // term (byte 31 = 1 << (252 − 248) = 0x10); nothing else is set.
        const ADDEND: u128 = 27_742_317_777_372_353_535_851_937_790_883_648_493;
        assert_eq!(L_LE[..16], ADDEND.to_le_bytes());
        assert_eq!(L_LE[16..31], [0u8; 15]);
        assert_eq!(L_LE[31], 1 << 4);

        // p: p + 19 == 2^255.
        let mut sum = P_LE;
        let mut carry = 19u16;
        for byte in &mut sum {
            let v = u16::from(*byte) + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0);
        let mut two_pow_255 = [0u8; 32];
        two_pow_255[31] = 0x80;
        assert_eq!(sum, two_pow_255);

        // The two x = 0 points.
        assert_eq!(Y_ONE_LE[0], 1);
        assert_eq!(Y_ONE_LE[1..], [0u8; 31]);
        let mut p_minus_one = P_LE;
        p_minus_one[0] -= 1;
        assert_eq!(Y_P_MINUS_ONE_LE, p_minus_one);
    }

    /// C12 accept: the pre-image is exactly `ctx ‖ 0x00 ‖ body`, with the
    /// frozen context bytes pinned.
    #[test]
    fn signing_message_is_the_frozen_prefix_construction() {
        assert_eq!(SIG_CONTEXT, b"antseal-manifest-v1");
        assert_eq!(SIG_CONTEXT.len(), 19);
        assert!(
            !SIG_CONTEXT.contains(&CONTEXT_SEPARATOR),
            "a 0x00 inside ctx would break the unambiguous split"
        );

        let message = signing_message(BODY);
        assert_eq!(&message[..19], SIG_CONTEXT);
        assert_eq!(message[19], 0x00);
        assert_eq!(&message[20..], BODY);
        assert_eq!(message.len(), 19 + 1 + BODY.len());
        // Empty body: the pre-image is still the prefix (a body is never
        // empty in practice; the construction must not special-case it).
        assert_eq!(signing_message(b"").len(), 20);
    }

    /// C12 accept: round-trip — a fixed test `W` yields a deterministic
    /// signature over a fixed body, and it verifies. The key/signature bytes
    /// are pinned so any change to the derivation, the pre-image, or the
    /// crate's arithmetic is a loud failure (C16 will lift these into
    /// `testdata/vectors/`).
    #[test]
    fn round_trip_is_deterministic_and_pinned() {
        let pk = public_key(w());
        let sig = sign(w(), BODY);

        assert_eq!(
            hex(pk.as_bytes()),
            "eee291b6c3994696f393226b02934c86ec161d1e5b0bd964e5ab7a72b85cc023"
        );
        assert_eq!(
            hex(sig.as_bytes()),
            "da5e0a7d5348bc11e752db8ac4cda9e0f6f0299765dd12edd8854f786cc4869e\
             e1b05e01ab65d2828c511089471f9269cefb2906e5ae07c1ae03c5b662814805"
        );

        assert_eq!(verify(&pk, BODY, &sig), Ok(()));

        // RFC 8032 determinism: signing twice yields identical bytes.
        assert_eq!(sign(w(), BODY), sig);
        assert_eq!(public_key(w()), pk);
    }

    /// C12 accept: context binding. A signature over `body` fails against the
    /// same body under any different context, and a signature made *without*
    /// the prefix fails through the public API.
    #[test]
    fn context_binding() {
        let pk = public_key(w());
        let sig = sign(w(), BODY);

        // Same body, different ctx (same length, and a longer one).
        for wrong_ctx in [&b"antseal-manifest-v2"[..], b"antseal-manifest-v10"] {
            let mut message = Vec::new();
            message.extend_from_slice(wrong_ctx);
            message.push(CONTEXT_SEPARATOR);
            message.extend_from_slice(BODY);
            assert_eq!(
                verify_message(&pk, &message, &sig).expect_err("must fail"),
                CryptoError::SignatureInvalid {
                    alg: SigAlg::Ed25519
                }
            );
        }

        // A signature made without the prefix does not verify as one made
        // with it.
        let unprefixed = sign_message(w(), BODY);
        assert_eq!(
            verify(&pk, BODY, &unprefixed).expect_err("must fail"),
            CryptoError::SignatureInvalid {
                alg: SigAlg::Ed25519
            }
        );
        // …and vice versa: the prefixed signature is not a valid signature
        // over the bare body.
        assert_eq!(
            verify_message(&pk, BODY, &sig).expect_err("must fail"),
            CryptoError::SignatureInvalid {
                alg: SigAlg::Ed25519
            }
        );

        // Separator matters: ctx ‖ body without the 0x00 is a different
        // pre-image.
        let mut no_separator = SIG_CONTEXT.to_vec();
        no_separator.extend_from_slice(BODY);
        assert_eq!(
            verify_message(&pk, &no_separator, &sig).expect_err("must fail"),
            CryptoError::SignatureInvalid {
                alg: SigAlg::Ed25519
            }
        );
    }

    /// C12 accept: `S ≥ L` mauled signature → `NonCanonicalSignature`, over
    /// several values straddling `L` (C15 will commit these as vectors).
    /// The maul is the *same signature mod L*, i.e. it would verify under a
    /// non-strict implementation — which is precisely the malleability the
    /// spec's strict rule exists to kill.
    #[test]
    fn s_out_of_range_is_non_canonical() {
        let pk = public_key(w());
        let sig = sign(w(), BODY);

        // s + L (canonical value, non-canonical encoding).
        let mut mauled = *sig.as_bytes();
        mauled[32..].copy_from_slice(&add_l(sig.s_bytes()));
        let mauled = Ed25519Signature::from_bytes(mauled);
        assert!(!scalar_is_canonical(mauled.s_bytes()));
        assert_eq!(
            verify(&pk, BODY, &mauled).expect_err("must fail"),
            CryptoError::NonCanonicalSignature {
                alg: SigAlg::Ed25519
            }
        );

        // Values straddling L: L − 1 (canonical), L, L + 1, and all-ones.
        let mut l_minus_one = L_LE;
        l_minus_one[0] -= 1;
        assert!(scalar_is_canonical(&l_minus_one));
        assert!(!scalar_is_canonical(&L_LE), "S == L is out of range");
        let mut l_plus_one = L_LE;
        l_plus_one[0] += 1;
        assert!(!scalar_is_canonical(&l_plus_one));
        assert!(!scalar_is_canonical(&[0xFFu8; 32]));
        assert!(scalar_is_canonical(&[0u8; 32]), "S == 0 is in range");

        for s in [L_LE, l_plus_one, [0xFFu8; 32]] {
            let mut bytes = *sig.as_bytes();
            bytes[32..].copy_from_slice(&s);
            assert_eq!(
                verify(&pk, BODY, &Ed25519Signature::from_bytes(bytes)).expect_err("must fail"),
                CryptoError::NonCanonicalSignature {
                    alg: SigAlg::Ed25519
                }
            );
        }
    }

    /// C12 accept: small-order `R` and small-order `A` → `NonCanonicalSignature`.
    #[test]
    fn small_order_points_are_non_canonical() {
        let pk = public_key(w());
        let sig = sign(w(), BODY);

        // The identity point (order 1) is the simplest small-order element.
        let identity = Y_ONE_LE;
        assert!(
            point_encoding_is_canonical(&identity),
            "canonically encoded"
        );

        // Small-order R, with S = 0 so the rejection is attributable to R.
        let mut small_r = [0u8; 64];
        small_r[..32].copy_from_slice(&identity);
        assert_eq!(
            verify(&pk, BODY, &Ed25519Signature::from_bytes(small_r)).expect_err("must fail"),
            CryptoError::NonCanonicalSignature {
                alg: SigAlg::Ed25519
            }
        );

        // Small-order A (the classic "verifies almost every message" key).
        let weak_pk = Ed25519PublicKey::from_bytes(identity);
        assert_eq!(
            verify(&weak_pk, BODY, &sig).expect_err("must fail"),
            CryptoError::NonCanonicalSignature {
                alg: SigAlg::Ed25519
            }
        );
        // Ground truth: dalek agrees these are small-order, and disagrees
        // about the honest key.
        assert!(
            VerifyingKey::from_bytes(&identity)
                .expect("identity decompresses")
                .is_weak()
        );
        assert!(
            !VerifyingKey::from_bytes(pk.as_bytes())
                .expect("honest key decompresses")
                .is_weak()
        );
        // The order-2 point y = p − 1 is small-order too.
        let order_two = Y_P_MINUS_ONE_LE;
        assert_eq!(
            verify(&Ed25519PublicKey::from_bytes(order_two), BODY, &sig).expect_err("must fail"),
            CryptoError::NonCanonicalSignature {
                alg: SigAlg::Ed25519
            }
        );
    }

    /// C12 accept (the D16 gap): non-canonical point *encodings* in `A` and
    /// `R` → `NonCanonicalSignature`. This is the check dalek does not
    /// perform on `A` at all (ZIP-215, probe bits 19/24) — asserted here, so
    /// a future pin bump that changed the crate's behavior would surface.
    #[test]
    fn non_canonical_point_encodings_are_rejected() {
        let pk = public_key(w());
        let sig = sign(w(), BODY);

        // y = p (≡ 0 mod p) — the classic non-canonical y encoding.
        let y_equals_p = P_LE;
        assert!(!point_encoding_is_canonical(&y_equals_p));
        // Dalek ACCEPTS it and keeps its byte identity: the gap we close.
        let accepted_by_dalek = VerifyingKey::from_bytes(&y_equals_p).expect("ZIP-215 accepts");
        assert_eq!(accepted_by_dalek.to_bytes(), y_equals_p);

        // …and "negative zero": sign bit set on a point with x = 0.
        let mut negative_zero_identity = Y_ONE_LE;
        negative_zero_identity[31] |= 0x80;
        let mut negative_zero_order_two = Y_P_MINUS_ONE_LE;
        negative_zero_order_two[31] |= 0x80;
        assert!(!point_encoding_is_canonical(&negative_zero_identity));
        assert!(!point_encoding_is_canonical(&negative_zero_order_two));

        // y > p as well (p + 1 … 2^255 − 1 are all non-canonical).
        let mut y_above_p = P_LE;
        y_above_p[0] = 0xff;
        assert!(!point_encoding_is_canonical(&y_above_p));

        for bad in [
            y_equals_p,
            negative_zero_identity,
            negative_zero_order_two,
            y_above_p,
        ] {
            // As A…
            assert_eq!(
                verify(&Ed25519PublicKey::from_bytes(bad), BODY, &sig).expect_err("must fail"),
                CryptoError::NonCanonicalSignature {
                    alg: SigAlg::Ed25519
                }
            );
            // …and as R.
            let mut bytes = *sig.as_bytes();
            bytes[..32].copy_from_slice(&bad);
            assert_eq!(
                verify(&pk, BODY, &Ed25519Signature::from_bytes(bytes)).expect_err("must fail"),
                CryptoError::NonCanonicalSignature {
                    alg: SigAlg::Ed25519
                }
            );
        }

        // An off-curve R/A (canonical encoding, no square root) is an
        // encoding fault too, not a "wrong signature".
        let mut off_curve = [0u8; 32];
        off_curve[0] = 2; // y = 2 is not on the curve
        assert!(point_encoding_is_canonical(&off_curve));
        assert!(VerifyingKey::from_bytes(&off_curve).is_err());
        assert_eq!(
            verify(&Ed25519PublicKey::from_bytes(off_curve), BODY, &sig).expect_err("must fail"),
            CryptoError::NonCanonicalSignature {
                alg: SigAlg::Ed25519
            }
        );
    }

    /// C12 accept: a valid-form signature by the WRONG key →
    /// `SignatureInvalid`, and the two variants are distinct. This is the
    /// pair the tamper matrix (spec line 168) needs to tell apart.
    #[test]
    fn wrong_key_is_invalid_not_non_canonical() {
        let pk = public_key(w());
        let sig_by_other = sign(other_w(), BODY);

        // Impeccable encoding…
        assert!(point_encoding_is_canonical(sig_by_other.r_bytes()));
        assert!(scalar_is_canonical(sig_by_other.s_bytes()));
        // …wrong signer.
        let invalid = verify(&pk, BODY, &sig_by_other).expect_err("must fail");
        assert_eq!(
            invalid,
            CryptoError::SignatureInvalid {
                alg: SigAlg::Ed25519
            }
        );

        // Right key, wrong body — also "invalid", not "non-canonical".
        let sig = sign(w(), BODY);
        let mut other_body = BODY.to_vec();
        other_body[0] ^= 0x01;
        assert_eq!(
            verify(&pk, &other_body, &sig).expect_err("must fail"),
            CryptoError::SignatureInvalid {
                alg: SigAlg::Ed25519
            }
        );

        // The two classes are distinct variants with distinct stable codes.
        let non_canonical = CryptoError::NonCanonicalSignature {
            alg: SigAlg::Ed25519,
        };
        assert_ne!(
            core::mem::discriminant(&invalid),
            core::mem::discriminant(&non_canonical)
        );
        assert_eq!(invalid.code(), "crypto-signature-invalid-ed25519");
        assert_eq!(
            non_canonical.code(),
            "crypto-non-canonical-signature-ed25519"
        );
    }

    /// C12 accept: RFC 8032 §7.1 known-answer vectors. Two legs:
    ///
    /// 1. **Verbatim** — the RFC's own (sk, pk, msg, sig) triples must
    ///    reproduce and verify through this module's strict verifier, proving
    ///    the primitive underneath is RFC 8032 Ed25519 (values transcribed
    ///    from rfc-editor.org/rfc/rfc8032.txt §7.1; the seeds also appear in
    ///    the pinned crate's own `tests/x25519.rs`).
    /// 2. **Adapted** — the same RFC seeds run through antseal's prefix
    ///    construction, with the resulting signatures pinned, so the
    ///    adaptation itself is a known answer and cannot drift.
    #[test]
    fn rfc8032_known_answer_vectors() {
        struct Kat {
            secret: &'static str,
            public: &'static str,
            message: &'static str,
            signature: &'static str,
            /// Antseal-adapted answer: the same key's signature over
            /// `ctx ‖ 0x00 ‖ message` (deterministic, so it is a known
            /// answer once pinned).
            adapted: &'static str,
        }
        // RFC 8032 §7.1 TEST 1 / TEST 2 / TEST 3.
        let kats = [
            Kat {
                secret: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                message: "",
                signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015\
                            55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                adapted: "63942efce50ea79ea97400917c40e059a5f6c396cdb2ac0bb3377064ba737169\
                          c65dec1f83059facad8948fe5dbbeaa682163b40806a39830cabbfead4474007",
            },
            Kat {
                secret: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                message: "72",
                signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69d\
                            a085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
                adapted: "c121e6ec7db2636e08bf31f3b5688f6e8f1f74f626dbd5e337652b89087b65e8\
                          9d8242864d232145b05f49ab1df6667ff45037aa071e821d01beece96f044c0f",
            },
            Kat {
                secret: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                public: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                message: "af82",
                signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3a\
                            c18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
                adapted: "de813b028b3d3bead8a258aae3cc5b717864befdd2c86d634dccb11a7627e4c3\
                          db9f3c42b3dc2071b8eee2156f9e3a55c2bdb99151e88fd55b6128af3ce48309",
            },
        ];

        for kat in &kats {
            let seed = unhex32(kat.secret);
            let expected_pk = unhex32(kat.public);
            let message = unhex(kat.message);
            let signature = Ed25519Signature::from_bytes(unhex64(kat.signature));

            // Leg 1: key derivation and strict verification match the RFC.
            let key = SigningKey::from_bytes(&seed);
            assert_eq!(key.verifying_key().to_bytes(), expected_pk);
            let pk = Ed25519PublicKey::from_bytes(expected_pk);
            assert_eq!(
                verify_message(&pk, &message, &signature),
                Ok(()),
                "RFC 8032 vector must verify strictly"
            );
            // The RFC's own signatures are canonical, as strictness requires.
            assert!(scalar_is_canonical(signature.s_bytes()));
            assert!(point_encoding_is_canonical(signature.r_bytes()));
            assert!(point_encoding_is_canonical(pk.as_bytes()));

            // Leg 2: the same key under antseal's prefix construction. The
            // RFC signature must NOT verify over the prefixed pre-image
            // (the adaptation really changes the signed bytes).
            let mut prefixed = SIG_CONTEXT.to_vec();
            prefixed.push(CONTEXT_SEPARATOR);
            prefixed.extend_from_slice(&message);
            assert_eq!(
                verify_message(&pk, &prefixed, &signature).expect_err("must fail"),
                CryptoError::SignatureInvalid {
                    alg: SigAlg::Ed25519
                }
            );
            let adapted = Ed25519Signature(key.sign(&prefixed).to_bytes());
            assert_eq!(verify_message(&pk, &prefixed, &adapted), Ok(()));
            assert_eq!(hex(adapted.as_bytes()), kat.adapted);
        }
    }

    /// C12 accept: the derived seed is zeroized. `Seed32` wipes on drop
    /// (C5's material type) and so does the crate's `SigningKey`
    /// (`zeroize` feature, enabled by the workspace pin) — both asserted at
    /// compile time so a pin bump that dropped the feature fails to build.
    #[test]
    fn seed_material_zeroizes_on_drop() {
        const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        const _: () = {
            assert_zeroize_on_drop::<Seed32>();
            assert_zeroize_on_drop::<SigningKey>();
        };

        // The HKDF-derived seed really is the key material (and, being a
        // `Seed32`, it is wiped when `signing_key` returns).
        let seed = derive_sig_ed25519_seed(w());
        assert_eq!(
            SigningKey::from_bytes(seed.as_bytes())
                .verifying_key()
                .to_bytes(),
            *public_key(w()).as_bytes()
        );
        // Public API never hands out the seed: only the public key and
        // signatures leave this module.
        let mut wiped = derive_sig_ed25519_seed(w());
        zeroize::Zeroize::zeroize(&mut wiped);
        assert_eq!(wiped.as_bytes(), &[0u8; 32]);
    }

    /// Wire values: exact lengths, hex `Debug`, and the length-checked slice
    /// constructors (defensive parsing — wrong lengths reject, never panic).
    #[test]
    fn wire_value_lengths_and_slice_constructors() {
        assert_eq!(PUBLIC_KEY_LEN, 32);
        assert_eq!(SIGNATURE_LEN, 64);
        assert_eq!(Ed25519PublicKey::LEN, PUBLIC_KEY_LEN);
        assert_eq!(Ed25519Signature::LEN, SIGNATURE_LEN);

        let pk = public_key(w());
        let sig = sign(w(), BODY);
        assert_eq!(
            Ed25519PublicKey::try_from_slice(pk.as_bytes()).expect("exact length"),
            pk
        );
        assert_eq!(
            Ed25519Signature::try_from_slice(sig.as_bytes()).expect("exact length"),
            sig
        );
        for bad_len in [0usize, 31, 33, 63, 65, 4096] {
            let bytes = vec![0u8; bad_len];
            if bad_len != 32 {
                assert_eq!(
                    Ed25519PublicKey::try_from_slice(&bytes).expect_err("must reject"),
                    CryptoError::NonCanonicalSignature {
                        alg: SigAlg::Ed25519
                    }
                );
            }
            if bad_len != 64 {
                assert_eq!(
                    Ed25519Signature::try_from_slice(&bytes).expect_err("must reject"),
                    CryptoError::NonCanonicalSignature {
                        alg: SigAlg::Ed25519
                    }
                );
            }
        }

        // R/S split and hex Debug.
        assert_eq!(sig.r_bytes(), &sig.as_bytes()[..32]);
        assert_eq!(sig.s_bytes(), &sig.as_bytes()[32..]);
        assert!(format!("{pk:?}").contains(&hex(pk.as_bytes())));
        assert!(format!("{sig:?}").starts_with("Ed25519Signature("));
    }

    /// Defensive parsing: an all-zero signature, an all-0xFF signature, and a
    /// signature whose halves are swapped reject cleanly (no panic, correct
    /// class).
    #[test]
    fn adversarial_signature_bytes_reject_cleanly() {
        let pk = public_key(w());
        let sig = sign(w(), BODY);

        // All-zero: R = y 0 (a valid, small-order point encoding: y = 0 is
        // on the curve and has order 4), S = 0 (canonical) ⇒ non-canonical
        // by the small-order rule.
        assert_eq!(
            verify(&pk, BODY, &Ed25519Signature::from_bytes([0u8; 64])).expect_err("must fail"),
            CryptoError::NonCanonicalSignature {
                alg: SigAlg::Ed25519
            }
        );
        // All-0xFF: y ≥ p and S ≥ L.
        assert_eq!(
            verify(&pk, BODY, &Ed25519Signature::from_bytes([0xFFu8; 64])).expect_err("must fail"),
            CryptoError::NonCanonicalSignature {
                alg: SigAlg::Ed25519
            }
        );
        // Swapped halves: whatever the classification, it must fail and not
        // panic.
        let mut swapped = [0u8; 64];
        swapped[..32].copy_from_slice(sig.s_bytes());
        swapped[32..].copy_from_slice(sig.r_bytes());
        assert!(verify(&pk, BODY, &Ed25519Signature::from_bytes(swapped)).is_err());
    }
}
