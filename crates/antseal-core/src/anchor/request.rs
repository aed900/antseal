//! The DER `TimeStampReq` constructor (task **A4**; decision
//! [D59](../../../docs/decisions/D59-request-nonce-persistence.md)).
//!
//! ```text
//! TimeStampReq ::= SEQUENCE {
//!     version         INTEGER { v1(1) },
//!     messageImprint  MessageImprint,
//!     reqPolicy       TSAPolicyId              OPTIONAL,
//!     nonce           INTEGER                  OPTIONAL,
//!     certReq         BOOLEAN            DEFAULT FALSE,
//!     extensions      [0] IMPLICIT Extensions  OPTIONAL }
//! ```
//!
//! antseal emits exactly one shape: `version 1`, a SHA-256 `messageImprint`
//! over `anchor_digest`, an 8-byte `nonce`, `certReq TRUE`, and **neither**
//! `reqPolicy` nor `extensions`. `reqPolicy` would pin a TSA to one policy
//! OID and A20 needs whatever policy the endpoint issues under; `extensions`
//! has nothing to carry.
//!
//! # Why this lives in `antseal-core` and takes the nonce as a parameter
//!
//! [`build_timestamp_req`] reads no clock, no socket and no RNG: it is a pure
//! function of two byte arrays, which is what makes it golden-vectorable and
//! what keeps it inside the crate the `core-dep-graph` lane scans for exactly
//! those three things. **Nonce generation is `antseal-anchor`'s**
//! (`antseal_anchor::nonce`, D59 §4) — the OS CSPRNG lives on the network
//! side, and the constraint that binds here is the opposite one: no RNG may
//! enter `antseal-core`.
//!
//! # `certReq = true`
//!
//! RFC 3161 §2.4.1: when `certReq` is TRUE the TSA "SHALL" include its
//! signing certificate in the `SignedData` `certificates` field. That is the
//! chain A8 verifies against and the bundle embeds as intermediates, so a
//! request without it produces a token antseal can parse and cannot validate.
//! It is not configurable.
//!
//! # The nonce is exactly 8 bytes, and the width is a permanent cost
//!
//! `tasks/A.md` A4 originally said "≥ 64 bits". D59 corrected it to exactly
//! 8 bytes and the signature enforces that with an array rather than a slice:
//! a `&[u8]` parameter re-admits the open-ended floor the correction removed,
//! and the value is echoed into the signed `TSTInfo` of every token a bundle
//! then carries forever. It is also the interoperable width — openssl's own
//! default is 8 bytes, which is what the project's default TSAs see from the
//! rest of the world (measured, D59 Evidence 1).
//!
//! **The 16-byte analogy to `unit_salt`/`path_salt`/`file_salt` does not
//! apply**: those are secret and hiding-critical (MVP-SPEC.md line 121); this
//! one is published in every bundle.
//!
//! # The DER INTEGER trap, and where the two spellings must not be confused
//!
//! The nonce is carried as an ASN.1 `INTEGER`, which is **signed**. Eight
//! drawn bytes are an unsigned magnitude, so the canonical DER encoding is
//! not the draw:
//!
//! - a draw whose high bit is set gets a `0x00` sign octet prepended, giving
//!   **nine** content octets (real capture: `D60-tsa-dfn-req.tsq` carries
//!   `02 09 00 d9 10 79 b3 fa 3d b7 b9`);
//! - redundant leading zero octets are stripped, so a draw of
//!   `00 00 12 …` is **six** content octets, and an all-zero draw is the
//!   single octet `00`.
//!
//! Two spellings therefore exist for one value, and D59 §4 rules which is
//! which: the vault's `request_nonce` record is **the 8 drawn bytes**, while
//! A10's capture-time comparison against the TSA's echo is over the *decoded
//! content octets*. [`canonical_request_nonce`] is that second spelling,
//! exposed so A10 compares against the same encoding this module emitted
//! rather than re-deriving it and getting the sign octet wrong.

use super::alg;

// The oracle below is the only consumer of `der`'s encoder in this module;
// everything on the production path writes tag/length octets directly.
#[cfg(test)]
use {
    super::rfc3161::MessageImprint,
    der::asn1::{OctetString, Uint},
    der::{Encode as _, Sequence},
    x509_cert::spki::AlgorithmIdentifierOwned,
};

/// The width of a TSA request nonce, in bytes — **exactly** this, never a
/// floor (D59 §4; the correction to `tasks/A.md` A4 of 2026-08-02).
pub const TSA_REQUEST_NONCE_LEN: usize = 8;

/// `TimeStampReq.version` — the only value RFC 3161 defines.
const TIME_STAMP_REQ_V1: u8 = 1;

// ─── DER literals ───────────────────────────────────────────────────────────
//
// The encoder below writes tag/length octets directly rather than routing
// through `der`'s `Encode`, and the reason is the signature: A4's `Do` is
// `-> Vec<u8>`, and every path through this function is total. There is no
// input for which a `TimeStampReq` of this shape fails to encode — the whole
// structure is 62..=70 bytes, so every length is short-form — and a fallible
// signature would either carry an error variant no caller can trigger or
// invite an `unwrap` in the one crate that must not have one.
//
// The cost of hand-writing it is that DER-correctness is now this module's to
// prove rather than `der`'s to provide, and it is proven three ways in
// `tests`: byte-equality against four real OpenSSL-generated `.tsq` captures
// that nine live TSAs accepted, a differential against `der`'s own derived
// encoder for the identical structure, and a decode round-trip.

/// Universal, primitive, INTEGER.
const TAG_INTEGER: u8 = 0x02;
/// Universal, primitive, BOOLEAN.
const TAG_BOOLEAN: u8 = 0x01;
/// Universal, primitive, OCTET STRING.
const TAG_OCTET_STRING: u8 = 0x04;
/// Universal, primitive, OBJECT IDENTIFIER.
const TAG_OID: u8 = 0x06;
/// Universal, primitive, NULL.
const TAG_NULL: u8 = 0x05;
/// Universal, constructed, SEQUENCE.
const TAG_SEQUENCE: u8 = 0x30;
/// X.690 §11.1: DER encodes TRUE as all-ones, never as any other non-zero.
const DER_TRUE: u8 = 0xFF;

/// Build a DER `TimeStampReq` over `anchor_digest` with `nonce`.
///
/// `anchor_digest` is SHA-256 of the full manifest bytes (F7) and goes into
/// `messageImprint` verbatim. `nonce` is the 8 bytes drawn by
/// `antseal_anchor::nonce::draw_request_nonce`; it is encoded as a canonical
/// DER INTEGER (see the module docs for the sign-octet rule).
///
/// The result is strict DER: definite short-form lengths throughout, minimal
/// INTEGER encodings, and no OPTIONAL field encoded at its DEFAULT.
///
/// # Determinism
///
/// Byte-exact for a given `(anchor_digest, nonce)` pair, on every target
/// including `wasm32-unknown-unknown`. Nothing here allocates from a hash
/// map, reads an environment variable, or branches on a platform width.
#[must_use]
pub fn build_timestamp_req(
    anchor_digest: &[u8; 32],
    nonce: &[u8; TSA_REQUEST_NONCE_LEN],
) -> Vec<u8> {
    let imprint = message_imprint_der(anchor_digest);
    let nonce_content = canonical_request_nonce(nonce);

    let mut body = Vec::with_capacity(
        // version(3) + imprint + nonce header(2) + nonce + certReq(3)
        3 + imprint.len() + 2 + nonce_content.len() + 3,
    );
    // version INTEGER 1
    body.extend_from_slice(&[TAG_INTEGER, 1, TIME_STAMP_REQ_V1]);
    // messageImprint
    body.extend_from_slice(&imprint);
    // nonce INTEGER — `canonical_request_nonce` never yields more than 9
    // octets, so the length is always short-form.
    body.push(TAG_INTEGER);
    body.push(short_form_len(nonce_content.len()));
    body.extend_from_slice(&nonce_content);
    // certReq BOOLEAN TRUE (never DEFAULT FALSE, so it is always encoded)
    body.extend_from_slice(&[TAG_BOOLEAN, 1, DER_TRUE]);

    wrap(TAG_SEQUENCE, &body)
}

/// The **content octets** of the DER INTEGER this module encodes `nonce` as.
///
/// This is the spelling A10 compares the TSA's echoed `TSTInfo.nonce` against
/// (D59 §4): the raw 8-byte draw is what the vault stores, and comparing the
/// draw against a decoded INTEGER would report a mismatch for every nonce
/// whose high bit is set or whose leading octet is zero.
#[must_use]
pub fn canonical_request_nonce(nonce: &[u8; TSA_REQUEST_NONCE_LEN]) -> Vec<u8> {
    let magnitude = nonce
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&nonce[..0], |first| &nonce[first..]);

    match magnitude.first() {
        // An all-zero draw is the integer zero, whose minimal encoding is the
        // single octet 0x00 — never the empty string.
        None => vec![0x00],
        // High bit set: the magnitude would read as a negative number, so a
        // 0x00 sign octet is prepended (X.690 §8.3.2).
        Some(first) if first & 0x80 != 0 => {
            let mut out = Vec::with_capacity(magnitude.len() + 1);
            out.push(0x00);
            out.extend_from_slice(magnitude);
            out
        }
        Some(_) => magnitude.to_vec(),
    }
}

/// `MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }`, SHA-256.
///
/// The algorithm identifier carries an explicit NULL parameter. RFC 4055 §2.1
/// prefers it absent for SHA-2 while RFC 3161's own examples and every
/// OpenSSL-generated request carry it; all nine TSAs captured at A25 were
/// asked with the NULL present and answered, so the interoperable spelling is
/// the measured one.
fn message_imprint_der(anchor_digest: &[u8; 32]) -> Vec<u8> {
    let oid = alg::SHA_256.as_bytes();

    let mut algorithm = Vec::with_capacity(oid.len() + 4);
    algorithm.push(TAG_OID);
    algorithm.push(short_form_len(oid.len()));
    algorithm.extend_from_slice(oid);
    algorithm.extend_from_slice(&[TAG_NULL, 0]);

    let mut imprint = wrap(TAG_SEQUENCE, &algorithm);
    imprint.push(TAG_OCTET_STRING);
    imprint.push(short_form_len(anchor_digest.len()));
    imprint.extend_from_slice(anchor_digest);

    wrap(TAG_SEQUENCE, &imprint)
}

/// `tag ‖ short-form length ‖ content`.
fn wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 2);
    out.push(tag);
    out.push(short_form_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// A DER short-form length octet.
///
/// Saturating rather than panicking or truncating. Every caller in this
/// module is structurally bounded well under 128 — the whole request is at
/// most 68 bytes — and `tests::every_length_in_the_request_is_short_form`
/// asserts that, so the saturation is unreachable by construction. It is
/// written this way because the alternative at an unreachable site is a
/// `debug_assert` that does nothing in release or a panic in a crate that
/// must not have one; a saturated length produces a *malformed request the
/// TSA rejects*, which is a loud failure and not a silent truncation.
const fn short_form_len(len: usize) -> u8 {
    if len < 0x80 { len as u8 } else { 0x7F }
}

// ─── the test oracle ────────────────────────────────────────────────────────

/// The same structure, as `der` would encode it.
///
/// **Deliberately private and test-only.** A public encodable `TimeStampReq`
/// would let a caller build a request with `certReq` unset or a `reqPolicy`
/// pinned — producing a token A8 cannot validate, or no token at all — which
/// is exactly the freedom [`build_timestamp_req`] exists to remove. Its role
/// here is to be an *independent* encoder of the same ASN.1, so
/// `tests::the_hand_written_encoder_agrees_with_der` fails if either one
/// drifts.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
struct TimeStampReqOracle {
    version: u8,
    message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    nonce: Option<Uint>,
    cert_req: bool,
}

#[cfg(test)]
impl TimeStampReqOracle {
    fn new(anchor_digest: &[u8; 32], nonce: &[u8; TSA_REQUEST_NONCE_LEN]) -> Self {
        Self {
            version: TIME_STAMP_REQ_V1,
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifierOwned {
                    oid: alg::SHA_256,
                    parameters: Some(der::Any::null()),
                },
                hashed_message: OctetString::new(&anchor_digest[..])
                    .expect("32 bytes is a valid OCTET STRING"),
            },
            nonce: Some(Uint::new(nonce).expect("8 bytes is a valid unsigned INTEGER")),
            cert_req: true,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_der()
            .expect("a fixed-shape 68-byte structure encodes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode as _;

    /// The four real requests OpenSSL produced during the A25 bootstrap
    /// capture, each of which a live TSA answered with a granted token. They
    /// are the strongest available oracle for "strict DER, and the shape the
    /// world accepts", because they were not written by this project.
    const DFN_REQ: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/D60-tsa-dfn-req.tsq");
    const FREETSA_REQ: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/D60-tsa-freetsa-req.tsq");
    const APPLE_REQ: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/D60-tsa-apple-req.tsq");
    const D59_REQ: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/freetsa-D59-req.tsq");
    const DIGEST_A: &[u8; 32] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/digest-A.bin");

    /// A4's Accept row 1, against material this project did not author.
    ///
    /// Each capture is `SEQUENCE { INTEGER 1, MessageImprint, INTEGER nonce,
    /// BOOLEAN TRUE }`, so the nonce is recoverable from the capture itself
    /// and the vector is "fixed digest + fixed nonce -> byte-exact request"
    /// with the expected bytes supplied by OpenSSL rather than by us.
    ///
    /// **`D60-tsa-dfn-req.tsq` is the sign-octet case** (`02 09 00 d9 …`) and
    /// is what makes this set non-vacuous: an encoder that wrote the eight
    /// drawn bytes verbatim reproduces the other three and fails this one.
    #[test]
    fn real_openssl_requests_are_reproduced_byte_for_byte() {
        let cases: &[(&str, &[u8])] = &[
            ("dfn (sign octet: 9 content octets)", DFN_REQ),
            ("freetsa", FREETSA_REQ),
            ("apple", APPLE_REQ),
            ("freetsa/D59", D59_REQ),
        ];

        let mut saw_sign_octet = false;
        for (name, capture) in cases {
            let (digest, nonce) = dissect(capture);
            assert_eq!(&digest, DIGEST_A, "{name}: the capture is over digest A");
            let built = build_timestamp_req(&digest, &nonce);
            assert_eq!(
                built.as_slice(),
                *capture,
                "{name}: built request differs from the real capture"
            );
            if canonical_request_nonce(&nonce).len() == TSA_REQUEST_NONCE_LEN + 1 {
                saw_sign_octet = true;
            }
        }
        assert!(
            saw_sign_octet,
            "the fixture set must contain a high-bit nonce, or the sign-octet \
             rule is untested and an encoder that ignores it passes"
        );
    }

    /// Recover `(digest, nonce)` from a captured request, so the vector's
    /// inputs come from the fixture rather than from a transcription.
    fn dissect(capture: &[u8]) -> ([u8; 32], [u8; TSA_REQUEST_NONCE_LEN]) {
        // SEQUENCE header (2) + version (3) + imprint header (2) +
        // algorithm (15) + OCTET STRING header (2) = 24
        let digest_at = 24;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&capture[digest_at..digest_at + 32]);

        let nonce_tag = digest_at + 32;
        assert_eq!(capture[nonce_tag], TAG_INTEGER, "nonce tag");
        let len = usize::from(capture[nonce_tag + 1]);
        let content = &capture[nonce_tag + 2..nonce_tag + 2 + len];
        // Undo the canonical encoding to recover the 8 drawn bytes: strip a
        // sign octet, then left-pad with zeros.
        let magnitude = if content.len() == TSA_REQUEST_NONCE_LEN + 1 && content[0] == 0 {
            &content[1..]
        } else {
            content
        };
        let mut nonce = [0u8; TSA_REQUEST_NONCE_LEN];
        nonce[TSA_REQUEST_NONCE_LEN - magnitude.len()..].copy_from_slice(magnitude);
        (digest, nonce)
    }

    /// The differential the hand-written encoder is checked against: `der`'s
    /// own derive, over the same ASN.1, reusing A5's `MessageImprint`.
    ///
    /// Both encoders would have to break in the same direction for this to
    /// pass while the output is wrong, and the fixture test above pins the
    /// absolute bytes independently of both.
    #[test]
    fn the_hand_written_encoder_agrees_with_der() {
        for nonce in nonce_corpus() {
            let ours = build_timestamp_req(DIGEST_A, &nonce);
            let theirs = TimeStampReqOracle::new(DIGEST_A, &nonce).to_bytes();
            assert_eq!(ours, theirs, "nonce {nonce:02x?}");
        }
    }

    /// The corner cases of the INTEGER encoding, named so a reader can see
    /// that each is covered rather than trusting a random sweep.
    fn nonce_corpus() -> Vec<[u8; TSA_REQUEST_NONCE_LEN]> {
        vec![
            // High bit clear — 8 content octets, the common case.
            [0x4c, 0xc6, 0x41, 0x96, 0x5b, 0x77, 0xb3, 0xcb],
            // High bit set — 9 content octets with the 0x00 sign prefix.
            [0xd9, 0x10, 0x79, 0xb3, 0xfa, 0x3d, 0xb7, 0xb9],
            // Exactly on the boundary.
            [0x80, 0, 0, 0, 0, 0, 0, 0],
            [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            // One redundant leading zero — 7 content octets.
            [0x00, 0x91, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            // Leading zero followed by a high-bit octet: strip, then prefix
            // again. Net length is 8, which an encoder that did only one of
            // the two steps also produces — so the *bytes* matter here.
            [0x00, 0xff, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            // Seven redundant zeros — 1 content octet.
            [0, 0, 0, 0, 0, 0, 0, 0x2a],
            // All zeros — the integer 0, encoded as the single octet 0x00.
            [0; TSA_REQUEST_NONCE_LEN],
            // All ones.
            [0xff; TSA_REQUEST_NONCE_LEN],
        ]
    }

    /// The canonical-nonce spelling A10 compares against, stated as bytes.
    #[test]
    fn the_canonical_nonce_is_the_der_integer_content_not_the_draw() {
        let cases: &[([u8; TSA_REQUEST_NONCE_LEN], &[u8])] = &[
            (
                [0x4c, 0xc6, 0x41, 0x96, 0x5b, 0x77, 0xb3, 0xcb],
                &[0x4c, 0xc6, 0x41, 0x96, 0x5b, 0x77, 0xb3, 0xcb],
            ),
            (
                [0xd9, 0x10, 0x79, 0xb3, 0xfa, 0x3d, 0xb7, 0xb9],
                &[0x00, 0xd9, 0x10, 0x79, 0xb3, 0xfa, 0x3d, 0xb7, 0xb9],
            ),
            ([0x00, 0x00, 0x00, 0, 0, 0, 0, 0x2a], &[0x2a]),
            ([0; TSA_REQUEST_NONCE_LEN], &[0x00]),
            (
                [0x00, 0xff, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
                &[0x00, 0xff, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            ),
        ];
        for (draw, expected) in cases {
            assert_eq!(canonical_request_nonce(draw), *expected, "draw {draw:02x?}");
        }
    }

    /// The round-trip A4's Accept asks for: what we emit decodes back through
    /// the `der`/A5 types to the values that went in.
    #[test]
    fn a_built_request_round_trips_through_the_der_types() {
        for nonce in nonce_corpus() {
            let bytes = build_timestamp_req(DIGEST_A, &nonce);
            let decoded = TimeStampReqOracle::from_der(&bytes)
                .unwrap_or_else(|e| panic!("nonce {nonce:02x?} must decode: {e}"));
            assert_eq!(decoded.version, TIME_STAMP_REQ_V1);
            assert!(decoded.cert_req, "certReq must be TRUE");
            assert_eq!(decoded.message_imprint.hash_algorithm.oid, alg::SHA_256);
            assert_eq!(
                decoded.message_imprint.hashed_message.as_bytes(),
                &DIGEST_A[..]
            );
            let carried = decoded.nonce.expect("the nonce is always present");
            // Compared as the re-encoded INTEGER rather than as `Uint`'s
            // internal magnitude: `Uint::as_bytes` is `der`'s own normalised
            // spelling (it keeps a single `0x00` for zero and drops the sign
            // octet), and asserting on it would pin `der`'s representation
            // instead of our wire bytes.
            let content = canonical_request_nonce(&nonce);
            let mut expected = vec![TAG_INTEGER, short_form_len(content.len())];
            expected.extend_from_slice(&content);
            assert_eq!(
                carried.to_der().expect("re-encodes"),
                expected,
                "nonce {nonce:02x?}"
            );
        }
    }

    /// The precondition that makes [`short_form_len`]'s saturation
    /// unreachable. If a future edit adds `extensions` or a `reqPolicy` the
    /// request could cross 127 bytes, and this goes red before the silent
    /// truncation ships.
    #[test]
    fn every_length_in_the_request_is_short_form() {
        for nonce in nonce_corpus() {
            let bytes = build_timestamp_req(DIGEST_A, &nonce);
            // 2 (outer header) + 3 (version) + 51 (imprint) + 3 (certReq)
            // = 59, plus the nonce's 2 + 1..=9 content octets. The real
            // captures are 69 bytes (8-octet nonce) and 70 (the dfn sign
            // octet), both inside this range.
            assert!(
                (62..=70).contains(&bytes.len()),
                "unexpected request length {} for {nonce:02x?}",
                bytes.len()
            );
            // Walk the four length octets this structure has: the outer
            // SEQUENCE, the messageImprint SEQUENCE, its AlgorithmIdentifier
            // SEQUENCE, and the hashedMessage OCTET STRING.
            for at in [1usize, 6, 8, 23] {
                assert!(
                    bytes[at] < 0x80,
                    "length octet at {at} is long-form: {:#x}",
                    bytes[at]
                );
            }
        }
    }

    /// The OID bytes are consumed from `const-oid` by name (A30's containment
    /// rule), and this pins what that name resolves to. A `SHA_256` that
    /// silently became SHA-384 would otherwise produce requests every TSA
    /// answers about the wrong algorithm.
    #[test]
    fn the_message_imprint_algorithm_is_sha_256() {
        assert_eq!(
            alg::SHA_256.as_bytes(),
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            "id-sha256, 2.16.840.1.101.3.4.2.1"
        );
        let bytes = build_timestamp_req(DIGEST_A, &[1; TSA_REQUEST_NONCE_LEN]);
        assert_eq!(
            &bytes[5..24],
            &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20
            ],
            "messageImprint prologue: SEQUENCE, AlgorithmIdentifier(sha256, NULL), OCTET STRING(32)"
        );
    }

    /// Determinism, stated as a test rather than as a comment: the same
    /// inputs give the same bytes, and a one-bit change in either input
    /// changes them.
    #[test]
    fn the_encoding_is_deterministic_and_input_sensitive() {
        let nonce = [0x11; TSA_REQUEST_NONCE_LEN];
        let first = build_timestamp_req(DIGEST_A, &nonce);
        assert_eq!(first, build_timestamp_req(DIGEST_A, &nonce));

        let mut other_digest = *DIGEST_A;
        other_digest[31] ^= 0x01;
        assert_ne!(first, build_timestamp_req(&other_digest, &nonce));

        let mut other_nonce = nonce;
        other_nonce[7] ^= 0x01;
        assert_ne!(first, build_timestamp_req(DIGEST_A, &other_nonce));
    }
}
