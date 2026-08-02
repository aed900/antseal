//! The manifest envelope (F6): deterministic CBOR `{0: body, 1:
//! signatures}` where `body` is an **embedded byte string**
//! (MVP-SPEC.md lines 73–74).
//!
//! # Why the body is bytes and not a nested map
//!
//! Signatures and `work_id` are computed over *exactly the bytes the
//! envelope carried* — "verifiers never re-encode" (spec line 74). An
//! embedded `bstr` makes that literal: [`Manifest::body_bytes`] hands
//! back a sub-slice of the caller's input, zero-copy, so the bytes fed to
//! [`crate::manifest::work_id`] and to signature verification are the
//! received ones by construction rather than by convention. In a
//! production build there is also no path from a decoded body back to
//! bytes: [`ManifestBodyV1`] derives `Clone` only under the
//! dev-dependency-only `test-util` feature (a compile-time guard on the
//! type enforces the absence everywhere else) and
//! [`encode_body`](super::body::encode_body) consumes its argument, so in
//! every shipped verifier re-encoding a received body is a compile
//! error, not a code-review finding. Test builds re-open that path on
//! purpose: the F16 round-trip properties are claims *about the
//! encoder*, not verification paths (F41).
//!
//! # Two strict layers, two distinguishable error classes
//!
//! An embedded byte string is opaque payload to the pass that reads it,
//! so the inner bytes get their own strict pass. Both passes are the F3
//! layer, but their failures arrive as
//! [`ManifestError::Envelope`](super::ManifestError::Envelope) and
//! [`ManifestError::Body`](super::ManifestError::Body) respectively —
//! distinct variants over the same wrapped
//! [`DecodeError`](crate::codec::DecodeError), so a tamper row can name
//! which layer a mutation broke.
//!
//! # Envelope shape is frozen forever
//!
//! `{0: body, 1: signatures}` never gains a key (registry §1 rule 6):
//! version dispatch happens *after* the envelope opens, on the body's own
//! key 0. The envelope therefore reserves nothing, and any key besides
//! 0/1 is an unknown key — permanently.

use crate::codec::caps::MAX_MANIFEST_BYTES;
use crate::codec::{CanonicalDecoder, CappedArtifact, DecodeError, EncodeError, encode_item};

use super::body::ManifestBodyV1;
use super::error::ManifestError;
use super::registry::{KeyClass, MapId, key};

pub use super::sigmap::{SigAlgMap, SigMaterial};

/// Wrap a codec rejection as an envelope-layer failure (F6's outer layer).
const fn envelope_layer(source: DecodeError) -> ManifestError {
    ManifestError::Envelope { source }
}

/// A decoded manifest: the received bytes, the body bytes inside them,
/// the decoded body, and the signatures container.
///
/// Borrows the input for `'b`; nothing is copied out of it except the
/// body's decoded field values.
#[derive(Debug, PartialEq, Eq)]
pub struct Manifest<'b> {
    encoded: &'b [u8],
    body_bytes: &'b [u8],
    body: ManifestBodyV1,
    signatures: SigAlgMap,
}

impl<'b> Manifest<'b> {
    /// Strict-decode an envelope, then strict-decode the body from the
    /// embedded bytes.
    ///
    /// Both layers reject non-canonical input (spec line 73); the outer
    /// pass additionally rejects trailing bytes after the envelope, so
    /// [`Self::encoded_bytes`] is exactly the whole input.
    ///
    /// # The size cap runs first (F11 / decision D10 §5)
    ///
    /// `input.len() > MAX_MANIFEST_BYTES` is the **first statement**, before
    /// the decoder is constructed. Besides refusing an oversized manifest in
    /// O(1), it is what bounds the SHA-256 work behind `work_id` and
    /// `anchor_digest`, whose pre-images are exactly these bytes. The
    /// **body** needs no cap of its own: it is a `bstr` inside this envelope,
    /// so `len(body) < len(envelope) <= MAX_MANIFEST_BYTES` by construction.
    ///
    /// # Errors
    ///
    /// [`ManifestError::InputTooLarge`] for an over-cap input;
    /// [`ManifestError::Envelope`] / [`ManifestError::Body`] for
    /// canonicality failures at the respective layer, plus every
    /// `manifest-*` schema class.
    pub fn decode(input: &'b [u8]) -> Result<Self, ManifestError> {
        const MAP: MapId = MapId::Envelope;
        let len = input.len() as u64;
        if len > MAX_MANIFEST_BYTES {
            return Err(ManifestError::InputTooLarge {
                len,
                cap: MAX_MANIFEST_BYTES,
            });
        }
        let mut d = CanonicalDecoder::new(input);
        let mut reader = d.map().map_err(envelope_layer)?;

        let mut body_bytes: Option<&'b [u8]> = None;
        let mut signatures: Option<SigAlgMap> = None;

        while let Some(k) = reader.next_key(&mut d).map_err(envelope_layer)? {
            match MAP.classify(k) {
                KeyClass::Assigned => {}
                // The envelope reserves nothing (registry §1 rule 6), so
                // `classify` never returns Reserved here; the arm exists
                // for totality and stays correct if that ever changes.
                KeyClass::Reserved => return Err(ManifestError::ReservedKey { map: MAP, key: k }),
                KeyClass::Unknown => return Err(ManifestError::UnknownKey { map: MAP, key: k }),
            }
            match k {
                key::envelope::BODY => body_bytes = Some(d.bytes().map_err(envelope_layer)?),
                key::envelope::SIGNATURES => {
                    signatures = Some(SigAlgMap::decode(
                        &mut d,
                        SigMaterial::Signature,
                        envelope_layer,
                    )?);
                }
                other => {
                    return Err(ManifestError::UnknownKey {
                        map: MAP,
                        key: other,
                    });
                }
            }
        }
        d.finish().map_err(envelope_layer)?;

        let body_bytes = body_bytes.ok_or(ManifestError::MissingKey {
            map: MAP,
            key: key::envelope::BODY,
        })?;
        let signatures = signatures.ok_or(ManifestError::MissingKey {
            map: MAP,
            key: key::envelope::SIGNATURES,
        })?;
        let body = ManifestBodyV1::decode(body_bytes)?;

        Ok(Self {
            encoded: input,
            body_bytes,
            body,
            signatures,
        })
    }

    /// The **exact** bytes of the embedded `body` byte string, borrowed
    /// from the input — the pre-image of `work_id` and of every author
    /// signature (spec lines 74–75).
    #[must_use]
    pub const fn body_bytes(&self) -> &'b [u8] {
        self.body_bytes
    }

    /// The whole envelope as received — the pre-image of `anchor_digest`
    /// (spec line 75: anchoring the signature-bearing bytes binds the
    /// signatures into the timestamp).
    #[must_use]
    pub const fn encoded_bytes(&self) -> &'b [u8] {
        self.encoded
    }

    /// The decoded body. Lent, never surrendered: the caller cannot move
    /// it out, and outside `test-util` builds cannot clone it either
    /// ([`ManifestBodyV1`]'s gated derive and compile-time guard), which
    /// is what makes re-encoding a received body unreachable in
    /// production verifiers.
    ///
    /// The move half holds in **every** configuration:
    ///
    /// ```compile_fail,E0507
    /// use antseal_core::manifest::{Manifest, ManifestBodyV1};
    ///
    /// fn steal(manifest: &Manifest<'_>) -> ManifestBodyV1 {
    ///     // error[E0507]: cannot move out of a shared reference — the
    ///     // owned body `encode_body` would need never escapes.
    ///     *manifest.body()
    /// }
    /// ```
    #[must_use]
    pub const fn body(&self) -> &ManifestBodyV1 {
        &self.body
    }

    /// The signatures container — enumerable, so C14/R5 can compare the
    /// present set against `sig_policy` and hard-fail on a
    /// present-but-unlisted signature (spec line 97).
    #[must_use]
    pub const fn signatures(&self) -> &SigAlgMap {
        &self.signatures
    }
}

/// Encode an envelope around already-encoded body bytes.
///
/// The seal-side counterpart of [`Manifest::decode`], and deliberately
/// **not** "encode a body object": it takes the bytes, which is what
/// keeps the pipeline the spec's DAG (line 90) —
/// `encode_body` → `work_id` → sign → `encode_envelope` →
/// `anchor_digest` — with the signed bytes and the embedded bytes
/// necessarily identical.
///
/// # The aggregate size gate (F53)
///
/// This is where `MAX_MANIFEST_BYTES` is enforced on the seal side. It
/// cannot be enforced anywhere earlier: F41 gave every constructor the
/// D10 *count* caps, but the byte cap is a property of the encoding, and
/// the encoding exists only here. The body needs no separate gate — it is
/// the `bstr` this function embeds, so `len(body) < len(envelope)` and an
/// over-cap body cannot produce an in-cap envelope.
///
/// Position in the spec's DAG (line 90) matters: the refusal lands after
/// signing but **before** `anchor_digest`, anchoring, payment and upload,
/// so nothing is spent on bytes no verifier would accept.
///
/// # Errors
///
/// - [`EncodeError::TooLarge`] — the envelope exceeds
///   [`MAX_MANIFEST_BYTES`], reported with the decode path's own
///   `manifest-too-large` code.
/// - The three F2 caller-bug variants; none is reachable here (two
///   constant keys, one item per scope).
pub fn encode_envelope(body_bytes: &[u8], signatures: &SigAlgMap) -> Result<Vec<u8>, EncodeError> {
    let encoded = encode_item(|e| {
        e.map(|m| {
            m.entry(key::envelope::BODY, |e| e.bytes(body_bytes))?;
            m.entry(key::envelope::SIGNATURES, |e| {
                e.map(|sm| signatures.encode_into(sm))
            })
        })
    })?;
    CappedArtifact::ManifestEnvelope.gate(&encoded)?;
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::fixtures;

    /// **F53**: the encode-side aggregate size gate, at the boundary.
    ///
    /// The witness is a body whose only large field is `title`, which has
    /// no count cap and needs none (D10 §3) — so every *part* is legal and
    /// only the aggregate is not. That is the whole class F41 could not
    /// reach from a constructor.
    ///
    /// The boundary is hit exactly rather than approximately: for a title
    /// of 2^16 bytes or more the `tstr` head and the embedding `bstr` head
    /// are both five bytes, so envelope length is affine in title length
    /// and one probe encode fixes the offset. At-cap **encodes** and is
    /// exactly `MAX_MANIFEST_BYTES` long; one byte more is refused.
    ///
    /// Red before the gate landed: the cap+1 envelope encoded fine at
    /// 16 777 217 bytes. Planted-fault direction: delete the
    /// `CappedArtifact::ManifestEnvelope.gate` line and this goes red
    /// again, with that message.
    #[test]
    fn encode_refuses_an_envelope_one_byte_over_the_aggregate_cap() {
        use super::super::body::{ManifestBodyV1, encode_body};
        use crate::crypto::error::SigAlg;
        use crate::manifest::ManifestError;

        fn envelope_for_title(len: usize, signatures: &SigAlgMap) -> Result<Vec<u8>, EncodeError> {
            let body = ManifestBodyV1::new(
                "app".to_owned(),
                fixtures::seal_id(),
                "x".repeat(len),
                0,
                fixtures::hybrid_pubkeys(),
                vec![SigAlg::Ed25519, SigAlg::MlDsa65],
                vec![fixtures::binary_file(0)],
            )
            .expect("body is otherwise schema-valid");
            let body_bytes = encode_body(body).expect("body encodes");
            encode_envelope(&body_bytes, signatures)
        }

        let signatures = fixtures::hybrid_signatures();
        const PROBE: usize = 65_536;
        let probe_len = envelope_for_title(PROBE, &signatures)
            .expect("the probe envelope is far under the cap")
            .len() as u64;
        let at_cap_title = PROBE as u64 + (MAX_MANIFEST_BYTES - probe_len);

        let at_cap = envelope_for_title(at_cap_title as usize, &signatures)
            .expect("an envelope of exactly MAX_MANIFEST_BYTES is admitted");
        assert_eq!(at_cap.len() as u64, MAX_MANIFEST_BYTES);
        drop(at_cap);

        let err = envelope_for_title(at_cap_title as usize + 1, &signatures)
            .expect_err("one byte over the cap is refused");
        assert_eq!(
            err,
            EncodeError::TooLarge {
                artifact: CappedArtifact::ManifestEnvelope,
                len: MAX_MANIFEST_BYTES + 1,
                cap: MAX_MANIFEST_BYTES,
            }
        );

        // The code is the *decode* path's, taken from the decode path's own
        // variant rather than spelled again — so the two can never drift
        // and no code is minted (D30; the universe stays 194).
        assert_eq!(
            err.code(),
            Some(
                ManifestError::InputTooLarge {
                    len: MAX_MANIFEST_BYTES + 1,
                    cap: MAX_MANIFEST_BYTES,
                }
                .code()
            )
        );
    }

    /// F6 accept: the decoded `body_bytes()` is the wire bstr contents,
    /// and re-encoding the envelope from those bytes reproduces the input
    /// byte-for-byte.
    #[test]
    fn round_trip_is_byte_identical() {
        let sealed = fixtures::text_with_mirror_manifest();
        let manifest = Manifest::decode(&sealed.envelope).expect("fixture decodes");

        assert_eq!(manifest.body_bytes(), sealed.body.as_slice());
        assert_eq!(manifest.encoded_bytes(), sealed.envelope.as_slice());
        assert_eq!(manifest.body(), &fixtures::text_with_mirror_body());

        let re_encoded = encode_envelope(manifest.body_bytes(), manifest.signatures())
            .expect("re-encode from received bytes");
        assert_eq!(re_encoded, sealed.envelope);
    }

    /// The body slice really is a sub-slice of the input, not a copy —
    /// the zero-copy claim, checked by pointer containment.
    #[test]
    fn body_bytes_borrow_from_the_input() {
        let sealed = fixtures::binary_single_unit_manifest();
        let manifest = Manifest::decode(&sealed.envelope).expect("fixture decodes");
        let input = sealed.envelope.as_ptr_range();
        let body = manifest.body_bytes().as_ptr_range();
        assert!(input.start <= body.start && body.end <= input.end);
    }
}
