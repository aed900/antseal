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
//! received ones by construction rather than by convention. There is no
//! public path from a decoded body back to bytes: [`ManifestBodyV1`] is
//! not `Clone` and [`encode_body`](super::body::encode_body) consumes its
//! argument, so re-encoding is a borrow-checker error, not a code-review
//! finding.
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

use crate::codec::{CanonicalDecoder, DecodeError, EncodeError, encode_item};

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
    /// # Errors
    ///
    /// [`ManifestError::Envelope`] / [`ManifestError::Body`] for
    /// canonicality failures at the respective layer, plus every
    /// `manifest-*` schema class.
    pub fn decode(input: &'b [u8]) -> Result<Self, ManifestError> {
        const MAP: MapId = MapId::Envelope;
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
    /// or clone it, which is what makes re-encoding unreachable.
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
/// # Errors
///
/// [`EncodeError`] reports caller bugs the F2 layer detects; none is
/// reachable here (two constant keys, one item per scope).
pub fn encode_envelope(body_bytes: &[u8], signatures: &SigAlgMap) -> Result<Vec<u8>, EncodeError> {
    encode_item(|e| {
        e.map(|m| {
            m.entry(key::envelope::BODY, |e| e.bytes(body_bytes))?;
            m.entry(key::envelope::SIGNATURES, |e| {
                e.map(|sm| signatures.encode_into(sm))
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::fixtures;

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
