//! The `.sealproof` nested decode pipeline (F9): [`SealProof`] composes the
//! **three strict layers** of registry §7.6.3 over one input buffer.
//!
//! ```text
//! layer 1   the whole file          BundleV1::decode          BundleError
//! layer 2   bundle key 1's bstr     Manifest::decode          ManifestError::Envelope
//! layer 3   the envelope's body     ManifestBodyV1::decode    ManifestError::Body
//! ```
//!
//! Each layer runs its own strict canonical-CBOR pass (spec line 73): an
//! embedded byte string is opaque payload to the pass that reads it, so the
//! inner bytes get their own walk rather than being re-interpreted mid-item.
//! That is also why verifiers never re-encode (spec line 74).
//!
//! # D78, expressed in the type system
//!
//! Layer 1's error type ([`BundleError`]) has **no arm that can carry a
//! [`ManifestError`]**, and layers 2–3's error type has no arm that can carry
//! a `BundleError`. The two only meet here, in [`SealProofError`], which
//! keeps them in separate variants and surfaces each inner code unchanged. So
//! "malformed bundle" and "malformed manifest inside a well-formed bundle"
//! are different values, different variants, and different code families — a
//! structural property rather than a convention, which is what D30's
//! permanent-families rule needs.
//!
//! # Zero-copy across the seam
//!
//! Layer 2 is handed a **sub-slice of the bundle input**, never a copy.
//! [`Manifest`]'s guarantee — that the bytes fed to `work_id` and to
//! signature verification are the *received* ones by construction — only
//! holds if the slice really is the bundle's own bytes; a decode-into-`Vec`
//! step would silently downgrade it to a convention. The same slice is the
//! `anchor_digest` pre-image (spec line 75), and
//! [`SealProof::anchor_digest_preimage`] returns it from the decoded object
//! rather than making the caller re-derive it.

use core::fmt;

use thiserror::Error;

use crate::manifest::{Layer, Manifest, ManifestError};

use super::error::BundleError;
use super::schema::BundleV1;

/// Which of the three strict decode layers a [`SealProofError`] came from
/// (registry §7.6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofLayer {
    /// Layer 1 — the `.sealproof`'s own bytes and bundle schema.
    Bundle,
    /// Layer 2 — the embedded manifest envelope `{body, signatures}`.
    ManifestEnvelope,
    /// Layer 3 — the manifest body inside that envelope.
    ManifestBody,
}

impl ProofLayer {
    /// Every layer, for exhaustive tests.
    pub const ALL: [Self; 3] = [Self::Bundle, Self::ManifestEnvelope, Self::ManifestBody];
}

impl fmt::Display for ProofLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bundle => "bundle",
            Self::ManifestEnvelope => "manifest envelope",
            Self::ManifestBody => "manifest body",
        })
    }
}

/// A failure anywhere in the three-layer pipeline.
///
/// `#[non_exhaustive]`, like every other error type in the crate. There are
/// exactly two arms and there will not be a third for a *layer*: layers 2 and
/// 3 are already distinguished inside [`ManifestError`], which owns that
/// split (F6).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SealProofError {
    /// Layer 1: the bundle's own bytes or schema (D78 — decided without ever
    /// opening the embedded manifest).
    #[error("{source}")]
    Bundle {
        /// The layer-1 rejection; its `bundle-*` (or delegated `cbor-*` /
        /// `content-*`) code is surfaced unchanged.
        #[from]
        #[source]
        source: BundleError,
    },

    /// Layers 2–3: the embedded manifest. The wrapped error already
    /// distinguishes envelope from body (F6), so this arm does not split
    /// further.
    #[error("{source}")]
    Manifest {
        /// The manifest-layer rejection; its `manifest-*` (or delegated
        /// `cbor-*`) code is surfaced unchanged.
        #[from]
        #[source]
        source: ManifestError,
    },
}

impl SealProofError {
    /// The stable machine-readable code — the **inner** error's, unchanged.
    ///
    /// Composition is not a rejection class: a failure keeps its owning
    /// domain's identity rather than acquiring a second one when it passes
    /// through the pipeline (the `ManifestError::Envelope` /
    /// `VerifyError::Codec` precedent). Which layer it happened in is
    /// available separately from [`Self::layer`].
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Bundle { source } => source.code(),
            Self::Manifest { source } => source.code(),
        }
    }

    /// Which of the three strict decode layers rejected (registry
    /// §7.6.3). Total: a [`Self::Bundle`] failure is layer 1 by
    /// construction, and a [`Self::Manifest`] failure carries its own
    /// layer ([`ManifestError::layer`]).
    ///
    /// Before D86 this returned `Option<ProofLayer>`, `None` for a
    /// manifest schema rejection — an asymmetry that made `null` mean
    /// "schema rejection *inside the manifest*" (D86 §2).
    #[must_use]
    pub const fn layer(&self) -> ProofLayer {
        match self {
            Self::Bundle { .. } => ProofLayer::Bundle,
            Self::Manifest { source } => match source.layer() {
                Layer::Envelope => ProofLayer::ManifestEnvelope,
                Layer::Body => ProofLayer::ManifestBody,
            },
        }
    }
}

/// A decoded `.sealproof`: the bundle **and** the manifest inside it, both
/// borrowing the one input buffer.
///
/// This is the API surface R's M3 bundle verifier consumes. Assembly and
/// verification logic stay out of this module: nothing here checks a
/// commitment, a signature, an anchor, or any rule that needs both sides
/// (MVP-SPEC.md line 121 — all of that is R's, tier `[R]`).
#[derive(Debug)]
pub struct SealProof<'b> {
    bundle: BundleV1<'b>,
    manifest: Manifest<'b>,
}

impl<'b> SealProof<'b> {
    /// Run all three strict layers over one input buffer.
    ///
    /// # Errors
    ///
    /// [`SealProofError::Bundle`] for a layer-1 failure and
    /// [`SealProofError::Manifest`] for a layer-2/3 one. The two can never be
    /// confused: they are different variants over different error types.
    pub fn decode(input: &'b [u8]) -> Result<Self, SealProofError> {
        // Layer 1. Nothing about the embedded manifest is consulted (D78).
        let bundle = BundleV1::decode(input)?;
        // Layers 2 and 3, over a sub-slice of `input` — not a copy.
        let manifest = Manifest::decode(bundle.manifest_bytes())?;
        Ok(Self { bundle, manifest })
    }

    /// The layer-1 bundle.
    #[must_use]
    pub const fn bundle(&self) -> &BundleV1<'b> {
        &self.bundle
    }

    /// The embedded manifest, decoded through layers 2 and 3.
    #[must_use]
    pub const fn manifest(&self) -> &Manifest<'b> {
        &self.manifest
    }

    /// The `anchor_digest` pre-image: the embedded manifest envelope bytes
    /// **exactly as received** (MVP-SPEC.md line 75).
    ///
    /// Taken from the decoded object rather than re-derived by the caller,
    /// and identical to [`BundleV1::manifest_bytes`] by construction — the
    /// assertion `Manifest::encoded_bytes() == BundleV1::manifest_bytes()` is
    /// what makes the zero-copy seam observable.
    #[must_use]
    pub const fn anchor_digest_preimage(&self) -> &'b [u8] {
        self.manifest.encoded_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::DecodeError;

    /// One exemplar per composition arm. The *codes* are the inner errors',
    /// already exemplified by their own domains' meta-tests, so this list
    /// checks delegation and layer attribution rather than distinctness.
    fn exemplars() -> Vec<(SealProofError, ProofLayer, &'static str)> {
        let cbor = DecodeError::NonShortestInt { position: 7 };
        vec![
            (
                SealProofError::Bundle {
                    source: BundleError::UnitRevealedTwice { unit_id: 3 },
                },
                ProofLayer::Bundle,
                "bundle-unit-revealed-twice",
            ),
            (
                SealProofError::Bundle {
                    source: BundleError::Cbor {
                        source: cbor.clone(),
                    },
                },
                ProofLayer::Bundle,
                "cbor-non-shortest-int",
            ),
            (
                SealProofError::Manifest {
                    source: ManifestError::Envelope {
                        source: cbor.clone(),
                    },
                },
                ProofLayer::ManifestEnvelope,
                "cbor-non-shortest-int",
            ),
            (
                SealProofError::Manifest {
                    source: ManifestError::Body { source: cbor },
                },
                ProofLayer::ManifestBody,
                "cbor-non-shortest-int",
            ),
            // A manifest **schema** rejection is layered too (D86): it names
            // its own map, and the map coarsens to a layer. `sig_policy` is
            // body key 6, so this is layer 3.
            (
                SealProofError::Manifest {
                    source: ManifestError::SigPolicyEmpty,
                },
                ProofLayer::ManifestBody,
                "manifest-sig-policy-empty",
            ),
            // The envelope's own schema rejections stay at layer 2, which is
            // what makes `manifest-unknown-key` there distinguishable from
            // the same code at the body (D86 §2).
            (
                SealProofError::Manifest {
                    source: ManifestError::UnknownKey {
                        map: crate::manifest::MapId::Envelope,
                        key: 24,
                    },
                },
                ProofLayer::ManifestEnvelope,
                "manifest-unknown-key",
            ),
            (
                SealProofError::Manifest {
                    source: ManifestError::UnknownKey {
                        map: crate::manifest::MapId::Body,
                        key: 24,
                    },
                },
                ProofLayer::ManifestBody,
                "manifest-unknown-key",
            ),
        ]
    }

    /// Codes delegate unchanged and layers attribute as documented.
    #[test]
    fn codes_delegate_and_layers_attribute() {
        for (err, layer, code) in exemplars() {
            assert_eq!(err.layer(), layer, "{err}");
            assert_eq!(err.code(), code, "{err}");
        }
        // All three layers are reachable.
        let reached: Vec<ProofLayer> = exemplars().iter().map(|(e, ..)| e.layer()).collect();
        for layer in ProofLayer::ALL {
            assert!(reached.contains(&layer), "{layer} unreachable");
        }
    }

    /// D86 §2, as a test: one code at two layers is two observables. Before
    /// D86 both of these reported no layer, so `envelope-unknown-key` could
    /// not prove it had hit the envelope.
    #[test]
    fn one_schema_code_at_two_layers_stays_two_observables() {
        let at_envelope = SealProofError::Manifest {
            source: ManifestError::UnknownKey {
                map: crate::manifest::MapId::Envelope,
                key: 24,
            },
        };
        let at_body = SealProofError::Manifest {
            source: ManifestError::UnknownKey {
                map: crate::manifest::MapId::Body,
                key: 24,
            },
        };
        assert_eq!(at_envelope.code(), at_body.code());
        assert_ne!(at_envelope.layer(), at_body.layer());
    }

    /// The same wrapped codec error at two different layers stays two
    /// distinguishable values, even though its code is identical — the F9
    /// "each reports its layer" requirement.
    #[test]
    fn identical_codes_at_different_layers_stay_distinguishable() {
        let cbor = DecodeError::NonShortestInt { position: 7 };
        let at_bundle = SealProofError::Bundle {
            source: BundleError::Cbor {
                source: cbor.clone(),
            },
        };
        let at_envelope = SealProofError::Manifest {
            source: ManifestError::Envelope {
                source: cbor.clone(),
            },
        };
        let at_body = SealProofError::Manifest {
            source: ManifestError::Body { source: cbor },
        };

        assert_eq!(at_bundle.code(), at_envelope.code());
        assert_eq!(at_envelope.code(), at_body.code());
        assert_ne!(at_bundle, at_envelope);
        assert_ne!(at_envelope, at_body);
        assert_ne!(at_bundle.layer(), at_envelope.layer());
        assert_ne!(at_envelope.layer(), at_body.layer());
    }

    /// `?` conversions exist for both inner types, so the pipeline reads as
    /// straight-line code without hand-written maps.
    #[test]
    fn from_conversions_target_the_right_arm() {
        let from_bundle: SealProofError = BundleError::UnitRevealedTwice { unit_id: 0 }.into();
        assert_eq!(from_bundle.layer(), ProofLayer::Bundle);
        let from_manifest: SealProofError = ManifestError::SigPolicyEmpty.into();
        assert!(matches!(from_manifest, SealProofError::Manifest { .. }));
    }
}
