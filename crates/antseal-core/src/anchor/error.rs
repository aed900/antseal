//! The anchor-stage error taxonomy for RFC 3161 / RFC 5652 / X.509 artifacts
//! (A5, A8) — one distinct code per rejection class a mutation can be pinned
//! to (MVP-SPEC.md line 168).
//!
//! # The namespace, and why there is exactly one
//!
//! **`anchor-`, owner A, and nothing else** (decision D91 §6.1). `ots-` and
//! `tsa-` are closed as not-taken; `docs/testing/error-code-contract.md` §2's
//! rule that a domain never mints under another domain's prefix applies with
//! no exception here.
//!
//! D91 exists because that rule was, at the time it was written, enforced by
//! **nothing**: `error_universe::census` sorts an unrecognised code into its
//! `"(unprefixed)"` bucket and prints it, so a family invented under an
//! unregistered namespace passes every check in the tree. A sibling decision
//! specified sixteen codes that way with a fully green suite. Q77/A38 lands
//! the machine check; until it does, [`tests::every_code_is_under_the_anchor_prefix`]
//! and [`tests::codes_are_disjoint_from_the_committed_universe`] are this
//! module's own guard, and they are deliberately not the kind that can pass
//! vacuously — both assert a non-empty roster first.
//!
//! # Which codes were ruled elsewhere and must not be respelled
//!
//! Ten of the codes below are fixed by resolved decisions and are permanent
//! from the moment anything binds to them (error-code contract §3):
//!
//! | code | ruled by |
//! | --- | --- |
//! | `anchor-der-not-strict`, `anchor-der-malformed`, `anchor-der-nesting-depth` | D60 §7.3 |
//! | `anchor-chain-cert-count`, `anchor-chain-cert-size`, `anchor-signed-attr-count` | D60 §7.3 |
//! | `anchor-digest-alg-unsupported`, `anchor-signature-alg-unsupported` | D60 §7.3 |
//! | `anchor-tsa-imprint-mismatch` | D53 §8 row 2 (`MATRIX.json` binds it) |
//! | `anchor-tsa-nonce-mismatch` | D59 §5 (owner-backed) |
//!
//! The rest are minted here because A8's Accept row requires distinct errors
//! for outcomes no decision enumerated — a stripped content-type attribute, a
//! message-digest mismatch, an ESSCertID naming a different certificate, a
//! missing or non-critical EKU — and a rejection class with no code of its
//! own cannot be a tamper row. They follow D91 §7.3's advisory convention:
//! the segment after `anchor-` names the check.
//!
//! # Secret hygiene (project rule 6)
//!
//! Payloads are counts, byte lengths, closed enum discriminants and OIDs read
//! out of the artifact under test. A TSA token is public material by
//! construction — it is what the bundle publishes — but `anchor_digest`,
//! nonces and hash values are still never rendered: an error says *that* the
//! imprint mismatched, never what either side was.
//! [`tests::display_renders_metadata_only`] asserts it.

use core::fmt;

use const_oid::ObjectIdentifier;
use thiserror::Error;

/// Which parse produced a `der` failure. Diagnostic only — every value maps
/// through the same [`DerFault`] classification, so the site never changes a
/// code. It exists because "the token is not DER" and "an extension inside
/// the signer certificate is not DER" are the same verdict and very different
/// debugging sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DerSite {
    /// The outer `TimeStampResp` (RFC 3161 §2.4.2).
    Response,
    /// The `ContentInfo` / `SignedData` shell (RFC 5652 §5.1).
    SignedData,
    /// The encapsulated `TSTInfo` (RFC 3161 §2.4.2).
    TstInfo,
    /// A certificate out of the token's `certificates` bag.
    Certificate,
    /// The `signedAttrs` SET, or one attribute's value.
    SignedAttrs,
    /// A `SigningCertificate` / `SigningCertificateV2` attribute value
    /// (RFC 2634 §5.4 / RFC 5035 §4).
    EssCertId,
    /// A certificate extension's `extnValue`, re-parsed as its own document.
    Extension,
    /// A `SubjectPublicKeyInfo` body, re-parsed to read the key.
    PublicKey,
}

impl fmt::Display for DerSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Response => "TimeStampResp",
            Self::SignedData => "CMS SignedData",
            Self::TstInfo => "TSTInfo",
            Self::Certificate => "certificate",
            Self::SignedAttrs => "signedAttrs",
            Self::EssCertId => "ESSCertID",
            Self::Extension => "certificate extension",
            Self::PublicKey => "SubjectPublicKeyInfo",
        })
    }
}

/// The three DER outcome classes, per D60 §7.2.
///
/// [`DerFault::NotStrict`] is deliberately wider than "is BER". `der`'s
/// `ErrorKind::Length` carries both a non-minimal length (a strictness fault)
/// and a wrong-length-for-type such as a 2-octet BOOLEAN, and `der` gives no
/// way to separate them. Both are non-conforming encodings and both get this
/// class. The alternative — a hand-written minimal-length prescan — is the
/// stack-overflow hazard D60 §2.4 measured, and the tamper row this class
/// serves (`MATRIX.json` row `anchor-ber-not-der`) binds to fixtures rather
/// than to a claim of perfect classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DerFault {
    /// The input's encoding does not conform to DER.
    NotStrict,
    /// The input is not well-formed at all.
    Malformed,
    /// `der`'s depth guard fired: more than 63 nested constructions in one
    /// parse invocation.
    NestingDepth,
}

/// Where in the artifact an algorithm identifier was read. The discriminator
/// is diagnostic; both algorithm codes are single-valued because a tamper row
/// binds to "an unsupported digest appeared", not to which field carried it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgPosition {
    /// `SignedData.digestAlgorithms`.
    SignedDataDigests,
    /// `SignerInfo.digestAlgorithm`.
    SignerDigest,
    /// `SignerInfo.signatureAlgorithm`.
    SignerSignature,
    /// `TSTInfo.messageImprint.hashAlgorithm` — SHA-256 exactly (D60 §3.3).
    MessageImprint,
    /// `ESSCertIDv2.hashAlgorithm`.
    EssCertHash,
}

impl fmt::Display for AlgPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SignedDataDigests => "SignedData.digestAlgorithms",
            Self::SignerDigest => "SignerInfo.digestAlgorithm",
            Self::SignerSignature => "SignerInfo.signatureAlgorithm",
            Self::MessageImprint => "TSTInfo.messageImprint.hashAlgorithm",
            Self::EssCertHash => "ESSCertIDv2.hashAlgorithm",
        })
    }
}

/// A CMS signed attribute antseal names. Diagnostic discriminator on the two
/// structural attribute faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignedAttrId {
    /// `id-contentType` (1.2.840.113549.1.9.3).
    ContentType,
    /// `id-messageDigest` (1.2.840.113549.1.9.4).
    MessageDigest,
    /// `id-aa-signingCertificate` (1.2.840.113549.1.9.16.2.12).
    SigningCertificate,
    /// `id-aa-signingCertificateV2` (1.2.840.113549.1.9.16.2.47).
    SigningCertificateV2,
}

impl fmt::Display for SignedAttrId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ContentType => "content-type",
            Self::MessageDigest => "message-digest",
            Self::SigningCertificate => "signingCertificate",
            Self::SigningCertificateV2 => "signingCertificateV2",
        })
    }
}

/// Every way an RFC 3161 timestamp artifact can be refused before A9's path
/// validation runs — stages T1 and T2 of D53's per-artifact order.
///
/// Under F2/F3 each of these renders **that anchor** `invalid` and nothing
/// else: never the bundle, never the manifest verdict, never another anchor.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AnchorError {
    // ── A5: encoding ────────────────────────────────────────────────────
    /// The artifact's DER encoding was rejected.
    #[error("{site} is not valid DER ({fault:?})")]
    Der {
        /// Which parse failed.
        site: DerSite,
        /// Which of D60 §7.2's three classes it fell into.
        fault: DerFault,
    },

    // ── A5: the (b)-class limits (D60 §6) ───────────────────────────────
    /// More certificate material than [`super::caps::MAX_CHAIN_CERTS`].
    #[error("token offers {count} certificates for path building, limit {}", super::caps::MAX_CHAIN_CERTS)]
    ChainCertCount {
        /// How many were offered.
        count: usize,
    },
    /// A certificate out of a token exceeds
    /// [`super::caps::MAX_CHAIN_CERT_BYTES`].
    #[error("certificate is {bytes} B, limit {}", super::caps::MAX_CHAIN_CERT_BYTES)]
    ChainCertSize {
        /// The offending certificate's DER length.
        bytes: u64,
    },
    /// More signed attributes than [`super::caps::MAX_SIGNED_ATTRS`].
    #[error("signedAttrs carries {count} attributes, limit {}", super::caps::MAX_SIGNED_ATTRS)]
    SignedAttrCount {
        /// How many were present.
        count: usize,
    },

    // ── A5: the RFC 3161 response envelope ──────────────────────────────
    /// `PKIStatusInfo.status` is neither `granted` (0) nor `grantedWithMods`
    /// (1), so the response carries no usable token (RFC 3161 §2.4.2).
    #[error("PKIStatus is {status}, not granted(0) or grantedWithMods(1)")]
    StatusNotGranted {
        /// The status value as encoded.
        status: u32,
    },
    /// The status said granted but `timeStampToken` is absent.
    #[error("PKIStatus is granted but timeStampToken is absent")]
    TokenAbsent,

    // ── A8: CMS shape ───────────────────────────────────────────────────
    /// `ContentInfo.contentType` is not `id-signedData`.
    #[error("ContentInfo carries {oid}, not id-signedData")]
    NotSignedData {
        /// The content type actually present.
        oid: ObjectIdentifier,
    },
    /// `encapContentInfo.eContentType` is not `id-ct-TSTInfo`.
    #[error("eContentType is {oid}, not id-ct-TSTInfo")]
    NotTstInfo {
        /// The encapsulated content type actually present.
        oid: ObjectIdentifier,
    },
    /// The signature is detached: `eContent` is absent, so there is no
    /// `TSTInfo` to verify and nothing binds the token to a digest.
    #[error("eContent is absent (detached signature)")]
    EContentAbsent,
    /// `signerInfos` does not hold exactly one `SignerInfo`. RFC 3161 §2.4.2
    /// admits only one signer for a timestamp token, and accepting several
    /// would make "the signer certificate" ambiguous.
    #[error("signerInfos holds {count} entries, expected exactly 1")]
    SignerCount {
        /// How many were present.
        count: usize,
    },
    /// `signedAttrs` is absent. RFC 5652 §5.3 makes it optional in general;
    /// RFC 3161 §2.4.2 does not, because the content-type and message-digest
    /// attributes are what bind the signature to the `TSTInfo`.
    #[error("signedAttrs is absent")]
    SignedAttrsAbsent,
    /// An attribute type appears more than once (RFC 5652 §5.3).
    #[error("signedAttrs carries {attr} more than once")]
    DuplicateSignedAttr {
        /// Which attribute.
        attr: SignedAttrId,
    },
    /// An attribute carries other than exactly one value.
    #[error("the {attr} attribute does not carry exactly one value")]
    SignedAttrNotSingleValued {
        /// Which attribute.
        attr: SignedAttrId,
    },
    /// The mandatory `content-type` signed attribute is missing.
    #[error("the content-type signed attribute is missing")]
    ContentTypeAttrMissing,
    /// The `content-type` attribute does not equal `eContentType`.
    #[error("the content-type attribute does not match eContentType")]
    ContentTypeAttrMismatch,
    /// The mandatory `message-digest` signed attribute is missing.
    #[error("the message-digest signed attribute is missing")]
    MessageDigestAttrMissing,
    /// The `message-digest` attribute does not equal the digest of
    /// `eContent`, so the signed attributes do not commit to the `TSTInfo`.
    #[error("the message-digest attribute does not match the eContent digest")]
    MessageDigestAttrMismatch,
    /// The signature over the DER `SET OF` re-encoding of `signedAttrs` does
    /// not verify under the signer certificate's public key.
    ///
    /// Distinct from A9's `anchor-chain-signature-invalid`, which is a
    /// certificate-link signature: this one says the *token* is not signed by
    /// the certificate it names.
    #[error("the CMS signature over signedAttrs does not verify")]
    SignatureInvalid,

    // ── A8: signer identification and its binding ───────────────────────
    /// `SignerInfo.sid` uses `subjectKeyIdentifier`. All nine live TSAs
    /// surveyed at D60 use `issuerAndSerialNumber`, so this branch has no
    /// real fixture, and an algorithm branch whose only fixture is one
    /// antseal generated for itself is a defect that cannot be detected until
    /// the day it matters (D60 §4's standard, applied here).
    #[error("SignerInfo.sid uses subjectKeyIdentifier, which is unsupported")]
    SignerIdUnsupported,
    /// No certificate in the token's bag matches `SignerInfo.sid`.
    #[error("no embedded certificate matches SignerInfo.sid")]
    SignerCertNotFound,
    /// Neither `SigningCertificate` nor `SigningCertificateV2` is present.
    ///
    /// One of them is required because `SignerInfo.sid` is **not covered by
    /// the signature** (RFC 5652 §5.4 signs only `signedAttrs`), so without
    /// this attribute nothing signed says which certificate the TSA used —
    /// exactly the lever an attacker needs to swap in a certificate with a
    /// wider validity window.
    #[error("neither signingCertificate nor signingCertificateV2 is present")]
    EssCertMissing,
    /// The attribute is present but its `certs` sequence is empty, so it
    /// identifies nothing.
    #[error("the signingCertificate attribute names no certificate")]
    EssCertEmpty,
    /// The **first** `ESSCertID` does not identify the signer certificate —
    /// its `certHash` does not match, or its `issuerSerial` does not equal
    /// `SignerInfo.sid`.
    ///
    /// Only the first is checked: RFC 5035 §5.4 makes it normative
    /// ("the first certificate identified … MUST be the certificate used to
    /// verify the signature"), "any entry matches" is too weak, and "all
    /// entries match" rejects Sectigo and Entrust, which send signer + CA +
    /// root.
    #[error("the first ESSCertID does not identify the signer certificate")]
    EssCertMismatch,

    // ── A8: extended key usage (RFC 3161 §2.3) ──────────────────────────
    /// The signer certificate has no `extendedKeyUsage` extension.
    #[error("the signer certificate has no extendedKeyUsage extension")]
    EkuMissing,
    /// The signer certificate's `extendedKeyUsage` is not marked critical.
    ///
    /// The rule binds the **signer** certificate only. DigiCert's
    /// intermediate carries a non-critical EKU, so a chain-wide reading fails
    /// a default TSA.
    #[error("the signer certificate's extendedKeyUsage is not critical")]
    EkuNotCritical,
    /// The signer certificate's `extendedKeyUsage` does not contain
    /// `id-kp-timeStamping`.
    #[error("the signer certificate's extendedKeyUsage lacks id-kp-timeStamping")]
    EkuNotTimeStamping,

    // ── A8: TSTInfo content ─────────────────────────────────────────────
    /// `TSTInfo.version` is not 1 (RFC 3161 §2.4.2).
    #[error("TSTInfo version is {version}, expected 1")]
    TstVersionUnsupported {
        /// The version as encoded.
        version: i64,
    },
    /// `TSTInfo.messageImprint.hashedMessage` is not this seal's
    /// `anchor_digest`: the token timestamps something else.
    ///
    /// D53 §8 fixes that this fires at stage T2, before any chain rule, so a
    /// token for a different digest is never classified by its chain.
    #[error("TSTInfo.messageImprint does not equal the anchor digest")]
    ImprintMismatch,
    /// `TSTInfo.nonce` is absent or does not equal the expected nonce.
    ///
    /// Reachable **only** on the capture path, where an expected nonce is
    /// supplied. On every bundle path the caller passes `None` and the field
    /// is verdict-inert (D59 §1).
    #[error("TSTInfo.nonce is absent or does not match the expected nonce")]
    NonceMismatch,

    // ── A8: the algorithm registry (D60 §3.3) ───────────────────────────
    /// A digest OID outside D60 §3.3's table appeared where antseal chooses a
    /// hash.
    #[error("unsupported digest algorithm {oid} at {position}")]
    DigestAlgUnsupported {
        /// Where it appeared.
        position: AlgPosition,
        /// The OID that was refused.
        oid: ObjectIdentifier,
    },
    /// A signature OID outside D60 §3.3's table appeared, or bare
    /// `rsaEncryption` appeared in a **certificate**'s `signatureAlgorithm`,
    /// where it would leave the digest unbound.
    #[error("unsupported signature algorithm {oid} at {position}")]
    SignatureAlgUnsupported {
        /// Where it appeared.
        position: AlgPosition,
        /// The OID that was refused.
        oid: ObjectIdentifier,
    },
    /// The signer certificate's `SubjectPublicKeyInfo` names a key type
    /// antseal does not verify with: not `rsaEncryption`, not
    /// `id-ecPublicKey` on `secp384r1`.
    #[error("unsupported subject public key algorithm {oid}")]
    SpkiUnsupported {
        /// The key algorithm OID that was refused.
        oid: ObjectIdentifier,
    },
    /// The signature algorithm and the signer's key type disagree — an ECDSA
    /// signature named over an RSA key, or the reverse.
    #[error("the signature algorithm does not match the signer's key type")]
    KeyAlgMismatch,
}

impl AnchorError {
    /// The stable machine-readable name of this failure class.
    ///
    /// Every distinct value returns a distinct code, every code is under
    /// `anchor-` (D91 §6.1), and every one has an exemplar in
    /// [`all_code_exemplars`].
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Der { fault, .. } => match fault {
                DerFault::NotStrict => "anchor-der-not-strict",
                DerFault::Malformed => "anchor-der-malformed",
                DerFault::NestingDepth => "anchor-der-nesting-depth",
            },
            Self::ChainCertCount { .. } => "anchor-chain-cert-count",
            Self::ChainCertSize { .. } => "anchor-chain-cert-size",
            Self::SignedAttrCount { .. } => "anchor-signed-attr-count",
            Self::StatusNotGranted { .. } => "anchor-tsa-status-not-granted",
            Self::TokenAbsent => "anchor-tsa-token-absent",
            Self::NotSignedData { .. } => "anchor-cms-not-signed-data",
            Self::NotTstInfo { .. } => "anchor-cms-not-tst-info",
            Self::EContentAbsent => "anchor-cms-econtent-absent",
            Self::SignerCount { .. } => "anchor-cms-signer-count",
            Self::SignedAttrsAbsent => "anchor-cms-signed-attrs-absent",
            Self::DuplicateSignedAttr { .. } => "anchor-cms-attr-duplicate",
            Self::SignedAttrNotSingleValued { .. } => "anchor-cms-attr-not-single-valued",
            Self::ContentTypeAttrMissing => "anchor-cms-content-type-attr-missing",
            Self::ContentTypeAttrMismatch => "anchor-cms-content-type-attr-mismatch",
            Self::MessageDigestAttrMissing => "anchor-cms-message-digest-attr-missing",
            Self::MessageDigestAttrMismatch => "anchor-cms-message-digest-attr-mismatch",
            Self::SignatureInvalid => "anchor-cms-signature-invalid",
            Self::SignerIdUnsupported => "anchor-cms-signer-id-unsupported",
            Self::SignerCertNotFound => "anchor-signer-cert-not-found",
            Self::EssCertMissing => "anchor-esscert-attr-missing",
            Self::EssCertEmpty => "anchor-esscert-empty",
            Self::EssCertMismatch => "anchor-esscert-mismatch",
            Self::EkuMissing => "anchor-eku-missing",
            Self::EkuNotCritical => "anchor-eku-not-critical",
            Self::EkuNotTimeStamping => "anchor-eku-no-timestamping",
            Self::TstVersionUnsupported { .. } => "anchor-tst-version-unsupported",
            Self::ImprintMismatch => "anchor-tsa-imprint-mismatch",
            Self::NonceMismatch => "anchor-tsa-nonce-mismatch",
            Self::DigestAlgUnsupported { .. } => "anchor-digest-alg-unsupported",
            Self::SignatureAlgUnsupported { .. } => "anchor-signature-alg-unsupported",
            Self::SpkiUnsupported { .. } => "anchor-spki-unsupported",
            Self::KeyAlgMismatch => "anchor-key-alg-mismatch",
        }
    }
}

/// Classify a `der` failure into one of D60 §7.2's three outcome classes.
///
/// # The deviation from D60 §7.2, recorded rather than hidden
///
/// D60 §7.2 says the variants are "mapped rather than left to a catch-all so
/// the match stays exhaustive and a new `der` variant is a compile error".
/// **That is not achievable at this pin**: `der::ErrorKind` is
/// `#[non_exhaustive]` (`der-0.8.1/src/error.rs`), so a downstream match must
/// carry a wildcard arm and cargo cannot make an added variant a build
/// failure. Every variant that exists today is still named explicitly, the
/// wildcard resolves to the conservative class ([`DerFault::Malformed`] —
/// "not well-formed at all", which claims the least), and
/// `tests/der_pin_eval.rs::der_error_kind_mapping_is_pinned` walks the whole
/// table so a *reclassification* by a `der` bump is caught even though an
/// *addition* cannot be.
///
/// D60 §7.2's own table is also incomplete: it omits `ErrorKind::Utf8`, which
/// `der 0.8.1` really does produce (a `Utf8String`/`PrintableString` with
/// invalid UTF-8 inside a `Name`). It is classified `Malformed` here.
#[must_use]
#[allow(deprecated)] // `ErrorKind::SetDuplicate` is deprecated in der 0.8.1;
// D60 §7.2 requires it mapped, and mapping it is how the day `der` starts
// producing it again yields the right code instead of a silent default.
pub(crate) const fn classify_der(kind: der::ErrorKind) -> DerFault {
    use der::ErrorKind as K;
    match kind {
        // Strictness: the bytes are a well-formed TLV stream, but not the
        // *canonical* one DER requires.
        K::IndefiniteLength
        | K::Noncanonical { .. }
        | K::Length { .. }
        | K::Overlength
        | K::SetOrdering
        | K::SetDuplicate => DerFault::NotStrict,

        // The depth guard: its own code, because it is the "distinct cap
        // error" A5's Accept row requires for limit b1.
        K::NestingDepth => DerFault::NestingDepth,

        // Not well-formed at all.
        K::Incomplete { .. }
        | K::TrailingData { .. }
        | K::TagUnknown { .. }
        | K::TagUnexpected { .. }
        | K::TagNumberInvalid
        | K::TagModeUnknown
        | K::Value { .. }
        | K::OidMalformed
        | K::OidUnknown { .. }
        | K::DateTime
        | K::Overflow
        | K::Failed
        | K::Reader
        | K::EncodingRules
        | K::Utf8(_) => DerFault::Malformed,

        // `ErrorKind` is #[non_exhaustive]; see the doc comment.
        _ => DerFault::Malformed,
    }
}

/// Turn a `der` failure at a named site into an [`AnchorError`].
pub(crate) fn der_error(site: DerSite, err: der::Error) -> AnchorError {
    AnchorError::Der {
        site,
        fault: classify_der(err.kind()),
    }
}

/// One value per distinct code, for the Q52 error-code universe.
///
/// **Not yet wired into [`crate::error_universe::by_enumerator`]** — D91 §8.2
/// makes that A38's move, together with the roster-size assertion going from
/// eight enumerators to nine and the `testdata/error-codes/v1/CODES.txt`
/// snapshot gaining these rows. Landing it from this lane would flip a test
/// that exists to make the roster change deliberate. The function is `pub` so
/// A38 needs no edit here beyond the one line in `by_enumerator`, and this
/// module's own tests already assert the two properties A38's check will
/// enforce workspace-wide.
#[must_use]
pub fn all_code_exemplars() -> Vec<AnchorError> {
    use AnchorError as E;
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.3.4");
    vec![
        E::Der {
            site: DerSite::Response,
            fault: DerFault::NotStrict,
        },
        E::Der {
            site: DerSite::Response,
            fault: DerFault::Malformed,
        },
        E::Der {
            site: DerSite::Response,
            fault: DerFault::NestingDepth,
        },
        E::ChainCertCount { count: 9 },
        E::ChainCertSize { bytes: 20_480 },
        E::SignedAttrCount { count: 17 },
        E::StatusNotGranted { status: 2 },
        E::TokenAbsent,
        E::NotSignedData { oid: OID },
        E::NotTstInfo { oid: OID },
        E::EContentAbsent,
        E::SignerCount { count: 2 },
        E::SignedAttrsAbsent,
        E::DuplicateSignedAttr {
            attr: SignedAttrId::ContentType,
        },
        E::SignedAttrNotSingleValued {
            attr: SignedAttrId::MessageDigest,
        },
        E::ContentTypeAttrMissing,
        E::ContentTypeAttrMismatch,
        E::MessageDigestAttrMissing,
        E::MessageDigestAttrMismatch,
        E::SignatureInvalid,
        E::SignerIdUnsupported,
        E::SignerCertNotFound,
        E::EssCertMissing,
        E::EssCertEmpty,
        E::EssCertMismatch,
        E::EkuMissing,
        E::EkuNotCritical,
        E::EkuNotTimeStamping,
        E::TstVersionUnsupported { version: 2 },
        E::ImprintMismatch,
        E::NonceMismatch,
        E::DigestAlgUnsupported {
            position: AlgPosition::SignerDigest,
            oid: OID,
        },
        E::SignatureAlgUnsupported {
            position: AlgPosition::SignerSignature,
            oid: OID,
        },
        E::SpkiUnsupported { oid: OID },
        E::KeyAlgMismatch,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every exemplar carries a code no other exemplar carries. Without this
    /// a copy-pasted arm silently merges two rejection classes into one, and
    /// the tamper matrix's "distinct error per mutation" claim quietly stops
    /// being true.
    #[test]
    fn codes_are_pairwise_distinct() {
        let exemplars = all_code_exemplars();
        assert!(!exemplars.is_empty(), "the roster must not be empty");
        let codes: BTreeSet<&'static str> = exemplars.iter().map(AnchorError::code).collect();
        assert_eq!(
            codes.len(),
            exemplars.len(),
            "two exemplars share a code; the roster is {exemplars:#?}"
        );
    }

    /// D91 §6.1's ruling, asserted where the codes are written rather than
    /// waited on. Q77/A38 makes it workspace-wide; until then a code minted
    /// under `ots-` or `tsa-` here would go unnoticed, which is exactly how a
    /// sibling decision came to specify sixteen codes under an unregistered
    /// namespace with a fully green suite.
    #[test]
    fn every_code_is_under_the_anchor_prefix() {
        let exemplars = all_code_exemplars();
        assert!(!exemplars.is_empty());
        for e in &exemplars {
            let code = e.code();
            assert!(
                code.starts_with("anchor-"),
                "`{code}` is not under the `anchor-` prefix (D91 §6.1)"
            );
            assert!(
                code.len() > "anchor-".len(),
                "`{code}` is the bare prefix with no check name"
            );
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "`{code}` is not lowercase kebab-case"
            );
            assert!(
                !code.ends_with('-') && !code.contains("--"),
                "`{code}` has an empty path segment"
            );
        }
    }

    /// The ten codes fixed by resolved decisions are spelled exactly as those
    /// decisions spell them. These are permanent from the moment anything
    /// binds to them (error-code contract §3), and `MATRIX.json` already
    /// binds `anchor-tsa-imprint-mismatch`. A rename is not a fix.
    #[test]
    fn the_decision_ruled_codes_are_spelled_as_ruled() {
        let codes: BTreeSet<&'static str> = all_code_exemplars()
            .iter()
            .map(AnchorError::code)
            .collect();
        for ruled in [
            // D60 §7.3
            "anchor-der-not-strict",
            "anchor-der-malformed",
            "anchor-der-nesting-depth",
            "anchor-chain-cert-count",
            "anchor-chain-cert-size",
            "anchor-signed-attr-count",
            "anchor-digest-alg-unsupported",
            "anchor-signature-alg-unsupported",
            // D53 §8 row 2 — bound by testdata/tamper/MATRIX.json
            "anchor-tsa-imprint-mismatch",
            // D59 §5 — owner-backed
            "anchor-tsa-nonce-mismatch",
        ] {
            assert!(codes.contains(ruled), "the ruled code `{ruled}` is missing");
        }
    }

    /// Project rule 6, and the narrower promise this module makes: an error's
    /// rendered text never carries a digest, a nonce or a hash — only *that*
    /// the comparison failed.
    #[test]
    fn display_renders_metadata_only() {
        for e in all_code_exemplars() {
            let text = e.to_string();
            assert!(!text.is_empty());
            // Nothing renders raw bytes: no hex run long enough to be a
            // digest, nonce or key fragment.
            let longest_hex_run = text
                .split(|c: char| !c.is_ascii_hexdigit())
                .map(str::len)
                .max()
                .unwrap_or(0);
            assert!(
                longest_hex_run < 16,
                "`{text}` renders a {longest_hex_run}-char hex run — possible byte payload"
            );
        }
    }

    /// The sweep D91 §7 ran by hand, run by machine: not one of these codes
    /// collides with a code already frozen in the committed universe.
    ///
    /// This is what Q77/A38 will generalise. It is native-only for the same
    /// reason `error_universe` is — `wasm32-unknown-unknown` has no
    /// filesystem — and it asserts both sets non-empty first, because a
    /// disjointness test over an empty set is the purest form of a test that
    /// cannot fail.
    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn codes_are_disjoint_from_the_committed_universe() {
        const SNAPSHOT: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/error-codes/v1/CODES.txt"
        );
        let frozen: BTreeSet<String> = std::fs::read_to_string(SNAPSHOT)
            .expect("testdata/error-codes/v1/CODES.txt must be readable")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_owned)
            .collect();
        assert!(
            frozen.len() > 100,
            "the committed universe looks unparsed ({} entries)",
            frozen.len()
        );
        let mine: BTreeSet<&'static str> = all_code_exemplars()
            .iter()
            .map(AnchorError::code)
            .collect();
        assert!(!mine.is_empty());
        let collisions: Vec<&&str> = mine.iter().filter(|c| frozen.contains(**c)).collect();
        assert!(
            collisions.is_empty(),
            "these anchor codes are already claimed by another domain: {collisions:?}"
        );
    }

    /// D60 §7.2's table, walked. An addition to `der::ErrorKind` cannot be a
    /// compile error (the enum is `#[non_exhaustive]`), so this is what
    /// catches a *reclassification* — the mutation that would silently turn a
    /// strictness rejection into a malformedness rejection and break the
    /// tamper row bound to `anchor-der-not-strict`.
    #[test]
    fn der_error_kind_mapping_is_pinned() {
        use der::{ErrorKind as K, Length, Tag};
        let strict = [
            K::IndefiniteLength,
            K::Noncanonical { tag: Tag::Integer },
            K::Length { tag: Tag::Boolean },
            K::Overlength,
            K::SetOrdering,
        ];
        for k in strict {
            assert_eq!(classify_der(k), DerFault::NotStrict, "{k:?}");
        }
        assert_eq!(classify_der(K::NestingDepth), DerFault::NestingDepth);
        let malformed = [
            K::Incomplete {
                expected_len: Length::ZERO,
                actual_len: Length::ZERO,
            },
            K::TrailingData {
                decoded: Length::ZERO,
                remaining: Length::ZERO,
            },
            K::TagUnknown { byte: 0x24 },
            K::TagUnexpected {
                expected: None,
                actual: Tag::Null,
            },
            K::TagNumberInvalid,
            K::TagModeUnknown,
            K::Value { tag: Tag::Boolean },
            K::OidMalformed,
            K::DateTime,
            K::Overflow,
            K::Failed,
            K::Reader,
            K::EncodingRules,
        ];
        for k in malformed {
            assert_eq!(classify_der(k), DerFault::Malformed, "{k:?}");
        }
    }
}
