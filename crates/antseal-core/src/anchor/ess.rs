//! `SigningCertificate` / `SigningCertificateV2` — the signed statement of
//! *which* certificate signed the token (task **A8**).
//!
//! # Why this attribute is load-bearing rather than ceremonial
//!
//! `SignerInfo.sid` is **not covered by the signature**: RFC 5652 §5.4 signs
//! only `signedAttrs`, and `sid` is outside it. So without this attribute
//! nothing *signed* says which certificate the TSA used, and since antseal
//! evaluates chain validity at `genTime` (D53), an unchecked certificate
//! identity is exactly the lever an attacker would use — swap in a
//! certificate with a wider validity window and turn
//! `valid-at-stamping-cert-since-expired` into `proven`.
//!
//! # SHA-1 is here, and the reasoning belongs in front of the code
//!
//! `ESSCertID` (v1, RFC 2634 §5.4) defines `certHash` as **the SHA-1 hash of
//! the certificate**. Not "a hash" — SHA-1, by definition, with no algorithm
//! field to negotiate. Four of nine live TSAs send v1 and nothing else, and
//! **FreeTSA — the normative ECDSA P-384 TSA (MVP-SPEC.md line 109) — is one
//! of them**. So the two ways to avoid SHA-1 are: require ESSCertIDv2, which
//! rejects the normative TSA; or skip the check, which gives up the only
//! signed statement of signer identity. Both are worse.
//!
//! SHA-1 is broken for collision resistance (SHAttered 2017, chosen-prefix
//! 2020) and X.509 certificate collisions are the demonstrated application,
//! so the objection is real and gets a real answer:
//!
//! 1. **SHA-1 is a selector here, never the trust decision.** The trust
//!    decision is A9's path validation to a *pinned, compiled-in* root: name
//!    chaining, per-link signature verification under [`super::alg`]'s
//!    registry, `cA = TRUE` on every CA, KeyUsage, critical EKU on the
//!    signer, validity at `genTime`. A colliding certificate must satisfy
//!    all of that against a pinned root — i.e. the attacker needs a real CA
//!    to issue it. This comparison can only ever **narrow** the trusted set;
//!    it can never widen it.
//! 2. **It is a redundant check.** The signer is located by `sid`'s
//!    issuerAndSerialNumber *and* must satisfy the certHash; where
//!    ESSCertIDv2 is present it is checked under SHA-256 too; where
//!    `issuerSerial` is present it must equal `sid`. Delete the SHA-1 leg
//!    and the chain validation is untouched.
//!
//! `sha1` is confined to this module by construction: it is the only `use
//! sha1::` in the crate, its pin carries `default-features = false` (so no
//! `oid` feature and therefore no way to reach SHA-1 through an
//! `AssociatedOid` bound), and A30 makes the confinement a lane rule.
//!
//! # Only the first entry is checked, and that is normative
//!
//! RFC 5035 §5.4: *"The first certificate identified in the sequence of
//! certificate identifiers MUST be the certificate used to verify the
//! signature."* Both weaker readings are wrong on real material: "any entry
//! matches" is too weak, and "all entries match" **rejects Sectigo and
//! Entrust**, which send three entries — signer, CA and root.

use const_oid::ObjectIdentifier;
use const_oid::db::rfc5912;
use der::asn1::{OctetString, SetOfVec};
use der::{
    Any, Decode, DecodeValue, Encode, EncodeValue, ErrorKind, Header, Length, Reader, Sequence,
    Tag, Writer,
};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::error::{AlgPosition, AnchorError, DerSite, SignedAttrId, der_error};

/// `id-aa-signingCertificate` — RFC 2634 §5.4.
pub const ID_AA_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
/// `id-aa-signingCertificateV2` — RFC 5035 §3.
pub const ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

/// ```text
/// IssuerSerial ::= SEQUENCE {
///     issuer        GeneralNames,
///     serialNumber  CertificateSerialNumber }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct IssuerSerial {
    /// The issuer, as `GeneralNames`.
    pub issuer: Vec<GeneralName>,
    /// The certificate serial number.
    pub serial_number: SerialNumber,
}

/// ```text
/// ESSCertID ::= SEQUENCE {
///     certHash      Hash,            -- SHA-1, by definition
///     issuerSerial  IssuerSerial OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct EssCertId {
    /// SHA-1 of the whole certificate. There is no algorithm field: RFC 2634
    /// §5.4 fixes it.
    pub cert_hash: OctetString,
    /// The issuer and serial, when the TSA populated it.
    #[asn1(optional = "true")]
    pub issuer_serial: Option<IssuerSerial>,
}

/// ```text
/// ESSCertIDv2 ::= SEQUENCE {
///     hashAlgorithm  AlgorithmIdentifier DEFAULT {algorithm id-sha256},
///     certHash       Hash,
///     issuerSerial   IssuerSerial OPTIONAL }
/// ```
///
/// Hand-decoded for the DEFAULT rule, which `der_derive` does not enforce
/// (its `default` attribute expands to
/// `Option::<T>::decode(..).unwrap_or_else(..)` and happily accepts an
/// explicitly encoded default). DigiCert and DFN omit `hashAlgorithm`
/// entirely, so *absent ⇒ SHA-256*; an explicitly encoded
/// `{algorithm id-sha256}` is a DER violation (X.690 §11.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EssCertIdV2 {
    hash_algorithm: Option<AlgorithmIdentifierOwned>,
    cert_hash: OctetString,
    issuer_serial: Option<IssuerSerial>,
}

impl EssCertIdV2 {
    /// The digest algorithm, resolved through the DEFAULT.
    ///
    /// # Errors
    ///
    /// [`AnchorError::DigestAlgUnsupported`] when an explicit algorithm is
    /// outside D60 §3.3's table.
    pub fn digest_alg(&self) -> Result<super::alg::Digest, AnchorError> {
        match &self.hash_algorithm {
            None => Ok(super::alg::Digest::Sha256),
            Some(alg) => super::alg::digest(alg, AlgPosition::EssCertHash),
        }
    }

    /// The certificate hash.
    #[must_use]
    pub fn cert_hash(&self) -> &[u8] {
        self.cert_hash.as_bytes()
    }

    /// The issuer and serial, when present.
    #[must_use]
    pub const fn issuer_serial(&self) -> Option<&IssuerSerial> {
        self.issuer_serial.as_ref()
    }
}

impl<'a> Sequence<'a> for EssCertIdV2 {}

impl<'a> DecodeValue<'a> for EssCertIdV2 {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        // `hashAlgorithm` is a SEQUENCE and `certHash` an OCTET STRING, so
        // the OPTIONAL-with-DEFAULT is decidable by tag.
        let hash_algorithm = if !reader.is_finished() && Tag::peek(reader)? == Tag::Sequence {
            let alg = AlgorithmIdentifierOwned::decode(reader)?;
            // X.690 §11.5: the DEFAULT value must not be encoded. The
            // default is `{algorithm id-sha256}` with the parameters field
            // ABSENT, so that exact shape — and only that shape — is the
            // violation. `{id-sha256, NULL}` is a different encoding of the
            // same algorithm, not an encoding of the default value, and is
            // accepted.
            if alg.oid == rfc5912::ID_SHA_256 && alg.parameters.is_none() {
                return Err(reader.error(ErrorKind::Noncanonical { tag: Tag::Sequence }));
            }
            Some(alg)
        } else {
            None
        };
        let cert_hash = OctetString::decode(reader)?;
        let issuer_serial = if reader.is_finished() {
            None
        } else {
            Some(IssuerSerial::decode(reader)?)
        };
        if !reader.is_finished() {
            let decoded = reader.position();
            let remaining = reader.remaining_len();
            return Err(reader.error(ErrorKind::TrailingData { decoded, remaining }));
        }
        Ok(Self {
            hash_algorithm,
            cert_hash,
            issuer_serial,
        })
    }
}

impl EncodeValue for EssCertIdV2 {
    fn value_len(&self) -> der::Result<Length> {
        self.hash_algorithm.encoded_len()?
            + self.cert_hash.encoded_len()?
            + self.issuer_serial.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.hash_algorithm.encode(writer)?;
        self.cert_hash.encode(writer)?;
        self.issuer_serial.encode(writer)
    }
}

/// ```text
/// SigningCertificate ::= SEQUENCE {
///     certs     SEQUENCE OF ESSCertID,
///     policies  SEQUENCE OF PolicyInformation OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct SigningCertificate {
    /// The certificate identifiers. The first is the signer's.
    pub certs: Vec<EssCertId>,
    /// Policies, unread.
    #[asn1(optional = "true")]
    pub policies: Option<Vec<Any>>,
}

/// ```text
/// SigningCertificateV2 ::= SEQUENCE {
///     certs     SEQUENCE OF ESSCertIDv2,
///     policies  SEQUENCE OF PolicyInformation OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct SigningCertificateV2 {
    /// The certificate identifiers. The first is the signer's.
    pub certs: Vec<EssCertIdV2>,
    /// Policies, unread.
    #[asn1(optional = "true")]
    pub policies: Option<Vec<Any>>,
}

/// The signer's identity as `SignerInfo.sid` states it — the thing
/// `issuerSerial` must agree with when it is present.
#[derive(Debug, Clone, Copy)]
pub struct SignerId<'a> {
    /// The issuer name, DER-encoded.
    pub issuer_der: &'a [u8],
    /// The serial number's DER INTEGER content octets.
    pub serial: &'a [u8],
}

/// Check a `signingCertificate` / `signingCertificateV2` attribute against
/// the certificate the token claims to be signed by.
///
/// `attr_values` is the attribute's value set; `signer_der` is the signer
/// certificate's DER encoding.
///
/// # Errors
///
/// - [`AnchorError::SignedAttrNotSingleValued`] — the attribute does not
///   carry exactly one value.
/// - [`AnchorError::Der`] — the value is not a well-formed, strictly-DER
///   `SigningCertificate`/`V2`.
/// - [`AnchorError::EssCertEmpty`] — `certs` is empty, so the attribute
///   identifies nothing.
/// - [`AnchorError::EssCertMismatch`] — the first entry's `certHash` is not
///   the signer's, or its `issuerSerial` disagrees with `sid`.
/// - [`AnchorError::DigestAlgUnsupported`] — a v2 `hashAlgorithm` outside
///   the registry.
pub fn check_signing_certificate(
    version: EssVersion,
    attr_values: &SetOfVec<Any>,
    signer_der: &[u8],
    sid: SignerId<'_>,
) -> Result<(), AnchorError> {
    let value = single_value(version, attr_values)?;
    let encoded = value
        .to_der()
        .map_err(|e| der_error(DerSite::EssCertId, e))?;
    match version {
        EssVersion::V1 => {
            let attr = SigningCertificate::from_der(&encoded)
                .map_err(|e| der_error(DerSite::EssCertId, e))?;
            let first = attr.certs.first().ok_or(AnchorError::EssCertEmpty)?;
            // v1 has no algorithm field: RFC 2634 §5.4 fixes SHA-1.
            let expected = Sha1::digest(signer_der);
            if first.cert_hash.as_bytes() != expected.as_slice() {
                return Err(AnchorError::EssCertMismatch);
            }
            check_issuer_serial(first.issuer_serial.as_ref(), sid)
        }
        EssVersion::V2 => {
            let attr = SigningCertificateV2::from_der(&encoded)
                .map_err(|e| der_error(DerSite::EssCertId, e))?;
            let first = attr.certs.first().ok_or(AnchorError::EssCertEmpty)?;
            let matches = match first.digest_alg()? {
                super::alg::Digest::Sha256 => {
                    first.cert_hash() == Sha256::digest(signer_der).as_slice()
                }
                super::alg::Digest::Sha384 => {
                    first.cert_hash() == sha2::Sha384::digest(signer_der).as_slice()
                }
                super::alg::Digest::Sha512 => {
                    first.cert_hash() == sha2::Sha512::digest(signer_der).as_slice()
                }
            };
            if !matches {
                return Err(AnchorError::EssCertMismatch);
            }
            check_issuer_serial(first.issuer_serial(), sid)
        }
    }
}

/// Which of the two attributes is being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EssVersion {
    /// `signingCertificate` — `ESSCertID`, SHA-1 `certHash`.
    V1,
    /// `signingCertificateV2` — `ESSCertIDv2`, algorithm-agile `certHash`.
    V2,
}

impl EssVersion {
    /// The attribute id this version lives under.
    #[must_use]
    pub const fn attr(self) -> SignedAttrId {
        match self {
            Self::V1 => SignedAttrId::SigningCertificate,
            Self::V2 => SignedAttrId::SigningCertificateV2,
        }
    }
}

fn single_value(version: EssVersion, values: &SetOfVec<Any>) -> Result<&Any, AnchorError> {
    let mut iter = values.iter();
    match (iter.next(), iter.next()) {
        (Some(v), None) => Ok(v),
        _ => Err(AnchorError::SignedAttrNotSingleValued {
            attr: version.attr(),
        }),
    }
}

/// When `issuerSerial` is present it must agree with `SignerInfo.sid`.
///
/// Absent is legal — RFC 5035 makes the field OPTIONAL and four of the nine
/// live TSAs omit it — so absence is not a failure. Present-and-different is,
/// because it is the attacker's opportunity to sign a statement about one
/// certificate while `sid` names another.
fn check_issuer_serial(
    issuer_serial: Option<&IssuerSerial>,
    sid: SignerId<'_>,
) -> Result<(), AnchorError> {
    let Some(is) = issuer_serial else {
        return Ok(());
    };
    if is.serial_number.as_bytes() != sid.serial {
        return Err(AnchorError::EssCertMismatch);
    }
    // `GeneralNames` is a SEQUENCE OF; the issuer of a certificate is a
    // `directoryName`. Exactly one entry, and it must be that — a set of
    // alternatives would make "the issuer" ambiguous, which is precisely the
    // ambiguity this check exists to remove.
    let mut names = is.issuer.iter();
    let (Some(GeneralName::DirectoryName(name)), None) = (names.next(), names.next()) else {
        return Err(AnchorError::EssCertMismatch);
    };
    if name_der(name)? != sid.issuer_der {
        return Err(AnchorError::EssCertMismatch);
    }
    Ok(())
}

/// A `Name`'s DER encoding, for byte-exact comparison.
///
/// Byte equality, not RFC 5280 §7.1 name matching. It is the stricter rule
/// and it is the right one here: both sides of every comparison antseal makes
/// are written by the *same* issuer into the *same* token, so a difference in
/// encoding is a difference in intent rather than a locale artifact.
/// `signer_certificate_is_found_in_every_real_token` measures that this holds
/// on all nine live captures.
pub(crate) fn name_der(name: &Name) -> Result<Vec<u8>, AnchorError> {
    name.to_der()
        .map_err(|e| der_error(DerSite::Certificate, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two attribute OIDs, spelled out. A wrong constant here makes the
    /// binding silently unreachable — the attribute is simply "not present"
    /// — which fails open rather than closed, and is exactly the mistake
    /// `EssCertMissing` cannot distinguish from a genuinely absent
    /// attribute.
    #[test]
    fn attribute_oids() {
        assert_eq!(
            ID_AA_SIGNING_CERTIFICATE.to_string(),
            "1.2.840.113549.1.9.16.2.12"
        );
        assert_eq!(
            ID_AA_SIGNING_CERTIFICATE_V2.to_string(),
            "1.2.840.113549.1.9.16.2.47"
        );
    }

    /// D60 §3.4's DER rule for ESSCertIDv2, which no derive enforces. The
    /// default is `{algorithm id-sha256}` with parameters ABSENT, so that is
    /// the shape refused.
    #[test]
    fn an_explicitly_encoded_default_hash_algorithm_is_rejected() {
        // SEQUENCE { SEQUENCE { OID id-sha256 }, OCTET STRING (32 zero) }
        let mut inner = vec![0x30, 0x0b, 0x06, 0x09];
        inner.extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
        let mut body = inner;
        body.extend_from_slice(&[0x04, 0x20]);
        body.extend_from_slice(&[0u8; 32]);
        let mut der = vec![0x30, u8::try_from(body.len()).expect("fits")];
        der.extend_from_slice(&body);
        let err = EssCertIdV2::from_der(&der).expect_err("DEFAULT must not be encoded");
        assert!(matches!(
            err.kind(),
            ErrorKind::Noncanonical { tag: Tag::Sequence }
        ));
    }

    /// The other direction, without which the test above proves only that
    /// something failed: `hashAlgorithm` absent is legal (DigiCert and DFN
    /// send it that way) and resolves to SHA-256 through the DEFAULT.
    #[test]
    fn an_absent_hash_algorithm_resolves_to_sha256() {
        let mut body = vec![0x04, 0x20];
        body.extend_from_slice(&[0u8; 32]);
        let mut der = vec![0x30, u8::try_from(body.len()).expect("fits")];
        der.extend_from_slice(&body);
        let id = EssCertIdV2::from_der(&der).expect("absent hashAlgorithm is legal");
        assert_eq!(
            id.digest_alg().expect("the DEFAULT is SHA-256"),
            super::super::alg::Digest::Sha256
        );
        assert_eq!(id.cert_hash(), [0u8; 32]);
    }

    /// An explicit non-default algorithm is accepted and resolved, so the
    /// DEFAULT check above is not simply "reject every hashAlgorithm".
    #[test]
    fn an_explicit_non_default_hash_algorithm_is_accepted() {
        // SEQUENCE { SEQUENCE { OID id-sha512 }, OCTET STRING (64 zero) }
        let mut body = vec![0x30, 0x0b, 0x06, 0x09];
        body.extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]);
        body.extend_from_slice(&[0x04, 0x40]);
        body.extend_from_slice(&[0u8; 64]);
        let mut der = vec![0x30, u8::try_from(body.len()).expect("fits")];
        der.extend_from_slice(&body);
        let id = EssCertIdV2::from_der(&der).expect("an explicit non-default algorithm is legal");
        assert_eq!(
            id.digest_alg().expect("SHA-512 is in the registry"),
            super::super::alg::Digest::Sha512
        );
    }

    /// SHA-1 is refused as an ESSCertIDv2 `hashAlgorithm`. v1's `certHash`
    /// is SHA-1 by definition and has no algorithm field to check; v2 has
    /// one, and there the registry applies like anywhere else.
    #[test]
    fn sha1_is_refused_as_an_explicit_v2_hash_algorithm() {
        // SEQUENCE { SEQUENCE { OID sha1 }, OCTET STRING (20 zero) }
        let mut body = vec![0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];
        body.extend_from_slice(&[0x04, 0x14]);
        body.extend_from_slice(&[0u8; 20]);
        let mut der = vec![0x30, u8::try_from(body.len()).expect("fits")];
        der.extend_from_slice(&body);
        let id = EssCertIdV2::from_der(&der).expect("well-formed DER");
        assert_eq!(
            id.digest_alg()
                .expect_err("SHA-1 is not a cert-link digest")
                .code(),
            "anchor-digest-alg-unsupported"
        );
    }
}
