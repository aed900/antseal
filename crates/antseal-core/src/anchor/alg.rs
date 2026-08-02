//! D60 §3.3's accepted-algorithm registry, **as data** (task **A8**).
//!
//! Written as tables rather than `match` arms for one operational reason:
//! D60 §4 prices adding an algorithm as "two rows in the curve and signature
//! tables, one recorded fixture, one A21 row". That is only true if adding
//! one really is a data change.
//!
//! # Three things measurement changed about the naive reading
//!
//! Each was wrong in `tasks/A.md` A8 before D60 corrected it, each measured
//! against nine live TSAs, and each would have failed an Accept row:
//!
//! 1. **Bare `rsaEncryption` is a legal signature AlgorithmIdentifier.**
//!    Five of nine TSAs — DigiCert, Sectigo, Apple, Certum, Entrust — put
//!    `1.2.840.113549.1.1.1` in `SignerInfo.signatureAlgorithm` and leave the
//!    digest to `SignerInfo.digestAlgorithm` (RFC 5754 §3.2). Accepting only
//!    `shaNNNWithRSAEncryption` breaks the majority, DigiCert included.
//!    It is accepted **there and nowhere else**: in a certificate,
//!    `signatureAlgorithm` is the only statement of which digest the issuer
//!    used, so a bare `rsaEncryption` there leaves the digest unbound.
//!    Measured: all 27 certificates across the nine tokens carry an explicit
//!    `shaNNNWithRSAEncryption`, so the restriction costs no real TSA
//!    anything.
//! 2. **ECDSA P-384 is paired with SHA-512, not SHA-384.** FreeTSA — the
//!    normative ECDSA TSA — signs `ecdsa-with-SHA512`
//!    (`1.2.840.10045.4.3.4`) on a P-384 key. `p384`'s
//!    `VerifyingKey::verify_prehash` takes the full 64-byte hash and applies
//!    FIPS 186-5 §6.4 leftmost-bits truncation internally.
//! 3. **SHA-1 has a live positive case as a rejection.** Apple's TSA really
//!    does set `SignerInfo.digestAlgorithm = sha1`, so
//!    `anchor-digest-alg-unsupported` has a committed real fixture rather
//!    than a synthetic one. SHA-1 is refused in **every** position this
//!    module governs; its one sanctioned use in the whole crate is
//!    `ESSCertID` v1's `certHash` ([`super::ess`]), where it is a selector
//!    and never the trust decision.
//!
//! # P-256 is not here, and that is a decision
//!
//! Of nine live TSAs surveyed, exactly one uses ECDSA at all and it is P-384.
//! Zero serve P-256, across both spec defaults and all three documented
//! alternates. A verification path no real TSA exercises can never be
//! validated against a real token, so a defect in it is undetectable until
//! the day it matters — the same defect as a test that cannot fail. D60 §4
//! records the revisit trigger and prices it at one pin plus two rows here.

use const_oid::ObjectIdentifier;
use const_oid::db::rfc5912;
use der::Tagged;
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::error::{AlgPosition, AnchorError};

/// A SHA-2 digest antseal will compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Digest {
    /// SHA-256 — the only digest accepted for `messageImprint`.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl Digest {
    /// Output length in bytes.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// The public-key family a signature is verified under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigFamily {
    /// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2).
    RsaPkcs1v15,
    /// ECDSA on `secp384r1`.
    EcdsaP384,
}

/// A signature algorithm as antseal resolved it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureAlg {
    /// Which key family verifies it.
    pub family: SigFamily,
    /// The digest the OID names, or `None` for bare `rsaEncryption`, where
    /// RFC 5754 §3.2 puts the digest in `SignerInfo.digestAlgorithm`.
    pub digest: Option<Digest>,
}

/// `id-ecPublicKey` — the SPKI algorithm for every EC key.
pub const ID_EC_PUBLIC_KEY: ObjectIdentifier = rfc5912::ID_EC_PUBLIC_KEY;
/// `secp384r1` — the only curve antseal verifies on (D60 §4).
pub const SECP384R1: ObjectIdentifier = rfc5912::SECP_384_R_1;
/// `rsaEncryption`.
pub const RSA_ENCRYPTION: ObjectIdentifier = rfc5912::RSA_ENCRYPTION;

/// One row of D60 §3.3's digest table.
struct DigestRow {
    oid: ObjectIdentifier,
    digest: Digest,
    /// Whether the row is accepted for `TSTInfo.messageImprint`, which must
    /// be SHA-256 exactly: A4 always requests it and `anchor_digest` is
    /// SHA-256 (MVP-SPEC.md line 109).
    message_imprint: bool,
}

const DIGESTS: &[DigestRow] = &[
    DigestRow {
        oid: rfc5912::ID_SHA_256,
        digest: Digest::Sha256,
        message_imprint: true,
    },
    DigestRow {
        oid: rfc5912::ID_SHA_384,
        digest: Digest::Sha384,
        message_imprint: false,
    },
    DigestRow {
        oid: rfc5912::ID_SHA_512,
        digest: Digest::Sha512,
        message_imprint: false,
    },
];

/// One row of D60 §3.3's signature table.
struct SigRow {
    oid: ObjectIdentifier,
    family: SigFamily,
    digest: Option<Digest>,
    /// Whether the row may appear as a **certificate**'s
    /// `signatureAlgorithm`. False only for bare `rsaEncryption`.
    in_certificate: bool,
}

const SIGNATURES: &[SigRow] = &[
    SigRow {
        oid: rfc5912::ECDSA_WITH_SHA_256,
        family: SigFamily::EcdsaP384,
        digest: Some(Digest::Sha256),
        in_certificate: true,
    },
    SigRow {
        oid: rfc5912::ECDSA_WITH_SHA_384,
        family: SigFamily::EcdsaP384,
        digest: Some(Digest::Sha384),
        in_certificate: true,
    },
    SigRow {
        oid: rfc5912::ECDSA_WITH_SHA_512,
        family: SigFamily::EcdsaP384,
        digest: Some(Digest::Sha512),
        in_certificate: true,
    },
    SigRow {
        oid: rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
        family: SigFamily::RsaPkcs1v15,
        digest: Some(Digest::Sha256),
        in_certificate: true,
    },
    SigRow {
        oid: rfc5912::SHA_384_WITH_RSA_ENCRYPTION,
        family: SigFamily::RsaPkcs1v15,
        digest: Some(Digest::Sha384),
        in_certificate: true,
    },
    SigRow {
        oid: rfc5912::SHA_512_WITH_RSA_ENCRYPTION,
        family: SigFamily::RsaPkcs1v15,
        digest: Some(Digest::Sha512),
        in_certificate: true,
    },
    SigRow {
        oid: rfc5912::RSA_ENCRYPTION,
        family: SigFamily::RsaPkcs1v15,
        digest: None,
        in_certificate: false,
    },
];

/// Resolve a digest `AlgorithmIdentifier`.
///
/// # Errors
///
/// [`AnchorError::DigestAlgUnsupported`] when the OID is outside the table,
/// when the position is `messageImprint` and the OID is not SHA-256, or when
/// the parameters are neither absent nor NULL.
pub fn digest(
    alg: &AlgorithmIdentifierOwned,
    position: AlgPosition,
) -> Result<Digest, AnchorError> {
    let row = DIGESTS
        .iter()
        .find(|r| r.oid == alg.oid)
        .filter(|r| position != AlgPosition::MessageImprint || r.message_imprint)
        .ok_or(AnchorError::DigestAlgUnsupported {
            position,
            oid: alg.oid,
        })?;
    // RFC 5754 §2: the parameters field is preferably absent, and NULL is
    // tolerated for compatibility. Anything else is a different algorithm
    // wearing a known OID.
    if !params_absent_or_null(alg) {
        return Err(AnchorError::DigestAlgUnsupported {
            position,
            oid: alg.oid,
        });
    }
    Ok(row.digest)
}

/// Resolve a signature `AlgorithmIdentifier`.
///
/// `in_certificate` selects the stricter table: bare `rsaEncryption` is
/// accepted as a `SignerInfo.signatureAlgorithm` and refused as a
/// certificate's, because there it would leave the digest unbound.
///
/// # Errors
///
/// [`AnchorError::SignatureAlgUnsupported`] when the OID is outside the
/// table, when it is bare `rsaEncryption` in a certificate, or when the
/// parameters do not match what the family requires.
pub fn signature(
    alg: &AlgorithmIdentifierOwned,
    position: AlgPosition,
    in_certificate: bool,
) -> Result<SignatureAlg, AnchorError> {
    let unsupported = AnchorError::SignatureAlgUnsupported {
        position,
        oid: alg.oid,
    };
    let row = SIGNATURES
        .iter()
        .find(|r| r.oid == alg.oid)
        .filter(|r| r.in_certificate || !in_certificate)
        .ok_or_else(|| unsupported.clone())?;
    let params_ok = match row.family {
        // RFC 4055 §5 / RFC 8017: RSA algorithm identifiers carry NULL
        // parameters; absent is accepted for the same reason RFC 5754 does.
        SigFamily::RsaPkcs1v15 => params_absent_or_null(alg),
        // RFC 5758 §3.2: ECDSA signature algorithm identifiers MUST omit the
        // parameters field.
        SigFamily::EcdsaP384 => alg.parameters.is_none(),
    };
    if !params_ok {
        return Err(unsupported);
    }
    Ok(SignatureAlg {
        family: row.family,
        digest: row.digest,
    })
}

/// Resolve a `SubjectPublicKeyInfo`'s algorithm to the family that verifies
/// under it.
///
/// # Errors
///
/// [`AnchorError::SpkiUnsupported`] for any key type outside `rsaEncryption`
/// and `id-ecPublicKey` on `secp384r1` — including `id-ecPublicKey` on any
/// other curve, which is where a P-256 key lands (D60 §4).
pub fn public_key_family(spki_alg: &AlgorithmIdentifierOwned) -> Result<SigFamily, AnchorError> {
    let unsupported = AnchorError::SpkiUnsupported { oid: spki_alg.oid };
    if spki_alg.oid == RSA_ENCRYPTION {
        return if params_absent_or_null(spki_alg) {
            Ok(SigFamily::RsaPkcs1v15)
        } else {
            Err(unsupported)
        };
    }
    if spki_alg.oid == ID_EC_PUBLIC_KEY {
        let curve = spki_alg
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        return if curve == Some(SECP384R1) {
            Ok(SigFamily::EcdsaP384)
        } else {
            Err(unsupported)
        };
    }
    Err(unsupported)
}

/// Is the `parameters` field absent, or an explicit ASN.1 NULL?
fn params_absent_or_null(alg: &AlgorithmIdentifierOwned) -> bool {
    match &alg.parameters {
        None => true,
        Some(any) => any.tag() == der::Tag::Null && any.value().is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::Null;
    use der::{Any, Encode};

    fn alg(oid: &str, params: Option<Any>) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap(oid),
            parameters: params,
        }
    }

    fn null() -> Any {
        Any::from(Null)
    }

    /// The table's OIDs are the ones D60 §3.3 lists, spelled out rather than
    /// taken on trust from `const-oid`'s names: a wrong constant would make
    /// the whole registry accept the wrong algorithm silently, and the `db::`
    /// path is exactly where that slip is invisible.
    #[test]
    fn registry_oids_are_the_ruled_ones() {
        let digests: Vec<String> = DIGESTS.iter().map(|r| r.oid.to_string()).collect();
        assert_eq!(
            digests,
            [
                "2.16.840.1.101.3.4.2.1",
                "2.16.840.1.101.3.4.2.2",
                "2.16.840.1.101.3.4.2.3"
            ]
        );
        let sigs: Vec<String> = SIGNATURES.iter().map(|r| r.oid.to_string()).collect();
        assert_eq!(
            sigs,
            [
                "1.2.840.10045.4.3.2",
                "1.2.840.10045.4.3.3",
                "1.2.840.10045.4.3.4",
                "1.2.840.113549.1.1.11",
                "1.2.840.113549.1.1.12",
                "1.2.840.113549.1.1.13",
                "1.2.840.113549.1.1.1",
            ]
        );
        assert_eq!(SECP384R1.to_string(), "1.3.132.0.34");
        assert_eq!(ID_EC_PUBLIC_KEY.to_string(), "1.2.840.10045.2.1");
    }

    /// SHA-1 is refused in every position this module governs. Apple's real
    /// token is the positive case for the `SignerDigest` position; the rest
    /// are covered here so a future edit cannot re-admit it through a
    /// position no fixture exercises.
    #[test]
    fn sha1_is_rejected_in_every_digest_position() {
        let sha1 = alg("1.3.14.3.2.26", Some(null()));
        for position in [
            AlgPosition::SignedDataDigests,
            AlgPosition::SignerDigest,
            AlgPosition::MessageImprint,
            AlgPosition::EssCertHash,
        ] {
            let err = digest(&sha1, position).expect_err("SHA-1 must never be accepted");
            assert_eq!(err.code(), "anchor-digest-alg-unsupported");
        }
        // And as a signature digest, where D60 §3.3 also refuses it.
        let sha1_rsa = alg("1.2.840.113549.1.1.5", Some(null()));
        let err = signature(&sha1_rsa, AlgPosition::SignerSignature, false)
            .expect_err("sha1WithRSAEncryption must never be accepted");
        assert_eq!(err.code(), "anchor-signature-alg-unsupported");
    }

    /// `messageImprint` is SHA-256 exactly. SHA-384 and SHA-512 are accepted
    /// everywhere else, which is what makes this a real restriction and not a
    /// restatement of the table.
    #[test]
    fn message_imprint_is_sha256_only() {
        for (oid, d) in [
            ("2.16.840.1.101.3.4.2.2", Digest::Sha384),
            ("2.16.840.1.101.3.4.2.3", Digest::Sha512),
        ] {
            let a = alg(oid, None);
            assert_eq!(
                digest(&a, AlgPosition::SignerDigest).expect("accepted elsewhere"),
                d
            );
            let err = digest(&a, AlgPosition::MessageImprint)
                .expect_err("messageImprint must be SHA-256");
            assert_eq!(err.code(), "anchor-digest-alg-unsupported");
        }
        let sha256 = alg("2.16.840.1.101.3.4.2.1", None);
        assert_eq!(
            digest(&sha256, AlgPosition::MessageImprint).expect("SHA-256 is the imprint algorithm"),
            Digest::Sha256
        );
    }

    /// The asymmetry that makes bare `rsaEncryption` safe: accepted as a
    /// `SignerInfo.signatureAlgorithm` (5 of 9 real TSAs), refused as a
    /// certificate's, where it would leave the digest unbound.
    #[test]
    fn bare_rsa_encryption_is_accepted_only_outside_a_certificate() {
        let bare = alg("1.2.840.113549.1.1.1", Some(null()));
        let resolved = signature(&bare, AlgPosition::SignerSignature, false)
            .expect("5 of 9 live TSAs emit this");
        assert_eq!(resolved.family, SigFamily::RsaPkcs1v15);
        assert_eq!(
            resolved.digest, None,
            "the digest comes from SignerInfo.digestAlgorithm"
        );
        let err = signature(&bare, AlgPosition::SignerSignature, true)
            .expect_err("a certificate must name its digest");
        assert_eq!(err.code(), "anchor-signature-alg-unsupported");
    }

    /// RFC 5758 §3.2 — ECDSA algorithm identifiers omit their parameters. A
    /// token carrying parameters there is claiming something the table does
    /// not describe.
    #[test]
    fn ecdsa_parameters_must_be_absent_and_rsa_may_be_null() {
        let ecdsa_ok = alg("1.2.840.10045.4.3.4", None);
        assert_eq!(
            signature(&ecdsa_ok, AlgPosition::SignerSignature, false)
                .expect("FreeTSA's algorithm")
                .digest,
            Some(Digest::Sha512)
        );
        let ecdsa_bad = alg("1.2.840.10045.4.3.4", Some(null()));
        assert_eq!(
            signature(&ecdsa_bad, AlgPosition::SignerSignature, false)
                .expect_err("parameters are forbidden")
                .code(),
            "anchor-signature-alg-unsupported"
        );
        for params in [None, Some(null())] {
            let rsa = alg("1.2.840.113549.1.1.11", params);
            assert!(signature(&rsa, AlgPosition::SignerSignature, true).is_ok());
        }
    }

    /// P-256 is out of v1 by decision, so a P-256 key must be refused with
    /// the key-type code rather than silently verified on the wrong curve.
    #[test]
    fn only_p384_ec_keys_are_accepted() {
        let p384_params = Any::new(der::Tag::ObjectIdentifier, SECP384R1.as_bytes().to_vec())
            .expect("well-formed OID parameters");
        let p384 = alg("1.2.840.10045.2.1", Some(p384_params));
        assert_eq!(
            public_key_family(&p384).expect("P-384 is the supported curve"),
            SigFamily::EcdsaP384
        );

        let p256_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
        let p256_params =
            Any::new(der::Tag::ObjectIdentifier, p256_oid.as_bytes().to_vec()).expect("well-formed");
        let p256 = alg("1.2.840.10045.2.1", Some(p256_params));
        assert_eq!(
            public_key_family(&p256)
                .expect_err("P-256 is out of v1")
                .code(),
            "anchor-spki-unsupported"
        );

        // An EC key with no curve at all is refused, not defaulted.
        let naked = alg("1.2.840.10045.2.1", None);
        assert_eq!(
            public_key_family(&naked).expect_err("no curve named").code(),
            "anchor-spki-unsupported"
        );

        let rsa = alg("1.2.840.113549.1.1.1", Some(null()));
        assert_eq!(
            public_key_family(&rsa).expect("RSA keys verify"),
            SigFamily::RsaPkcs1v15
        );
    }

    /// A digest identifier whose parameters are neither absent nor NULL is
    /// refused. Without this the registry would accept
    /// `id-sha256 { <arbitrary> }` as SHA-256.
    #[test]
    fn digest_parameters_must_be_absent_or_null() {
        let junk = Any::new(der::Tag::OctetString, vec![0xAAu8]).expect("well-formed");
        let a = alg("2.16.840.1.101.3.4.2.1", Some(junk));
        assert_eq!(
            digest(&a, AlgPosition::SignerDigest)
                .expect_err("unexpected parameters")
                .code(),
            "anchor-digest-alg-unsupported"
        );
        // A NULL is not "any value with the NULL tag": one with content is
        // refused, and the real NULL is two bytes.
        let fake_null = Any::new(der::Tag::Null, vec![0x00u8]).expect("well-formed");
        let b = alg("2.16.840.1.101.3.4.2.1", Some(fake_null));
        assert!(digest(&b, AlgPosition::SignerDigest).is_err());
        assert_eq!(null().to_der().expect("NULL encodes"), vec![0x05, 0x00]);
    }
}
