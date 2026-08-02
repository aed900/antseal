//! CMS `SignedData` verification over an RFC 3161 timestamp token
//! (task **A8**) — stage **T2** of D53's per-artifact order.
//!
//! This is the spec's explicitly budgeted "no turnkey pure-Rust CMS verifier
//! exists" work (MVP-SPEC.md line 108, measured still true at the pinned
//! versions): `cms` supplies the RFC 5652 *model* and stops there — every
//! check below is antseal's.
//!
//! # What T2 decides, and what it deliberately does not
//!
//! T2 answers one question: **is this token internally what it claims to
//! be** — signed by the certificate it names, over the `TSTInfo` it carries,
//! committing to this seal's `anchor_digest`. It does **not** decide whether
//! the signer is trusted; that is A9's path validation to a pinned root
//! (stage T3), and it runs afterwards.
//!
//! The order is normative and load-bearing (D53): a token whose CMS
//! signature does not verify must never reach chain classification, because
//! `internally-consistent-only` means *cryptographically well-formed but not
//! anchored to a pinned root*. A validator that builds the chain first would
//! label a non-token `internally-consistent-only` — the natural wrong
//! implementation, and the one D53 §9 pins a test against.
//!
//! # The nonce is verdict-inert unless a nonce is supplied
//!
//! [`verify_token`] takes `expected_nonce: Option<&[u8]>` (D59 §1).
//!
//! - `Some(n)` — capture path only. `TSTInfo.nonce` MUST be present and its
//!   DER INTEGER **content octets** must equal `n`. Absent counts as a
//!   mismatch: treating absence as "nothing to compare" is the defect that
//!   makes a replayed token pass.
//! - `None` — every bundle path, always. The field is parsed (a malformed
//!   nonce is a malformed token) and then **ignored**: it moves no state, no
//!   code, no `verified_time_unix`, and no byte of report v1. Nothing below
//!   branches on its presence, and *nothing may be made to*: any rule keyed
//!   on nonce presence is a rule an adversary passes for free (include a
//!   token that has one) and an honest party can fail (a nonce-free request,
//!   or a token imported from other tooling).
//!
//! # No local clock, here or anywhere below
//!
//! `genTime` is returned, never compared against a clock. `antseal-core`
//! reads no clock at all and verification time is an explicit parameter, so
//! the mistake is unmakeable here — but it is worth naming, because the host
//! that captured the committed fixtures ran **129 s slow**, and the obvious
//! `gen_time <= fetch_date` sanity check rejects every one of them. A32 owns
//! the prohibition on the capture side, where a clock does exist.

use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use const_oid::ObjectIdentifier;
use const_oid::db::{rfc5911, rfc5912};
use der::asn1::{GeneralizedTime, SetOfVec};
use der::{Any, Encode, Tagged};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use x509_cert::Certificate;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

use super::alg::{self, Digest, SigFamily, SignatureAlg};
use super::caps::{MAX_CHAIN_CERT_BYTES, MAX_CHAIN_CERTS, MAX_SIGNED_ATTRS};
use super::error::{AlgPosition, AnchorError, DerSite, SignedAttrId, der_error};
use super::ess::{self, EssVersion, SignerId};
use super::rfc3161::{ID_CT_TST_INFO, TstInfo, token_content_info};

/// `id-kp-timeStamping` — RFC 3161 §2.3.
pub const ID_KP_TIME_STAMPING: ObjectIdentifier = rfc5912::ID_KP_TIME_STAMPING;
/// `id-contentType` — RFC 5652 §11.1.
const ID_CONTENT_TYPE: ObjectIdentifier = rfc5911::ID_CONTENT_TYPE;
/// `id-messageDigest` — RFC 5652 §11.2.
const ID_MESSAGE_DIGEST: ObjectIdentifier = rfc5911::ID_MESSAGE_DIGEST;
/// `id-signedData` — RFC 5652 §5.1.
const ID_SIGNED_DATA: ObjectIdentifier = rfc5911::ID_SIGNED_DATA;

/// What T2 establishes about a token, for A9 and the verdict layer.
///
/// Every field is a *statement the token's own signature covers*, except
/// `chain_material`, which is explicitly untrusted input to A9's path build:
/// the `.sealproof` bundle is unsigned (D8), so any relay can add or reorder
/// a certificate, and nothing here may treat the bag's contents or its order
/// as authoritative.
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    gen_time: GeneralizedTime,
    policy: ObjectIdentifier,
    serial_number: Vec<u8>,
    signer: Certificate,
    signer_der: Vec<u8>,
    chain_material: Vec<Certificate>,
    signature_alg: SignatureAlg,
    ess_checked: EssVersion,
}

impl VerifiedToken {
    /// The claimed stamping time, as the token states it.
    ///
    /// **Never compare this to a local clock** (A32). A9 evaluates the
    /// certificate chain *at* this instant, which is its only use.
    #[must_use]
    pub const fn gen_time(&self) -> GeneralizedTime {
        self.gen_time
    }

    /// `genTime` as whole seconds since the Unix epoch.
    #[must_use]
    pub fn gen_time_unix(&self) -> u64 {
        self.gen_time.to_unix_duration().as_secs()
    }

    /// The TSA policy the token was issued under.
    #[must_use]
    pub const fn policy(&self) -> ObjectIdentifier {
        self.policy
    }

    /// The token's serial number, as DER INTEGER content octets. Not an
    /// integer: DigiCert's real serial is 17 octets.
    #[must_use]
    pub fn serial_number(&self) -> &[u8] {
        &self.serial_number
    }

    /// The certificate that signed the token, located by `SignerInfo.sid`
    /// and bound by the ESS attribute.
    #[must_use]
    pub const fn signer(&self) -> &Certificate {
        &self.signer
    }

    /// The signer certificate's DER encoding.
    #[must_use]
    pub fn signer_der(&self) -> &[u8] {
        &self.signer_der
    }

    /// Every certificate the token carried, in no meaningful order, for A9
    /// to build paths from. **Untrusted**: bundle-embedded certificates are
    /// consumed strictly as intermediates and never as trust anchors — and
    /// that is not hypothetical, FreeTSA ships its own self-signed root in
    /// the bag as a candidate.
    #[must_use]
    pub fn chain_material(&self) -> &[Certificate] {
        &self.chain_material
    }

    /// The algorithm the token's signature was verified under.
    #[must_use]
    pub const fn signature_alg(&self) -> SignatureAlg {
        self.signature_alg
    }

    /// Which ESS attribute bound the signer. Diagnostic: both are accepted,
    /// and v1 is not weaker in this design (see [`super::ess`]).
    #[must_use]
    pub const fn ess_checked(&self) -> EssVersion {
        self.ess_checked
    }
}

/// Verify an RFC 3161 timestamp artifact against a seal's `anchor_digest`.
///
/// `artifact` is the bundle's `token` field (registry §7.9 key 1) or a
/// capture-path `TimeStampResp`; both shapes are accepted, see
/// [`token_content_info`].
///
/// The check order is D60 §7.6's, exactly: a failure at any step renders
/// **that anchor** `invalid` (F3) and nothing else (F2).
///
/// # Errors
///
/// One of the `anchor-` codes in [`AnchorError`]. Adversarial input never
/// panics: every fallible step returns a typed error, no slice is indexed
/// without a length check, and no recursive DER traversal exists to overflow
/// the stack.
pub fn verify_token(
    artifact: &[u8],
    anchor_digest: &[u8; 32],
    expected_nonce: Option<&[u8]>,
) -> Result<VerifiedToken, AnchorError> {
    // 1-2. Strict-DER parse and the response status (in `token_content_info`).
    let content_info = token_content_info(artifact)?;

    // 3. ContentInfo -> SignedData.
    if content_info.content_type != ID_SIGNED_DATA {
        return Err(AnchorError::NotSignedData {
            oid: content_info.content_type,
        });
    }
    let signed_data: SignedData = content_info
        .content
        .decode_as()
        .map_err(|e| der_error(DerSite::SignedData, e))?;

    // 3b. Exactly one signer. RFC 3161 §2.4.2 admits one signer for a
    // timestamp token, and several would make "the signer certificate"
    // ambiguous — which is the whole thing the ESS attribute exists to fix.
    let signer = single_signer(&signed_data)?;
    let signed_attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or(AnchorError::SignedAttrsAbsent)?;
    if signed_attrs.len() > MAX_SIGNED_ATTRS {
        return Err(AnchorError::SignedAttrCount {
            count: signed_attrs.len(),
        });
    }

    // 4. The certificate bag, with both (b)-class limits.
    let (chain_material, chain_der) = chain_certificates(&signed_data)?;

    // 5. The algorithm registry, BEFORE any signature verification, so an
    // unsupported algorithm is a distinct code and not a verification
    // failure that reads as forgery.
    for d in signed_data.digest_algorithms.iter() {
        alg::digest(d, AlgPosition::SignedDataDigests)?;
    }
    let signer_digest = alg::digest(&signer.digest_alg, AlgPosition::SignerDigest)?;
    let signature_alg = alg::signature(
        &signer.signature_algorithm,
        AlgPosition::SignerSignature,
        false,
    )?;
    // Bare `rsaEncryption` leaves the digest to `SignerInfo.digestAlgorithm`
    // (RFC 5754 §3.2); an explicit `shaNNNWith…` names its own and that name
    // wins. No consistency rule is imposed between the two: D60 §3.2.6 is
    // explicit that `digestAlgorithm` is self-checking in both of its uses
    // and that A8 must take no other decision from it.
    let signature_digest = signature_alg.digest.unwrap_or(signer_digest);

    // 6. Locate the signer certificate and bind it.
    let SignerIdentifier::IssuerAndSerialNumber(isn) = &signer.sid else {
        // `subjectKeyIdentifier` has no fixture among the nine live TSAs, and
        // an algorithm branch whose only fixture is one antseal generated for
        // itself cannot be validated (D60 §4's standard).
        return Err(AnchorError::SignerIdUnsupported);
    };
    let sid_issuer_der = ess::name_der(&isn.issuer)?;
    let sid = SignerId {
        issuer_der: &sid_issuer_der,
        serial: isn.serial_number.as_bytes(),
    };
    let (signer_cert, signer_cert_der) = find_signer_cert(sid, &chain_material, &chain_der)?;
    let ess_checked = check_ess_binding(signed_attrs, &signer_cert_der, sid)?;

    // 7. The signed attributes' content bindings, then the TSTInfo.
    let econtent = encapsulated_tst_info(&signed_data)?;
    check_content_type_attr(signed_attrs, &signed_data)?;
    check_message_digest_attr(signed_attrs, econtent, signer_digest)?;

    let tst_info = TstInfo::parse(econtent)?;
    check_message_imprint(&tst_info, anchor_digest)?;
    check_nonce(&tst_info, expected_nonce)?;

    // 8. The signature, over the DER `SET OF` re-encoding of signedAttrs
    // (RFC 5652 §5.4) — NOT over the wire bytes of the `[0] IMPLICIT` field.
    let signed_attrs_der = signed_attrs
        .to_der()
        .map_err(|e| der_error(DerSite::SignedAttrs, e))?;
    verify_signature(
        signature_alg.family,
        signature_digest,
        signer_cert.tbs_certificate().subject_public_key_info(),
        &signed_attrs_der,
        signer.signature.as_bytes(),
    )?;

    // 9. Critical EKU `id-kp-timeStamping`, on the SIGNER certificate only.
    check_signer_eku(&signer_cert)?;

    Ok(VerifiedToken {
        gen_time: tst_info.gen_time(),
        policy: tst_info.policy(),
        serial_number: tst_info.serial_number().to_vec(),
        signer: signer_cert,
        signer_der: signer_cert_der,
        chain_material,
        signature_alg,
        ess_checked,
    })
}

/// `signerInfos` must hold exactly one `SignerInfo`.
fn single_signer(sd: &SignedData) -> Result<&SignerInfo, AnchorError> {
    let count = sd.signer_infos.0.len();
    let mut iter = sd.signer_infos.0.iter();
    match (iter.next(), iter.next()) {
        (Some(si), None) => Ok(si),
        _ => Err(AnchorError::SignerCount { count }),
    }
}

/// The certificate bag, with the two (b)-class limits D60 §6 ruled.
///
/// The count bounds **every** `CertificateChoices` entry, not only the plain
/// `Certificate` ones. A `[3] other` entry is not path material, but counting
/// it keeps the limit a bound on how much the token can make A9 enumerate,
/// which is what the limit is for (path building is quadratic in candidates).
fn chain_certificates(sd: &SignedData) -> Result<(Vec<Certificate>, Vec<Vec<u8>>), AnchorError> {
    let Some(set) = sd.certificates.as_ref() else {
        return Ok((Vec::new(), Vec::new()));
    };
    let count = set.0.len();
    if count > MAX_CHAIN_CERTS {
        return Err(AnchorError::ChainCertCount { count });
    }
    let mut certs = Vec::with_capacity(count);
    let mut ders = Vec::with_capacity(count);
    for choice in set.0.iter() {
        let cms::cert::CertificateChoices::Certificate(cert) = choice else {
            // Not a plain X.509 certificate: counted above, carried nowhere.
            continue;
        };
        let der = cert
            .to_der()
            .map_err(|e| der_error(DerSite::Certificate, e))?;
        let bytes = u64::try_from(der.len()).unwrap_or(u64::MAX);
        if bytes > u64::from(MAX_CHAIN_CERT_BYTES) {
            return Err(AnchorError::ChainCertSize { bytes });
        }
        certs.push(cert.clone());
        ders.push(der);
    }
    Ok((certs, ders))
}

/// Find the certificate `SignerInfo.sid` names.
///
/// **Position in the bag means nothing.** The signer is entry 1 for six of
/// the nine live TSAs, entry 2 for DFN and entry 3 for SwissSign, so a
/// leaf-first assumption is wrong for two of the spec's three documented
/// alternates — and `cms` re-sorts the SET on decode anyway, so even the wire
/// order is gone by the time this runs.
fn find_signer_cert(
    sid: SignerId<'_>,
    certs: &[Certificate],
    ders: &[Vec<u8>],
) -> Result<(Certificate, Vec<u8>), AnchorError> {
    for (cert, der) in certs.iter().zip(ders) {
        let tbs = cert.tbs_certificate();
        if tbs.serial_number().as_bytes() == sid.serial
            && ess::name_der(tbs.issuer())? == sid.issuer_der
        {
            return Ok((cert.clone(), der.clone()));
        }
    }
    Err(AnchorError::SignerCertNotFound)
}

/// Exactly one attribute of the given type, or `None` when absent.
///
/// `SignedAttributes` is a `SetOfVec`, whose decode **canonicalises order and
/// preserves duplicates** (`der`'s own test is named
/// `der_sort_preserves_duplicates`), so a duplicate attribute type reaches
/// here intact and must be rejected explicitly. RFC 5652 §5.3 permits each
/// attribute type at most once.
fn unique_attr<'a>(
    attrs: &'a SetOfVec<x509_cert::attr::Attribute>,
    oid: ObjectIdentifier,
    id: SignedAttrId,
) -> Result<Option<&'a SetOfVec<Any>>, AnchorError> {
    let mut found = None;
    for attr in attrs.iter() {
        if attr.oid != oid {
            continue;
        }
        if found.is_some() {
            return Err(AnchorError::DuplicateSignedAttr { attr: id });
        }
        found = Some(&attr.values);
    }
    Ok(found)
}

/// Exactly one value inside an attribute.
fn single_value<'a>(
    values: &'a SetOfVec<Any>,
    id: SignedAttrId,
) -> Result<&'a Any, AnchorError> {
    let mut iter = values.iter();
    match (iter.next(), iter.next()) {
        (Some(v), None) => Ok(v),
        _ => Err(AnchorError::SignedAttrNotSingleValued { attr: id }),
    }
}

/// The `content-type` signed attribute must equal `eContentType`.
fn check_content_type_attr(
    attrs: &SetOfVec<x509_cert::attr::Attribute>,
    sd: &SignedData,
) -> Result<(), AnchorError> {
    let values = unique_attr(attrs, ID_CONTENT_TYPE, SignedAttrId::ContentType)?
        .ok_or(AnchorError::ContentTypeAttrMissing)?;
    let value = single_value(values, SignedAttrId::ContentType)?;
    let declared: ObjectIdentifier = value
        .decode_as()
        .map_err(|e| der_error(DerSite::SignedAttrs, e))?;
    if declared != sd.encap_content_info.econtent_type {
        return Err(AnchorError::ContentTypeAttrMismatch);
    }
    Ok(())
}

/// The `message-digest` signed attribute must equal the digest of the
/// encapsulated content under `SignerInfo.digestAlgorithm`.
///
/// This is the link that makes the signature cover the `TSTInfo` at all: the
/// signature is over `signedAttrs`, and `signedAttrs` reaches the content
/// only through this one 32/48/64-byte comparison.
fn check_message_digest_attr(
    attrs: &SetOfVec<x509_cert::attr::Attribute>,
    econtent: &[u8],
    digest: Digest,
) -> Result<(), AnchorError> {
    let values = unique_attr(attrs, ID_MESSAGE_DIGEST, SignedAttrId::MessageDigest)?
        .ok_or(AnchorError::MessageDigestAttrMissing)?;
    let value = single_value(values, SignedAttrId::MessageDigest)?;
    let declared: der::asn1::OctetString = value
        .decode_as()
        .map_err(|e| der_error(DerSite::SignedAttrs, e))?;
    let computed = hash(digest, econtent);
    if declared.as_bytes() != computed.as_slice() {
        return Err(AnchorError::MessageDigestAttrMismatch);
    }
    Ok(())
}

/// The `TSTInfo` octets out of `encapContentInfo`.
fn encapsulated_tst_info(sd: &SignedData) -> Result<&[u8], AnchorError> {
    if sd.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return Err(AnchorError::NotTstInfo {
            oid: sd.encap_content_info.econtent_type,
        });
    }
    let econtent = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(AnchorError::EContentAbsent)?;
    // RFC 5652 §5.2: `eContent [0] EXPLICIT OCTET STRING`. The digest in the
    // message-digest attribute is over the octets *comprising the value* of
    // that OCTET STRING — not its tag and length — so the tag is checked
    // here and `value()` is what everything downstream uses.
    if econtent.tag() != der::Tag::OctetString {
        return Err(AnchorError::EContentAbsent);
    }
    Ok(econtent.value())
}

/// `TSTInfo.messageImprint` must be SHA-256 over exactly this seal's
/// `anchor_digest`.
///
/// D53 §8 fixes that this fires at stage T2, before any chain rule, so a
/// token for a different digest is never classified by its chain.
fn check_message_imprint(tst: &TstInfo, anchor_digest: &[u8; 32]) -> Result<(), AnchorError> {
    let imprint = tst.message_imprint();
    // SHA-256 exactly: A4 always requests it and `anchor_digest` is SHA-256.
    alg::digest(&imprint.hash_algorithm, AlgPosition::MessageImprint)?;
    if imprint.hashed_message.as_bytes() != anchor_digest.as_slice() {
        return Err(AnchorError::ImprintMismatch);
    }
    Ok(())
}

/// The conditional nonce comparison of D59 §1.
///
/// With `None` this function reads the field and returns `Ok(())` no matter
/// what it holds — no branch, no state, no code. With `Some`, absence is a
/// mismatch: "nothing to compare" is how a replayed token gets accepted.
fn check_nonce(tst: &TstInfo, expected: Option<&[u8]>) -> Result<(), AnchorError> {
    let Some(expected) = expected else {
        // Parsed above by `TstInfo::parse`; deliberately unread here.
        let _ = tst.nonce();
        return Ok(());
    };
    match tst.nonce() {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(AnchorError::NonceMismatch),
    }
}

/// The signer certificate must carry a **critical** `extendedKeyUsage`
/// containing `id-kp-timeStamping` (RFC 3161 §2.3).
///
/// The rule binds the **signer** certificate and nothing else. All nine live
/// signer certificates satisfy it, but **DigiCert's intermediate carries a
/// non-critical EKU**, so the same rule applied chain-wide rejects a default
/// TSA. A9 checks CA certificates under its own rules; this is not one of
/// them.
fn check_signer_eku(cert: &Certificate) -> Result<(), AnchorError> {
    let found = cert
        .tbs_certificate()
        .get_extension::<ExtendedKeyUsage>()
        .map_err(|e| der_error(DerSite::Extension, e))?;
    let (critical, eku) = found.ok_or(AnchorError::EkuMissing)?;
    if !critical {
        return Err(AnchorError::EkuNotCritical);
    }
    if !eku.0.iter().any(|o| *o == ID_KP_TIME_STAMPING) {
        return Err(AnchorError::EkuNotTimeStamping);
    }
    Ok(())
}

/// The ESS binding: at least one of the two attributes must be present, and
/// the one that is must identify the signer.
///
/// When **both** are present — DigiCert and Certum send both — both are
/// checked. Checking only one would let a token carry a correct v2 attribute
/// beside a v1 attribute naming a different certificate, which is a signed
/// contradiction the verifier should not silently pick a side in.
fn check_ess_binding(
    attrs: &SetOfVec<x509_cert::attr::Attribute>,
    signer_der: &[u8],
    sid: SignerId<'_>,
) -> Result<EssVersion, AnchorError> {
    let v1 = unique_attr(
        attrs,
        ess::ID_AA_SIGNING_CERTIFICATE,
        SignedAttrId::SigningCertificate,
    )?;
    let v2 = unique_attr(
        attrs,
        ess::ID_AA_SIGNING_CERTIFICATE_V2,
        SignedAttrId::SigningCertificateV2,
    )?;
    match (v1, v2) {
        (None, None) => Err(AnchorError::EssCertMissing),
        (Some(values), None) => {
            ess::check_signing_certificate(EssVersion::V1, values, signer_der, sid)?;
            Ok(EssVersion::V1)
        }
        (None, Some(values)) => {
            ess::check_signing_certificate(EssVersion::V2, values, signer_der, sid)?;
            Ok(EssVersion::V2)
        }
        (Some(a), Some(b)) => {
            ess::check_signing_certificate(EssVersion::V1, a, signer_der, sid)?;
            ess::check_signing_certificate(EssVersion::V2, b, signer_der, sid)?;
            Ok(EssVersion::V2)
        }
    }
}

/// Compute one of the registry's digests.
fn hash(digest: Digest, msg: &[u8]) -> Vec<u8> {
    match digest {
        Digest::Sha256 => Sha256::digest(msg).to_vec(),
        Digest::Sha384 => Sha384::digest(msg).to_vec(),
        Digest::Sha512 => Sha512::digest(msg).to_vec(),
    }
}

/// Verify a signature under the signer's `SubjectPublicKeyInfo`.
///
/// The key type is resolved from the SPKI and must agree with the family the
/// signature algorithm named — an ECDSA signature declared over an RSA key is
/// [`AnchorError::KeyAlgMismatch`], not a verification failure, because
/// "verification failed" reads as forgery and this is a malformed claim.
fn verify_signature(
    family: SigFamily,
    digest: Digest,
    spki: &SubjectPublicKeyInfoOwned,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), AnchorError> {
    if alg::public_key_family(&spki.algorithm)? != family {
        return Err(AnchorError::KeyAlgMismatch);
    }
    // A BIT STRING with unused bits has no `as_bytes`; `der` already rejects
    // `unused > 7`, and a key or signature is always whole octets.
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(AnchorError::SpkiUnsupported {
            oid: spki.algorithm.oid,
        })?;
    match family {
        SigFamily::RsaPkcs1v15 => verify_rsa(digest, key_bytes, msg, sig),
        SigFamily::EcdsaP384 => verify_ecdsa_p384(digest, key_bytes, msg, sig),
    }
}

fn verify_rsa(digest: Digest, key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), AnchorError> {
    use rsa::pkcs1::DecodeRsaPublicKey as _;
    use rsa::signature::Verifier as _;

    // The SPKI BIT STRING for `rsaEncryption` contains a PKCS#1
    // `RSAPublicKey` (RFC 3279 §2.3.1).
    let key = rsa::RsaPublicKey::from_pkcs1_der(key).map_err(|_| AnchorError::SpkiUnsupported {
        oid: alg::RSA_ENCRYPTION,
    })?;
    let signature =
        rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| AnchorError::SignatureInvalid)?;
    let ok = match digest {
        Digest::Sha256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key)
            .verify(msg, &signature)
            .is_ok(),
        Digest::Sha384 => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(key)
            .verify(msg, &signature)
            .is_ok(),
        Digest::Sha512 => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(key)
            .verify(msg, &signature)
            .is_ok(),
    };
    if ok {
        Ok(())
    } else {
        Err(AnchorError::SignatureInvalid)
    }
}

fn verify_ecdsa_p384(
    digest: Digest,
    key: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), AnchorError> {
    use p384::ecdsa::signature::hazmat::PrehashVerifier as _;

    let verifying_key =
        p384::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| AnchorError::SpkiUnsupported {
            oid: alg::ID_EC_PUBLIC_KEY,
        })?;
    let signature =
        p384::ecdsa::Signature::from_der(sig).map_err(|_| AnchorError::SignatureInvalid)?;
    // `verify_prehash` takes the FULL digest and applies FIPS 186-5 §6.4
    // leftmost-bits truncation itself, which is what makes SHA-512 on a
    // P-384 key — FreeTSA's real pairing — work without antseal truncating
    // anything by hand.
    let prehash = hash(digest, msg);
    verifying_key
        .verify_prehash(&prehash, &signature)
        .map_err(|_| AnchorError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four OIDs this module compares against, spelled out. Every one of
    /// them fails *open-looking* if wrong — a mistyped `id-contentType`
    /// makes the attribute "absent" rather than "mismatched" — so they are
    /// asserted directly rather than trusted to `const-oid`'s naming.
    #[test]
    fn the_compared_oids_are_the_rfc_ones() {
        assert_eq!(ID_SIGNED_DATA.to_string(), "1.2.840.113549.1.7.2");
        assert_eq!(ID_CONTENT_TYPE.to_string(), "1.2.840.113549.1.9.3");
        assert_eq!(ID_MESSAGE_DIGEST.to_string(), "1.2.840.113549.1.9.4");
        assert_eq!(ID_KP_TIME_STAMPING.to_string(), "1.3.6.1.5.5.7.3.8");
    }
}
