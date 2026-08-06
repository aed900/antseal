//! The **signing mock TSA** (task **A59**; completes **A24**'s remaining
//! half), and the test CA it issues from.
//!
//! # Why this lives in `antseal-core`
//!
//! A30's containment rule (`tasks/A.md` A30(c)) is that the seven D60 pins —
//! `der`, `const-oid`, `x509-cert`, `cms`, `p384`, `rsa`, `sha1` — are
//! **declared by `antseal-core` and by no other crate**, read from
//! `cargo metadata --no-deps`. That command reports *every* declared edge,
//! normal and **dev** alike, so "it is only a dev-dependency" is not an
//! exemption: a separate `antseal-mock-tsa` crate would be a second
//! declaration site, and the workspace manifest's own words for that are
//! *"a second declaration site is how that containment erodes"*.
//!
//! The previous lane's conclusion — *"a crate that mints and signs tokens is
//! not `antseal-anchor`"* — is right about `antseal-anchor` and points here
//! rather than at a new crate. Putting the minter in `antseal-core` behind the
//! existing `test-util` feature costs **zero new dependency declarations
//! anywhere**, and puts it next to A6's
//! [`TsaRootStore::from_static`](super::roots::TsaRootStore::from_static),
//! which is gated identically and which every test using this mock needs.
//!
//! # RNG-free, and therefore reproducible
//!
//! The signer keys are fixed 48-byte constants below and ECDSA here is
//! **RFC 6979 deterministic**, so this module draws no randomness at all.
//! Three consequences:
//!
//! - `getrandom`/`rand` stay out of `antseal-core`'s graph, which the
//!   `core-dep-graph` lane's layer-1 prohibition requires;
//! - it compiles for `wasm32-unknown-unknown` under `cfg(test)` — verified
//!   2026-08-05 by `cargo test -p antseal-core --lib --target
//!   wasm32-unknown-unknown --no-run`, which is exactly what
//!   `scripts/wasm-tests.sh` builds, so this module and its tests are inside
//!   the wasm32 lane rather than beside it. (The *other* gate on this module,
//!   `--features test-util`, does **not** build for wasm32 — `test-util`
//!   enables `dep:proptest`, which pulls `getrandom`, which needs a backend
//!   cfg the target does not have. That predates this module and is why the
//!   wasm32 dev-dependency in `Cargo.toml` asks for `test-vectors`, not
//!   `test-util`.)
//! - the same configuration yields **byte-identical** tokens on every run, so
//!   a token minted here is a fixture rather than a source of flakiness.
//!
//! # ECDSA P-384 only, deliberately — and what that costs
//!
//! A24 asks for "RSA and ECDSA P-384 signer variants". This module ships the
//! ECDSA half and **not** the RSA half, for a reason that is not convenience:
//! `tasks/P.md` justifies the mandatory `RUSTSEC-2023-0071` (Marvin) ignore in
//! `deny.toml` by asserting that *"no antseal code path performs an RSA
//! private-key operation … which A30's containment rules keep true"*, and
//! `deny.toml` scans with `all-features = true`. An RSA signer here — even
//! feature-gated, even fixture-only — falsifies the stated premise of a live
//! security exception, which is not a side effect a test helper may have.
//!
//! What that costs is small, and smaller than it was when A24 was written: the
//! RSA path already has **five real RSA tokens** in the committed corpus
//! (DigiCert, Sectigo, Entrust, DFN, Certum) exercising every branch A8 has
//! for it. What a mock uniquely provides is a *controllable* CA, `genTime`,
//! validity window and `PKIStatus` — none of which needs RSA. The RSA signer
//! variant is recorded as owed work (A70) with this reason attached.
//!
//! # Fixture-only key material
//!
//! The two private scalars below are **published constants in a public
//! repository**. They are not vault material, they protect nothing, and they
//! must never be treated as secret — project rule 6 governs `W`, unit keys and
//! salts, and a key whose bytes are in the source tree is categorically not
//! one of those. The [`MockTsa`] root is only ever trusted by a store built
//! with `TsaRootStore::from_static`, which reports
//! [`INJECTED_STORE_VERSION`](super::roots::INJECTED_STORE_VERSION) = 0 and
//! exists in no default build.

use std::str::FromStr;

use const_oid::ObjectIdentifier;
use const_oid::db::{rfc5911, rfc5912};
use der::asn1::{Any, BitString, GeneralizedTime, Int, OctetString, SetOfVec, UtcTime};
use der::{Decode, Encode, Sequence};
use p384::ecdsa::signature::hazmat::PrehashSigner;
use p384::ecdsa::{Signature, SigningKey};
use sha2::{Digest as _, Sha256, Sha384};
use x509_cert::attr::Attribute;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::name::Name;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;

use super::rfc3161::{ID_CT_TST_INFO, MessageImprint};
use super::roots::{PinnedRoot, TsaRootStore};
use super::tsa::ID_KP_TIME_STAMPING;

/// The minimal `.ots` writer (**A82**) — the shapes no captured artifact
/// contains, mintable from the tamper matrix and from integration targets.
///
/// It lives here for the same reason [`MockTsa`] does: under one gate, in the
/// one crate that may declare the D60 pins, reachable from `cfg(test)` (so it
/// is inside the `wasm32-core-tests` `--lib` lane) and from `test-util` (so it
/// is inside `crates/antseal-core/tests/`), and absent from every production
/// build.
pub mod ots_writer;

/// **A21's eight M2 anchor tamper rows** (task **A21**), as exercises rather
/// than as tests.
///
/// It lives here for the reason [`ots_writer`] does, one step further: A21's
/// rows must execute natively *and* on wasm32, and no single home reaches
/// both lanes. Writing each exercise once, under this gate, is what stops the
/// matrix slice and the in-module wasm32 tests from becoming two hand-written
/// copies of one claim.
pub mod tamper_rows;

/// `id-ecPublicKey` (RFC 5480 §2.1.1).
const ID_EC_PUBLIC_KEY: ObjectIdentifier = rfc5912::ID_EC_PUBLIC_KEY;
/// `secp384r1` (RFC 5480 §2.1.1.1).
const SECP_384_R1: ObjectIdentifier = rfc5912::SECP_384_R_1;
/// `ecdsa-with-SHA384`.
const ECDSA_WITH_SHA384: ObjectIdentifier = rfc5912::ECDSA_WITH_SHA_384;
/// `id-sha384`.
const ID_SHA384: ObjectIdentifier = rfc5912::ID_SHA_384;
/// `id-sha256`.
const ID_SHA256: ObjectIdentifier = rfc5912::ID_SHA_256;
/// `id-signedData`.
const ID_SIGNED_DATA: ObjectIdentifier = rfc5911::ID_SIGNED_DATA;
/// `id-contentType`.
const ID_CONTENT_TYPE: ObjectIdentifier = rfc5911::ID_CONTENT_TYPE;
/// `id-messageDigest`.
const ID_MESSAGE_DIGEST: ObjectIdentifier = rfc5911::ID_MESSAGE_DIGEST;
/// `id-aa-signingCertificateV2` (RFC 5035 §3).
const ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
/// `id-basicConstraints`.
const ID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
/// `id-keyUsage`.
const ID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
/// `id-extKeyUsage`.
const ID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
/// An arbitrary TSA policy OID under the ISO example arc — this mock is not
/// any real TSA and must not borrow a real TSA's policy identifier.
const MOCK_TSA_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.1");

/// The mock CA's private scalar. **Fixture-only; published; not a secret.**
const CA_SCALAR: [u8; 48] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
];

/// The mock signer's private scalar. **Fixture-only; published; not a secret.**
const SIGNER_SCALAR: [u8; 48] = [
    0x21, 0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12,
    0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
    0x01, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
];

/// What a caller wants the mock to do. Every field is a lever A24's Accept
/// row names ("controllable `genTime`, `PKIStatus`, and failure modes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockTsaConfig {
    /// The `genTime` the token asserts, POSIX seconds.
    pub gen_time_unix: u64,
    /// The `PKIStatus` of the response. `0` is granted, `1` is
    /// granted-with-mods, anything else is a rejection with no token.
    pub status: u32,
    /// The signer certificate's validity window, POSIX seconds.
    pub signer_validity: (u64, u64),
    /// The CA certificate's validity window, POSIX seconds.
    pub ca_validity: (u64, u64),
    /// How the signer certificate carries `extendedKeyUsage`.
    pub eku: MockEku,
    /// Whether the certificate bag includes the CA certificate. With it
    /// absent, a verifier holding only the pinned root can still build the
    /// path only if it was given the CA elsewhere — the lever A21 row 3 and
    /// A9's "junk intermediate" cases need.
    pub include_ca_cert: bool,
    /// Whether to echo the request's nonce. `false` is the replay lever: the
    /// token is otherwise perfect and the capture path must still refuse it.
    pub echo_nonce: bool,
}

/// How the mock's signer certificate carries `extendedKeyUsage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockEku {
    /// Critical, containing `id-kp-timeStamping` — RFC 3161 §2.3's rule.
    CriticalTimeStamping,
    /// Present and containing the right purpose, but **not** critical.
    NonCritical,
    /// Critical, but naming a different purpose.
    WrongPurpose,
    /// Absent entirely.
    Absent,
}

/// A validity window comfortably around [`DEFAULT_GEN_TIME`].
const DEFAULT_WINDOW: (u64, u64) = (1_700_000_000, 1_900_000_000);

/// The default `genTime`: 2026-08-03T08:40:00Z, inside [`DEFAULT_WINDOW`] and
/// chosen as a literal so no test ever reads a clock.
pub const DEFAULT_GEN_TIME: u64 = 1_785_000_000;

impl Default for MockTsaConfig {
    fn default() -> Self {
        Self {
            gen_time_unix: DEFAULT_GEN_TIME,
            status: 0,
            signer_validity: DEFAULT_WINDOW,
            ca_validity: DEFAULT_WINDOW,
            eku: MockEku::CriticalTimeStamping,
            include_ca_cert: true,
            echo_nonce: true,
        }
    }
}

/// A TSA that really signs.
///
/// Built from the fixed keys above and one [`MockTsaConfig`], so the CA and
/// signer certificates are minted once and every response reuses them.
#[derive(Debug, Clone)]
pub struct MockTsa {
    config: MockTsaConfig,
    ca_cert_der: Vec<u8>,
    signer_cert_der: Vec<u8>,
    serial: u64,
}

/// The mock could not be driven — always a defect in the *test*, never a
/// property of the artifact under test.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MockTsaError {
    /// A DER encoding step failed.
    #[error("mock TSA: DER encoding failed: {0}")]
    Der(String),
    /// The request handed to [`MockTsa::respond`] is not a `TimeStampReq`.
    #[error("mock TSA: the request is not a well-formed TimeStampReq: {0}")]
    Request(String),
}

impl MockTsa {
    /// Build a mock TSA with the given configuration.
    ///
    /// # Errors
    ///
    /// [`MockTsaError::Der`] if certificate minting fails, which it cannot for
    /// any value this type can hold.
    pub fn new(config: MockTsaConfig) -> Result<Self, MockTsaError> {
        let ca_key = signing_key(&CA_SCALAR);
        let signer_key = signing_key(&SIGNER_SCALAR);
        let ca_name = name("CN=antseal mock TSA root CA,O=antseal fixtures")?;
        let signer_name = name("CN=antseal mock TSA signer,O=antseal fixtures")?;

        let ca_cert_der = mint_certificate(
            &ca_key,
            &ca_name,
            &ca_name,
            &ca_key,
            1,
            config.ca_validity,
            &ca_extensions()?,
        )?;
        let signer_cert_der = mint_certificate(
            &signer_key,
            &signer_name,
            &ca_name,
            &ca_key,
            2,
            config.signer_validity,
            &signer_extensions(config.eku)?,
        )?;
        Ok(Self {
            config,
            ca_cert_der,
            signer_cert_der,
            serial: 0x0102_0304_0506_0708,
        })
    }

    /// A mock TSA in its default, fully-valid configuration.
    ///
    /// # Errors
    ///
    /// As [`MockTsa::new`].
    pub fn granted() -> Result<Self, MockTsaError> {
        Self::new(MockTsaConfig::default())
    }

    /// The CA certificate's DER — this mock's **root**.
    #[must_use]
    pub fn root_der(&self) -> &[u8] {
        &self.ca_cert_der
    }

    /// The signer certificate's DER.
    #[must_use]
    pub fn signer_der(&self) -> &[u8] {
        &self.signer_cert_der
    }

    /// A [`PinnedRoot`] for this mock's CA, for
    /// [`TsaRootStore::from_static`].
    ///
    /// Leaks the DER, because the const-table API takes `&'static [u8]` and a
    /// test needs some way to satisfy it. A few kilobytes per call is the
    /// right trade for keeping the production type free of lifetimes — the
    /// same trade `anchor::chain`'s own suite already makes.
    #[must_use]
    pub fn pinned_root(&self) -> PinnedRoot {
        let der: &'static [u8] = Box::leak(self.ca_cert_der.clone().into_boxed_slice());
        let cert_sha256 = sha256(der);
        let spki_sha256 = match x509_cert::Certificate::from_der(der) {
            Ok(cert) => cert
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()
                .map_or([0u8; 32], |bytes| sha256(&bytes)),
            Err(_) => [0u8; 32],
        };
        PinnedRoot {
            der,
            cert_sha256,
            spki_sha256,
            label: "antseal-mock-tsa-root",
        }
    }

    /// A root store trusting **only** this mock. Reports
    /// [`INJECTED_STORE_VERSION`](super::roots::INJECTED_STORE_VERSION).
    #[must_use]
    pub fn root_store(&self) -> TsaRootStore {
        let roots: &'static [PinnedRoot] = Box::leak(Box::new([self.pinned_root()]));
        TsaRootStore::from_static(roots)
    }

    /// Answer a DER `TimeStampReq` with a DER `TimeStampResp`.
    ///
    /// The imprint and (unless [`MockTsaConfig::echo_nonce`] is off) the nonce
    /// are taken **from the request**, which is what lets a capture client
    /// draw a fresh nonce and still be answered — the thing a replayed
    /// recording can never do.
    ///
    /// # Errors
    ///
    /// [`MockTsaError::Request`] if the request is not a `TimeStampReq`;
    /// [`MockTsaError::Der`] on an encoding failure.
    pub fn respond(&self, request: &[u8]) -> Result<Vec<u8>, MockTsaError> {
        let parsed = TimeStampReqView::from_der(request)
            .map_err(|e| MockTsaError::Request(e.to_string()))?;
        let nonce = if self.config.echo_nonce {
            parsed.nonce.clone()
        } else {
            // A nonce one greater than the request's — present, well-formed
            // and wrong, which is the shape a replay looks like.
            parsed
                .nonce
                .as_ref()
                .map(|n| {
                    let mut bytes = n.as_bytes().to_vec();
                    if let Some(last) = bytes.last_mut() {
                        *last = last.wrapping_add(1);
                    }
                    Int::new(&bytes).unwrap_or_else(|_| n.clone())
                })
                .or_else(|| Int::new(&[0x01]).ok())
        };
        self.respond_to(&parsed.message_imprint, nonce)
    }

    /// Answer without a request — for tests that want a token over a chosen
    /// digest and nonce.
    ///
    /// # Errors
    ///
    /// [`MockTsaError::Der`] on an encoding failure.
    pub fn issue(
        &self,
        anchor_digest: &[u8; 32],
        nonce: Option<&[u8]>,
    ) -> Result<Vec<u8>, MockTsaError> {
        let imprint = MessageImprint {
            hash_algorithm: alg_id(ID_SHA256),
            hashed_message: OctetString::new(anchor_digest.as_slice()).map_err(der_err)?,
        };
        let nonce = match nonce {
            Some(bytes) => Some(Int::new(bytes).map_err(der_err)?),
            None => None,
        };
        self.respond_to(&imprint, nonce)
    }

    fn respond_to(
        &self,
        imprint: &MessageImprint,
        nonce: Option<Int>,
    ) -> Result<Vec<u8>, MockTsaError> {
        if self.config.status > 1 {
            // A rejection carries no token at all.
            return TimeStampRespView {
                status: PkiStatusInfoView {
                    status: self.config.status,
                },
                token: None,
            }
            .to_der()
            .map_err(der_err);
        }

        let tst_info = TstInfoView {
            version: 1,
            policy: MOCK_TSA_POLICY,
            message_imprint: imprint.clone(),
            serial_number: Int::new(&self.serial.to_be_bytes()).map_err(der_err)?,
            gen_time: GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(
                self.config.gen_time_unix,
            ))
            .map_err(der_err)?,
            nonce,
        };
        let econtent = tst_info.to_der().map_err(der_err)?;

        let signed_attrs = self.signed_attributes(&econtent)?;
        let signed_attrs_der = signed_attrs.to_der().map_err(der_err)?;
        let signature = sign(&signing_key(&SIGNER_SCALAR), &signed_attrs_der);

        let mut certificates = Vec::new();
        certificates.push(Any::from_der(&self.signer_cert_der).map_err(der_err)?);
        if self.config.include_ca_cert {
            certificates.push(Any::from_der(&self.ca_cert_der).map_err(der_err)?);
        }
        let signer_cert =
            x509_cert::Certificate::from_der(&self.signer_cert_der).map_err(der_err)?;

        let signed_data = SignedDataView {
            version: 3,
            digest_algorithms: set_of(alg_id(ID_SHA384))?,
            encap_content_info: EncapContentInfoView {
                econtent_type: ID_CT_TST_INFO,
                econtent: Some(OctetString::new(econtent.as_slice()).map_err(der_err)?),
            },
            certificates: Some(certificates),
            signer_infos: set_of(
                Any::from_der(
                    &SignerInfoView {
                        version: 1,
                        sid: IssuerAndSerialView {
                            issuer: signer_cert.tbs_certificate().issuer().clone(),
                            serial_number: Int::new(
                                signer_cert.tbs_certificate().serial_number().as_bytes(),
                            )
                            .map_err(der_err)?,
                        },
                        digest_algorithm: alg_id(ID_SHA384),
                        signed_attrs: Some(signed_attrs),
                        signature_algorithm: alg_id(ECDSA_WITH_SHA384),
                        signature: OctetString::new(signature.as_slice()).map_err(der_err)?,
                    }
                    .to_der()
                    .map_err(der_err)?,
                )
                .map_err(der_err)?,
            )?,
        };

        let content_info = ContentInfoView {
            content_type: ID_SIGNED_DATA,
            content: Any::from_der(&signed_data.to_der().map_err(der_err)?).map_err(der_err)?,
        };
        TimeStampRespView {
            status: PkiStatusInfoView {
                status: self.config.status,
            },
            token: Some(Any::from_der(&content_info.to_der().map_err(der_err)?).map_err(der_err)?),
        }
        .to_der()
        .map_err(der_err)
    }

    fn signed_attributes(&self, econtent: &[u8]) -> Result<SetOfVec<Attribute>, MockTsaError> {
        let content_type = attribute(ID_CONTENT_TYPE, &ID_CT_TST_INFO.to_der().map_err(der_err)?)?;
        let digest = OctetString::new(Sha384::digest(econtent).as_slice()).map_err(der_err)?;
        let message_digest = attribute(ID_MESSAGE_DIGEST, &digest.to_der().map_err(der_err)?)?;
        // `SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }`
        // with `ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256,
        // certHash OCTET STRING }` — the default omitted, which is the shape
        // DFN emits and A8 must accept.
        let cert_hash =
            OctetString::new(sha256(&self.signer_cert_der).as_slice()).map_err(der_err)?;
        let ess = SigningCertificateV2View {
            certs: vec![EssCertIdV2View { cert_hash }],
        };
        let signing_cert = attribute(
            ID_AA_SIGNING_CERTIFICATE_V2,
            &ess.to_der().map_err(der_err)?,
        )?;
        SetOfVec::try_from(vec![content_type, message_digest, signing_cert]).map_err(der_err)
    }
}

// ─── ASN.1 mirrors ──────────────────────────────────────────────────────────
//
// `cms`'s and `x509-cert`'s own types are parse-shaped: `TbsCertificateInner`'s
// fields are `pub(crate)` in 0.3 and construction runs through a `builder`
// feature this workspace does not enable. Mirroring the few SEQUENCEs the mock
// emits is cheaper than turning on a feature and its `std`/`sha1`/`signature`
// closure — and it keeps the emitted shapes visible at the byte level, which is
// the point of a fixture generator.

#[derive(Sequence)]
struct TbsCertificateView {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    version: u8,
    serial_number: Int,
    signature: AlgorithmIdentifierOwned,
    issuer: Name,
    validity: ValidityView,
    subject: Name,
    subject_public_key_info: Any,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT")]
    extensions: Vec<Extension>,
}

/// `Validity ::= SEQUENCE { notBefore Time, notAfter Time }`. Mirrored
/// because `x509_cert::time::Validity`'s fields are `pub(crate)` in 0.3 and
/// its only public constructor is behind the `builder` feature.
#[derive(Sequence)]
struct ValidityView {
    not_before: Time,
    not_after: Time,
}

#[derive(Sequence)]
struct CertificateView {
    tbs_certificate: Any,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: BitString,
}

#[derive(Sequence)]
struct SubjectPublicKeyInfoView {
    algorithm: AlgorithmIdentifierOwned,
    subject_public_key: BitString,
}

#[derive(Sequence, Clone)]
struct TimeStampReqView {
    version: u8,
    message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    req_policy: Option<ObjectIdentifier>,
    #[asn1(optional = "true")]
    nonce: Option<Int>,
    #[asn1(default = "bool::default")]
    cert_req: bool,
}

#[derive(Sequence)]
struct TstInfoView {
    version: u8,
    policy: ObjectIdentifier,
    message_imprint: MessageImprint,
    serial_number: Int,
    gen_time: GeneralizedTime,
    #[asn1(optional = "true")]
    nonce: Option<Int>,
}

#[derive(Sequence)]
struct PkiStatusInfoView {
    status: u32,
}

#[derive(Sequence)]
struct TimeStampRespView {
    status: PkiStatusInfoView,
    #[asn1(optional = "true")]
    token: Option<Any>,
}

#[derive(Sequence)]
struct ContentInfoView {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    content: Any,
}

#[derive(Sequence)]
struct EncapContentInfoView {
    econtent_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    econtent: Option<OctetString>,
}

#[derive(Sequence)]
struct IssuerAndSerialView {
    issuer: Name,
    serial_number: Int,
}

#[derive(Sequence)]
struct SignerInfoView {
    version: u8,
    sid: IssuerAndSerialView,
    digest_algorithm: AlgorithmIdentifierOwned,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    signed_attrs: Option<SetOfVec<Attribute>>,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: OctetString,
}

#[derive(Sequence)]
struct SignedDataView {
    version: u8,
    digest_algorithms: SetOfVec<AlgorithmIdentifierOwned>,
    encap_content_info: EncapContentInfoView,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    certificates: Option<Vec<Any>>,
    signer_infos: SetOfVec<Any>,
}

#[derive(Sequence)]
struct EssCertIdV2View {
    cert_hash: OctetString,
}

#[derive(Sequence)]
struct SigningCertificateV2View {
    certs: Vec<EssCertIdV2View>,
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn der_err<E: core::fmt::Display>(error: E) -> MockTsaError {
    MockTsaError::Der(error.to_string())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn signing_key(scalar: &[u8; 48]) -> SigningKey {
    SigningKey::from_slice(scalar).unwrap_or_else(|_| {
        // Both constants are valid P-384 scalars; a change that broke that
        // would break every test in the crate loudly, which is the intent.
        panic!("the committed fixture scalar is not a valid P-384 key")
    })
}

/// RFC 6979 deterministic ECDSA over SHA-384. No RNG anywhere.
fn sign(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let prehash = Sha384::digest(message);
    let signature: Signature = key
        .sign_prehash(&prehash)
        .unwrap_or_else(|_| panic!("signing a 48-byte prehash with a valid key cannot fail"));
    signature.to_der().as_bytes().to_vec()
}

fn alg_id(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
    // `parameters: None` for both SHA-2 (RFC 5754 §2: absent is preferred) and
    // ECDSA (RFC 5758 §3.2: MUST be absent).
    AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    }
}

fn name(text: &str) -> Result<Name, MockTsaError> {
    Name::from_str(text).map_err(der_err)
}

fn set_of<T: der::DerOrd + Eq>(value: T) -> Result<SetOfVec<T>, MockTsaError> {
    SetOfVec::try_from(vec![value]).map_err(der_err)
}

fn attribute(oid: ObjectIdentifier, value_der: &[u8]) -> Result<Attribute, MockTsaError> {
    Ok(Attribute {
        oid,
        values: set_of(Any::from_der(value_der).map_err(der_err)?)?,
    })
}

fn extension(
    oid: ObjectIdentifier,
    critical: bool,
    value_der: &[u8],
) -> Result<Extension, MockTsaError> {
    Ok(Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value_der).map_err(der_err)?,
    })
}

fn ca_extensions() -> Result<Vec<Extension>, MockTsaError> {
    let bc = BasicConstraints {
        ca: true,
        path_len_constraint: None,
    };
    Ok(vec![
        extension(ID_BASIC_CONSTRAINTS, true, &bc.to_der().map_err(der_err)?)?,
        extension(
            ID_KEY_USAGE,
            true,
            &KeyUsage(KeyUsages::KeyCertSign.into())
                .to_der()
                .map_err(der_err)?,
        )?,
    ])
}

fn signer_extensions(eku: MockEku) -> Result<Vec<Extension>, MockTsaError> {
    // Deliberately **no** `basicConstraints` on the signer: SwissSign's real
    // leaf has none, so requiring one rejects a documented alternate (D60).
    // The mock matches the real shape rather than the tidy one.
    let purpose = match eku {
        MockEku::WrongPurpose => rfc5912::ID_KP_CLIENT_AUTH,
        _ => ID_KP_TIME_STAMPING,
    };
    let value = ExtendedKeyUsage(vec![purpose]).to_der().map_err(der_err)?;
    Ok(match eku {
        MockEku::Absent => Vec::new(),
        MockEku::NonCritical => vec![extension(ID_EXT_KEY_USAGE, false, &value)?],
        MockEku::CriticalTimeStamping | MockEku::WrongPurpose => {
            vec![extension(ID_EXT_KEY_USAGE, true, &value)?]
        }
    })
}

fn validity(window: (u64, u64)) -> Result<ValidityView, MockTsaError> {
    let at = |secs: u64| -> Result<Time, MockTsaError> {
        Ok(Time::UtcTime(
            UtcTime::from_unix_duration(core::time::Duration::from_secs(secs)).map_err(der_err)?,
        ))
    };
    Ok(ValidityView {
        not_before: at(window.0)?,
        not_after: at(window.1)?,
    })
}

fn spki(key: &SigningKey) -> Result<Vec<u8>, MockTsaError> {
    // `to_sec1_point(false)` — the UNCOMPRESSED form, and explicitly so:
    // `to_sec1_bytes()` would take the curve's `PointCompression` default, and
    // an SPKI whose point encoding depends on a crate default is a fixture
    // whose bytes can change under a dependency bump.
    let point = key.verifying_key().to_sec1_point(false);
    SubjectPublicKeyInfoView {
        algorithm: AlgorithmIdentifierOwned {
            oid: ID_EC_PUBLIC_KEY,
            parameters: Some(
                Any::from_der(&SECP_384_R1.to_der().map_err(der_err)?).map_err(der_err)?,
            ),
        },
        subject_public_key: BitString::from_bytes(point.as_bytes()).map_err(der_err)?,
    }
    .to_der()
    .map_err(der_err)
}

#[allow(clippy::too_many_arguments)]
fn mint_certificate(
    subject_key: &SigningKey,
    subject: &Name,
    issuer: &Name,
    issuer_key: &SigningKey,
    serial: u8,
    window: (u64, u64),
    extensions: &[Extension],
) -> Result<Vec<u8>, MockTsaError> {
    let spki_der = spki(subject_key)?;
    let tbs = TbsCertificateView {
        version: 2, // v3
        serial_number: Int::new(&[serial]).map_err(der_err)?,
        signature: alg_id(ECDSA_WITH_SHA384),
        issuer: issuer.clone(),
        validity: validity(window)?,
        subject: subject.clone(),
        subject_public_key_info: Any::from_der(&spki_der).map_err(der_err)?,
        extensions: extensions.to_vec(),
    };
    let tbs_der = tbs.to_der().map_err(der_err)?;
    let signature = sign(issuer_key, &tbs_der);
    CertificateView {
        // `Any` re-emits the exact bytes that were signed — the one place a
        // re-encode would silently invalidate the signature.
        tbs_certificate: Any::from_der(&tbs_der).map_err(der_err)?,
        signature_algorithm: alg_id(ECDSA_WITH_SHA384),
        signature: BitString::from_bytes(&signature).map_err(der_err)?,
    }
    .to_der()
    .map_err(der_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::chain::validate_token_chain;
    use crate::anchor::error::AnchorError;
    use crate::anchor::request::{build_timestamp_req, canonical_request_nonce};
    use crate::anchor::tsa::verify_token;
    use crate::verify::report::AnchorState;

    const DIGEST: [u8; 32] = [0x5A; 32];
    const NONCE: [u8; 8] = [0xE4, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

    /// **A59's whole point.** A token minted here, over a nonce chosen at call
    /// time, verifies through the *unmodified production* pipeline — A8's
    /// `verify_token` with the nonce supplied, then A9's path validation — and
    /// reaches `proven` against a store that pins only this mock's root.
    ///
    /// A replaying stub cannot produce this: it can only echo the nonce of the
    /// request it was recorded from.
    #[test]
    fn a_minted_token_verifies_and_chains_to_the_injected_root() {
        let tsa = MockTsa::granted().expect("mint");
        let request = build_timestamp_req(&DIGEST, &NONCE);
        let response = tsa.respond(&request).expect("respond");

        let nonce = canonical_request_nonce(&NONCE);
        let token = verify_token(&response, &DIGEST, Some(&nonce)).expect("T2 accepts the token");
        assert_eq!(token.gen_time_unix(), DEFAULT_GEN_TIME);

        let store = tsa.root_store();
        let verdict = validate_token_chain(&token, &[], &store, DEFAULT_GEN_TIME);
        assert_eq!(verdict.state(), AnchorState::Proven);
        assert_eq!(verdict.anchor_label(), Some("antseal-mock-tsa-root"));
        assert_eq!(verdict.root_store_version(), 0, "an injected store is v0");
    }

    /// The mock echoes **the request's** nonce and imprint, not its own.
    #[test]
    fn the_response_answers_the_request_it_was_given() {
        let tsa = MockTsa::granted().expect("mint");
        for nonce in [[0u8; 8], [0xFF; 8], NONCE] {
            let digest = [nonce[0]; 32];
            let response = tsa
                .respond(&build_timestamp_req(&digest, &nonce))
                .expect("respond");
            let canonical = canonical_request_nonce(&nonce);
            verify_token(&response, &digest, Some(&canonical)).expect("answers this request");
            // …and only this one.
            assert_eq!(
                verify_token(&response, &[0xAB; 32], Some(&canonical)).err(),
                Some(AnchorError::ImprintMismatch)
            );
        }
    }

    /// Deterministic: same configuration, same request, byte-identical output.
    /// RFC 6979 signing plus fixed keys means a minted token is a fixture.
    #[test]
    fn minting_is_byte_reproducible() {
        let request = build_timestamp_req(&DIGEST, &NONCE);
        let first = MockTsa::granted().expect("mint").respond(&request);
        let second = MockTsa::granted().expect("mint").respond(&request);
        assert_eq!(first, second);
        assert!(!first.expect("bytes").is_empty());
    }

    /// The replay lever: a token that is perfect except for its nonce.
    #[test]
    fn a_non_echoing_mock_produces_exactly_a_nonce_mismatch() {
        let tsa = MockTsa::new(MockTsaConfig {
            echo_nonce: false,
            ..MockTsaConfig::default()
        })
        .expect("mint");
        let response = tsa
            .respond(&build_timestamp_req(&DIGEST, &NONCE))
            .expect("respond");
        let nonce = canonical_request_nonce(&NONCE);
        assert_eq!(
            verify_token(&response, &DIGEST, Some(&nonce)).err(),
            Some(AnchorError::NonceMismatch)
        );
        // The same token with no expected nonce verifies, which is what makes
        // the mismatch the *only* difference (D59: the nonce is verdict-inert
        // on every bundle path).
        verify_token(&response, &DIGEST, None).expect("inert without an expectation");
    }

    /// `PKIStatus` is controllable, and a rejection carries no token.
    #[test]
    fn a_rejecting_mock_is_a_status_error() {
        let tsa = MockTsa::new(MockTsaConfig {
            status: 2,
            ..MockTsaConfig::default()
        })
        .expect("mint");
        let response = tsa
            .respond(&build_timestamp_req(&DIGEST, &NONCE))
            .expect("respond");
        assert_eq!(
            verify_token(&response, &DIGEST, None).err(),
            Some(AnchorError::StatusNotGranted { status: 2 })
        );
    }

    /// Each EKU shape produces its own distinct error — the levers A21 rows
    /// and A8's EKU tests need, in the one place a *synthetic* certificate is
    /// required (no live TSA emits a wrong EKU).
    #[test]
    fn every_eku_shape_produces_its_own_outcome() {
        let outcome = |eku| {
            let tsa = MockTsa::new(MockTsaConfig {
                eku,
                ..MockTsaConfig::default()
            })
            .expect("mint");
            let response = tsa
                .respond(&build_timestamp_req(&DIGEST, &NONCE))
                .expect("respond");
            verify_token(&response, &DIGEST, None).map(|_| ())
        };
        assert_eq!(outcome(MockEku::CriticalTimeStamping), Ok(()));
        assert_eq!(outcome(MockEku::Absent), Err(AnchorError::EkuMissing));
        assert_eq!(
            outcome(MockEku::NonCritical),
            Err(AnchorError::EkuNotCritical)
        );
        assert_eq!(
            outcome(MockEku::WrongPurpose),
            Err(AnchorError::EkuNotTimeStamping)
        );
    }

    /// `genTime` and the certificate window are independent levers, so A9's
    /// three temporal outcomes are all reachable from one mock — the cases
    /// no real TSA will ever issue.
    #[test]
    fn the_temporal_levers_reach_all_three_chain_outcomes() {
        let at = |gen_time: u64, window: (u64, u64), verify_at: u64| {
            let tsa = MockTsa::new(MockTsaConfig {
                gen_time_unix: gen_time,
                signer_validity: window,
                ..MockTsaConfig::default()
            })
            .expect("mint");
            let response = tsa
                .respond(&build_timestamp_req(&DIGEST, &NONCE))
                .expect("respond");
            let token = verify_token(&response, &DIGEST, None).expect("T2");
            let store = tsa.root_store();
            validate_token_chain(&token, &[], &store, verify_at).state()
        };

        // Valid at genTime and still valid at verify_at.
        assert_eq!(
            at(1_785_000_000, (1_700_000_000, 1_900_000_000), 1_785_000_100),
            AnchorState::Proven
        );
        // Valid at genTime, expired by verify_at — the aging-bundle state.
        assert_eq!(
            at(1_785_000_000, (1_700_000_000, 1_790_000_000), 1_800_000_000),
            AnchorState::ValidAtStampingCertSinceExpired
        );
        // Expired already at genTime.
        assert_eq!(
            at(1_785_000_000, (1_700_000_000, 1_750_000_000), 1_785_000_100),
            AnchorState::Invalid
        );
        // Not yet valid at genTime — D53's back-dating direction.
        assert_eq!(
            at(1_785_000_000, (1_790_000_000, 1_900_000_000), 1_795_000_000),
            AnchorState::Invalid
        );
    }

    /// The mock's root is trusted **only** by an injected store: against the
    /// production pinned store the same token is `internally-consistent-only`,
    /// never `proven`. A fixture CA that could reach `proven` in a shipped
    /// build would be a backdoor.
    #[test]
    fn the_mock_root_is_worthless_against_the_pinned_store() {
        let tsa = MockTsa::granted().expect("mint");
        let response = tsa
            .respond(&build_timestamp_req(&DIGEST, &NONCE))
            .expect("respond");
        let token = verify_token(&response, &DIGEST, None).expect("T2");
        let verdict = validate_token_chain(&token, &[], TsaRootStore::pinned(), DEFAULT_GEN_TIME);
        assert_eq!(verdict.state(), AnchorState::InternallyConsistentOnly);
        assert!(!verdict.headline_eligible());
    }

    /// A garbage request is a typed error, never a panic — this module parses
    /// attacker-shaped input in exactly one place and must obey the same rule
    /// as the rest of the crate.
    #[test]
    fn a_malformed_request_is_a_typed_error() {
        let tsa = MockTsa::granted().expect("mint");
        for bad in [&b""[..], &[0x30][..], &[0xFF; 64][..], &[0x30, 0x80][..]] {
            assert!(matches!(tsa.respond(bad), Err(MockTsaError::Request(_))));
        }
    }
}
