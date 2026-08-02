//! The three (b)-class limits A5 chose at M2, each proved **reachable**
//! (D60 §6, §7.4) and each obeying F1–F3.
//!
//! # Reachability is the assertion, not a nicety
//!
//! D60 §6 b2 rejects `MAX_CHAIN_CERTS = 18` — the arithmetic ceiling
//! `MAX_INTERMEDIATE_COUNT + signer + root` — on exactly this ground: a path
//! can never *exceed* 18, so an 18-limit is a check that cannot fail, and a
//! test that cannot fail is a defect. Every test below therefore builds a
//! real artifact that crosses the limit and asserts the distinct cap code. If
//! a limit were ever raised to its ceiling, the corresponding test here would
//! become unwritable, which is the property that keeps the argument honest.
//!
//! # Every fixture is derived from a real token
//!
//! A synthetic blob would be rejected for a dozen reasons and prove nothing
//! about *which* check fired. Each fixture below decodes a real captured
//! response, changes exactly one thing, and re-encodes — so the artifact
//! remains a well-formed CMS token that fails on the limit and only the
//! limit.
#![cfg(not(target_arch = "wasm32"))]

use antseal_core::anchor::caps::{MAX_CHAIN_CERT_BYTES, MAX_CHAIN_CERTS, MAX_SIGNED_ATTRS};
use antseal_core::anchor::rfc3161::token_content_info;
use antseal_core::anchor::tsa::verify_token;
use antseal_core::bundle::SealProof;
use antseal_core::codec::caps::{MAX_CERT_BYTES, MAX_TSA_TOKEN_BYTES};
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{CertificateSet, SignedData, SignerInfos};
use const_oid::ObjectIdentifier;
use der::asn1::SetOfVec;
use der::{Any, Decode, Encode};
use x509_cert::Certificate;
use x509_cert::attr::Attribute;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/anchors/A25-bootstrap"
);

const STAMPED: [u8; 32] = [
    0x08, 0x3f, 0x87, 0xdf, 0x00, 0xfd, 0x5c, 0x70, 0x3d, 0x35, 0xb8, 0x83, 0xd8, 0x35, 0x35, 0x64,
    0x4c, 0x68, 0x6f, 0x9e, 0x53, 0xf1, 0x58, 0x4d, 0x7d, 0xf1, 0x26, 0xab, 0xda, 0xbd, 0x69, 0xdf,
];

/// `id-signedData`.
const ID_SIGNED_DATA: ObjectIdentifier = const_oid::db::rfc5911::ID_SIGNED_DATA;

fn response(tsa: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/D60-tsa-{tsa}-resp.tsr"))
        .unwrap_or_else(|e| panic!("{tsa}: {e}"))
}

fn signed_data(tsa: &str) -> SignedData {
    let ci = token_content_info(&response(tsa)).expect("a granted response");
    ci.content.decode_as().expect("SignedData")
}

/// Re-wrap a modified `SignedData` as a bare timestamp token — the second of
/// the two artifact shapes registry §7.9 admits, so no `TimeStampResp` shell
/// has to be rebuilt around it.
fn as_token(sd: &SignedData) -> Vec<u8> {
    let der = sd.to_der().expect("re-encode SignedData");
    let content = Any::from_der(&der).expect("the SignedData as an Any");
    ContentInfo {
        content_type: ID_SIGNED_DATA,
        content,
    }
    .to_der()
    .expect("re-encode ContentInfo")
}

/// Emit a TLV with a minimal DER length. Used to grow a certificate past the
/// per-certificate cap without disturbing anything else about it.
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();
    if len < 0x80 {
        out.push(u8::try_from(len).expect("checked"));
    } else if len <= 0xFF {
        out.extend_from_slice(&[0x81, u8::try_from(len).expect("checked")]);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.extend_from_slice(&u16::try_from(len).expect("checked").to_be_bytes());
    } else {
        out.push(0x83);
        let b = u32::try_from(len)
            .expect("fixtures stay under 16 MiB")
            .to_be_bytes();
        out.extend_from_slice(&b[1..]);
    }
    out.extend_from_slice(body);
    out
}

/// Grow a real certificate past `MAX_CHAIN_CERT_BYTES` by inflating its
/// **signature** BIT STRING — the one field whose content is opaque to every
/// parser, so the result still decodes as a `Certificate` and still fails on
/// size rather than on shape.
fn inflate_certificate(cert_der: &[u8], target: usize) -> Vec<u8> {
    let mut reader = der::SliceReader::new(cert_der).expect("a certificate");
    let header = der::Header::decode(&mut reader).expect("outer SEQUENCE");
    assert_eq!(header.tag(), der::Tag::Sequence);
    let tbs = Any::decode(&mut reader).expect("tbsCertificate");
    let alg = Any::decode(&mut reader).expect("signatureAlgorithm");
    let _sig = Any::decode(&mut reader).expect("signature");

    let mut body = tbs.to_der().expect("re-encode tbs");
    body.extend_from_slice(&alg.to_der().expect("re-encode alg"));
    // BIT STRING: one leading "unused bits" octet, then padding.
    let pad = target.saturating_sub(body.len());
    let mut bits = vec![0u8; pad + 1];
    bits[0] = 0x00;
    body.extend_from_slice(&tlv(0x03, &bits));
    tlv(0x30, &body)
}

// ── b3: per-certificate size ────────────────────────────────────────────

/// A 20 KiB certificate out of a token is refused, and the constant it is
/// refused against is provably below the bundle field's cap.
///
/// The second half is the A28-shaped constraint D60 §6 b3 attaches to this
/// limit: a certificate accepted out of a token must afterwards be
/// embeddable in a `.sealproof` as an intermediate, or the seal anchors and
/// then cannot be revealed. It is a `const` assertion in `anchor::caps`;
/// asserted again here so the relationship is visible at the point it is
/// relied on.
#[test]
fn chain_cert_size_cap_is_reachable_and_bounded_by_bundle_cap() {
    assert!(
        u64::from(MAX_CHAIN_CERT_BYTES) <= MAX_CERT_BYTES,
        "a certificate accepted out of a token must fit the bundle field"
    );

    let mut sd = signed_data("digicert");
    let set = sd
        .certificates
        .take()
        .expect("DigiCert embeds certificates");
    let real = set
        .0
        .iter()
        .find_map(|c| match c {
            CertificateChoices::Certificate(cert) => Some(cert.to_der().expect("re-encode")),
            CertificateChoices::Other(_) => None,
        })
        .expect("at least one plain certificate");

    let big = inflate_certificate(&real, 20 * 1024);
    assert!(
        big.len() > MAX_CHAIN_CERT_BYTES as usize,
        "the fixture must actually exceed the cap ({} B)",
        big.len()
    );
    assert!(
        (big.len() as u64) < MAX_TSA_TOKEN_BYTES,
        "and must stay inside the bundle's own token cap, or stage 1 would \
         reject it first and F1 would not be what is under test"
    );
    let parsed = Certificate::from_der(&big).expect("an inflated certificate still parses");

    sd.certificates = Some(CertificateSet(
        SetOfVec::try_from(vec![CertificateChoices::Certificate(parsed)])
            .expect("a one-element SET"),
    ));
    let artifact = as_token(&sd);

    let err = verify_token(&artifact, &STAMPED, None).expect_err("an oversized certificate");
    assert_eq!(err.code(), "anchor-chain-cert-size");
}

// ── b2: certificate count in a validated chain ──────────────────────────

/// Nine certificates offered as path material are refused at eight.
///
/// The nine are **distinct real certificates**, gathered from three different
/// tokens: a bag of nine copies of one certificate would be canonicalised
/// differently and would not prove the count is what is being bounded.
#[test]
fn chain_cert_count_cap_is_reachable() {
    let mut all: Vec<CertificateChoices> = Vec::new();
    for tsa in ["digicert", "dfn", "sectigo"] {
        let sd = signed_data(tsa);
        for choice in sd.certificates.expect("certificates").0.iter() {
            all.push(choice.clone());
        }
    }
    assert_eq!(all.len(), 9, "three tokens of three certificates each");
    assert!(
        all.len() > MAX_CHAIN_CERTS,
        "the fixture must cross the limit ({MAX_CHAIN_CERTS})"
    );

    let mut sd = signed_data("digicert");
    sd.certificates = Some(CertificateSet(
        SetOfVec::try_from(all).expect("nine distinct certificates"),
    ));
    let artifact = as_token(&sd);

    let err = verify_token(&artifact, &STAMPED, None).expect_err("nine certificates");
    assert_eq!(err.code(), "anchor-chain-cert-count");
}

/// The other direction, without which the test above could pass on a build
/// whose limit is 1: the real maximum bag — GlobalSign's four — is accepted.
#[test]
fn the_largest_real_certificate_bag_is_accepted() {
    let sd = signed_data("globalsign");
    let count = sd.certificates.as_ref().expect("certificates").0.len();
    assert_eq!(count, 4, "GlobalSign carries the largest observed bag");
    assert!(count <= MAX_CHAIN_CERTS);
    verify_token(&response("globalsign"), &STAMPED, None).expect("the largest real bag verifies");
}

// ── b4: signed-attribute count ──────────────────────────────────────────

/// Seventeen signed attributes are refused at sixteen.
#[test]
fn signed_attr_count_cap_is_reachable() {
    let mut sd = signed_data("digicert");
    let mut si = sd.signer_infos.0.iter().next().expect("one signer").clone();

    let mut attrs: Vec<Attribute> = Vec::new();
    for i in 0..17u32 {
        attrs.push(Attribute {
            oid: ObjectIdentifier::new_unwrap(match i {
                0 => "1.2.3.100",
                1 => "1.2.3.101",
                2 => "1.2.3.102",
                3 => "1.2.3.103",
                4 => "1.2.3.104",
                5 => "1.2.3.105",
                6 => "1.2.3.106",
                7 => "1.2.3.107",
                8 => "1.2.3.108",
                9 => "1.2.3.109",
                10 => "1.2.3.110",
                11 => "1.2.3.111",
                12 => "1.2.3.112",
                13 => "1.2.3.113",
                14 => "1.2.3.114",
                15 => "1.2.3.115",
                _ => "1.2.3.116",
            }),
            values: SetOfVec::try_from(vec![Any::from(der::asn1::Null)]).expect("one value"),
        });
    }
    assert!(attrs.len() > MAX_SIGNED_ATTRS);
    si.signed_attrs = Some(SetOfVec::try_from(attrs).expect("seventeen distinct attributes"));
    sd.signer_infos = SignerInfos(SetOfVec::try_from(vec![si]).expect("one signer"));

    let artifact = as_token(&sd);
    let err = verify_token(&artifact, &STAMPED, None).expect_err("seventeen attributes");
    assert_eq!(err.code(), "anchor-signed-attr-count");
}

/// The real maximum — five, on DigiCert/DFN/SwissSign/Certum — is accepted,
/// so the limit above is not merely "any number of attributes is too many".
#[test]
fn the_largest_real_signed_attr_set_is_accepted() {
    let sd = signed_data("digicert");
    let count = sd
        .signer_infos
        .0
        .iter()
        .next()
        .expect("one signer")
        .signed_attrs
        .as_ref()
        .expect("signedAttrs")
        .len();
    assert_eq!(count, 5, "D60 §5.1 measured a maximum of 5");
    assert!(count <= MAX_SIGNED_ATTRS);
}

// ── F1 / F2 / F3 ────────────────────────────────────────────────────────

/// **F1 demonstrated, not asserted** (A5's Accept row).
///
/// A bundle carrying an over-limit TSA token must still decode, and its
/// embedded manifest must be untouched: artifact-internal limits live in the
/// anchor stage and `SealProof::decode` must never open an artifact (F1). The
/// over-limit token is what fails, and only when the anchor stage looks at it
/// (F3).
///
/// The construction is deliberately a **substitution into a real fixture**:
/// the same bundle is decoded before and after, so the "manifest unchanged"
/// claim is a byte comparison against a bundle that genuinely verified,
/// rather than an assertion about a bundle built to satisfy it.
///
/// What this test does **not** claim: that the anchor's rendered verdict is
/// `invalid` while its siblings are unaffected. That is R12/A18's wiring and
/// its own test — the anchor stage is not yet connected to the report.
#[test]
fn f1_over_limit_token_leaves_bundle_decodable() {
    use antseal_core::bundle::{BundleV1, OpaqueBytes, TsaAnchor, encode_bundle};
    use antseal_core::test_util::bundle_fixtures::{Selection, build, shapes};

    let built = build(&shapes::multi_file_anchored(), &Selection::all(3));
    let before = SealProof::decode(&built.bytes).expect("the fixture bundle decodes");
    let manifest_before = before.anchor_digest_preimage().to_vec();

    // The over-limit artifact: a token whose only certificate is 20 KiB.
    let over_limit = {
        let mut sd = signed_data("digicert");
        let set = sd.certificates.take().expect("certificates");
        let real = set
            .0
            .iter()
            .find_map(|c| match c {
                CertificateChoices::Certificate(cert) => Some(cert.to_der().expect("re-encode")),
                CertificateChoices::Other(_) => None,
            })
            .expect("a plain certificate");
        let big = inflate_certificate(&real, 20 * 1024);
        sd.certificates = Some(CertificateSet(
            SetOfVec::try_from(vec![CertificateChoices::Certificate(
                Certificate::from_der(&big).expect("parses"),
            )])
            .expect("one element"),
        ));
        as_token(&sd)
    };
    assert!(
        (over_limit.len() as u64) < MAX_TSA_TOKEN_BYTES,
        "stage 1's D10 cap must NOT be what rejects it, or F1 is untested"
    );

    // Substitute it into the bundle and re-encode.
    let mut parts = BundleV1::decode(&built.bytes)
        .expect("decode to the model")
        .into_parts();
    assert!(
        !parts.tsa_anchors.is_empty(),
        "the fixture must carry a TSA anchor to substitute into"
    );
    let (status, intermediates, fetch_date) = {
        let old = &parts.tsa_anchors[0];
        (old.status(), old.intermediates().to_vec(), old.fetch_date())
    };
    parts.tsa_anchors[0] = TsaAnchor::new(
        status,
        OpaqueBytes::from_vec(over_limit.clone()),
        intermediates,
        fetch_date,
    )
    .expect("F1: an over-limit-for-the-anchor-stage token still passes every D10 stage-1 cap");
    let rebuilt = encode_bundle(&BundleV1::new(parts).expect("a well-formed bundle"))
        .expect("re-encode the bundle");

    // F1: stage 1 does not open the artifact, so the bundle still decodes.
    let after = SealProof::decode(&rebuilt).expect("F1: the bundle must still decode");
    // F2: the manifest — and therefore the manifest verdict — is untouched.
    assert_eq!(
        after.anchor_digest_preimage(),
        manifest_before.as_slice(),
        "F2: substituting an anchor artifact must not disturb the manifest"
    );

    // F3: and the anchor stage is where it fails, with its own code.
    let carried = after.bundle().tsa_anchors()[0].token().as_slice().to_vec();
    assert_eq!(carried, over_limit, "the artifact survived the round trip");
    let err = verify_token(&carried, &STAMPED, None).expect_err("the anchor stage refuses it");
    assert_eq!(err.code(), "anchor-chain-cert-size");
}
