//! A5 and A8 against **nine real TSA responses** (D60 §7.4).
//!
//! Every fixture here was captured from a live public TSA on 2026-08-02 over
//! one published digest; provenance, endpoints and the derivation of each
//! tamper variant are in `testdata/anchors/A25-bootstrap/D60-CAPTURE.log`.
//!
//! # Why nine and not two
//!
//! A5's and A8's Accept rows name FreeTSA and DigiCert — the spec's two
//! normative TSAs. The other seven are the parser's diversity corpus, and
//! they are not decoration: every one of the traps below was *found* on a
//! non-default TSA and would have shipped as a broken default.
//!
//! | fixture | what only it proves |
//! | --- | --- |
//! | Apple | a real `SignerInfo.digestAlgorithm = sha1`, so the SHA-1 rejection has a live positive case rather than a synthetic one |
//! | DFN | the signer is **not** first in the certificate bag (index 1) and ESSCertIDv2 omits `hashAlgorithm` |
//! | SwissSign | the signer is at index 2 **and** has no `BasicConstraints` extension at all |
//! | Sectigo | three `ESSCertID` entries — signer, CA, root — which "all entries must match" would reject |
//! | GlobalSign | four certificates, the largest bag, and the deepest DER (19) |
//! | Certum | both ESS attributes at once |
//! | Entrust | the same signer certificate as Sectigo: two endpoints, one TSA |
//!
//! # The one thing this file must never do
//!
//! Compare a `genTime` to a clock. The capture host ran **129 s slow**, so
//! `gen_time <= fetch_date` rejects all nine. A32 owns the prohibition.
#![cfg(not(target_arch = "wasm32"))]

use antseal_core::anchor::error::AnchorError;
use antseal_core::anchor::ess::EssVersion;
use antseal_core::anchor::rfc3161::{TimeStampResp, TstInfo, token_content_info};
use antseal_core::anchor::tsa::verify_token;
use cms::signed_data::SignedData;
use der::Encode;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/anchors/A25-bootstrap"
);

/// The digest all nine `D60-*` captures were taken over — the committed
/// golden vector's `anchor_digest`.
const STAMPED: [u8; 32] = [
    0x08, 0x3f, 0x87, 0xdf, 0x00, 0xfd, 0x5c, 0x70, 0x3d, 0x35, 0xb8, 0x83, 0xd8, 0x35, 0x35, 0x64,
    0x4c, 0x68, 0x6f, 0x9e, 0x53, 0xf1, 0x58, 0x4d, 0x7d, 0xf1, 0x26, 0xab, 0xda, 0xbd, 0x69, 0xdf,
];

/// The nine live TSAs, by fixture stem.
const TSAS: [&str; 9] = [
    "freetsa",
    "digicert",
    "dfn",
    "sectigo",
    "swisssign",
    "apple",
    "globalsign",
    "certum",
    "entrust",
];

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn response(tsa: &str) -> Vec<u8> {
    fixture(&format!("D60-tsa-{tsa}-resp.tsr"))
}

/// The `TSTInfo` inside an artifact, without running the verifier — used to
/// read a token's own imprint when the fixture was stamped over a digest
/// other than [`STAMPED`].
fn tst_info_of(artifact: &[u8]) -> TstInfo {
    let ci = token_content_info(artifact).expect("a granted response");
    let sd: SignedData = ci.content.decode_as().expect("SignedData");
    let ec = sd
        .encap_content_info
        .econtent
        .expect("eContent is present in every real token");
    TstInfo::parse(ec.value()).expect("TSTInfo parses")
}

fn imprint_of(artifact: &[u8]) -> [u8; 32] {
    let tst = tst_info_of(artifact);
    let mut out = [0u8; 32];
    out.copy_from_slice(tst.message_imprint().hashed_message.as_bytes());
    out
}

/// Replace the single occurrence of `needle` with `repl`, asserting there is
/// exactly one. The assertion is the point: a mutation helper that silently
/// changes zero bytes turns every "the mutant is rejected" test into a test
/// of the pristine fixture.
fn splice(hay: &[u8], needle: &[u8], repl: &[u8]) -> Vec<u8> {
    assert_eq!(
        needle.len(),
        repl.len(),
        "splice must preserve every length"
    );
    let hits: Vec<usize> = hay
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one occurrence, found {}",
        hits.len()
    );
    let mut out = hay.to_vec();
    out[hits[0]..hits[0] + repl.len()].copy_from_slice(repl);
    out
}

// ── A5: the parse layer ─────────────────────────────────────────────────

/// A5's first Accept row, widened from two TSAs to nine.
#[test]
fn real_tsa_tokens_parse() {
    for tsa in TSAS {
        let bytes = response(tsa);
        let resp = TimeStampResp::parse(&bytes).unwrap_or_else(|e| panic!("{tsa}: {e}"));
        assert!(
            resp.status.is_granted(),
            "{tsa}: every committed capture is PKIStatus granted"
        );
        assert!(resp.time_stamp_token.is_some(), "{tsa}: token present");
    }
}

/// Both artifact shapes registry §7.9 admits — a `TimeStampResp` and a bare
/// token — reach the same `ContentInfo`, and the choice is structural.
///
/// The registry describes the field as *"DER TimeStampResp/token"*, naming
/// two ASN.1 types with one slash. This pins that antseal reads both, and
/// that the two routes agree byte-for-byte.
#[test]
fn both_registered_artifact_shapes_are_accepted() {
    for tsa in TSAS {
        let resp_bytes = response(tsa);
        let from_response = token_content_info(&resp_bytes).expect("response route");
        let token_only = from_response.to_der().expect("re-encode the bare token");
        let from_token = token_content_info(&token_only).expect("bare-token route");
        assert_eq!(from_response, from_token, "{tsa}: the two routes disagree");
    }
}

/// Every `genTime` is the one DER-legal spelling: 15 octets, second
/// precision, `Z`-terminated. Measured across all nine so that a future
/// `GeneralizedTime` change is visible on real material and not only on the
/// synthetic cases in `der_pin_eval.rs`.
#[test]
fn every_gen_time_is_the_canonical_15_octet_form() {
    for tsa in TSAS {
        let bytes = response(tsa);
        let tst = tst_info_of(&bytes);
        let der = tst.gen_time().to_der().expect("re-encode genTime");
        assert_eq!(der[0], 0x18, "{tsa}: tag is GeneralizedTime");
        assert_eq!(der[1], 15, "{tsa}: exactly 15 content octets");
        assert_eq!(der[16], b'Z', "{tsa}: Z-terminated");
        assert!(
            tst.gen_time_unix() > 1_700_000_000,
            "{tsa}: genTime decodes to a plausible epoch second"
        );
    }
}

/// No live TSA sends `TSTInfo` extensions, so nothing today exercises the
/// question of what a *critical* unrecognised one should mean — and no
/// decision in the register rules on it.
///
/// This test records the measurement rather than inventing a rule against
/// zero fixtures. It goes red the day a TSA starts sending them, which is
/// exactly when the question needs answering.
#[test]
fn no_live_tsa_sends_tst_info_extensions() {
    for tsa in TSAS {
        let bytes = response(tsa);
        let tst = tst_info_of(&bytes);
        assert!(
            tst.extensions().is_none(),
            "{tsa}: a TSA now sends TSTInfo extensions — the criticality rule is unruled (see A33)"
        );
    }
}

/// Re-encoding a parsed certificate must reproduce its wire bytes exactly.
///
/// Everything downstream depends on it: `certHash` is computed over
/// `to_der(parsed)`, and A9 will validate the parsed structure. If the two
/// ever diverged, an honest token would fail its own ESS binding. Asserted
/// as **containment in the original artifact**, over all 27 certificates in
/// the nine tokens, so it is a statement about real encodings and not about
/// a round-trip of our own output.
#[test]
fn every_embedded_certificate_re_encodes_to_its_wire_bytes() {
    let mut total = 0usize;
    for tsa in TSAS {
        let bytes = response(tsa);
        let ci = token_content_info(&bytes).expect("granted");
        let sd: SignedData = ci.content.decode_as().expect("SignedData");
        let set = sd
            .certificates
            .expect("every real token embeds certificates");
        for choice in set.0.iter() {
            let cms::cert::CertificateChoices::Certificate(cert) = choice else {
                continue;
            };
            let der = cert.to_der().expect("re-encode");
            assert!(
                bytes.windows(der.len()).any(|w| w == der.as_slice()),
                "{tsa}: a re-encoded certificate is not a subslice of the captured response"
            );
            total += 1;
        }
    }
    assert_eq!(
        total, 27,
        "D60 §3.3 counted 27 embedded certificates across the nine tokens"
    );
}

// ── A8: verification ────────────────────────────────────────────────────

/// A8's first Accept row: the two normative TSAs verify end to end.
///
/// FreeTSA needs **both** algorithm families in one token — ECDSA-P384 with
/// SHA-512 for the signature — and DigiCert needs bare `rsaEncryption` with
/// the digest taken from `SignerInfo.digestAlgorithm`.
#[test]
fn freetsa_verifies_ecdsa_p384_sha512() {
    let bytes = response("freetsa");
    let verified = verify_token(&bytes, &STAMPED, None).expect("FreeTSA must verify");
    use antseal_core::anchor::alg::{Digest, SigFamily};
    assert_eq!(verified.signature_alg().family, SigFamily::EcdsaP384);
    assert_eq!(
        verified.signature_alg().digest,
        Some(Digest::Sha512),
        "FreeTSA signs ecdsa-with-SHA512, not the SHA-384 the pairing suggests"
    );
    assert_eq!(
        verified.ess_checked(),
        EssVersion::V1,
        "FreeTSA sends ESSCertID v1 only"
    );
}

#[test]
fn digicert_verifies_rsa_pkcs1v15_sha256() {
    let bytes = response("digicert");
    let verified = verify_token(&bytes, &STAMPED, None).expect("DigiCert must verify");
    use antseal_core::anchor::alg::SigFamily;
    assert_eq!(verified.signature_alg().family, SigFamily::RsaPkcs1v15);
    assert_eq!(
        verified.signature_alg().digest,
        None,
        "DigiCert emits bare rsaEncryption; the digest comes from digestAlgorithm"
    );
}

/// Every TSA whose algorithms are inside D60 §3.3's registry verifies, and
/// the one outside it fails with the algorithm code rather than with a
/// signature failure.
///
/// Apple is the outlier and it is a **real** one: its
/// `SignerInfo.digestAlgorithm` is SHA-1. That gives
/// `anchor-digest-alg-unsupported` a live positive case, and it is why the
/// registry check runs *before* any signature verification — an unsupported
/// algorithm must not read as forgery.
#[test]
fn all_nine_tsas_verify_or_fail_for_a_named_algorithm_reason() {
    let mut verified = 0;
    for tsa in TSAS {
        let bytes = response(tsa);
        match verify_token(&bytes, &STAMPED, None) {
            Ok(_) => verified += 1,
            Err(e) => {
                assert_eq!(
                    tsa,
                    "apple",
                    "{tsa} failed unexpectedly with {} ({e})",
                    e.code()
                );
                assert_eq!(
                    e.code(),
                    "anchor-digest-alg-unsupported",
                    "Apple's SHA-1 digestAlgorithm must be named, not reported as a bad signature"
                );
            }
        }
    }
    assert_eq!(
        verified, 8,
        "eight of the nine live TSAs must verify; only Apple's SHA-1 is refused"
    );
}

/// `sha1_rejected_as_cms_digest_algorithm`, stated on its own so the claim
/// is greppable and cannot be diluted into the loop above.
#[test]
fn sha1_rejected_as_cms_digest_algorithm() {
    let bytes = response("apple");
    // The token itself is well-formed and parses — the rejection is a policy
    // decision about an algorithm, not a parse failure.
    assert!(TimeStampResp::parse(&bytes).is_ok());
    let err = verify_token(&bytes, &STAMPED, None).expect_err("SHA-1 is not a signature digest");
    assert_eq!(err.code(), "anchor-digest-alg-unsupported");
}

/// The signer is located by `sid`, never by position.
///
/// `cms` re-sorts the `certificates` SET on decode, so wire order is gone
/// before any antseal code runs — but the assertion that matters is the
/// positive one: DFN's signer is at bag index 1 and SwissSign's at index 2
/// among the *captured* bytes, and both verify.
#[test]
fn signer_cert_is_not_assumed_first_in_bag() {
    for tsa in ["dfn", "swisssign"] {
        let bytes = response(tsa);
        let verified = verify_token(&bytes, &STAMPED, None)
            .unwrap_or_else(|e| panic!("{tsa} must verify: {e}"));
        // The signer really is not the first certificate in the decoded bag,
        // or this test would pass under a leaf-first implementation.
        let first = verified
            .chain_material()
            .first()
            .expect("the bag is non-empty")
            .to_der()
            .expect("re-encode");
        assert_ne!(
            first,
            verified.signer_der(),
            "{tsa}: the signer must NOT be the first certificate, or this test is vacuous"
        );
    }
}

/// RFC 5280 §4.2.1.9 permits an end entity to omit `BasicConstraints`, and
/// SwissSign's signer does. A "BasicConstraints required on the signer" rule
/// would reject a real TSA.
#[test]
fn signer_cert_without_basic_constraints_is_accepted() {
    let bytes = response("swisssign");
    let verified = verify_token(&bytes, &STAMPED, None).expect("SwissSign must verify");
    let bc = verified
        .signer()
        .tbs_certificate()
        .get_extension::<x509_cert::ext::pkix::BasicConstraints>()
        .expect("extension decode");
    assert!(
        bc.is_none(),
        "SwissSign's signer must really lack BasicConstraints, or this test is vacuous"
    );
}

/// The EKU criticality rule binds the **signer** certificate only.
///
/// DigiCert's intermediate carries a *non-critical* EKU, so a chain-wide
/// reading fails a default TSA. Both legs are asserted: DigiCert verifies,
/// and its intermediate really is non-critical.
#[test]
fn eku_criticality_required_on_signer_only() {
    let bytes = response("digicert");
    let verified = verify_token(&bytes, &STAMPED, None).expect("DigiCert must verify");

    let (signer_critical, _) = verified
        .signer()
        .tbs_certificate()
        .get_extension::<x509_cert::ext::pkix::ExtendedKeyUsage>()
        .expect("decode")
        .expect("the signer has an EKU");
    assert!(signer_critical, "the signer's EKU is critical");

    let non_critical_ca = verified
        .chain_material()
        .iter()
        .filter(|c| c.to_der().expect("re-encode") != verified.signer_der())
        .filter_map(|c| {
            c.tbs_certificate()
                .get_extension::<x509_cert::ext::pkix::ExtendedKeyUsage>()
                .ok()
                .flatten()
        })
        .any(|(critical, _)| !critical);
    assert!(
        non_critical_ca,
        "DigiCert's intermediate must really carry a NON-critical EKU, or this test is vacuous"
    );
}

// ── A8: the ESS binding ─────────────────────────────────────────────────

/// ESSCertID **v1**, on two independent captures of the same TSA, plus the
/// mutant that makes the test non-vacuous.
///
/// Without the mutant leg, an implementation that never reads the attribute
/// at all passes: the two pristine tokens verify for other reasons.
#[test]
fn esscertid_v1_binds_signer_cert_by_sha1() {
    // Both captures, independent runs, same signer certificate.
    let a = response("freetsa");
    let b = fixture("freetsa-D59-resp.tsr");
    let va = verify_token(&a, &STAMPED, None).expect("D60 capture verifies");
    // The D59 pair was stamped over a different digest; read its own.
    let vb = verify_token(&b, &imprint_of(&b), None).expect("D59 capture verifies");
    assert_eq!(
        va.signer_der(),
        vb.signer_der(),
        "the two captures must share a signer certificate, or they are not independent evidence"
    );
    assert_eq!(va.ess_checked(), EssVersion::V1);

    // The mutant: flip one byte of the certHash the attribute carries.
    let hash = sha1_of(va.signer_der());
    let mut flipped = hash.clone();
    flipped[0] ^= 0x01;
    let mutant = splice(&a, &hash, &flipped);
    let err = verify_token(&mutant, &STAMPED, None).expect_err("a wrong certHash must be refused");
    assert_eq!(err.code(), "anchor-esscert-mismatch");
}

/// **Two legs, because one of them is vacuous alone** (D60 §7.4).
///
/// (a) Sectigo verifies — which fails an "all entries must match" rule, since
///     its entries 2 and 3 are the CA and the root.
/// (b) A mutant whose **first** entry is swapped for the CA's own SHA-1 — a
///     legitimate hash of a certificate genuinely in the bag — is rejected,
///     which fails an "any entry matches" rule.
///
/// Leg (a) alone passes under both rules and would witness nothing.
#[test]
fn esscertid_v1_only_first_entry_is_checked() {
    let bytes = response("sectigo");
    let verified = verify_token(&bytes, &STAMPED, None).expect("Sectigo must verify");
    assert_eq!(verified.ess_checked(), EssVersion::V1);

    let signer_hash = sha1_of(verified.signer_der());
    // Some other certificate genuinely in the bag — the CA or the root.
    let other = verified
        .chain_material()
        .iter()
        .map(|c| c.to_der().expect("re-encode"))
        .find(|d| d.as_slice() != verified.signer_der())
        .expect("Sectigo embeds more than one certificate");
    let other_hash = sha1_of(&other);
    assert!(
        bytes
            .windows(other_hash.len())
            .any(|w| w == other_hash.as_slice()),
        "the CA's SHA-1 must already appear in the token, or leg (b) is not the case D60 describes"
    );

    let mutant = splice(&bytes, &signer_hash, &other_hash);
    let err = verify_token(&mutant, &STAMPED, None)
        .expect_err("only the FIRST ESSCertID identifies the signer");
    assert_eq!(err.code(), "anchor-esscert-mismatch");
}

/// **Two legs**, same reason.
///
/// (a) DFN sends ESSCertIDv2 with `hashAlgorithm` absent, so the DEFAULT must
///     resolve to SHA-256 for it to verify at all.
/// (b) A one-byte flip in the 32-byte hash is rejected — without which (a)
///     passes on an implementation that ignores the attribute entirely.
#[test]
fn esscertid_v2_absent_hash_alg_defaults_sha256() {
    let bytes = response("dfn");
    let verified = verify_token(&bytes, &STAMPED, None).expect("DFN must verify");
    assert_eq!(verified.ess_checked(), EssVersion::V2, "DFN sends v2 only");

    let hash = sha256_of(verified.signer_der());
    let mut flipped = hash.clone();
    flipped[31] ^= 0x80;
    let mutant = splice(&bytes, &hash, &flipped);
    let err = verify_token(&mutant, &STAMPED, None).expect_err("a wrong v2 certHash is refused");
    assert_eq!(err.code(), "anchor-esscert-mismatch");
}

/// Certum and DigiCert send **both** ESS attributes. Both are checked: a
/// token carrying a correct v2 attribute beside a v1 attribute naming a
/// different certificate is a signed contradiction, and the verifier must
/// not silently pick a side.
#[test]
fn when_both_ess_attributes_are_present_both_are_checked() {
    for tsa in ["digicert", "certum"] {
        let bytes = response(tsa);
        let verified = verify_token(&bytes, &STAMPED, None).expect("must verify");
        assert!(
            bytes
                .windows(20)
                .any(|w| w == sha1_of(verified.signer_der()).as_slice()),
            "{tsa}: the v1 attribute must really be present, or this test is vacuous"
        );
        // Corrupting the *v1* hash must still be caught even though v2 is
        // present and correct.
        let hash = sha1_of(verified.signer_der());
        let mut flipped = hash.clone();
        flipped[10] ^= 0xFF;
        let mutant = splice(&bytes, &hash, &flipped);
        let err = verify_token(&mutant, &STAMPED, None)
            .expect_err("a corrupt v1 attribute must be caught");
        assert_eq!(
            err.code(),
            "anchor-esscert-mismatch",
            "{tsa}: a corrupt v1 attribute must not be masked by a correct v2 one"
        );
    }
}

// ── A8: the content bindings ────────────────────────────────────────────

/// The `messageImprint` names this seal's digest and no other.
///
/// D53 §8 fixes that this fires at stage T2, **before** any chain rule, so a
/// token for a different digest is never classified by its chain.
#[test]
fn a_token_for_a_different_digest_is_refused() {
    let bytes = response("digicert");
    let mut other = STAMPED;
    other[0] ^= 0x01;
    let err = verify_token(&bytes, &other, None).expect_err("wrong digest");
    assert_eq!(err.code(), "anchor-tsa-imprint-mismatch");
}

/// Tampering with the encapsulated `TSTInfo` breaks the message-digest
/// attribute — the single comparison through which the signature reaches the
/// content at all.
#[test]
fn a_mutated_tst_info_breaks_the_message_digest_attribute() {
    let bytes = response("digicert");
    // Flip a byte of the stamped digest *inside* the TSTInfo. The imprint
    // check would also catch it, so the digest is left intact and the
    // serialNumber is moved instead.
    let tst = tst_info_of(&bytes);
    let serial = tst.serial_number().to_vec();
    let mut flipped = serial.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    let mutant = splice(&bytes, &serial, &flipped);
    let err = verify_token(&mutant, &STAMPED, None).expect_err("a mutated TSTInfo is refused");
    assert_eq!(
        err.code(),
        "anchor-cms-message-digest-attr-mismatch",
        "the eContent digest is what binds signedAttrs to the TSTInfo"
    );
}

/// Tampering with the signature bytes is a signature failure and nothing
/// else — a distinct code from every structural class above.
#[test]
fn a_mutated_signature_is_refused_as_a_signature() {
    let bytes = response("digicert");
    let ci = token_content_info(&bytes).expect("granted");
    let sd: SignedData = ci.content.decode_as().expect("SignedData");
    let si = sd.signer_infos.0.iter().next().expect("one signer");
    let sig = si.signature.as_bytes().to_vec();
    let mut flipped = sig.clone();
    flipped[0] ^= 0x01;
    let mutant = splice(&bytes, &sig, &flipped);
    let err = verify_token(&mutant, &STAMPED, None).expect_err("a broken signature is refused");
    assert_eq!(err.code(), "anchor-cms-signature-invalid");
}

/// The SET OF malleability D60 §2.2 measured, on real material: a token whose
/// four `signedAttrs` are reversed in place still verifies.
///
/// That is correct per RFC 5652 §5.4 — the signature is over the DER (i.e.
/// canonically ordered) encoding of `signedAttrs`, not over the wire bytes —
/// and it is recorded here because it means **token bytes are malleable**.
/// A22's golden vectors must key on the verdict, never on token bytes.
#[test]
fn a_reordered_signed_attrs_token_still_verifies() {
    let pristine = response("freetsa");
    let reordered = fixture("D60-ber-unsorted-setof-freetsa.tsr");
    assert_ne!(
        pristine, reordered,
        "the fixtures must really differ, or this measures nothing"
    );
    let a = verify_token(&pristine, &STAMPED, None).expect("pristine verifies");
    let b = verify_token(&reordered, &STAMPED, None)
        .expect("reordering signedAttrs does not break the signature — token bytes are malleable");
    assert_eq!(a.gen_time_unix(), b.gen_time_unix());
    assert_eq!(a.signer_der(), b.signer_der());
}

// ── A8: the nonce (D59) ─────────────────────────────────────────────────

/// The nonce is **verdict-inert** with `expected_nonce = None`.
///
/// The pristine tokens all carry a nonce (all nine echoed one). Verified with
/// `None`, every observable this layer produces must be identical to the same
/// verification with the nonce field's value changed — i.e. nothing may
/// branch on it. Mutating the nonce also breaks the CMS signature, so the
/// inertness claim is made where it is checkable: the nonce is read and the
/// verdict does not consult it, asserted by comparing a `Some`-run against a
/// `None`-run on the same bytes.
#[test]
fn nonce_is_inert_when_none_is_supplied() {
    for tsa in TSAS.iter().filter(|t| **t != "apple") {
        let bytes = response(tsa);
        let with_none = verify_token(&bytes, &STAMPED, None).expect("verifies with None");
        let echoed = tst_info_of(&bytes)
            .nonce()
            .expect("every capture echoed a nonce")
            .to_vec();
        let with_some =
            verify_token(&bytes, &STAMPED, Some(&echoed)).expect("verifies with the true nonce");
        assert_eq!(
            with_none.gen_time_unix(),
            with_some.gen_time_unix(),
            "{tsa}: supplying the correct nonce must change nothing"
        );
        assert_eq!(with_none.signer_der(), with_some.signer_der(), "{tsa}");
        assert_eq!(with_none.policy(), with_some.policy(), "{tsa}");
    }
}

/// The capture-path arm: `Some(n)` requires presence **and** equality.
///
/// Absence yields the same code as inequality, deliberately: treating a
/// missing nonce as "nothing to compare" is how a replayed token passes.
#[test]
fn expected_nonce_some_requires_presence_and_equality() {
    let bytes = response("digicert");
    let echoed = tst_info_of(&bytes).nonce().expect("echoed").to_vec();

    assert!(verify_token(&bytes, &STAMPED, Some(&echoed)).is_ok());

    let mut wrong = echoed.clone();
    wrong[0] ^= 0x01;
    let err = verify_token(&bytes, &STAMPED, Some(&wrong)).expect_err("a wrong nonce is refused");
    assert_eq!(err.code(), "anchor-tsa-nonce-mismatch");

    // A different length is also a mismatch, not a panic and not a
    // truncating comparison.
    let err =
        verify_token(&bytes, &STAMPED, Some(&echoed[..4])).expect_err("a short nonce is refused");
    assert_eq!(err.code(), "anchor-tsa-nonce-mismatch");
}

// ── Adversarial input never panics ──────────────────────────────────────

/// Every single-byte mutation of a real token either verifies or returns a
/// typed error. Never a panic, never an abort.
///
/// This is A5's and A8's "no panics on adversarial input" row made concrete
/// on real bytes rather than on random noise: a mutation of a valid token
/// reaches far deeper into the parser than a random buffer ever would.
/// Bounded to a stride so the suite stays fast on a two-core box; the fuzz
/// target (A23) is where exhaustive coverage lives.
#[test]
fn single_byte_mutations_of_a_real_token_never_panic() {
    let bytes = response("freetsa");
    let mut errors = 0usize;
    let mut accepted = 0usize;
    for i in (0..bytes.len()).step_by(7) {
        for mask in [0x01u8, 0x80] {
            let mut mutant = bytes.clone();
            mutant[i] ^= mask;
            match verify_token(&mutant, &STAMPED, None) {
                Ok(_) => accepted += 1,
                Err(e) => {
                    assert!(e.code().starts_with("anchor-"), "{}", e.code());
                    errors += 1;
                }
            }
        }
    }
    assert!(
        errors > 100,
        "the mutation sweep must actually reject things"
    );
    assert!(
        accepted < errors,
        "a mutation sweep that mostly ACCEPTS is measuring the wrong thing"
    );
}

/// Truncation at every prefix length is a typed error, never a panic.
#[test]
fn truncated_tokens_never_panic() {
    let bytes = response("freetsa");
    for len in (0..bytes.len()).step_by(37) {
        let err = verify_token(&bytes[..len], &STAMPED, None)
            .expect_err("a truncated token can never verify");
        assert!(err.code().starts_with("anchor-"));
    }
}

/// An empty artifact, a lone tag byte and a well-formed but empty SEQUENCE
/// are all typed errors.
#[test]
fn degenerate_inputs_are_typed_errors() {
    for input in [&[][..], &[0x30][..], &[0x30, 0x00][..], &[0xFF, 0xFF][..]] {
        let err = verify_token(input, &STAMPED, None).expect_err("degenerate input");
        assert!(
            matches!(err, AnchorError::Der { .. }),
            "expected a DER class, got {}",
            err.code()
        );
    }
}

fn sha1_of(bytes: &[u8]) -> Vec<u8> {
    use sha1::Digest as _;
    sha1::Sha1::digest(bytes).to_vec()
}

fn sha256_of(bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).to_vec()
}
