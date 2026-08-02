//! **A11 Accept: F1 and F2 demonstrated, not asserted.**
//!
//! `docs/format/anchor-artifact-limits.md`, rules F1–F3:
//!
//! > **F1 — Placement.** Artifact-internal limits are evaluated **only in the
//! > anchor stage (R12)**, never in verify stage 1. … `SealProof::decode`
//! > must never open an artifact.
//! >
//! > **F2 — Blast radius.** Exceeding an artifact-internal limit produces a
//! > **per-anchor verdict for that anchor only**. It never fails bundle
//! > decoding, never fails the evidence layer, never changes another
//! > anchor's state, and never changes the manifest verdict. **A bundle
//! > whose sole `.ots` is over-limit still verifies its content and still
//! > renders its TSA anchors.**
//! >
//! > **F3 — Verdict mapping.** An over-limit artifact renders **`invalid`**
//! > … not `internally-consistent-only` (that state means
//! > well-formed-but-unanchored; an artifact we refused to finish reading is
//! > not known to be well-formed).
//!
//! Those are claims about a *whole bundle*, so they are checked over one —
//! built, re-encoded with a hostile `.ots` in the OTS anchor slot, and put
//! through `SealProof::decode` and `verify_bundle` unchanged.
//!
//! # What this test can and cannot reach today
//!
//! The anchor stage itself is **A18**'s, and R12 has not replaced the M0 stub
//! that renders every anchor `absent`. So the parts of F2 that name a
//! *verdict* are exercised against A11's own `parse_ots` plus A2's verdict
//! constructors rather than against a wired pipeline, and the moment A18
//! lands they should be re-pointed at it. What **is** end-to-end here is the
//! load-bearing half, F1: the bundle decodes, the manifest verifies and the
//! evidence layer passes with an over-limit `.ots` embedded, which is
//! exactly the assertion that goes red if a limit leaks into
//! `SealProof::decode`.

use antseal_core::anchor::model::{AnchorDiagnostic, AnchorKind, AnchorState, AnchorVerdict};
use antseal_core::anchor::ots::{
    MAX_OTS_ATTESTATION_PAYLOAD_BYTES, MAX_OTS_DEPTH, MAX_OTS_OPERAND_BYTES, OtsError, parse_ots,
};
use antseal_core::bundle::{BundleV1, SealProof};
use antseal_core::codec::caps::MAX_OTS_BYTES;
use antseal_core::test_util::bundle_fixtures::{self, AnchorSet, shapes};
use antseal_core::verify::{VerifyOptions, verify_bundle};

// ── building a bundle whose sole `.ots` is hostile ────────────────────────

/// The 31-byte container magic plus a version and digest-type byte.
fn container(digest: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let mut out = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94".to_vec();
    out.push(0x01);
    out.push(0x08);
    out.extend_from_slice(digest);
    out.extend_from_slice(body);
    out
}

/// Every hostile `.ots` this file embeds, with the code it must produce and
/// the limit it breaks. All are **under** `MAX_OTS_BYTES`, so none of them
/// can be rejected by the stage-1 byte cap instead — which would make the
/// whole test pass for the wrong reason.
fn hostile_artifacts() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let digest = [0x42_u8; 32];
    let attestation = {
        // A minimal pending attestation, so a chain has something to end in.
        let uri = b"ab";
        let mut out = vec![0x00_u8];
        out.extend_from_slice(&[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);
        out.push(uri.len() as u8 + 1);
        out.push(uri.len() as u8);
        out.extend_from_slice(uri);
        out
    };

    let too_deep = {
        let mut body = vec![0x08_u8; MAX_OTS_DEPTH as usize + 1];
        body.extend_from_slice(&attestation);
        container(&digest, &body)
    };

    let operand_too_long = {
        let operand = vec![0xab_u8; MAX_OTS_OPERAND_BYTES as usize + 1];
        let mut body = vec![0xf0_u8];
        // varuint of 16 385
        body.extend_from_slice(&[0x81, 0x80, 0x01]);
        body.extend_from_slice(&operand);
        body.extend_from_slice(&attestation);
        container(&digest, &body)
    };

    let payload_too_long = {
        let payload = vec![0x5a_u8; MAX_OTS_ATTESTATION_PAYLOAD_BYTES as usize + 1];
        let mut body = vec![0x00_u8];
        body.extend_from_slice(&[0xde; 8]);
        // varuint of 8 193
        body.extend_from_slice(&[0x81, 0xc0, 0x00]);
        body.extend_from_slice(&payload);
        container(&digest, &body)
    };

    vec![
        ("MAX_OTS_DEPTH", "anchor-ots-too-deep", too_deep),
        (
            "MAX_OTS_OPERAND_BYTES",
            "anchor-ots-operand-too-long",
            operand_too_long,
        ),
        (
            "MAX_OTS_ATTESTATION_PAYLOAD_BYTES",
            "anchor-ots-attestation-payload-too-long",
            payload_too_long,
        ),
    ]
}

/// The `.ots` placeholder byte string the F13 fixture catalogue embeds, with
/// its canonical-CBOR `bstr` header (major 2, length 21 → `0x55`).
const PLACEHOLDER_OTS: &[u8] = b"fixture .ots artifact";

/// Canonical-CBOR `bstr` header plus payload.
fn cbor_bstr(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 5);
    let len = bytes.len() as u64;
    if len < 24 {
        out.push(0x40 | len as u8);
    } else if len <= u64::from(u8::MAX) {
        out.push(0x58);
        out.push(len as u8);
    } else if len <= u64::from(u16::MAX) {
        out.push(0x59);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x5a);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.extend_from_slice(bytes);
    out
}

/// A fixture bundle with its single OTS artifact replaced, **in place, at the
/// byte level**.
///
/// Splicing rather than re-encoding, for a reason worth stating: the F-layer
/// section types are deliberately not `Clone`, so reconstructing a
/// `BundleParts` from a decoded bundle is not available, and adding the
/// derives would be an edit to another task's surface. Splicing is also the
/// stronger move — everything except the `.ots` `bstr` is carried across
/// *byte for byte*, so the control and the hostile bundle differ in exactly
/// one field and the report comparison below is a measurement rather than an
/// assertion. It is sound because canonical CBOR encodes maps and arrays by
/// **element count**, never by byte length, so no enclosing header changes.
fn bundle_with_ots(artifact: &[u8]) -> Vec<u8> {
    let original = control_bundle_bytes();
    let needle = cbor_bstr(PLACEHOLDER_OTS);
    let at = original
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("the fixture's placeholder .ots must be findable");
    assert!(
        original[at + needle.len()..]
            .windows(needle.len())
            .all(|window| window != needle),
        "the placeholder must occur exactly once, or the splice is ambiguous"
    );

    let mut out = Vec::with_capacity(original.len() + artifact.len());
    out.extend_from_slice(&original[..at]);
    out.extend_from_slice(&cbor_bstr(artifact));
    out.extend_from_slice(&original[at + needle.len()..]);
    out
}

/// The unmodified fixture: F13's one-OTS/two-TSA anchored shape.
fn control_bundle_bytes() -> Vec<u8> {
    let spec = shapes::multi_file_anchored();
    let selection = shapes::multi_file_mixed_selection();
    bundle_fixtures::build(&spec, &selection).bytes
}

// ── F1 ────────────────────────────────────────────────────────────────────

/// **F1.** An over-limit `.ots` never reaches `SealProof::decode`, so the
/// bundle still decodes, still verifies its manifest and its content, and
/// still carries both TSA anchors.
///
/// Red the moment any (b)-class limit is evaluated in stage 1.
#[test]
fn over_limit_ots_fails_only_its_own_anchor() {
    // The control: the same bundle, same everything, with the fixture's own
    // placeholder `.ots`. Its report is what the hostile bundles must match.
    let control_bytes = control_bundle_bytes();
    let control =
        verify_bundle(&control_bytes, &VerifyOptions::new()).expect("the control fixture verifies");

    for (limit, code, artifact) in hostile_artifacts() {
        assert!(
            (artifact.len() as u64) < MAX_OTS_BYTES,
            "{limit}'s artifact is {} B — the stage-1 byte cap would reject \
             it first and this test would pass for the wrong reason",
            artifact.len()
        );

        let bytes = bundle_with_ots(&artifact);

        // Layer 1 — the bundle decodes. F1's whole content.
        let decoded = BundleV1::decode(&bytes)
            .unwrap_or_else(|error| panic!("{limit}: bundle must still decode: {error}"));
        assert_eq!(decoded.ots_anchors().len(), 1);
        assert_eq!(
            decoded.tsa_anchors().len(),
            2,
            "{limit}: both TSA anchors survive"
        );

        // Layers 2/3 — the embedded manifest still decodes and verifies.
        SealProof::decode(&bytes)
            .unwrap_or_else(|error| panic!("{limit}: .sealproof must still decode: {error}"));

        // The whole pipeline — content verified, report unchanged.
        let report = verify_bundle(&bytes, &VerifyOptions::new())
            .unwrap_or_else(|error| panic!("{limit}: bundle must still verify: {error}"));
        assert_eq!(
            report, control,
            "{limit}: an over-limit .ots changed something outside its own anchor"
        );

        // …and the artifact really is over-limit, at the anchor stage, with
        // its own code. Without this the assertions above would hold for a
        // bundle carrying a perfectly good `.ots`.
        let digest = [0x42_u8; 32];
        let error = parse_ots(&artifact, &digest).expect_err("must be over-limit");
        assert_eq!(error.code(), code, "{limit}");
    }
}

// ── F2 / F3 ───────────────────────────────────────────────────────────────

/// **F3.** An over-limit artifact renders `invalid`, and specifically **not**
/// `internally-consistent-only` — that state carries the positive claim that
/// everything checkable was checked and passed, and an artifact we refused to
/// finish reading has not earned it.
///
/// The verdict constructor is A2's and the diagnostic is A11's; A18 wires the
/// two together. What this pins is that the pair is expressible and that the
/// resulting verdict is not headline-eligible.
#[test]
fn an_over_limit_artifact_maps_to_invalid_and_carries_no_time() {
    for (_, code, artifact) in hostile_artifacts() {
        let error = parse_ots(&artifact, &[0x42; 32]).expect_err("over-limit");
        assert_eq!(error.code(), code);

        let verdict = AnchorVerdict::invalid(
            AnchorKind::Ots,
            AnchorDiagnostic::new(error.code()),
            None,
            None,
        );
        assert_eq!(verdict.state(), AnchorState::Invalid);
        assert_ne!(
            verdict.state(),
            AnchorState::InternallyConsistentOnly,
            "rule F3: over-limit is not well-formed-but-unanchored"
        );
        assert_eq!(
            verdict.verified_time_unix(),
            None,
            "an invalid anchor can never contribute a headline time"
        );
    }
}

/// **F2, the sibling half.** A second `.ots` in the same bundle is untouched
/// by the first one's limit failure, because each artifact is parsed on its
/// own bytes with its own `anchor_digest` and nothing is shared between them.
#[test]
fn an_over_limit_ots_does_not_change_a_sibling_anchors_state() {
    let digest = [0x42_u8; 32];
    let honest = {
        // A one-branch pending `.ots` over the same digest.
        let mut body = vec![0x00_u8];
        body.extend_from_slice(&[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);
        body.push(0x03);
        body.push(0x02);
        body.extend_from_slice(b"ab");
        container(&digest, &body)
    };

    let honest_before = parse_ots(&honest, &digest).expect("honest artifact parses");
    for (_, _, hostile) in hostile_artifacts() {
        assert!(parse_ots(&hostile, &digest).is_err());
        assert_eq!(
            parse_ots(&honest, &digest).expect("still parses"),
            honest_before,
            "a sibling's rejection must not disturb this one"
        );
    }
}

/// The D79 upgrade group is carried across the re-encode untouched, so the
/// hostile-`.ots` bundles above differ from the control in exactly one field.
///
/// Stated as its own test because `bundle_with_ots` silently dropping the
/// group would make the F1 test weaker without making it fail.
#[test]
fn the_splice_changes_the_artifact_and_nothing_else() {
    let original = control_bundle_bytes();
    let decoded = BundleV1::decode(&original).expect("decodes");
    let before_status = decoded.ots_anchors()[0].status();
    let before_upgrade = decoded.ots_anchors()[0].upgrade().is_some();
    let before_tsa: Vec<&[u8]> = decoded
        .tsa_anchors()
        .iter()
        .map(|anchor| anchor.token().as_slice())
        .collect();

    // Splicing the *same* artifact back in must reproduce the input exactly.
    assert_eq!(
        bundle_with_ots(PLACEHOLDER_OTS),
        original,
        "the splice is byte-identical when nothing changes"
    );

    let spliced = bundle_with_ots(&hostile_artifacts()[0].2);
    let rebuilt = BundleV1::decode(&spliced).expect("decodes");
    assert_eq!(rebuilt.ots_anchors()[0].status(), before_status);
    assert_eq!(rebuilt.ots_anchors()[0].upgrade().is_some(), before_upgrade);
    assert_eq!(
        rebuilt
            .tsa_anchors()
            .iter()
            .map(|anchor| anchor.token().as_slice())
            .collect::<Vec<_>>(),
        before_tsa,
        "the TSA half is untouched"
    );
    assert_eq!(
        rebuilt.ots_anchors()[0].ots().as_slice(),
        hostile_artifacts()[0].2.as_slice()
    );
}

/// The fixture catalogue's placeholder `.ots` is not a valid one, and that is
/// fine — but it means no committed vector exercises a *real* artifact end to
/// end. Recorded as an assertion rather than a comment so that the day a
/// fixture carries real `.ots` bytes, this goes red and someone re-reads it.
#[test]
fn the_committed_fixtures_still_carry_placeholder_ots_bytes() {
    let bytes = control_bundle_bytes();
    let bundle = BundleV1::decode(&bytes).expect("decodes");

    assert!(!bundle.ots_anchors().is_empty(), "fixture carries an .ots");
    assert_eq!(
        parse_ots(bundle.ots_anchors()[0].ots().as_slice(), &[0; 32]),
        Err(OtsError::BadMagic),
        "F13's anchor artifacts are schema-opaque placeholders by design \
         (bundle_fixtures docs); when that changes, so must this"
    );
    assert_eq!(bundle.ots_anchors()[0].ots().as_slice(), PLACEHOLDER_OTS);
    assert_eq!(
        shapes::multi_file_anchored().anchors,
        AnchorSet::OneOtsTwoTsa
    );
}
