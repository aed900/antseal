//! F9 acceptance: the `.sealproof` codec — deterministic encode, and the
//! three-layer nested strict decode of registry §7.6.3.
//!
//! The fixtures are produced by the **independent** hand-rolled CBOR writer
//! ([`bundle_wire`]), never by the encoder under test, so "round-trip
//! byte-identity" means the encoder agrees with a second opinion on what
//! canonical CBOR looks like — not merely with itself.

#[path = "manifest_wire/mod.rs"]
mod manifest_wire;

#[path = "bundle_wire/mod.rs"]
mod bundle_wire;

use antseal_core::bundle::registry::key;
use antseal_core::bundle::{AnchorStatus, OtsUpgrade, ReceiptRecord};
use antseal_core::bundle::{
    BundleParts, BundleV1, CoverEntry, CoveredReveal, FullReveal, NonCoveredReveal, OpaqueBytes,
    OtsAnchor, PathNode, ProofLayer, SealProof, StorageRecord, TouchedFile, TsaAnchor,
    encode_bundle,
};
use antseal_core::content::ggm::NodeAddress;
use antseal_core::crypto::material::{Key32, NodeHash32, Salt16, Seed32};
use antseal_core::manifest::{ContentAddress, Nonce24};

use manifest_wire::{set, uint_non_shortest};

// ---------------------------------------------------------------------------
// round-trip byte identity
// ---------------------------------------------------------------------------

/// Decode `bytes`, re-encode, and assert byte identity.
fn assert_round_trips(name: &str, bytes: &[u8]) {
    let bundle = BundleV1::decode(bytes).unwrap_or_else(|e| panic!("{name}: must decode: {e}"));
    let re_encoded = encode_bundle(&bundle).unwrap_or_else(|e| panic!("{name}: must encode: {e}"));
    assert_eq!(re_encoded, bytes, "{name}: re-encode is not byte-identical");
}

/// **F9 accept**: round-trip byte identity across every shape the accept
/// criterion names. Each row is decoded from independently written canonical
/// bytes and re-encoded to exactly those bytes.
#[test]
fn every_fixture_shape_round_trips_byte_identically() {
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

    cases.push((
        "maximal: both anchor kinds, receipt in, all reveal kinds",
        bundle_wire::encode(&bundle_wire::default_bundle()),
    ));
    cases.push((
        "empty-anchor, zero-revealed-unit bundle",
        bundle_wire::encode(&bundle_wire::empty_bundle()),
    ));

    // Receipt absent — the other half of the opt-in.
    let mut without_receipt = bundle_wire::default_bundle();
    manifest_wire::remove(&mut without_receipt, key::bundle::RECEIPT);
    cases.push(("receipt opted out", bundle_wire::encode(&without_receipt)));

    // Covered-unit reveal alone, including the whole-grid shape whose
    // boundary path is legitimately empty.
    let mut covered_only = bundle_wire::default_bundle();
    set(
        &mut covered_only,
        key::bundle::NONCOVERED_REVEALS,
        bundle_wire::section(&[]),
    );
    cases.push((
        "covered-unit reveals only",
        bundle_wire::encode(&covered_only),
    ));

    // Non-covered reveals only — and note that a **raw-mirror** reveal is
    // exactly this shape: no mirror flag, no link field, because the
    // manifest's `kind` identifies it (D23, registry §7.12). The second
    // entry stands for the file's mirror, which by D23 sorts last among its
    // file's non-covered entries — an ordering property that comes free from
    // ascending `unit_id` and must not be separately enforced.
    let mut noncovered_only = bundle_wire::default_bundle();
    set(
        &mut noncovered_only,
        key::bundle::COVERED_REVEALS,
        bundle_wire::section(&[]),
    );
    set(
        &mut noncovered_only,
        key::bundle::NONCOVERED_REVEALS,
        bundle_wire::section(&[
            bundle_wire::noncovered_reveal(0),
            bundle_wire::noncovered_reveal(1),
        ]),
    );
    cases.push((
        "non-covered + raw-mirror reveals only",
        bundle_wire::encode(&noncovered_only),
    ));

    // A full-file reveal with `file_salt` + `s_root`, and one without
    // `s_root` (the `--no-fine-tree` / empty-file shape).
    for (name, with_s_root) in [
        ("full-file reveal with file_salt and s_root", true),
        ("full-file reveal without s_root", false),
    ] {
        let mut bundle = bundle_wire::default_bundle();
        set(
            &mut bundle,
            key::bundle::FULL_REVEALS,
            bundle_wire::section(&[bundle_wire::full_reveal(0, with_s_root)]),
        );
        cases.push((name, bundle_wire::encode(&bundle)));
    }

    // Every anchor kind and status, upgraded and not; a TSA artifact with
    // and without its optional `source`, with and without intermediates.
    for status in AnchorStatus::ALL {
        let mut bundle = bundle_wire::default_bundle();
        set(
            &mut bundle,
            key::bundle::OTS_ANCHORS,
            bundle_wire::section(&[
                bundle_wire::ots_anchor(status.to_wire(), true),
                bundle_wire::ots_anchor(status.to_wire(), false),
            ]),
        );
        set(
            &mut bundle,
            key::bundle::TSA_ANCHORS,
            bundle_wire::section(&[
                bundle_wire::tsa_anchor(status.to_wire(), 0, 0x30),
                bundle_wire::tsa_anchor(status.to_wire(), 3, 0x31),
            ]),
        );
        cases.push((status.registry_value_name(), bundle_wire::encode(&bundle)));
    }

    // Touched files with no other disclosure at all.
    let mut touched_only = bundle_wire::empty_bundle();
    set(
        &mut touched_only,
        key::bundle::TOUCHED_FILES,
        bundle_wire::section(&[
            bundle_wire::touched_file(0, "notes/pitch.md"),
            bundle_wire::touched_file(3, "assets/logo.png"),
        ]),
    );
    cases.push((
        "touched-file entries only",
        bundle_wire::encode(&touched_only),
    ));

    assert!(cases.len() >= 12, "the accept list must stay covered");
    for (name, bytes) in &cases {
        assert_round_trips(name, bytes);
    }
}

/// **F9 accept**: encoding is deterministic — the same logical bundle always
/// produces identical bytes across repeated runs.
///
/// Registry §8's rider is why this asserts *stability*, not a sort: the two
/// anchor sections are the one unsorted bundle list, because an anchor
/// artifact has no content-independent sort key. Their order is a builder
/// rule backed by the seal journal, so determinism holds **per builder
/// state** — the fixture fixes the anchor order rather than asserting one.
#[test]
fn encoding_is_deterministic_across_repeated_runs() {
    let bytes = bundle_wire::encode(&bundle_wire::default_bundle());
    let bundle = BundleV1::decode(&bytes).expect("fixture decodes");

    let first = encode_bundle(&bundle).expect("encodes");
    for _ in 0..8 {
        assert_eq!(encode_bundle(&bundle).expect("encodes"), first);
    }
    assert_eq!(first, bytes);

    // Byte-identical native↔wasm32 output is P14/Q5's shared harness lane
    // (the crate is `usize`-free on every wire path precisely so it holds);
    // this test is the native half of that pair.
}

/// Two anchor artifacts that differ only in capture order produce different
/// bytes, and both are legitimate — the property registry §8 records so a
/// future editor does not "fix" it by sorting.
#[test]
fn anchor_capture_order_is_preserved_not_sorted() {
    let forward = {
        let mut b = bundle_wire::default_bundle();
        set(
            &mut b,
            key::bundle::TSA_ANCHORS,
            bundle_wire::section(&[
                bundle_wire::tsa_anchor(0, 0, 0xAA),
                bundle_wire::tsa_anchor(0, 0, 0xBB),
            ]),
        );
        bundle_wire::encode(&b)
    };
    let reversed = {
        let mut b = bundle_wire::default_bundle();
        set(
            &mut b,
            key::bundle::TSA_ANCHORS,
            bundle_wire::section(&[
                bundle_wire::tsa_anchor(0, 0, 0xBB),
                bundle_wire::tsa_anchor(0, 0, 0xAA),
            ]),
        );
        bundle_wire::encode(&b)
    };

    assert_ne!(forward, reversed, "order is content, not noise");
    assert_round_trips("anchors in capture order", &forward);
    assert_round_trips("anchors in the other capture order", &reversed);
    let decoded = BundleV1::decode(&reversed).expect("decodes");
    assert_eq!(decoded.tsa_anchors()[0].token().as_slice(), [0xBB; 128]);
}

/// The reveal-side path: build a bundle from typed values, encode it, and
/// decode it back. This is the surface R's M3 builder consumes, and it must
/// produce bytes this crate's own decoder accepts.
#[test]
fn seal_side_construction_encodes_and_decodes() {
    let manifest = bundle_wire::embedded_manifest();
    let address = NodeAddress::try_new(1, 0).expect("in bounds");

    let parts = BundleParts {
        manifest: &manifest,
        storage_record: StorageRecord::new(
            ContentAddress::from_bytes([0xA0; 32]),
            Nonce24::from_bytes([0xA1; 24]),
            Key32::from_bytes([0xA2; 32]),
        ),
        ots_anchors: vec![OtsAnchor::new(
            AnchorStatus::Attested,
            OpaqueBytes::from_vec(vec![0x4F; 16]),
            Some(OtsUpgrade::new(870_000, [0xB7; 80], 1_767_225_600)),
        )],
        tsa_anchors: vec![TsaAnchor::new(
            AnchorStatus::Proven,
            OpaqueBytes::from_vec(vec![0x30; 32]),
            vec![OpaqueBytes::from_vec(vec![0xC0; 24])],
            1_767_225_601,
        )],
        receipt: Some(
            ReceiptRecord::new(
                vec![[0xE0; 32]],
                263_000_000,
                OpaqueBytes::from_vec(vec![1, 2]),
            )
            .expect("non-empty tx list"),
        ),
        covered_reveals: vec![
            CoveredReveal::new(
                0,
                Key32::from_bytes([0x11; 32]),
                OpaqueBytes::from_vec(vec![0x22; 272]),
                vec![CoverEntry::new(address, Seed32::from_bytes([0x31; 32]))],
                vec![PathNode::new(address, NodeHash32::from_bytes([0x41; 32]))],
            )
            .expect("valid covered reveal"),
        ],
        noncovered_reveals: vec![
            NonCoveredReveal::new(
                1,
                Key32::from_bytes([0x12; 32]),
                OpaqueBytes::from_vec(vec![0x23; 528]),
                Salt16::from_bytes([0x61; 16]),
            )
            .expect("valid non-covered reveal"),
        ],
        touched_files: vec![TouchedFile::new(
            0,
            "notes/pitch.md".to_owned(),
            Salt16::from_bytes([0x71; 16]),
        )],
        full_reveals: vec![FullReveal::new(
            0,
            Salt16::from_bytes([0x81; 16]),
            Some(Seed32::from_bytes([0x91; 32])),
        )],
    };

    let built = BundleV1::new(parts).expect("parts satisfy every [P]/[X] rule");
    let bytes = encode_bundle(&built).expect("encodes");

    let decoded = BundleV1::decode(&bytes).expect("our own output decodes");
    assert_eq!(decoded.revealed_unit_ids(), vec![0, 1]);
    assert_eq!(decoded.touched_files()[0].path(), "notes/pitch.md");
    assert_eq!(decoded.manifest_bytes(), manifest.as_slice());
    assert_eq!(encode_bundle(&decoded).expect("re-encodes"), bytes);
}

// ---------------------------------------------------------------------------
// three-layer nested strict decoding
// ---------------------------------------------------------------------------

/// All three layers succeed on a valid `.sealproof`, and the zero-copy seam
/// holds: layer 2 was handed a **sub-slice of the bundle input**, so the
/// `anchor_digest` pre-image is the received bytes by construction
/// (registry §7.6.3).
#[test]
fn all_three_layers_decode_and_the_seam_is_zero_copy() {
    let bytes = bundle_wire::encode(&bundle_wire::default_bundle());
    let proof = SealProof::decode(&bytes).expect("all three layers decode");

    assert_eq!(
        proof.anchor_digest_preimage(),
        proof.bundle().manifest_bytes()
    );
    assert_eq!(
        proof.manifest().encoded_bytes(),
        proof.bundle().manifest_bytes()
    );

    let input = bytes.as_ptr_range();
    for slice in [
        proof.anchor_digest_preimage(),
        proof.manifest().body_bytes(),
    ] {
        let range = slice.as_ptr_range();
        assert!(
            input.start <= range.start && range.end <= input.end,
            "layer 2/3 must borrow the bundle input, not a copy"
        );
    }

    // Layer 3 really ran: the body decoded into a schema object.
    assert!(!proof.manifest().body().files().is_empty());
}

/// **F9 accept**: a canonical bundle wrapping **non-canonical embedded
/// manifest bytes** fails at the manifest layer and says so.
#[test]
fn non_canonical_embedded_manifest_fails_at_layer_two() {
    let body = manifest_wire::map(&manifest_wire::default_body());
    // A canonical body inside an envelope whose two keys are emitted out of
    // order — a layer-2 canonicality failure, invisible to layer 1 because
    // the envelope is an opaque bstr there (D78).
    use antseal_core::manifest::registry::key::envelope;
    let envelope = manifest_wire::map_in_given_order(&[
        (
            envelope::SIGNATURES,
            manifest_wire::map(&manifest_wire::hybrid_signatures()),
        ),
        (envelope::BODY, manifest_wire::bstr(&body)),
    ]);

    let mut bundle = bundle_wire::default_bundle();
    set(
        &mut bundle,
        key::bundle::MANIFEST,
        manifest_wire::bstr(&envelope),
    );
    let bytes = bundle_wire::encode(&bundle);

    // Layer 1 alone is perfectly happy — the proof that D78 holds.
    BundleV1::decode(&bytes).expect("the bundle itself is well-formed");

    let err = SealProof::decode(&bytes)
        .map(|_| ())
        .expect_err("layer 2 must reject");
    assert_eq!(err.layer(), ProofLayer::ManifestEnvelope);
    assert_eq!(err.code(), "cbor-unsorted-map-keys");
}

/// **F9 accept**: a canonical manifest envelope carrying a **non-canonical
/// inner body** fails at the body layer and says so — a different layer from
/// the case above, reported distinctly.
#[test]
fn non_canonical_manifest_body_fails_at_layer_three() {
    let mut body_entries = manifest_wire::default_body();
    // A shortest-form-violating integer head deep inside the body.
    set(
        &mut body_entries,
        antseal_core::manifest::registry::key::body::CLAIMED_TIME,
        uint_non_shortest(1),
    );
    let envelope = manifest_wire::envelope_around(&manifest_wire::map(&body_entries));

    let mut bundle = bundle_wire::default_bundle();
    set(
        &mut bundle,
        key::bundle::MANIFEST,
        manifest_wire::bstr(&envelope),
    );
    let bytes = bundle_wire::encode(&bundle);

    BundleV1::decode(&bytes).expect("the bundle itself is well-formed");

    let err = SealProof::decode(&bytes)
        .map(|_| ())
        .expect_err("layer 3 must reject");
    assert_eq!(err.layer(), ProofLayer::ManifestBody);
    assert_eq!(err.code(), "cbor-non-shortest-int");
}

/// A layer-1 failure stays layer 1 and keeps its `bundle-` identity — the
/// third leg of the layer triple, and the D78 guarantee at pipeline level.
#[test]
fn a_bundle_failure_stays_in_the_bundle_family() {
    let mut bundle = bundle_wire::default_bundle();
    set(
        &mut bundle,
        key::bundle::FULL_REVEALS,
        bundle_wire::section(&[bundle_wire::full_reveal(9, true)]),
    );
    let bytes = bundle_wire::encode(&bundle);

    let err = SealProof::decode(&bytes)
        .map(|_| ())
        .expect_err("layer 1 must reject");
    assert_eq!(err.layer(), ProofLayer::Bundle);
    assert_eq!(err.code(), "bundle-full-reveal-without-touched-file");
}

/// A **manifest schema** rejection keeps its `manifest-` code and does not
/// leak into the bundle family, even though it surfaces through the bundle's
/// pipeline. It is layered like any other rejection (D86): the missing key
/// is body key 2 `seal_id`, so the error names the body map and reports
/// layer 3. Before D86 it reported no layer at all, which is what made
/// `manifest-unknown-key` at the envelope and at the body one observable.
#[test]
fn a_manifest_schema_failure_keeps_its_own_family() {
    let mut body_entries = manifest_wire::default_body();
    manifest_wire::remove(
        &mut body_entries,
        antseal_core::manifest::registry::key::body::SEAL_ID,
    );
    let envelope = manifest_wire::envelope_around(&manifest_wire::map(&body_entries));

    let mut bundle = bundle_wire::default_bundle();
    set(
        &mut bundle,
        key::bundle::MANIFEST,
        manifest_wire::bstr(&envelope),
    );
    let bytes = bundle_wire::encode(&bundle);

    let err = SealProof::decode(&bytes)
        .map(|_| ())
        .expect_err("the manifest schema must reject");
    assert_eq!(err.code(), "manifest-missing-key");
    assert_eq!(err.layer(), ProofLayer::ManifestBody);
    assert!(
        !err.code().starts_with("bundle-"),
        "a manifest failure must never acquire a bundle- code (D78/D30)"
    );
}

/// The empty-anchor bundle decodes through all three layers too — the M0
/// vector the spec names at line 153 must not be a layer-1-only shape.
#[test]
fn empty_anchor_bundle_decodes_through_all_three_layers() {
    let bytes = bundle_wire::encode(&bundle_wire::empty_bundle());
    let proof = SealProof::decode(&bytes).expect("decodes");
    assert!(proof.bundle().ots_anchors().is_empty());
    assert!(proof.bundle().tsa_anchors().is_empty());
    assert!(!proof.manifest().body().files().is_empty());
}
