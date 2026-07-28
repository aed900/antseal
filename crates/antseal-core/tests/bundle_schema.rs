//! F8 acceptance: `.sealproof` bundle schema types + parse-time shape
//! validation.
//!
//! Every reject case is built by the **independent** hand-rolled CBOR writer
//! in [`bundle_wire`] — bytes the F2 encoder and the F8 schema types make
//! unrepresentable — so a green suite means the validator rejects what it
//! claims to, not merely that its own encoder never emits it.
//!
//! Scope is layer 1 (registry §7.6.3). **D78**: none of these assertions may
//! depend on the embedded manifest, and none of them does — every fixture
//! carries the same valid manifest bytes, and no expected code is a
//! `manifest-` code.

#[path = "manifest_wire/mod.rs"]
mod manifest_wire;

mod bundle_wire;

use std::collections::BTreeSet;

use antseal_core::bundle::registry::{AnchorStatus, BundleMapId, key};
use antseal_core::bundle::{BundleV1, OpaqueBytes};

use manifest_wire::{remove, set};

// ---------------------------------------------------------------------------
// fixture plumbing
// ---------------------------------------------------------------------------

/// Decode a bundle from a mutated entry list, expecting success.
fn decode_ok(entries: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let bytes = bundle_wire::encode(entries);
    BundleV1::decode(&bytes).expect("fixture must decode");
    bytes
}

/// The stable code a mutated bundle rejects with.
fn reject_code(bytes: &[u8]) -> &'static str {
    BundleV1::decode(bytes)
        .map(|_| ())
        .expect_err("mutation must be rejected")
        .code()
}

/// A bundle whose `covered_reveals` section is replaced.
fn with_covered(reveals: &[Vec<(u64, Vec<u8>)>]) -> Vec<u8> {
    let mut bundle = bundle_wire::default_bundle();
    set(
        &mut bundle,
        key::bundle::COVERED_REVEALS,
        bundle_wire::section(reveals),
    );
    bundle_wire::encode(&bundle)
}

/// A bundle whose sole covered reveal is perturbed in place.
fn covered_with(mutate: impl FnOnce(&mut Vec<(u64, Vec<u8>)>)) -> Vec<u8> {
    let mut reveal = bundle_wire::covered_reveal(0);
    mutate(&mut reveal);
    with_covered(&[reveal])
}

/// A bundle whose sole non-covered reveal is perturbed in place.
fn noncovered_with(mutate: impl FnOnce(&mut Vec<(u64, Vec<u8>)>)) -> Vec<u8> {
    let mut reveal = bundle_wire::noncovered_reveal(2);
    mutate(&mut reveal);
    let mut bundle = bundle_wire::default_bundle();
    set(
        &mut bundle,
        key::bundle::NONCOVERED_REVEALS,
        bundle_wire::section(&[reveal]),
    );
    bundle_wire::encode(&bundle)
}

/// A bundle with one top-level section replaced wholesale.
fn with_section(section_key: u64, value: Vec<u8>) -> Vec<u8> {
    let mut bundle = bundle_wire::default_bundle();
    set(&mut bundle, section_key, value);
    bundle_wire::encode(&bundle)
}

// ---------------------------------------------------------------------------
// accept matrix (F8 accept: representable and decodable at schema level)
// ---------------------------------------------------------------------------

/// The maximal bundle — both anchor kinds present, the OTS one upgraded, the
/// receipt opted in, covered and non-covered reveals, touched files, a full
/// reveal — decodes, and every section reads back.
#[test]
fn maximal_bundle_decodes() {
    let bytes = bundle_wire::encode(&bundle_wire::default_bundle());
    let bundle = BundleV1::decode(&bytes).expect("maximal fixture decodes");

    assert_eq!(bundle.ots_anchors().len(), 1);
    assert_eq!(bundle.tsa_anchors().len(), 1);
    assert!(bundle.receipt().is_some());
    assert_eq!(bundle.covered_reveals().len(), 2);
    assert_eq!(bundle.noncovered_reveals().len(), 1);
    assert_eq!(bundle.touched_files().len(), 2);
    assert_eq!(bundle.full_reveals().len(), 1);
}

/// The **empty-anchor, zero-revealed-unit** bundle (an M0 vector the spec
/// names at line 153): every required section present and empty, receipt
/// absent. Required-may-be-empty means this is one shape, not a bundle with
/// keys missing (registry §7.6).
#[test]
fn empty_anchor_zero_reveal_bundle_decodes() {
    let bytes = bundle_wire::encode(&bundle_wire::empty_bundle());
    let bundle = BundleV1::decode(&bytes).expect("empty fixture decodes");

    assert!(bundle.ots_anchors().is_empty());
    assert!(bundle.tsa_anchors().is_empty());
    assert!(bundle.receipt().is_none());
    assert!(bundle.covered_reveals().is_empty());
    assert!(bundle.noncovered_reveals().is_empty());
    assert!(bundle.touched_files().is_empty());
    assert!(bundle.full_reveals().is_empty());
    assert!(bundle.revealed_unit_ids().is_empty());
}

/// Receipt presence *is* the opt-in: absence is never an error and presence
/// is never required (registry §7.6 key 5), so both shapes decode.
#[test]
fn receipt_is_optional_in_both_directions() {
    let with_receipt = bundle_wire::encode(&bundle_wire::default_bundle());
    assert!(
        BundleV1::decode(&with_receipt)
            .expect("receipt present")
            .receipt()
            .is_some()
    );

    let mut without = bundle_wire::default_bundle();
    remove(&mut without, key::bundle::RECEIPT);
    let without = decode_ok(&without);
    assert!(BundleV1::decode(&without).expect("ok").receipt().is_none());
}

/// Every registered `anchor_status` value decodes in both anchor sections —
/// which subset is legal *as recorded* is A/R's semantic rule, not a parse
/// rule (registry §6.1).
#[test]
fn every_anchor_status_value_decodes() {
    for status in AnchorStatus::ALL {
        let ots = with_section(
            key::bundle::OTS_ANCHORS,
            bundle_wire::section(&[bundle_wire::ots_anchor(status.to_wire(), false)]),
        );
        let decoded = BundleV1::decode(&ots).expect("OTS status decodes");
        assert_eq!(decoded.ots_anchors()[0].status(), *status);

        let tsa = with_section(
            key::bundle::TSA_ANCHORS,
            bundle_wire::section(&[bundle_wire::tsa_anchor(status.to_wire(), 0, None)]),
        );
        let decoded = BundleV1::decode(&tsa).expect("TSA status decodes");
        assert_eq!(decoded.tsa_anchors()[0].status(), *status);
    }
}

/// The OTS upgrade group is present-or-absent as a whole (D79), and both
/// shapes decode. The group is **free-standing**: neither shape's acceptance
/// depends on the sealer-written `status`, so an un-upgraded artifact
/// recording `attested` and an upgraded one recording `pending` both parse —
/// the contradiction is a verdict, not a parse error.
#[test]
fn ots_upgrade_group_is_free_standing_from_status() {
    for (status, upgraded) in [(2, true), (2, false), (3, true), (3, false)] {
        let bytes = with_section(
            key::bundle::OTS_ANCHORS,
            bundle_wire::section(&[bundle_wire::ots_anchor(status, upgraded)]),
        );
        let bundle = BundleV1::decode(&bytes).expect("group is independent of status");
        assert_eq!(bundle.ots_anchors()[0].upgrade().is_some(), upgraded);
    }
}

/// A TSA artifact's `source` is optional with no parse-decidable condition,
/// and its `intermediates` list may be empty (registry §7.9).
#[test]
fn tsa_source_is_optional_and_intermediates_may_be_empty() {
    let bare = with_section(
        key::bundle::TSA_ANCHORS,
        bundle_wire::section(&[bundle_wire::tsa_anchor(0, 0, None)]),
    );
    let bundle = BundleV1::decode(&bare).expect("bare TSA artifact");
    assert!(bundle.tsa_anchors()[0].source().is_none());
    assert!(bundle.tsa_anchors()[0].intermediates().is_empty());
}

/// A full reveal without `s_root` decodes: the key is genuinely optional at
/// schema level, because whether it *should* be there is D28's derived
/// predicate — tier [R], and R4's alone.
#[test]
fn full_reveal_s_root_is_optional_at_schema_level() {
    for with_s_root in [true, false] {
        let bytes = with_section(
            key::bundle::FULL_REVEALS,
            bundle_wire::section(&[bundle_wire::full_reveal(0, with_s_root)]),
        );
        let bundle = BundleV1::decode(&bytes).expect("both shapes are schema-valid");
        assert_eq!(
            bundle.full_reveals()[0].disclosed_s_root().is_some(),
            with_s_root
        );
    }
}

/// The embedded manifest is a **sub-slice of the bundle input**, not a copy —
/// the zero-copy requirement of registry §7.6.3, checked by pointer
/// containment. `Manifest<'b>`'s guarantee that the bytes fed to `work_id`
/// and to signature verification are the received ones only holds if the
/// slice really is the bundle's own bytes.
#[test]
fn manifest_bytes_borrow_from_the_bundle_input() {
    let bytes = bundle_wire::encode(&bundle_wire::default_bundle());
    let bundle = BundleV1::decode(&bytes).expect("fixture decodes");

    let input = bytes.as_ptr_range();
    let manifest = bundle.manifest_bytes().as_ptr_range();
    assert!(input.start <= manifest.start && manifest.end <= input.end);
    assert_eq!(bundle.manifest_bytes(), bundle_wire::embedded_manifest());
}

/// `revealed_unit_ids` follows the registry's canonical concatenation order:
/// `covered_reveals` ⧺ `noncovered_reveals`, i.e. section key order
/// (registry §7.6), so R5's first-duplicate report is deterministic.
#[test]
fn revealed_unit_ids_use_the_canonical_concatenation_order() {
    let mut bundle = bundle_wire::default_bundle();
    set(
        &mut bundle,
        key::bundle::COVERED_REVEALS,
        bundle_wire::section(&[bundle_wire::covered_reveal(5)]),
    );
    set(
        &mut bundle,
        key::bundle::NONCOVERED_REVEALS,
        bundle_wire::section(&[bundle_wire::noncovered_reveal(1)]),
    );
    let bytes = bundle_wire::encode(&bundle);
    let decoded = BundleV1::decode(&bytes).expect("fixture decodes");

    // Covered first even though 1 < 5: section order, not numeric order.
    assert_eq!(decoded.revealed_unit_ids(), vec![5, 1]);
}

// ---------------------------------------------------------------------------
// checklist: MVP-SPEC.md lines 112–114 → concrete fields
// ---------------------------------------------------------------------------

/// **F8 accept**: every content item the spec enumerates for a `.sealproof`
/// maps to a concrete field of the schema, checked on the maximal fixture.
///
/// The last row is the checklist's negative half: nonces are *not* bundle
/// fields (spec line 114 — the manifest is the single source of truth).
#[test]
fn every_spec_content_item_maps_to_a_field() {
    let bytes = bundle_wire::encode(&bundle_wire::default_bundle());
    let b = BundleV1::decode(&bytes).expect("fixture decodes");
    let ots = &b.ots_anchors()[0];
    let tsa = &b.tsa_anchors()[0];
    let receipt = b.receipt().expect("receipt opted in");
    let covered = &b.covered_reveals()[0];
    let noncovered = &b.noncovered_reveals()[0];
    let touched = &b.touched_files()[0];
    let full = &b.full_reveals()[0];

    let checklist: &[(&str, bool)] = &[
        ("plaintext manifest bytes", !b.manifest_bytes().is_empty()),
        (
            "manifest storage record: address",
            b.storage_record().address().as_bytes().len() == 32,
        ),
        (
            "manifest storage record: nonce",
            b.storage_record().nonce().as_bytes().len() == 24,
        ),
        (
            "manifest storage record: k_m",
            b.storage_record().k_m().as_bytes().len() == 32,
        ),
        ("per-anchor artifact: status", {
            let _ = ots.status();
            let _ = tsa.status();
            true
        }),
        ("per-anchor artifact: .ots bytes", !ots.ots().is_empty()),
        (
            "per-anchor artifact: embedded Bitcoin header where upgraded",
            ots.upgrade().is_some_and(|u| u.block_header().len() == 80),
        ),
        (
            "per-anchor artifact: attested block height",
            ots.upgrade().is_some_and(|u| u.block_height() > 0),
        ),
        ("per-anchor artifact: TSA token", !tsa.token().is_empty()),
        (
            "per-anchor artifact: intermediate certs",
            !tsa.intermediates().is_empty(),
        ),
        (
            "per-anchor artifact: fetch dates",
            tsa.fetch_date() > 0 && ots.upgrade().is_some_and(|u| u.fetch_date() > 0),
        ),
        (
            "receipt only if opted in",
            !receipt.tx_hashes().is_empty()
                && receipt.block_number() > 0
                && !receipt.payload().is_empty(),
        ),
        ("covered reveal: unit_id", covered.unit_id() == 0),
        ("covered reveal: k_u", covered.k_u().as_bytes().len() == 32),
        (
            "covered reveal: embedded ciphertext",
            covered.ciphertext().len() >= 272,
        ),
        (
            "covered reveal: leaf-exact GGM sub-cover",
            !covered.cover().is_empty(),
        ),
        (
            "covered reveal: boundary Merkle paths",
            !covered.paths().is_empty(),
        ),
        ("non-covered reveal: unit_id", noncovered.unit_id() == 2),
        (
            "non-covered reveal: unit_salt",
            noncovered.unit_salt().as_bytes().len() == 16,
        ),
        (
            "non-covered reveal: k_u",
            noncovered.k_u().as_bytes().len() == 32,
        ),
        (
            "non-covered reveal: embedded ciphertext",
            noncovered.ciphertext().len() >= 272,
        ),
        ("touched file: path", !touched.path().is_empty()),
        (
            "touched file: path_salt",
            touched.path_salt().as_bytes().len() == 16,
        ),
        ("fully revealed file: file_salt", {
            // `FileSalt` is opaque by C7's disclosure rule — presence is
            // what the checklist needs, and presence is total.
            let _ = full.file_salt();
            true
        }),
        (
            "fully revealed file: s_root",
            full.disclosed_s_root()
                .is_some_and(|s| s.as_bytes().len() == 32),
        ),
        (
            "NONCE IS NOT A BUNDLE FIELD (line 114: manifest is the single \
             source of truth)",
            BundleMapId::CoveredReveal.assigned_keys() == [0, 1, 2, 3, 4]
                && BundleMapId::NonCoveredReveal.assigned_keys() == [0, 1, 2, 3],
        ),
    ];

    let missing: Vec<&str> = checklist
        .iter()
        .filter(|(_, present)| !present)
        .map(|(item, _)| *item)
        .collect();
    assert!(
        missing.is_empty(),
        "spec content items with no reachable field: {missing:?}"
    );
    assert_eq!(
        checklist.len(),
        26,
        "checklist row count — extend deliberately when the spec list changes"
    );
}

/// **Registry §7.6.1, checked absences.** Four fields are absent by design;
/// an absence nobody tests is an absence that grows back.
///
/// The reveal-shape discriminant (D28 rider 1) is additionally banned
/// repo-wide by `tests/identifier_bans.rs`, which greps every source file —
/// this test pins the wire side.
#[test]
fn the_four_checked_absences_hold() {
    // 1. No per-unit nonce in either reveal section: their key sets are
    //    exactly the registry's, with no room for one.
    assert_eq!(BundleMapId::CoveredReveal.assigned_keys(), [0, 1, 2, 3, 4]);
    assert_eq!(BundleMapId::NonCoveredReveal.assigned_keys(), [0, 1, 2, 3]);

    // 2. No signature container at bundle level: the bundle is unsigned. Its
    //    authority is the embedded *signed* manifest plus the anchors, and a
    //    bundle signature would invite trusting the assembler — who is the
    //    sealer, who is the adversary (spec line 121).
    assert_eq!(
        BundleMapId::Bundle.assigned_keys(),
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    );

    // 3. No stored work_id / anchor_digest / seal_id: all three are derived,
    //    and a stored copy could disagree with the bytes it summarizes.
    //    Key 1 is the *pre-image*, never the digest.
    let bytes = bundle_wire::encode(&bundle_wire::default_bundle());
    let bundle = BundleV1::decode(&bytes).expect("fixture decodes");
    assert!(bundle.manifest_bytes().len() > 32, "bytes, not a digest");

    // 4. No reveal-shape discriminant at any level (D28 rider 1): every
    //    bundle map's key space is fully accounted for by the registry's
    //    named fields, so there is no unclaimed slot one could occupy.
    for map in BundleMapId::ALL {
        let (first, _) = map.reserved_band();
        assert_eq!(
            u64::try_from(map.assigned_keys().len()).expect("small"),
            first,
            "{map}: assigned keys must be 0..first_reserved with no gaps"
        );
    }
}

// ---------------------------------------------------------------------------
// reject matrix — every mutation fails with a distinct error
// ---------------------------------------------------------------------------

/// One reject row: a mutation of the valid fixture and the code it must
/// produce.
struct Reject {
    name: &'static str,
    bytes: Vec<u8>,
    code: &'static str,
}

fn rejects() -> Vec<Reject> {
    let row = |name: &'static str, bytes: Vec<u8>, code: &'static str| Reject { name, bytes, code };

    let mut rows = Vec::new();

    // ── key space ───────────────────────────────────────────────────
    rows.push(row(
        "unknown top-level key (>= 24)",
        {
            let mut b = bundle_wire::default_bundle();
            set(&mut b, 24, manifest_wire::uint(0));
            bundle_wire::encode(&b)
        },
        "bundle-unknown-key",
    ));
    rows.push(row(
        "reserved v1.1 slot present: bundle key 10 (range_reveals)",
        {
            let mut b = bundle_wire::default_bundle();
            set(
                &mut b,
                key::bundle::RESERVED_RANGE_REVEALS,
                manifest_wire::array(&[]),
            );
            bundle_wire::encode(&b)
        },
        "bundle-reserved-key",
    ));
    rows.push(row(
        "required key absent: storage record k_m",
        {
            let mut record = bundle_wire::storage_record();
            remove(&mut record, key::storage_record::K_M);
            with_section(key::bundle::STORAGE_RECORD, manifest_wire::map(&record))
        },
        "bundle-missing-key",
    ));

    // ── fixed lengths (12 classes) ──────────────────────────────────
    rows.push(row(
        "wrong-length k_u",
        covered_with(|r| {
            set(
                r,
                key::covered_reveal::K_U,
                manifest_wire::bstr(&[0x11; 31]),
            );
        }),
        "bundle-wrong-length-k-u",
    ));
    rows.push(row(
        "wrong-length k_m",
        {
            let mut record = bundle_wire::storage_record();
            set(
                &mut record,
                key::storage_record::K_M,
                manifest_wire::bstr(&[0xA2; 16]),
            );
            with_section(key::bundle::STORAGE_RECORD, manifest_wire::map(&record))
        },
        "bundle-wrong-length-k-m",
    ));
    rows.push(row(
        "wrong-length unit_salt",
        noncovered_with(|r| {
            set(
                r,
                key::noncovered_reveal::UNIT_SALT,
                manifest_wire::bstr(&[0x61; 32]),
            );
        }),
        "bundle-wrong-length-unit-salt",
    ));
    rows.push(row(
        "wrong-length path_salt",
        {
            let mut entry = bundle_wire::touched_file(0, "notes/pitch.md");
            set(
                &mut entry,
                key::touched_file::PATH_SALT,
                manifest_wire::bstr(&[0x71; 15]),
            );
            with_section(key::bundle::TOUCHED_FILES, bundle_wire::section(&[entry]))
        },
        "bundle-wrong-length-path-salt",
    ));
    rows.push(row(
        "wrong-length file_salt",
        {
            let mut entry = bundle_wire::full_reveal(0, true);
            set(
                &mut entry,
                key::full_reveal::FILE_SALT,
                manifest_wire::bstr(&[0x81; 32]),
            );
            with_section(key::bundle::FULL_REVEALS, bundle_wire::section(&[entry]))
        },
        "bundle-wrong-length-file-salt",
    ));
    rows.push(row(
        "wrong-length s_root",
        {
            let mut entry = bundle_wire::full_reveal(0, true);
            set(
                &mut entry,
                key::full_reveal::S_ROOT,
                manifest_wire::bstr(&[0x91; 16]),
            );
            with_section(key::bundle::FULL_REVEALS, bundle_wire::section(&[entry]))
        },
        "bundle-wrong-length-s-root",
    ));
    rows.push(row(
        "wrong-length GGM cover seed",
        covered_with(|r| {
            set(
                r,
                key::covered_reveal::COVER,
                manifest_wire::array(&[manifest_wire::array(&[
                    manifest_wire::uint(2),
                    manifest_wire::uint(0),
                    manifest_wire::bstr(&[0x31; 16]),
                ])]),
            );
        }),
        "bundle-wrong-length-cover-seed",
    ));
    rows.push(row(
        "wrong-length boundary node hash",
        covered_with(|r| {
            set(
                r,
                key::covered_reveal::PATHS,
                manifest_wire::array(&[manifest_wire::array(&[
                    manifest_wire::uint(3),
                    manifest_wire::uint(0),
                    manifest_wire::bstr(&[0x41; 31]),
                ])]),
            );
        }),
        "bundle-wrong-length-path-node-hash",
    ));
    rows.push(row(
        "wrong-length storage nonce",
        {
            let mut record = bundle_wire::storage_record();
            set(
                &mut record,
                key::storage_record::NONCE,
                manifest_wire::bstr(&[0xA1; 12]),
            );
            with_section(key::bundle::STORAGE_RECORD, manifest_wire::map(&record))
        },
        "bundle-wrong-length-storage-nonce",
    ));
    rows.push(row(
        "wrong-length storage address",
        {
            let mut record = bundle_wire::storage_record();
            set(
                &mut record,
                key::storage_record::ADDRESS,
                manifest_wire::bstr(&[0xA0; 20]),
            );
            with_section(key::bundle::STORAGE_RECORD, manifest_wire::map(&record))
        },
        "bundle-wrong-length-storage-address",
    ));
    rows.push(row(
        "Bitcoin block header != 80 bytes",
        {
            let mut anchor = bundle_wire::ots_anchor(2, true);
            set(
                &mut anchor,
                key::ots_anchor::BLOCK_HEADER,
                manifest_wire::bstr(&[0xB7; 79]),
            );
            with_section(key::bundle::OTS_ANCHORS, bundle_wire::section(&[anchor]))
        },
        "bundle-wrong-length-block-header",
    ));
    rows.push(row(
        "wrong-length receipt tx hash",
        {
            let mut receipt = bundle_wire::receipt();
            set(
                &mut receipt,
                key::receipt::TX_HASHES,
                manifest_wire::array(&[manifest_wire::bstr(&[0xE0; 20])]),
            );
            with_section(key::bundle::RECEIPT, manifest_wire::map(&receipt))
        },
        "bundle-wrong-length-tx-hash",
    ));

    // ── non-empty containers ────────────────────────────────────────
    rows.push(row(
        "empty cover on a covered reveal",
        covered_with(|r| {
            set(r, key::covered_reveal::COVER, manifest_wire::array(&[]));
        }),
        "bundle-empty-cover",
    ));
    rows.push(row(
        "empty receipt tx_hashes",
        {
            let mut receipt = bundle_wire::receipt();
            set(
                &mut receipt,
                key::receipt::TX_HASHES,
                manifest_wire::array(&[]),
            );
            with_section(key::bundle::RECEIPT, manifest_wire::map(&receipt))
        },
        "bundle-empty-tx-hashes",
    ));

    // ── parse-enforced ordering (6 lists) ───────────────────────────
    rows.push(row(
        "covered_reveals not ascending by unit_id",
        with_covered(&[
            bundle_wire::covered_reveal(4),
            bundle_wire::covered_reveal(1),
        ]),
        "bundle-unsorted-covered-reveals",
    ));
    rows.push(row(
        "noncovered_reveals not ascending by unit_id",
        with_section(
            key::bundle::NONCOVERED_REVEALS,
            bundle_wire::section(&[
                bundle_wire::noncovered_reveal(6),
                bundle_wire::noncovered_reveal(5),
            ]),
        ),
        "bundle-unsorted-noncovered-reveals",
    ));
    rows.push(row(
        "touched_files not ascending by file_id",
        with_section(
            key::bundle::TOUCHED_FILES,
            bundle_wire::section(&[
                bundle_wire::touched_file(1, "logo.png"),
                bundle_wire::touched_file(0, "notes/pitch.md"),
            ]),
        ),
        "bundle-unsorted-touched-files",
    ));
    rows.push(row(
        "full_reveals not ascending by file_id (duplicate id)",
        with_section(
            key::bundle::FULL_REVEALS,
            bundle_wire::section(&[
                bundle_wire::full_reveal(0, true),
                bundle_wire::full_reveal(0, true),
            ]),
        ),
        "bundle-unsorted-full-reveals",
    ));
    rows.push(row(
        "cover not ascending by leaf-interval start",
        covered_with(|r| {
            set(
                r,
                key::covered_reveal::COVER,
                manifest_wire::array(&[
                    bundle_wire::cover_entry(2, 2, 0x33),
                    bundle_wire::cover_entry(2, 0, 0x31),
                ]),
            );
        }),
        "bundle-unsorted-cover",
    ));
    rows.push(row(
        "paths not ascending by leaf-interval start",
        covered_with(|r| {
            set(
                r,
                key::covered_reveal::PATHS,
                manifest_wire::array(&[
                    bundle_wire::path_node(2, 3, 0x42),
                    bundle_wire::path_node(3, 0, 0x41),
                ]),
            );
        }),
        "bundle-unsorted-paths",
    ));

    // ── positional tuple arity ──────────────────────────────────────
    rows.push(row(
        "cover_entry with 4 elements",
        covered_with(|r| {
            set(
                r,
                key::covered_reveal::COVER,
                manifest_wire::array(&[manifest_wire::array(&[
                    manifest_wire::uint(2),
                    manifest_wire::uint(0),
                    bundle_wire::bytes32(0x31),
                    manifest_wire::uint(9),
                ])]),
            );
        }),
        "bundle-wrong-cover-entry-arity",
    ));
    rows.push(row(
        "path_node with 2 elements",
        covered_with(|r| {
            set(
                r,
                key::covered_reveal::PATHS,
                manifest_wire::array(&[manifest_wire::array(&[
                    manifest_wire::uint(3),
                    manifest_wire::uint(0),
                ])]),
            );
        }),
        "bundle-wrong-path-node-arity",
    ));

    // ── ciphertext length shape ─────────────────────────────────────
    rows.push(row(
        "ciphertext shorter than one padding block plus the tag",
        covered_with(|r| {
            set(
                r,
                key::covered_reveal::CIPHERTEXT,
                manifest_wire::bstr(&[0x22; 271]),
            );
        }),
        "bundle-ciphertext-too-short",
    ));
    rows.push(row(
        "ciphertext with the wrong residue modulo the padding block",
        covered_with(|r| {
            set(
                r,
                key::covered_reveal::CIPHERTEXT,
                manifest_wire::bstr(&[0x22; 273]),
            );
        }),
        "bundle-ciphertext-length-residue",
    ));

    // ── enums, version, presence group, cross-section ───────────────
    rows.push(row(
        "unregistered anchor_status value",
        with_section(
            key::bundle::OTS_ANCHORS,
            bundle_wire::section(&[bundle_wire::ots_anchor(7, false)]),
        ),
        "bundle-unknown-anchor-status",
    ));
    rows.push(row(
        "bundle format_version 2",
        {
            let mut b = bundle_wire::default_bundle();
            set(&mut b, key::bundle::FORMAT_VERSION, manifest_wire::uint(2));
            bundle_wire::encode(&b)
        },
        "bundle-unsupported-format-version",
    ));
    rows.push(row(
        "OTS upgrade group two-of-three (header without height)",
        {
            let mut anchor = bundle_wire::ots_anchor(2, true);
            remove(&mut anchor, key::ots_anchor::BLOCK_HEIGHT);
            with_section(key::bundle::OTS_ANCHORS, bundle_wire::section(&[anchor]))
        },
        "bundle-ots-upgrade-group-incomplete",
    ));
    rows.push(row(
        "one unit_id revealed in both reveal sections",
        {
            let mut b = bundle_wire::default_bundle();
            set(
                &mut b,
                key::bundle::COVERED_REVEALS,
                bundle_wire::section(&[bundle_wire::covered_reveal(2)]),
            );
            bundle_wire::encode(&b)
        },
        "bundle-unit-revealed-twice",
    ));
    rows.push(row(
        "full reveal whose file has no touched_files entry",
        with_section(
            key::bundle::FULL_REVEALS,
            bundle_wire::section(&[bundle_wire::full_reveal(7, true)]),
        ),
        "bundle-full-reveal-without-touched-file",
    ));

    rows
}

/// **F8 accept**: each reject case fails with its own distinct error, and the
/// matrix as a whole covers the full `bundle-` code space exactly once.
#[test]
fn reject_matrix_is_exhaustive_and_pairwise_distinct() {
    let rows = rejects();

    for Reject { name, bytes, code } in &rows {
        let actual = reject_code(bytes);
        assert_eq!(actual, *code, "{name}: wrong rejection code");
    }

    let codes: BTreeSet<&str> = rows.iter().map(|r| r.code).collect();
    assert_eq!(
        codes.len(),
        rows.len(),
        "every mutation must fail with a *distinct* error (MVP-SPEC.md line 168)"
    );
    // The exemplar list in `bundle::error` is the code space; the matrix
    // exercises all of it from real bytes.
    assert_eq!(
        codes.len(),
        32,
        "reject matrix must cover every bundle- code — extend deliberately"
    );
}

/// **D78**: no bundle-schema rejection ever lands in another domain's family.
/// The bundle carries a valid manifest in every fixture, so a `manifest-`
/// code here would mean the schema layer opened it.
#[test]
fn no_reject_borrows_another_domains_prefix() {
    for Reject { name, bytes, .. } in rejects() {
        let code = reject_code(&bytes);
        for banned in ["manifest-", "crypto-", "content-", "cbor-"] {
            assert!(
                !code.starts_with(banned),
                "{name}: code {code:?} escaped into the {banned} family"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// delegated rejections (the two wrapper arms)
// ---------------------------------------------------------------------------

/// UTF-8 validity of a path is F3's native `tstr` check, surfaced through the
/// layer-1 wrapper with the codec's own code: it is a canonicality property
/// of the encoding, not a schema rule (registry §7.13).
#[test]
fn invalid_utf8_path_reports_the_codec_code() {
    let mut entry = bundle_wire::touched_file(0, "ok");
    // A `tstr` head over bytes that are not valid UTF-8.
    let mut bad = manifest_wire::head(3, 2);
    bad.extend_from_slice(&[0xFF, 0xFE]);
    set(&mut entry, key::touched_file::PATH, bad);
    let bytes = with_section(key::bundle::TOUCHED_FILES, bundle_wire::section(&[entry]));
    assert_eq!(reject_code(&bytes), "cbor-invalid-utf8");
}

/// A non-canonical head anywhere in the bundle is F3's rejection, surfaced
/// unchanged — layer 1's wrapper re-labels the layer, not the class.
#[test]
fn non_canonical_encoding_reports_the_codec_code() {
    let mut b = bundle_wire::default_bundle();
    set(
        &mut b,
        key::bundle::FORMAT_VERSION,
        manifest_wire::uint_non_shortest(1),
    );
    assert_eq!(
        reject_code(&bundle_wire::encode(&b)),
        "cbor-non-shortest-int"
    );
}

/// Trailing bytes after the bundle are rejected at layer 1, so the decoded
/// sections account for the whole input (registry §7.6.3).
#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = bundle_wire::encode(&bundle_wire::default_bundle());
    bytes.push(0x00);
    assert_eq!(reject_code(&bytes), "cbor-trailing-bytes");
}

/// GGM node-address validity is G8's, constructed through
/// `NodeAddress::try_new` rather than re-checked inline — one implementation
/// of the bound, one code per class (registry §5). Both [P] checks surface
/// with their `content-` codes.
#[test]
fn node_address_bounds_report_g8s_codes() {
    let too_deep = covered_with(|r| {
        set(
            r,
            key::covered_reveal::COVER,
            manifest_wire::array(&[bundle_wire::cover_entry(65, 0, 0x31)]),
        );
    });
    assert_eq!(
        reject_code(&too_deep),
        "content-node-address-level-too-deep"
    );

    // A level too large even for `u8` saturates in the payload but keeps the
    // class and the code.
    let absurd = covered_with(|r| {
        set(
            r,
            key::covered_reveal::COVER,
            manifest_wire::array(&[bundle_wire::cover_entry(1_000_000, 0, 0x31)]),
        );
    });
    assert_eq!(reject_code(&absurd), "content-node-address-level-too-deep");

    let out_of_range = covered_with(|r| {
        set(
            r,
            key::covered_reveal::COVER,
            manifest_wire::array(&[bundle_wire::cover_entry(2, 4, 0x31)]),
        );
    });
    assert_eq!(
        reject_code(&out_of_range),
        "content-node-address-index-out-of-range"
    );
}

// ---------------------------------------------------------------------------
// D75: a full reveal ships covers *and* s_root
// ---------------------------------------------------------------------------

/// **D75 resolved: "both".** A covered reveal keeps its `cover` even when the
/// same file's [`FullReveal`] entry carries `s_root`, so bundle schema
/// validation stays decidable from the bundle alone (tier [P]). The
/// alternative — omitting covers on a full reveal — would make key 3's
/// presence depend on the derived full-reveal predicate and cross into tier
/// [R], which F8 cannot decide under D78.
///
/// The consequence is R's: with two independent routes to `fine_root`, they
/// must be required to *agree*.
#[test]
fn d75_full_reveal_carries_both_covers_and_s_root() {
    let bytes = bundle_wire::encode(&bundle_wire::default_bundle());
    let bundle = BundleV1::decode(&bytes).expect("fixture decodes");

    // File 0 is fully revealed with `s_root` …
    let full = &bundle.full_reveals()[0];
    assert_eq!(full.file_id(), 0);
    assert!(full.disclosed_s_root().is_some());

    // … and every covered reveal still ships its own non-empty cover.
    for reveal in bundle.covered_reveals() {
        assert!(
            !reveal.cover().is_empty(),
            "unit {}: cover is required regardless of full-reveal state",
            reveal.unit_id()
        );
    }
}

// ---------------------------------------------------------------------------
// hygiene
// ---------------------------------------------------------------------------

/// Project rule 6: no rendered rejection leaks disclosed key material, salt
/// bytes, ciphertext, or a path — only key numbers, lengths, ids, and enum
/// names.
#[test]
fn rejections_render_metadata_only() {
    for Reject { name, bytes, .. } in rejects() {
        let rendered = BundleV1::decode(&bytes)
            .map(|_| ())
            .expect_err("must reject")
            .to_string();
        for leak in ["notes/pitch.md", "logo.png", "0x", "freetsa"] {
            assert!(
                !rendered.contains(leak),
                "{name}: rendering leaked {leak:?}: {rendered}"
            );
        }
    }
}

/// `OpaqueBytes` is the type that carries every payload this layer refuses to
/// parse, and it renders as a byte count — so a `Debug`-printed bundle cannot
/// dump a ciphertext or a multi-kilobyte DER blob into a log.
#[test]
fn opaque_payload_debug_is_a_byte_count() {
    let bytes = bundle_wire::encode(&bundle_wire::default_bundle());
    let bundle = BundleV1::decode(&bytes).expect("fixture decodes");
    let rendered = format!("{:?}", bundle.ots_anchors()[0]);
    assert!(rendered.contains("OpaqueBytes(96 bytes)"), "{rendered}");
    assert_eq!(
        format!("{:?}", OpaqueBytes::from_vec(vec![1, 2, 3])),
        "OpaqueBytes(3 bytes)"
    );
}
