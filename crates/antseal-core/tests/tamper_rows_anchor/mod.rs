//! **F's anchor-artifact registry slice** (task F20): the schema-level tamper
//! rows over the anchor shapes F13 made constructible.
//!
//! F8 defines the D79 OTS upgrade group, the TSA intermediate list and
//! `source`, and the whole Arbitrum receipt record, and has schema-level
//! reject-tests for each. None of it had ever been *constructed* by a fixture
//! until F13 added `AnchorSet::EveryKind { receipt }`. These rows put those
//! shapes into the **global** registry, which is the thing the reject-tests
//! cannot do for themselves: a unit-level proof is invisible to Q8's
//! cross-domain distinctness sweep, so nothing before this checked that an
//! anchor rejection is distinguishable from every other domain's.
//!
//! Anchor **semantics** — what an upgraded attestation proves, chain
//! validation, the `--online` gate — stay A's at M2. These are shape rows,
//! and their ids are prefixed `anchor-schema-` precisely so the global matrix
//! cannot double-claim against A21's `anchor-*` semantic rows (which are
//! already pre-registered as pending in `testdata/tamper/MATRIX.json`).
//!
//! # Why the base is the hand-rolled wire writer, and F20's Accept is wrong
//!
//! F20's Accept asks for each row to be *"built by typed construction from
//! R6, never by byte-patching"*. **That is unachievable, and for the best
//! possible reason**: F8 made these exact states unrepresentable rather than
//! merely rejected. `OtsUpgrade::new` takes `[u8; 80]`, so a 79-byte header
//! cannot be typed; it holds all three group fields in one struct, so a
//! two-of-three group cannot be typed (its own doc comment says so);
//! `ReceiptRecord::new` refuses an empty `tx_hashes`; `tx_hashes` is
//! `Vec<[u8; 32]>`, so a short hash cannot be typed; `AnchorStatus` is a
//! closed enum, so an out-of-band status cannot be typed; and no typed API
//! can inject a reserved key at all. Typed construction and byte-patching are
//! not the only two options, which is the premise the Accept bullet got
//! wrong — there is a third, and the repository already contains it:
//! [`crate::bundle_wire`], the hand-rolled canonical writer whose module docs
//! name *"a two-of-three OTS upgrade group"* and *"an unregistered
//! `anchor_status`"* as the reason it exists.
//!
//! Building from it gives the row what byte-patching would not: the mutation
//! is expressed as **one field of one map**, and every other byte is written
//! by the same canonical writer, so "this mutation, this error" stays an
//! honest claim and the artifact is never accidentally non-canonical.
//!
//! What is lost is the provenance F20 actually cared about — that these
//! shapes are one field away from something *R6* can build — so that is
//! asserted directly instead of assumed:
//! [`tests::the_wire_base_is_the_r6_every_kind_shape`] decodes both and
//! compares the anchor structure section by section.
//!
//! # Five rows, seven mutations
//!
//! F20's Do enumerates seven mutations. Two of them cannot be rows, and both
//! for reasons worth recording rather than routing around:
//!
//! - **the 81-byte header** produces the same code as the 79-byte one
//!   (`BundleError::WrongLength` carries no over/under discriminator, nor
//!   should it — the field has one correct length). Kept as a named test.
//! - **a reserved `chain_inputs` key** produces `bundle-reserved-key`, which
//!   F15's row already claims — registry §7.15 makes a *named* reserved slot
//!   the ordinary reserved error deliberately, so a second row would fail
//!   Q7's distinctness assertion. Kept as a named test.
//!
//! And one enumerated mutation turns out not to be a rejection at all: an
//! **empty `intermediates` entry** is accepted by the schema layer, because
//! `decode_opaque` checks only the cap. That is correct at this layer (a
//! zero-length DER certificate is A's to reject at M2, with a real parser)
//! and is pinned as a named test so the silence is recorded rather than
//! assumed.

use antseal_core::bundle::registry::key;
use antseal_core::bundle::{SealProof, SealProofError};
use antseal_core::test_util::tamper::{ActualOutcome, ExpectedOutcome, TamperRow};

use crate::bundle_wire as w;
use crate::manifest_wire::{array, bstr, map, remove, set, uint};

// ---------------------------------------------------------------------------
// the base: R6's `AnchorSet::EveryKind { receipt: true }` shape, at the wire
// ---------------------------------------------------------------------------

/// `anchor_status` wire values (registry §6.1), named so a mutation reads as
/// what it is.
mod status {
    pub const PROVEN: u64 = 0;
    pub const VALID_AT_STAMPING_CERT_SINCE_EXPIRED: u64 = 1;
    pub const ATTESTED: u64 = 2;
    pub const PENDING: u64 = 3;
    /// One past the registered band — the "newer producer, older verifier"
    /// case the closed enum exists to catch.
    pub const OUT_OF_BAND: u64 = 7;
}

/// The OTS section R6's `EveryKind` builds: one artifact carrying the whole
/// D79 upgrade group, one carrying none of it, in the same bundle.
fn ots_section() -> Vec<Vec<(u64, Vec<u8>)>> {
    vec![
        w::ots_anchor(status::ATTESTED, true),
        w::ots_anchor(status::PENDING, false),
    ]
}

/// The TSA section R6's `EveryKind` builds: one artifact with intermediates,
/// one without, so both optional shapes are present at once.
///
/// **This function used to distinguish the two by a recorded `source`.** D8 §1
/// removed that field from v1 — zero producers, zero consumers — so the pair
/// is now told apart by `intermediates` (the shape the row set is about) and
/// by distinct token bytes. That is strictly better for a fixture: the
/// distinguishing bytes are the artifact's own, not a provenance string the
/// verifier is forbidden to trust.
fn tsa_section() -> Vec<Vec<(u64, Vec<u8>)>> {
    vec![
        w::tsa_anchor(status::PROVEN, 2, TSA_TOKEN_TAG_A),
        w::tsa_anchor(status::VALID_AT_STAMPING_CERT_SINCE_EXPIRED, 0, TSA_TOKEN_TAG_B),
    ]
}

/// Token fill bytes for the two TSA artifacts, distinct so a swap is visible.
const TSA_TOKEN_TAG_A: u8 = 0xA1;
const TSA_TOKEN_TAG_B: u8 = 0xB2;

/// The base bundle: a valid `.sealproof` whose anchor sections populate
/// **every** optional slot F8 defines.
fn base_entries() -> Vec<(u64, Vec<u8>)> {
    let mut bundle = w::default_bundle();
    set(
        &mut bundle,
        key::bundle::OTS_ANCHORS,
        w::section(&ots_section()),
    );
    set(
        &mut bundle,
        key::bundle::TSA_ANCHORS,
        w::section(&tsa_section()),
    );
    set(&mut bundle, key::bundle::RECEIPT, map(&w::receipt()));
    bundle
}

/// The base, encoded.
fn base() -> Vec<u8> {
    w::encode(&base_entries())
}

// ---------------------------------------------------------------------------
// the mutations — one field of one map each
// ---------------------------------------------------------------------------

/// Rebuild the base with its OTS section replaced.
fn with_ots(anchors: Vec<Vec<(u64, Vec<u8>)>>) -> Vec<u8> {
    let mut bundle = base_entries();
    set(&mut bundle, key::bundle::OTS_ANCHORS, w::section(&anchors));
    w::encode(&bundle)
}

/// Rebuild the base with its TSA section replaced.
fn with_tsa(anchors: Vec<Vec<(u64, Vec<u8>)>>) -> Vec<u8> {
    let mut bundle = base_entries();
    set(&mut bundle, key::bundle::TSA_ANCHORS, w::section(&anchors));
    w::encode(&bundle)
}

/// Rebuild the base with its receipt replaced.
fn with_receipt(receipt: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
    let mut bundle = base_entries();
    set(&mut bundle, key::bundle::RECEIPT, map(&receipt));
    w::encode(&bundle)
}

/// The upgraded OTS artifact with a `block_header` of `len` bytes.
fn ots_header_of_length(len: usize) -> Vec<u8> {
    let mut anchors = ots_section();
    set(
        &mut anchors[0],
        key::ots_anchor::BLOCK_HEADER,
        bstr(&vec![0xB7; len]),
    );
    with_ots(anchors)
}

/// The upgraded OTS artifact missing exactly one of the D79 group's three
/// keys — the partial state F8 makes unrepresentable in the typed API.
fn ots_upgrade_group_without(key: u64) -> Vec<u8> {
    let mut anchors = ots_section();
    remove(&mut anchors[0], key);
    with_ots(anchors)
}

/// The pending OTS artifact declaring an `anchor_status` outside the v1 band.
fn ots_out_of_band_status() -> Vec<u8> {
    let mut anchors = ots_section();
    set(
        &mut anchors[1],
        key::ots_anchor::STATUS,
        uint(status::OUT_OF_BAND),
    );
    with_ots(anchors)
}

/// The receipt with an empty `tx_hashes` list — "a payment with no
/// transaction", which is malformed rather than "no payment" (F8).
fn receipt_with_no_tx_hashes() -> Vec<u8> {
    let mut receipt = w::receipt();
    set(&mut receipt, key::receipt::TX_HASHES, array(&[]));
    with_receipt(receipt)
}

/// The receipt whose second transaction hash is one byte short.
fn receipt_with_short_tx_hash() -> Vec<u8> {
    let mut receipt = w::receipt();
    set(
        &mut receipt,
        key::receipt::TX_HASHES,
        array(&[bstr(&[0xE0; 32]), bstr(&[0xE1; 31])]),
    );
    with_receipt(receipt)
}

// ---------------------------------------------------------------------------
// running a mutation
// ---------------------------------------------------------------------------

/// Feed bytes to the whole-`.sealproof` surface and report the stable code.
///
/// `SealProof::decode` rather than `BundleV1::decode` because it is the
/// surface a verifier actually calls, and layer 1 is where these rejections
/// land — asserted per row in [`tests::every_row_reports_the_bundle_layer`].
fn outcome(bytes: &[u8]) -> ActualOutcome {
    ActualOutcome::from_result(SealProof::decode(bytes), SealProofError::code)
}

fn row_short_block_header() -> ActualOutcome {
    outcome(&ots_header_of_length(79))
}

fn row_partial_upgrade_group() -> ActualOutcome {
    outcome(&ots_upgrade_group_without(key::ots_anchor::FETCH_DATE))
}

fn row_unknown_status() -> ActualOutcome {
    outcome(&ots_out_of_band_status())
}

fn row_empty_tx_hashes() -> ActualOutcome {
    outcome(&receipt_with_no_tx_hashes())
}

fn row_short_tx_hash() -> ActualOutcome {
    outcome(&receipt_with_short_tx_hash())
}

// ---------------------------------------------------------------------------
// the registry slice
// ---------------------------------------------------------------------------

/// F20's rows. Row ids are permanent handles; every expected code already
/// existed in F8's taxonomy — this slice mints nothing (contract §3).
pub const ROWS: &[TamperRow] = &[
    TamperRow {
        id: "anchor-schema-short-block-header",
        base: "every-anchor-kind-with-receipt",
        mutation: "shorten the upgraded OTS artifact's `block_header` to 79 bytes",
        expected: ExpectedOutcome::ErrorCode("bundle-wrong-length-block-header"),
        exercise: row_short_block_header,
    },
    TamperRow {
        id: "anchor-schema-partial-upgrade-group",
        base: "every-anchor-kind-with-receipt",
        mutation: "drop `fetch_date` from the OTS upgrade group, leaving two of three (D79)",
        expected: ExpectedOutcome::ErrorCode("bundle-ots-upgrade-group-incomplete"),
        exercise: row_partial_upgrade_group,
    },
    TamperRow {
        id: "anchor-schema-unknown-status",
        base: "every-anchor-kind-with-receipt",
        mutation: "declare `anchor_status = 7`, outside the v1 registered band",
        expected: ExpectedOutcome::ErrorCode("bundle-unknown-anchor-status"),
        exercise: row_unknown_status,
    },
    TamperRow {
        id: "anchor-schema-empty-tx-hashes",
        base: "every-anchor-kind-with-receipt",
        mutation: "empty the receipt's `tx_hashes` list",
        expected: ExpectedOutcome::ErrorCode("bundle-empty-tx-hashes"),
        exercise: row_empty_tx_hashes,
    },
    TamperRow {
        id: "anchor-schema-short-tx-hash",
        base: "every-anchor-kind-with-receipt",
        mutation: "shorten the receipt's second transaction hash to 31 bytes",
        expected: ExpectedOutcome::ErrorCode("bundle-wrong-length-tx-hash"),
        exercise: row_short_tx_hash,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use antseal_core::bundle::BundleError;
    use antseal_core::test_util::bundle_fixtures::{FileSelection, Selection, build, shapes};
    use std::collections::BTreeSet;

    /// The stable code a byte string produces at the `.sealproof` surface,
    /// or `None` if it is accepted.
    fn code_of(bytes: &[u8]) -> Option<&'static str> {
        SealProof::decode(bytes).err().map(|e| e.code())
    }

    /// **Every row's base must be valid**, or a row could "pass" by pinning a
    /// defect the mutation had nothing to do with (the R7 rule).
    #[test]
    fn the_base_decodes_before_it_is_mutated() {
        SealProof::decode(&base()).expect("the F20 base is a valid .sealproof");
    }

    /// **The provenance claim, asserted rather than assumed** (module docs).
    /// The wire base carries the same anchor structure R6's
    /// `AnchorSet::EveryKind { receipt: true }` builds, so every row really
    /// is one field away from a shape the shared constructor produces.
    #[test]
    fn the_wire_base_is_the_r6_every_kind_shape() {
        let wire = base();
        let wire = SealProof::decode(&wire).expect("wire base decodes");
        let wire = wire.bundle();

        let r6 = build(
            &shapes::multi_file_every_anchor_kind().with_ed25519_only_policy(),
            // The `mixed` selection F13's own `every-anchor-kind-*` vectors
            // use, so this is the committed bundle rather than a variant.
            &Selection(vec![
                FileSelection::Full,
                FileSelection::Units(vec![1]),
                FileSelection::Untouched,
            ]),
        )
        .bytes;
        let r6 = SealProof::decode(&r6).expect("R6's EveryKind bundle decodes");
        let r6 = r6.bundle();

        // OTS: two artifacts, exactly one carrying the D79 upgrade group.
        assert_eq!(wire.ots_anchors().len(), r6.ots_anchors().len());
        let group_present = |b: &antseal_core::bundle::BundleV1<'_>| {
            b.ots_anchors()
                .iter()
                .map(|a| a.upgrade().is_some())
                .collect::<Vec<_>>()
        };
        assert_eq!(group_present(wire), group_present(r6));
        assert_eq!(
            group_present(wire),
            vec![true, false],
            "the shape under test is `one upgraded, one not, in the same bundle`"
        );

        // TSA: two artifacts, exactly one carrying intermediates.
        //
        // This compared `(intermediates, source.is_some())` until D8 §1 deleted
        // `source` from v1. The surviving half is the one that was ever load
        // -bearing: `intermediates` is the optional shape these rows exercise.
        assert_eq!(wire.tsa_anchors().len(), r6.tsa_anchors().len());
        let optional_slots = |b: &antseal_core::bundle::BundleV1<'_>| {
            b.tsa_anchors()
                .iter()
                .map(|a| a.intermediates().len())
                .collect::<Vec<_>>()
        };
        assert_eq!(optional_slots(wire), optional_slots(r6));
        assert_eq!(optional_slots(wire), vec![2, 0]);

        // Receipt: present, with the same number of transaction hashes.
        let hashes =
            |b: &antseal_core::bundle::BundleV1<'_>| b.receipt().map(|r| r.tx_hashes().len());
        assert_eq!(hashes(wire), hashes(r6));
        assert_eq!(hashes(wire), Some(2));
    }

    /// Every row produces its declared code, and does so at **layer 1** — the
    /// bundle map — which is what makes `(code, layer)` informative for these
    /// rejections the way F15's table requires (D86).
    #[test]
    fn every_row_reports_the_bundle_layer() {
        for row in ROWS {
            let ExpectedOutcome::ErrorCode(expected) = row.expected else {
                panic!("row `{}` is not an error-code row", row.id);
            };
            let ActualOutcome::ErrorCode(actual) = (row.exercise)() else {
                panic!("row `{}` did not reject its mutation", row.id);
            };
            assert_eq!(actual, expected, "row `{}`", row.id);
        }
        // The layer is a property of the surface, not of the row, so it is
        // asserted once on a representative mutation.
        let err = SealProof::decode(&ots_header_of_length(79)).expect_err("must reject");
        assert_eq!(err.layer().to_string(), "bundle");
    }

    /// The slice's own outcomes are pairwise distinct (contract §4 layer 1);
    /// the cross-domain sweep is `tests/tamper_matrix.rs`'s.
    #[test]
    fn the_slice_is_internally_distinct() {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for row in ROWS {
            assert!(
                seen.insert(row.expected.key()),
                "row `{}` re-claims `{}`",
                row.id,
                row.expected.key()
            );
        }
    }

    /// F20 mints nothing: every code it binds already existed in F8's shipped
    /// taxonomy.
    #[test]
    fn every_expected_code_is_a_real_bundle_error_code() {
        for row in ROWS {
            let ExpectedOutcome::ErrorCode(code) = row.expected else {
                panic!("row `{}` is not an error-code row", row.id);
            };
            assert!(
                code.starts_with("bundle-"),
                "row `{}` binds `{code}`, which is not in F8's namespace",
                row.id
            );
        }
    }

    // -----------------------------------------------------------------
    // the three enumerated mutations that are NOT rows (module docs)
    // -----------------------------------------------------------------

    /// **Not a row: the over-long header.** 79 and 81 bytes are one
    /// observable — the field has one correct length, and
    /// `BundleError::WrongLength` deliberately carries no over/under
    /// discriminator. Both directions are still pinned here, because "too
    /// long" silently passing would be the worse failure of the two.
    #[test]
    fn an_over_long_block_header_is_the_same_rejection_as_a_short_one() {
        assert_eq!(
            code_of(&ots_header_of_length(81)),
            Some("bundle-wrong-length-block-header")
        );
        assert_eq!(
            code_of(&ots_header_of_length(79)),
            code_of(&ots_header_of_length(81)),
            "if these ever became distinguishable, the second earns a row"
        );
        // …and the base's own header is the length the schema requires.
        assert_eq!(code_of(&ots_header_of_length(80)), None);
    }

    /// **Not a row: the other two thirds of D79's group.** Dropping any one
    /// of the three keys is the same code; what differs is the payload, which
    /// names the **lowest-numbered** absent key so two absences report
    /// deterministically.
    #[test]
    fn every_missing_upgrade_group_key_is_the_same_code_with_a_deterministic_payload() {
        for (dropped, expected_missing) in [
            (key::ots_anchor::BLOCK_HEIGHT, key::ots_anchor::BLOCK_HEIGHT),
            (key::ots_anchor::BLOCK_HEADER, key::ots_anchor::BLOCK_HEADER),
            (key::ots_anchor::FETCH_DATE, key::ots_anchor::FETCH_DATE),
        ] {
            let bytes = ots_upgrade_group_without(dropped);
            assert_eq!(
                code_of(&bytes),
                Some("bundle-ots-upgrade-group-incomplete"),
                "dropping key {dropped}"
            );
            match antseal_core::bundle::BundleV1::decode(&bytes) {
                Err(BundleError::OtsUpgradeGroupIncomplete { missing_key }) => {
                    assert_eq!(missing_key, expected_missing, "dropping key {dropped}");
                }
                other => panic!("dropping key {dropped}: expected the group error, got {other:?}"),
            }
        }
    }

    /// **Not a row: a reserved key in the receipt.** Registry §7.15 makes a
    /// *named* reserved slot take the ordinary reserved-slot error — spending
    /// a permanent code on a distinction no verifier acts on is what that
    /// rule exists to prevent — so this collides with F15's
    /// `bundle-reserved-key` row and `check_registry` would refuse the pair.
    #[test]
    fn a_reserved_chain_inputs_key_is_f15s_reserved_key_row() {
        let mut receipt = w::receipt();
        set(&mut receipt, key::receipt::RESERVED_CHAIN_INPUTS, uint(0));
        assert_eq!(
            code_of(&with_receipt(receipt)),
            Some("bundle-reserved-key"),
            "the v1.1 `chain_inputs` slot must not have a code of its own"
        );
    }

    /// **Not a row, and not a rejection: an empty `intermediates` entry.**
    /// The M0 format layer treats a certificate as an opaque `bstr` and
    /// checks only the cap (F8), so a zero-length one is *accepted* here.
    /// That is the correct layering — a DER parser is A's, at M2 — but it is
    /// a silence, and a silence that nothing asserts is indistinguishable
    /// from an oversight.
    #[test]
    fn an_empty_intermediates_entry_is_accepted_by_the_schema_layer() {
        let mut anchors = tsa_section();
        set(
            &mut anchors[0],
            key::tsa_anchor::INTERMEDIATES,
            array(&[bstr(&[]), bstr(&[0xC1; 48])]),
        );
        assert_eq!(
            code_of(&with_tsa(anchors)),
            None,
            "an empty intermediate must be A's to reject at M2, with a real DER parser"
        );

        // The contrast F20's Do draws: an empty *list* is legal too (R6
        // builds one), while an empty `tx_hashes` list is not — and that
        // asymmetry is deliberate, since absent intermediates mean "the TSA
        // sent none" and an absent transaction means "a payment with no
        // payment".
        let mut anchors = tsa_section();
        set(&mut anchors[0], key::tsa_anchor::INTERMEDIATES, array(&[]));
        assert_eq!(code_of(&with_tsa(anchors)), None);
        assert_eq!(
            code_of(&receipt_with_no_tx_hashes()),
            Some("bundle-empty-tx-hashes")
        );
    }

    /// Every registered `anchor_status` decodes, so the out-of-band row is
    /// pinning the band's edge rather than an arbitrary value.
    #[test]
    fn every_registered_anchor_status_is_accepted() {
        for status in antseal_core::bundle::registry::AnchorStatus::ALL {
            let mut anchors = ots_section();
            set(
                &mut anchors[1],
                key::ots_anchor::STATUS,
                uint(status.to_wire()),
            );
            assert_eq!(
                code_of(&with_ots(anchors)),
                None,
                "status {} is registered in v1",
                status.to_wire()
            );
        }
        assert_eq!(
            code_of(&ots_out_of_band_status()),
            Some("bundle-unknown-anchor-status")
        );
    }
}
