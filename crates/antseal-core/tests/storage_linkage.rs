//! **R20 — the storage-linkage layer through `verify_bundle`**, over whole
//! `.sealproof` fixtures rather than hand-built subjects.
//!
//! `verify::storage_linkage`'s own unit tests pin the arithmetic and run on
//! wasm32 (the `wasm32-core-tests` lane executes `--lib`). What only a bundle
//! can show is the property the layer exists for: **the evidence verdict does
//! not move.** MVP-SPEC.md line 118 — *"storage is the product's bonus, not
//! its proof"* — is a claim about two layers of one report, so it is asserted
//! between two layers of one report.
//!
//! # The four fixtures
//!
//! R6's builder records addresses under [`StorageAddresses`]. Three of the
//! four modes are R20's:
//!
//! | mode | manifest unit table | storage record |
//! |---|---|---|
//! | `Real` | BLAKE3-256 of each ciphertext | the real blob's address |
//! | `RealExceptUnit(id)` | one entry one bit off | the real blob's address |
//! | `RealExceptManifest` | BLAKE3-256 of each ciphertext | one bit off |
//! | `Placeholder` | `0xAD…` per unit | `0x5E…` |
//!
//! `Placeholder` is the M0 default every committed vector was generated
//! under, and it is included here because *"a bundle with no valid storage
//! linkage at all still verifies"* is the strongest form of the separation
//! claim — and because a lane that later makes the fixtures real should find
//! that fact asserted somewhere rather than discover it by inference.
//!
//! # `RealExceptManifest` is the controlled pair
//!
//! A bent **unit** address lives in the signed manifest, so bending it moves
//! `work_id` and the report legitimately differs in more than one place. A
//! bent **storage-record** address lives in the bundle only — the 88
//! unauthenticated bytes `verify_fuzz.rs` sweeps — so `Real` and
//! `RealExceptManifest` produce reports that must be **byte-identical apart
//! from the `storage_linkage` value**. That is asserted on the canonical
//! bytes, and it is the version of "the evidence verdict is untouched" that
//! cannot be satisfied by a renderer being careful.

use antseal_core::test_util::bundle_fixtures::{
    Selection, StorageAddresses, WorkSpec, build, shapes,
};
use antseal_core::verify::report::StorageLinkageResult;
use antseal_core::verify::wording;
use antseal_core::verify::{VerificationReport, VerifyOptions, verify_bundle};

/// The shape every case is built from: a multi-file work with a mixed
/// selection, so the bundle embeds several unit ciphertexts and leaves others
/// unrevealed.
fn spec(mode: StorageAddresses) -> WorkSpec {
    shapes::multi_file().with_storage_addresses(mode)
}

fn selection() -> Selection {
    shapes::multi_file_mixed_selection()
}

/// Verify under the default — which since D128 §3 R1 runs the layer.
fn linked(mode: StorageAddresses) -> VerificationReport {
    let fixture = build(&spec(mode), &selection());
    verify_bundle(&fixture.bytes, &VerifyOptions::new())
        .expect("a well-formed fixture verifies whatever its addresses say")
}

/// How many unit ciphertexts the bundle embeds — the number the layer can
/// speak about, derived from the fixture rather than written down.
fn embedded_units(mode: StorageAddresses) -> u64 {
    let fixture = build(&spec(mode), &selection());
    u64::try_from(fixture.revealed_unit_ids.len()).expect("a fixture has few units")
}

/// A revealed unit's id, so `RealExceptUnit` bends an address that is
/// actually checked. An unrevealed unit's entry would be bent and never
/// looked at — a fixture that proves nothing, and an easy one to write.
fn a_revealed_unit_id() -> u64 {
    let fixture = build(&spec(StorageAddresses::Real), &selection());
    *fixture
        .revealed_unit_ids
        .first()
        .expect("the mixed selection reveals at least one unit")
}

// ---------------------------------------------------------------------------
// the three Accept fixtures
// ---------------------------------------------------------------------------

/// All-match, unit mismatch and manifest mismatch each render a **distinct**
/// storage-linkage result, and the evidence outcome is **identical** across
/// all three.
#[test]
fn the_three_linkage_shapes_are_distinct_and_the_evidence_layer_is_not() {
    let units = embedded_units(StorageAddresses::Real);
    assert!(units >= 2, "the shape must embed more than one ciphertext");

    let all_match = linked(StorageAddresses::Real);
    let unit_bent = linked(StorageAddresses::RealExceptUnit(a_revealed_unit_id()));
    let manifest_bent = linked(StorageAddresses::RealExceptManifest);

    assert_eq!(
        all_match.storage_linkage,
        StorageLinkageResult::Evaluated {
            units_matched: units,
            units_mismatched: 0,
            manifest_matched: true,
        }
    );
    assert_eq!(
        unit_bent.storage_linkage,
        StorageLinkageResult::Evaluated {
            units_matched: units - 1,
            units_mismatched: 1,
            manifest_matched: true,
        }
    );
    assert_eq!(
        manifest_bent.storage_linkage,
        StorageLinkageResult::Evaluated {
            units_matched: units,
            units_mismatched: 0,
            manifest_matched: false,
        }
    );

    // Pairwise distinct — the property the arm's three fields exist for.
    let slots = [
        all_match.storage_linkage,
        unit_bent.storage_linkage,
        manifest_bent.storage_linkage,
    ];
    for (i, left) in slots.iter().enumerate() {
        for right in &slots[i + 1..] {
            assert_ne!(left, right, "two linkage shapes render the same value");
        }
    }

    // …and the evidence layer is the same object in all three.
    assert_eq!(all_match.evidence, unit_bent.evidence);
    assert_eq!(all_match.evidence, manifest_bent.evidence);
    assert!(all_match.evidence.passed);
    assert_eq!(all_match.evidence.units_verified, units);
}

/// The controlled pair: bending only the bundle's storage record changes the
/// `storage_linkage` value and **nothing else in the canonical bytes**.
///
/// Stronger than comparing the evidence struct, which a report could match on
/// while differing elsewhere: this compares the whole serialized report with
/// the one slot substituted out, so any second consequence of a bent address
/// — an anchor state, a work field, a reveal span — fails here.
#[test]
fn a_bent_storage_record_moves_the_linkage_slot_and_no_other_byte() {
    let all_match = linked(StorageAddresses::Real);
    let bent = linked(StorageAddresses::RealExceptManifest);
    assert_ne!(all_match.storage_linkage, bent.storage_linkage);

    let matched_slot = StorageLinkageResult::Evaluated {
        units_matched: embedded_units(StorageAddresses::Real),
        units_mismatched: 0,
        manifest_matched: true,
    };
    let realigned = VerificationReport {
        storage_linkage: matched_slot,
        ..bent
    };
    assert_eq!(
        realigned.to_canonical_json().expect("report serializes"),
        all_match.to_canonical_json().expect("report serializes"),
        "a bent storage-record address changed something other than the \
         storage-linkage slot — the layers are not separate"
    );
}

/// A bundle whose every recorded address is wrong still verifies, and says
/// so in both layers at once.
///
/// This is the M0 fixture default, so it is also the measurement behind
/// `VerifyOptions::without_storage_linkage`'s existence: running the layer
/// over the committed catalogue would re-value every case, which is why the
/// two committed-exhibit generators suppress it (D128 §3 R3) — and why
/// nothing else does.
#[test]
fn a_bundle_with_no_valid_linkage_at_all_still_verifies() {
    let units = embedded_units(StorageAddresses::Placeholder);
    let report = linked(StorageAddresses::Placeholder);
    assert!(report.evidence.passed);
    assert_eq!(
        report.storage_linkage,
        StorageLinkageResult::Evaluated {
            units_matched: 0,
            units_mismatched: units,
            manifest_matched: false,
        }
    );
}

/// The layer is silent **only** when it is suppressed — on every shape,
/// including the ones that would have matched. "The stage did not run" is a
/// statement about this run, never about the bundle.
///
/// The subject inverted at D128 §3.2. Before it, the default was off and this
/// test asked whether the layer stayed quiet unasked; now the default is on
/// (§3 R1) and the question is whether the one suppression switch in the tree
/// actually suppresses. That is the property R2's closed caller list depends
/// on: if `without_storage_linkage` were a no-op, the two committed-exhibit
/// generators would silently start re-valuing 21 frozen cases and 26 digest
/// rows, and this file is the only place that would say so.
#[test]
fn the_layer_is_silent_only_when_it_is_suppressed() {
    for mode in [
        StorageAddresses::Placeholder,
        StorageAddresses::Real,
        StorageAddresses::RealExceptManifest,
    ] {
        let fixture = build(&spec(mode), &selection());
        let report = verify_bundle(
            &fixture.bytes,
            &VerifyOptions::new().without_storage_linkage(),
        )
        .expect("a well-formed fixture verifies");
        assert_eq!(
            report.storage_linkage,
            StorageLinkageResult::NotEvaluated,
            "{mode:?}: the suppressed options ran the layer anyway"
        );

        // …and the default does not suppress. Without this half the test
        // above passes for a `storage_linkage()` accessor stuck at `false`.
        let default_run = verify_bundle(&fixture.bytes, &VerifyOptions::new())
            .expect("a well-formed fixture verifies");
        assert_ne!(
            default_run.storage_linkage,
            StorageLinkageResult::NotEvaluated,
            "{mode:?}: the default stopped running the layer (D128 §3 R1)"
        );
    }
}

// ---------------------------------------------------------------------------
// rendering (R18's frozen rows, dispatched)
// ---------------------------------------------------------------------------

/// Each shape renders through R18's frozen table, and the storage layer's
/// sentences never borrow the evidence layer's vocabulary.
///
/// **Recorded, not asserted away:** R18 froze *one* failure row, taking a
/// mismatch count and a checked count, so a bent unit address and a bent
/// manifest address produce the **same sentence** even though they are
/// different values in the report. The report is where the distinction
/// survives (`--json`, and R23's page); the CLI line is a count. Reported at
/// R20 as a wording-set question rather than resolved by a lane, which is why
/// the equality below is asserted rather than left as a surprise for whoever
/// reads the two fixtures' output side by side.
#[test]
fn the_frozen_rows_render_each_shape_and_borrow_no_verdict_words() {
    let units = embedded_units(StorageAddresses::Real);
    let pass = wording::storage_linkage_line(linked(StorageAddresses::Real).storage_linkage);
    let unit_fail = wording::storage_linkage_line(
        linked(StorageAddresses::RealExceptUnit(a_revealed_unit_id())).storage_linkage,
    );
    let manifest_fail =
        wording::storage_linkage_line(linked(StorageAddresses::RealExceptManifest).storage_linkage);
    let silent = wording::storage_linkage_line(StorageLinkageResult::NotEvaluated);

    assert_eq!(pass, wording::storage_linkage_pass_line(units));
    // The fail row counts *addresses*, so the manifest is one of them.
    assert_eq!(unit_fail, wording::storage_linkage_fail_line(1, units + 1));
    assert_eq!(manifest_fail, unit_fail);
    assert_eq!(silent, wording::storage_linkage_not_evaluated_line());

    // No storage row claims a verdict of its own. "Verdict" itself is not on
    // the list: the failure row **names** the evidence verdict on purpose,
    // under a negation, to say the thing above it did not move — the same
    // construction the positioning checklist allows the disclaimer row for
    // "authorship" and "exclusive". Asserted positively below, so deleting
    // that clause reddens rather than passing quietly.
    for line in [&pass, &unit_fail, &silent] {
        for claimed in ["proven", "certified", "valid", "authentic"] {
            assert!(
                !line.contains(claimed),
                "the storage layer's row claims {claimed:?}: {line}"
            );
        }
    }
    assert!(
        unit_fail.contains("the evidence verdict above is unchanged"),
        "the failure row stopped saying the evidence verdict did not move: {unit_fail}"
    );
    assert!(
        wording::STORAGE_LINKAGE_LAYER_LABEL.contains("not its proof"),
        "the layer label is what makes the section semantically distinct"
    );
}

/// A pass row is only reachable when **both** halves agree: one bent address
/// anywhere sends the render to the failure row.
#[test]
fn a_single_bent_address_costs_the_pass_row() {
    for mode in [
        StorageAddresses::RealExceptUnit(a_revealed_unit_id()),
        StorageAddresses::RealExceptManifest,
    ] {
        let line = wording::storage_linkage_line(linked(mode).storage_linkage);
        assert!(
            line.contains("do not match"),
            "{mode:?} rendered a pass row: {line}"
        );
    }
}
