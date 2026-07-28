//! **F's cap and shape rows** (task F22): the D10 parser caps and D77's
//! mirror-only rule, as harness rows on real sealed bytes.
//!
//! F11 minted **eighteen** permanent cap codes and D77 a nineteenth. One of
//! the nineteen had a row when this task started — `bundle-too-large`, which
//! F15 landed as `cbor-oversized`. This module lands the other end of the
//! decision: **five** new rows and **thirteen** recorded non-rows, which
//! together account for all nineteen.
//!
//! # The representative decision, and why it went this way
//!
//! F22's Do text leaves the call open: "all seventeen, or one representative
//! per *family* plus F11's unit matrix". The evidence that settles it is
//! `tests/parser_caps.rs`, which turns out to be much stronger than the
//! phrase "F11's unit matrix" suggests. It already drives **every one of the
//! nineteen caps through the real `BundleV1::decode` / `Manifest::decode`
//! wire surface**, as an at-cap/cap+1 pair per row of D10 §1, and it already
//! asserts the eighteen cap codes are pairwise distinct
//! (`the_eighteen_cap_codes_are_pairwise_distinct`). Per-discriminant
//! reachability is therefore not the thing a row would add.
//!
//! What a *row* adds over that is exactly three things:
//!
//! 1. membership in the cross-domain distinctness sweep, which runs over the
//!    assembled registry rather than within one domain's own test;
//! 2. the `catch_unwind` no-panic guard on that mutation;
//! 3. visibility in `testdata/tamper/MATRIX.json`.
//!
//! None of the three is per-*discriminant*: they are properties of the
//! code-generating construct. So the unit of representation here is the
//! **error variant**, not the list-kind or artifact-field discriminant it
//! carries — five constructs across the two enums, plus D77's:
//!
//! | construct | codes | representative row |
//! | --- | --- | --- |
//! | `BundleError::InputTooLarge` | 1 | `cbor-oversized` (F15, already landed) |
//! | `BundleError::ListTooLong` | 10 | `caps-bundle-too-many-intermediates` |
//! | `BundleError::ArtifactTooLarge` | 4 | `caps-bundle-cert-too-large` |
//! | `ManifestError::InputTooLarge` | 1 | `caps-manifest-too-large` |
//! | `ManifestError::ListTooLong` | 2 | `caps-manifest-too-many-units` |
//! | `ManifestError::EmptyContainer{NormalUnits}` (D77) | 1 | `caps-manifest-empty-normal-units` |
//!
//! The thirteen codes that remain are **named non-rows**, in
//! [`DELIBERATE_NON_ROWS`], each carrying its reason and the representative
//! that stands for it — the pattern Q8 uses, applied to the direction Q8
//! cannot see. A code is never silently unrowed:
//! [`tests::every_cap_code_is_rowed_or_named`] fails if one is.
//!
//! # A correction to F22's own text
//!
//! F22 says "the other **sixteen**" and then enumerates *seventeen*: ten
//! `bundle-too-many-*`, four `bundle-*-too-large`, `manifest-too-large`, and
//! the pair `manifest-too-many-files` / `manifest-too-many-units`. The
//! enumeration is right and the number is wrong. The slip is traceable: the
//! entry counts three of the nineteen as already owned, but one of those
//! three — `cbor-nesting-too-deep` — is a pre-existing `DecodeError` code and
//! is not among F11's eighteen or D77's one at all. Nineteen minus the two
//! genuinely owned (`bundle-too-large`, `manifest-empty-normal-units`) is
//! **seventeen**, and 5 rows + 13 non-rows − 1 (D77's code, which was one of
//! the two "owned" but had no row) accounts for exactly that.
//!
//! # Row id prefix
//!
//! `caps-`, including for D77's row, which is a *shape* rule rather than a
//! cap. The prefix is this task's namespace, chosen so concurrent lanes
//! cannot collide on row ids; it is not a claim about what the code means.
//! Row ids are permanent handles and carry no semantics (harness docs).
//!
//! # Why the list-cap representative is `intermediates`
//!
//! F14's independent cross-check requires a **schema-level fixture to be
//! perfectly good CBOR at its outer layer**, "which proves it exercises the
//! schema rather than tripping the codec first and never reaching it". That
//! rules out the obvious construction for a count cap: re-heading an array to
//! claim `cap + 1` entries without supplying them makes the document
//! *truncated*, so it carries two faults and which one is observed is an
//! ordering accident (a frozen one — D10 §4 — but an accident all the same).
//!
//! `MAX_INTERMEDIATE_COUNT` is **16**, the only bundle list cap small enough
//! that `cap + 1` real entries fit in a committable fixture. So the
//! representative supplies all seventeen and the document stays canonical;
//! the cross-check confirms it independently, and the row pins the cap and
//! nothing else. Every other bundle list caps at 256 or 16 384. D10 §2
//! separately calls this "the weakest-evidence cap in the table" and asks A
//! to confirm it before Q14, which makes it the one most worth a harness row.
//!
//! **The manifest side cannot have this property**, and the limitation is
//! recorded rather than hidden: `MAX_UNIT_COUNT` is 2^16, so
//! `body-units-over-cap` re-heads the `units` array and does not supply the
//! entries. Its *envelope* — the layer the cross-check inspects — is exact,
//! because the mutated body is re-encoded into a fresh envelope; its **body**
//! is deliberately truncated, which no committed fixture can avoid at that
//! cap. The cross-check's schema branch does not descend into embedded
//! layers, so it neither confirms nor refutes this; that gap is written up in
//! tasks/F.md under F36.
//!
//! # Bases
//!
//! Four fixtures mutate the two F15 bases. The `ArtifactTooLarge` one needs a
//! bundle that actually *carries* an anchor artifact, which neither F15 base
//! does (the UNANCHORED bundle's `ots_anchors` and `tsa_anchors` are both
//! empty), so it uses R6's `AnchorSet::EveryKind` shape — and it is
//! synthesized rather than committed, because the mutation is a length
//! (`MAX_CERT_BYTES + 1`) and a committed fixture would breach the 64 KiB
//! ceiling `tests/format_tamper_fixtures.rs` enforces. That is the same
//! escape F15 opened for `bundle-oversized`, used a second time, which is
//! the point of having made it general.

use crate::bundle::registry::key as bundle_key;
use crate::codec::caps::{
    MAX_CERT_BYTES, MAX_INTERMEDIATE_COUNT, MAX_MANIFEST_BYTES, MAX_UNIT_COUNT,
};
use crate::manifest::registry::{UnitKind, key as manifest_key};

use super::bundle_fixtures::{AnchorSet, Selection, WorkSpec, build, shapes};
use super::cbor_span::{
    MAJOR_ARRAY, MAJOR_BYTES, Step, canonical_head, span_at_path, splice_head_at_path,
    splice_item_at_path,
};
use super::tamper::{ActualOutcome, ExpectedOutcome, TamperRow};
use super::tamper_rows_format::{
    FormatFixture, Surface, base_body, base_manifest, envelope_around, exercise_by_id,
};

// ---------------------------------------------------------------------------
// paths into the two bases
// ---------------------------------------------------------------------------

/// The base body's file 0, unit 0 — the unit D77's fixture flips and the
/// `units` array F22's list-cap fixture re-heads.
const FIRST_UNIT_KIND: [Step; 5] = [
    Step::Value(manifest_key::body::FILES),
    Step::Index(0),
    Step::Value(manifest_key::file::UNITS),
    Step::Index(0),
    Step::Value(manifest_key::unit::KIND),
];

/// The base body's file 0 `units` array.
const FIRST_FILE_UNITS: [Step; 3] = [
    Step::Value(manifest_key::body::FILES),
    Step::Index(0),
    Step::Value(manifest_key::file::UNITS),
];

/// The every-kind bundle's first TSA anchor's `intermediates` list.
///
/// `tsa_anchors[0]` is the anchor R6 populates with intermediates and a
/// recorded `source`; `tsa_anchors[1]` deliberately has neither.
const INTERMEDIATES: [Step; 3] = [
    Step::Value(bundle_key::bundle::TSA_ANCHORS),
    Step::Index(0),
    Step::Value(bundle_key::tsa_anchor::INTERMEDIATES),
];

/// Its first certificate.
const FIRST_INTERMEDIATE: [Step; 4] = [
    Step::Value(bundle_key::bundle::TSA_ANCHORS),
    Step::Index(0),
    Step::Value(bundle_key::tsa_anchor::INTERMEDIATES),
    Step::Index(0),
];

/// The work the every-kind base is built from: the same single binary file
/// and ed25519-only policy as F15's bases (so no 3 309-byte ML-DSA signature
/// enters a fixture), with every anchor kind populated.
fn every_kind_work() -> WorkSpec {
    shapes::single_binary()
        .with_ed25519_only_policy()
        .with_anchors(AnchorSet::EveryKind { receipt: false })
}

/// The anchor-bearing base bundle: the only shape that carries an anchor
/// artifact at all, since both F15 bases have empty `ots_anchors` and
/// `tsa_anchors`. Not itself committed — see F38.
#[must_use]
pub fn base_bundle_every_kind() -> Vec<u8> {
    build(&every_kind_work(), &Selection::all(1)).bytes
}

// ---------------------------------------------------------------------------
// the five fixtures
// ---------------------------------------------------------------------------

/// **D77 §6's mirror-only file.** Flip file 0's only unit from `normal` (wire
/// 0) to `raw-mirror` (wire 1), so the file has units but no *normal* unit.
///
/// A byte mutation is the only route: `FileEntry::new` refuses to construct
/// the shape, which is D77's whole point. The two wire values are both
/// one-byte `uint`s, so the mutation is length-preserving inside the body —
/// but the envelope is re-encoded around it anyway, exactly as every F15 body
/// fixture is, so nothing depends on that coincidence.
fn body_mirror_only_unit() -> Option<Vec<u8>> {
    let body = base_body()?;
    let mutated = splice_item_at_path(
        &body,
        &FIRST_UNIT_KIND,
        &canonical_head(0, UnitKind::RawMirror.to_wire()),
    )?;
    envelope_around(&mutated)
}

/// `ManifestError::ListTooLong { list: Units }`: re-head file 0's `units`
/// array to claim `MAX_UNIT_COUNT + 1` entries.
///
/// Only the head is rewritten — the one real unit entry follows it verbatim —
/// because D10 §4 freezes the cap check *before* a single element is read.
/// The array therefore claims 65 537 elements and delivers one, and the cap
/// is what rejects it rather than the truncation that would otherwise follow.
fn body_units_over_cap() -> Option<Vec<u8>> {
    let body = base_body()?;
    let mutated = splice_head_at_path(
        &body,
        &FIRST_FILE_UNITS,
        &canonical_head(MAJOR_ARRAY, MAX_UNIT_COUNT.checked_add(1)?),
    )?;
    envelope_around(&mutated)
}

/// `ManifestError::InputTooLarge`: the base manifest zero-padded one byte past
/// [`MAX_MANIFEST_BYTES`].
///
/// Synthesized, for `bundle-oversized`'s reason: the mutation is a length.
/// `vec![0u8; n]` takes the `alloc_zeroed` path and `Manifest::decode`'s first
/// statement is the O(1) length comparison (D10 §5 row 3), so nothing past the
/// copied prefix is ever read.
#[must_use]
pub fn oversized_manifest() -> Option<Vec<u8>> {
    let base = base_manifest();
    let over = usize::try_from(MAX_MANIFEST_BYTES).ok()?.checked_add(1)?;
    if over < base.len() {
        return None;
    }
    let mut out = vec![0u8; over];
    out.get_mut(..base.len())?.copy_from_slice(&base);
    Some(out)
}

/// `BundleError::ListTooLong { list: Intermediates }`: grow the first TSA
/// anchor's `intermediates` list to `MAX_INTERMEDIATE_COUNT + 1` entries, all
/// of them really present.
///
/// **Intermediates rather than one of the nine larger lists, and that is the
/// whole reason for the choice.** `MAX_INTERMEDIATE_COUNT` is 16, so a
/// cap+1 list is seventeen real entries and the fixture stays **perfectly
/// canonical CBOR** — the property F14's independent cross-check demands of
/// every schema-level fixture, because a document that is *also* truncated
/// would be rejected by the codec before the schema layer ever saw it, and
/// the row would be pinning an ordering accident rather than the cap. Every
/// other bundle list caps at 256 or 16 384, where a canonical fixture is not
/// committable; re-heading such a list without supplying its elements yields
/// exactly the two-fault document the cross-check refuses. (D10 §2 also calls
/// this "the weakest-evidence cap in the table" and asks A to confirm it
/// before Q14, which makes it the one most worth having a harness row.)
fn bundle_intermediates_over_cap() -> Option<Vec<u8>> {
    let bundle = base_bundle_every_kind();
    let first = span_at_path(&bundle, &FIRST_INTERMEDIATE)?;
    let cert = bundle.get(first.start..first.end)?.to_vec();
    let count = MAX_INTERMEDIATE_COUNT.checked_add(1)?;
    let mut item = canonical_head(MAJOR_ARRAY, count);
    for _ in 0..count {
        item.extend_from_slice(&cert);
    }
    splice_item_at_path(&bundle, &INTERMEDIATES, &item)
}

/// `BundleError::ArtifactTooLarge { field: Certificate }`: replace the first
/// TSA intermediate with a `bstr` of `MAX_CERT_BYTES + 1` zero bytes.
///
/// Unlike the two list caps, this one cannot be a head-only rewrite: F3
/// refuses a claimed `bstr` length exceeding the remaining input *before* the
/// schema layer sees it (`cbor-truncated` would win), so the bytes have to be
/// really there. 64 KiB + 1 is the smallest of the four artifact caps, which
/// is why `Certificate` is the representative — and why the fixture is a
/// recipe rather than a committed file.
#[must_use]
pub fn oversized_certificate_bundle() -> Option<Vec<u8>> {
    let over = usize::try_from(MAX_CERT_BYTES).ok()?.checked_add(1)?;
    let mut item = canonical_head(MAJOR_BYTES, MAX_CERT_BYTES.checked_add(1)?);
    item.resize(item.len().checked_add(over)?, 0u8);
    splice_item_at_path(&base_bundle_every_kind(), &FIRST_INTERMEDIATE, &item)
}

/// F22's fixtures, in emit order.
pub const FIXTURES: &[FormatFixture] = &[
    FormatFixture {
        id: "body-mirror-only-unit",
        base: "manifest",
        mutation: "flip file 0's only unit from `normal` to `raw-mirror`, leaving the file with \
                   no normal unit",
        surface: Surface::ManifestDecode,
        code: "manifest-empty-normal-units",
        layer: Some("manifest body"),
        committed: true,
        row: Some("caps-manifest-empty-normal-units"),
        build: body_mirror_only_unit,
    },
    FormatFixture {
        id: "body-units-over-cap",
        base: "manifest",
        mutation: "re-head file 0's `units` array to claim MAX_UNIT_COUNT + 1 entries",
        surface: Surface::ManifestDecode,
        code: "manifest-too-many-units",
        layer: Some("manifest body"),
        committed: true,
        row: Some("caps-manifest-too-many-units"),
        build: body_units_over_cap,
    },
    FormatFixture {
        id: "manifest-oversized",
        base: "manifest",
        mutation: "zero-pad the manifest envelope to MAX_MANIFEST_BYTES + 1 bytes",
        surface: Surface::ManifestDecode,
        code: "manifest-too-large",
        // The size check is the first statement of the *envelope* decode
        // (D10 §5 row 3), so it names the envelope map and not the body.
        layer: Some("manifest envelope"),
        committed: false,
        row: Some("caps-manifest-too-large"),
        build: oversized_manifest,
    },
    FormatFixture {
        id: "bundle-intermediates-over-cap",
        base: "bundle-every-kind",
        mutation: "grow the first TSA anchor's `intermediates` list to MAX_INTERMEDIATE_COUNT + 1 \
                   real entries",
        surface: Surface::SealProofDecode,
        code: "bundle-too-many-intermediates",
        layer: Some("bundle"),
        committed: true,
        row: Some("caps-bundle-too-many-intermediates"),
        build: bundle_intermediates_over_cap,
    },
    FormatFixture {
        id: "bundle-cert-over-cap",
        base: "bundle-every-kind",
        mutation: "replace the first TSA intermediate with MAX_CERT_BYTES + 1 zero bytes",
        surface: Surface::SealProofDecode,
        code: "bundle-cert-too-large",
        layer: Some("bundle"),
        committed: false,
        row: Some("caps-bundle-cert-too-large"),
        build: oversized_certificate_bundle,
    },
];

// ---------------------------------------------------------------------------
// the deliberate non-rows
// ---------------------------------------------------------------------------

/// **Cap codes deliberately left unrowed, each with its reason.**
///
/// `(code, representative row, reason)`. The reason is not decoration: it is
/// what a future contributor reads before "completing" the matrix, and what
/// makes the representative decision reviewable rather than inferred from an
/// absence. The named representative must be a live row, which
/// [`tests::every_named_non_row_names_a_live_representative`] checks.
///
/// F23's `bundle-`/`manifest-` reverse-coverage sweep should consult this
/// list for its named-owner escape hatch; the two were authored in parallel
/// lanes, so wiring them together is a merge step rather than a change here.
pub const DELIBERATE_NON_ROWS: &[(&str, &str, &str)] = &[
    // ── BundleError::ListTooLong, nine non-representatives ──
    (
        "bundle-too-many-ots-anchors",
        "caps-bundle-too-many-intermediates",
        "One `BundleError::ListTooLong` discriminant of ten. Every one of the ten is produced by \
         the same `decode_section` cap check on a claimed array count, and `tests/parser_caps.rs` \
         already drives each through the real `BundleV1::decode` at-cap and cap+1. A row adds \
         cross-domain distinctness, the no-panic guard and MATRIX visibility — none of which is \
         per-discriminant. There is a second, independent reason this one cannot be the \
         representative: its cap is 256, so a cap+1 fixture supplying its entries is not \
         committable, and one that does NOT supply them is truncated as well as over-cap — two \
         faults, which F14's cross-check refuses for a schema-level fixture and rightly so. Only \
         `Intermediates` (cap 16) admits a canonical fixture at all.",
    ),
    (
        "bundle-too-many-tsa-anchors",
        "caps-bundle-too-many-intermediates",
        "As `bundle-too-many-ots-anchors`: the same cap check, a different list discriminant.",
    ),
    (
        "bundle-too-many-full-reveals",
        "caps-bundle-too-many-intermediates",
        "As `bundle-too-many-ots-anchors`: the same cap check, a different list discriminant.",
    ),
    (
        "bundle-too-many-tx-hashes",
        "caps-bundle-too-many-intermediates",
        "As `bundle-too-many-ots-anchors`: the same cap check, a different list discriminant.",
    ),
    (
        "bundle-too-many-covered-reveals",
        "caps-bundle-too-many-intermediates",
        "As `bundle-too-many-ots-anchors`: the same cap check, a different list discriminant.",
    ),
    (
        "bundle-too-many-noncovered-reveals",
        "caps-bundle-too-many-intermediates",
        "As `bundle-too-many-ots-anchors`: the same cap check, a different list discriminant.",
    ),
    (
        "bundle-too-many-cover-entries",
        "caps-bundle-too-many-intermediates",
        "As `bundle-too-many-ots-anchors`: the same cap check, a different list discriminant.",
    ),
    (
        "bundle-too-many-path-nodes",
        "caps-bundle-too-many-intermediates",
        "As `bundle-too-many-ots-anchors`: the same cap check, a different list discriminant.",
    ),
    (
        "bundle-too-many-touched-files",
        "caps-bundle-too-many-intermediates",
        "As `bundle-too-many-ots-anchors`: the same cap check, a different list discriminant.",
    ),
    // ── BundleError::ArtifactTooLarge, three non-representatives ──
    (
        "bundle-ots-too-large",
        "caps-bundle-cert-too-large",
        "One `BundleError::ArtifactTooLarge` discriminant of four, all produced by the same \
         `decode_opaque` byte-length check. A fixture for this one would have to carry 1 MiB + 1 \
         real bytes (F3 refuses an over-claimed `bstr` length before the schema sees it), against \
         `Certificate`'s 64 KiB + 1 — sixteen times the cost for the same construct.",
    ),
    (
        "bundle-tsa-token-too-large",
        "caps-bundle-cert-too-large",
        "As `bundle-ots-too-large`: same check, and 1 MiB of fixture for no new construct.",
    ),
    (
        "bundle-receipt-payload-too-large",
        "caps-bundle-cert-too-large",
        "As `bundle-ots-too-large`, and the most expensive of the four at 16 MiB + 1.",
    ),
    // ── ManifestError::ListTooLong, one non-representative ──
    (
        "manifest-too-many-files",
        "caps-manifest-too-many-units",
        "One `ManifestError::ListTooLong` discriminant of two. `Units` is the representative \
         because it is the *work-global* budget (`DecodeBudget`, D10 §1), so its row exercises \
         the one cap in the table whose accounting is not a plain per-head comparison; a `Files` \
         row would exercise strictly less.",
    ),
];

// ---------------------------------------------------------------------------
// the registry slice
// ---------------------------------------------------------------------------

fn row_manifest_empty_normal_units() -> ActualOutcome {
    exercise_by_id(FIXTURES, "body-mirror-only-unit")
}
fn row_manifest_too_many_units() -> ActualOutcome {
    exercise_by_id(FIXTURES, "body-units-over-cap")
}
fn row_manifest_too_large() -> ActualOutcome {
    exercise_by_id(FIXTURES, "manifest-oversized")
}
fn row_bundle_too_many_intermediates() -> ActualOutcome {
    exercise_by_id(FIXTURES, "bundle-intermediates-over-cap")
}
fn row_bundle_cert_too_large() -> ActualOutcome {
    exercise_by_id(FIXTURES, "bundle-cert-over-cap")
}

/// F22's M0 tamper rows. Row ids are permanent handles; see the harness docs
/// ([`super::tamper`]) for the add-a-row procedure and
/// `docs/testing/error-code-contract.md` for why an expected code may never
/// be edited to make a failing run pass.
pub const ROWS: &[TamperRow] = &[
    TamperRow {
        id: "caps-manifest-empty-normal-units",
        base: "golden-manifest-ed25519-only",
        mutation: "flip the file's only unit to `raw-mirror`, leaving it with no normal unit",
        expected: ExpectedOutcome::ErrorCode("manifest-empty-normal-units"),
        exercise: row_manifest_empty_normal_units,
    },
    TamperRow {
        id: "caps-manifest-too-many-units",
        base: "golden-manifest-ed25519-only",
        mutation: "re-head the file's `units` array to claim MAX_UNIT_COUNT + 1 entries",
        expected: ExpectedOutcome::ErrorCode("manifest-too-many-units"),
        exercise: row_manifest_too_many_units,
    },
    TamperRow {
        id: "caps-manifest-too-large",
        base: "golden-manifest-ed25519-only",
        mutation: "zero-pad the manifest envelope to MAX_MANIFEST_BYTES + 1 bytes",
        expected: ExpectedOutcome::ErrorCode("manifest-too-large"),
        exercise: row_manifest_too_large,
    },
    TamperRow {
        id: "caps-bundle-too-many-intermediates",
        base: "every-anchor-kind-bundle",
        mutation: "grow the first TSA anchor's `intermediates` list to MAX_INTERMEDIATE_COUNT + 1 \
                   entries",
        expected: ExpectedOutcome::ErrorCode("bundle-too-many-intermediates"),
        exercise: row_bundle_too_many_intermediates,
    },
    TamperRow {
        id: "caps-bundle-cert-too-large",
        base: "every-anchor-kind-bundle",
        mutation: "replace the first TSA intermediate with MAX_CERT_BYTES + 1 bytes",
        expected: ExpectedOutcome::ErrorCode("bundle-cert-too-large"),
        exercise: row_bundle_cert_too_large,
    },
];

#[cfg(test)]
mod tests {
    use super::super::tamper_rows_format::base_bundle;
    use super::*;
    use crate::bundle::error::all_code_exemplars as bundle_exemplars;
    use crate::bundle::{BundleError, SealProof};
    use crate::manifest::error::all_code_exemplars as manifest_exemplars;
    use crate::manifest::{Manifest, ManifestError};
    use std::collections::BTreeSet;

    /// Every cap code F11 and D77 minted is either claimed by a row somewhere
    /// or recorded in [`DELIBERATE_NON_ROWS`] with its reason. There is no
    /// third state — an unrowed, unnamed permanent code is exactly the gap
    /// this task exists to close, and after Q14 it would be permanent.
    #[test]
    fn every_cap_code_is_rowed_or_named() {
        let rowed: BTreeSet<&str> = ROWS
            .iter()
            .chain(super::super::tamper_rows_format::ROWS)
            .filter_map(|row| match row.expected {
                ExpectedOutcome::ErrorCode(code) => Some(code),
                ExpectedOutcome::VerdictState(_) => None,
            })
            .collect();
        let named: BTreeSet<&str> = DELIBERATE_NON_ROWS
            .iter()
            .map(|(code, _, _)| *code)
            .collect();

        let mut unaccounted = Vec::new();
        for code in cap_codes() {
            if !rowed.contains(code) && !named.contains(code) {
                unaccounted.push(code);
            }
        }
        assert!(
            unaccounted.is_empty(),
            "these cap/shape codes have neither a row nor a recorded reason: {unaccounted:?}\n\
             Add a row here, or an entry in DELIBERATE_NON_ROWS naming the representative that \
             stands for it. Silence is the one option this check removes."
        );
    }

    /// The nineteen D10/D77 codes, read off the error enums rather than
    /// listed by hand — a nineteenth-plus code arriving with F-side caps
    /// lands in this sweep automatically.
    fn cap_codes() -> Vec<&'static str> {
        let mut out = Vec::new();
        for e in bundle_exemplars() {
            if matches!(
                e,
                BundleError::InputTooLarge { .. }
                    | BundleError::ListTooLong { .. }
                    | BundleError::ArtifactTooLarge { .. }
            ) {
                out.push(e.code());
            }
        }
        for e in manifest_exemplars() {
            if matches!(
                e,
                ManifestError::InputTooLarge { .. } | ManifestError::ListTooLong { .. }
            ) {
                out.push(e.code());
            }
        }
        out.push("manifest-empty-normal-units");
        out
    }

    /// The arithmetic the module docs claim: nineteen codes, five rows here,
    /// thirteen recorded non-rows, one row already owned by F15.
    #[test]
    fn the_nineteen_are_accounted_for_exactly() {
        let codes: BTreeSet<&str> = cap_codes().into_iter().collect();
        assert_eq!(codes.len(), 19, "the cap/shape code universe is nineteen");
        assert_eq!(ROWS.len(), 5);
        assert_eq!(DELIBERATE_NON_ROWS.len(), 13);
        assert!(
            super::super::tamper_rows_format::ROWS
                .iter()
                .any(|r| r.expected == ExpectedOutcome::ErrorCode("bundle-too-large")),
            "F15's `cbor-oversized` row must still own `bundle-too-large`"
        );
        assert_eq!(ROWS.len() + DELIBERATE_NON_ROWS.len() + 1, codes.len());
    }

    /// A recorded non-row must name a representative that is a **live row**,
    /// and must not itself be claimed by one — the same two-directional
    /// staleness guard R7's coverage lists carry.
    #[test]
    fn every_named_non_row_names_a_live_representative() {
        let all_rows: Vec<&TamperRow> = ROWS
            .iter()
            .chain(super::super::tamper_rows_format::ROWS)
            .collect();
        let universe: BTreeSet<&str> = cap_codes().into_iter().collect();
        for (code, representative, reason) in DELIBERATE_NON_ROWS {
            assert!(
                universe.contains(code),
                "`{code}` is recorded as a non-row but no cap variant emits it"
            );
            assert!(
                all_rows.iter().any(|row| row.id == *representative),
                "`{code}`'s representative `{representative}` is not a live row"
            );
            assert!(
                !all_rows
                    .iter()
                    .any(|row| row.expected == ExpectedOutcome::ErrorCode(code)),
                "`{code}` is recorded as a non-row AND claimed by a row"
            );
            assert!(
                reason.len() > 60,
                "`{code}`'s reason is too short to be a reason"
            );
        }
    }

    /// Every fixture produces exactly its declared `(code, layer)` pair. The
    /// committed-bytes half lives in `tests/format_tamper_fixtures.rs`.
    #[test]
    fn every_fixture_produces_its_declared_code_and_layer() {
        for fixture in FIXTURES {
            let bytes = (fixture.build)()
                .unwrap_or_else(|| panic!("fixture `{}` failed to build", fixture.id));
            let observed = super::super::tamper_rows_format::run_surface(fixture.surface, &bytes);
            assert_eq!(
                observed.code.as_deref(),
                Some(fixture.code),
                "fixture `{}` reported the wrong code",
                fixture.id
            );
            assert_eq!(
                observed.layer.as_deref(),
                fixture.layer,
                "fixture `{}` reported the wrong layer",
                fixture.id
            );
        }
    }

    /// Every row is backed by a fixture that expects the same code, and ids
    /// are unique.
    #[test]
    fn rows_and_fixtures_agree() {
        let ids: BTreeSet<&str> = FIXTURES.iter().map(|f| f.id).collect();
        assert_eq!(ids.len(), FIXTURES.len(), "duplicate fixture id");
        let row_ids: BTreeSet<&str> = ROWS.iter().map(|r| r.id).collect();
        assert_eq!(row_ids.len(), ROWS.len(), "duplicate row id");
        for row in ROWS {
            let backing = FIXTURES
                .iter()
                .find(|f| f.row == Some(row.id))
                .unwrap_or_else(|| panic!("row `{}` has no backing fixture", row.id));
            assert_eq!(row.expected, ExpectedOutcome::ErrorCode(backing.code));
        }
    }

    /// The three bases are valid artifacts before anything is mutated: a row
    /// that "passed" because its base was already broken would pin nothing.
    #[test]
    fn the_bases_are_valid_before_mutation() {
        assert!(Manifest::decode(&base_manifest()).is_ok());
        assert!(SealProof::decode(&base_bundle()).is_ok());
        let every_kind = base_bundle_every_kind();
        assert!(
            SealProof::decode(&every_kind).is_ok(),
            "the every-anchor-kind base must decode"
        );
        // And it really carries the intermediate the fixture reaches for.
        let span = super::super::cbor_span::span_at_path(&every_kind, &FIRST_INTERMEDIATE)
            .expect("the first TSA intermediate");
        assert!(span.byte_len() > 1, "the intermediate is a non-empty bstr");
    }

    /// D77's mutation is one byte, and it is the byte the registry says it
    /// is: `unit_kind` 0 → 1. A fixture that flipped something else would
    /// still be rejected — by a different rule — and the row would be lying.
    #[test]
    fn the_d77_fixture_flips_exactly_the_unit_kind() {
        let base = base_body().expect("base body");
        let mutated = splice_item_at_path(
            &base,
            &FIRST_UNIT_KIND,
            &canonical_head(0, UnitKind::RawMirror.to_wire()),
        )
        .expect("the mirror-only body");
        assert_eq!(mutated.len(), base.len(), "length-preserving");
        let differing: Vec<usize> = mutated
            .iter()
            .zip(&base)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(differing.len(), 1, "exactly one byte differs");
        assert_eq!(base[differing[0]], UnitKind::Normal.to_wire() as u8);
        assert_eq!(mutated[differing[0]], UnitKind::RawMirror.to_wire() as u8);
    }

    /// The manifest list-cap fixture rewrites the head and nothing else — the
    /// one real unit entry survives verbatim, so the cap is what rejects it
    /// rather than a mangled element.
    #[test]
    fn the_manifest_list_cap_fixture_rewrites_only_a_head() {
        let base = base_body().expect("base body");
        let mutated = splice_head_at_path(
            &base,
            &FIRST_FILE_UNITS,
            &canonical_head(MAJOR_ARRAY, MAX_UNIT_COUNT + 1),
        )
        .expect("the over-cap body");
        // array(1) is one byte; array(65537) is five.
        assert_eq!(mutated.len(), base.len() + 4);
        let span = span_at_path(&base, &FIRST_FILE_UNITS).expect("the array");
        let elements = base.get(span.head_end..span.end).expect("elements");
        assert!(
            mutated
                .windows(elements.len())
                .any(|window| window == elements),
            "the unit entry survived the head rewrite"
        );
    }

    /// **The bundle list-cap fixture is perfectly canonical**, which is what
    /// F14's independent cross-check requires of every schema-level fixture:
    /// a document that is *also* truncated would be rejected by the codec
    /// before the schema layer saw it, so the row would pin an ordering
    /// accident rather than the cap. Seventeen real entries, all present.
    #[test]
    fn the_bundle_list_cap_fixture_is_canonical() {
        let mutated = bundle_intermediates_over_cap().expect("the over-cap bundle");
        assert_eq!(
            crate::codec::decode::check_canonical(&mutated),
            Ok(()),
            "the fixture must be canonical CBOR; only the cap may reject it"
        );
        let span = super::super::cbor_span::span_at_path(&mutated, &INTERMEDIATES)
            .expect("the intermediates array");
        let mut probe = crate::codec::decode::CanonicalDecoder::new(
            mutated.get(span.start..).expect("in range"),
        );
        assert_eq!(
            probe.array(),
            Ok(MAX_INTERMEDIATE_COUNT + 1),
            "the list claims exactly cap + 1"
        );
    }
}
