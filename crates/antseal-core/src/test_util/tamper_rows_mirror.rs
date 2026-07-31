//! **F's raw-mirror multiplicity slice** (task F40): D23 clause 3 — *at most
//! one raw mirror per file* — as a committed decode-surface fixture, its
//! harness row, and the **rejecting-direction** generator for the ≥ 2-mirror
//! shape that every valid generator is required never to produce.
//!
//! # Why this slice exists
//!
//! The 2026-07-31 adversarial review (findings 1–3, `high`) showed the rule
//! was decided (D23 clause 3), repeated as prose on `FileEntry::raw_mirror`,
//! and implemented by **no layer**: a file with units `{0: Normal,
//! 1: RawMirror, 2: RawMirror}` decoded and verified clean, with only one
//! mirror bound by the raw-mirror↔canonical MUST (MVP-SPEC.md line 121,
//! rows 9–10) and the other riding along signed and anchored — a second,
//! contradictory "original". F40 landed the count rule in `FileEntry::new`
//! (`manifest/body.rs`), minting `manifest-multiple-raw-mirrors` under D30
//! §3's append-only rule; this slice is the tamper-matrix half.
//!
//! **Why the suites never saw it:** every fixture and every valid strategy
//! generates 0 or 1 mirrors — `strategies::arb_file` by construction
//! (`usize::from(mirror)`), the wire-writer bases by authorship. That is the
//! correct property for a *valid* corpus and must stay true; the review's
//! lesson is that the **rejecting** direction needs the shape too. It lives
//! here, beside the row that pins it, and deliberately not in
//! [`super::strategies`], whose generators are schema-valid by contract.
//!
//! # The fixture
//!
//! One mutation of the F15 base manifest (the `minimal-binary-ed25519-only`
//! golden vector): grow file 0's unit table from its one covered `Normal`
//! unit to `[Normal, RawMirror, RawMirror]`, ids 0/1/2 in manifest order,
//! both mirrors fully well-formed — non-covered, so each carries the
//! `unit_commit` the coverage rules demand. Every other rule is satisfied on
//! purpose: D77 holds (the Normal unit is present), ordinals are sequential,
//! lengths are registry-exact, and the document is canonical CBOR at every
//! layer. The count rule is the **only** thing that rejects it, which is
//! what makes the row pin D23 clause 3 and nothing else (the same
//! one-fault discipline F14's independent cross-check enforces for every
//! schema-level fixture).
//!
//! A committed file rather than a synthesized recipe: the mutation is a
//! shape, not a length, and the bytes are a few hundred — the F15 default.

use crate::manifest::registry::{UnitKind, key as manifest_key};
use crate::manifest::{ByteRange, ContentAddress, Nonce24};

use super::cbor_span::{
    MAJOR_ARRAY, MAJOR_BYTES, MAJOR_UINT, Step, canonical_head, span_at_path, splice_item_at_path,
};
use super::tamper::{ActualOutcome, ExpectedOutcome, TamperRow};
use super::tamper_rows_format::{
    FormatFixture, Surface, base_body, envelope_around, exercise_by_id,
};

/// CBOR major type 5 (map). [`super::cbor_span`] names only the majors its
/// own splices need; this slice writes whole `unit_entry` maps.
const MAJOR_MAP: u8 = 5;

/// The base body's file 0 `units` array.
const FILE0_UNITS: [Step; 3] = [
    Step::Value(manifest_key::body::FILES),
    Step::Index(0),
    Step::Value(manifest_key::file::UNITS),
];

/// One canonical `unit_entry` map for a **raw-mirror** unit: keys 0–6
/// ascending, shortest-form heads, registry-exact lengths (32 B commit,
/// 24 B nonce, 32 B address), NON-SECRET constant-pattern payloads.
///
/// Mirrors are non-covered by kind (spec line 92), so the entry carries the
/// `unit_commit` the coverage rules require — the fixture must be rejected
/// by the count rule alone, never by a binding fault.
fn mirror_unit_item(unit_id: u64, seed: u8, start: u64, length: u64) -> Vec<u8> {
    let uint = |v: u64| canonical_head(MAJOR_UINT, v);
    let bstr = |payload: &[u8]| {
        let mut out = canonical_head(MAJOR_BYTES, payload.len() as u64);
        out.extend_from_slice(payload);
        out
    };
    let mut out = canonical_head(MAJOR_MAP, 7);
    out.extend(uint(manifest_key::unit::UNIT_ID));
    out.extend(uint(unit_id));
    out.extend(uint(manifest_key::unit::KIND));
    out.extend(uint(UnitKind::RawMirror.to_wire()));
    out.extend(uint(manifest_key::unit::RANGE));
    out.extend(canonical_head(MAJOR_ARRAY, 2));
    out.extend(uint(start));
    out.extend(uint(length));
    out.extend(uint(manifest_key::unit::TRUE_LENGTH));
    out.extend(uint(length));
    out.extend(uint(manifest_key::unit::UNIT_COMMIT));
    out.extend(bstr(&[seed; 32]));
    out.extend(uint(manifest_key::unit::NONCE));
    out.extend(bstr(&[seed ^ 0x0F; 24]));
    out.extend(uint(manifest_key::unit::ADDRESS));
    out.extend(bstr(&[seed ^ 0xF0; 32]));
    out
}

/// **The D23-clause-3 mutation**: file 0's unit table grown from its one
/// covered `Normal` unit (kept verbatim) to `[Normal, RawMirror,
/// RawMirror]`, ids 0/1/2.
///
/// The body is mutated and the envelope re-encoded around it, exactly as
/// every F15/F22 body fixture is.
fn body_second_raw_mirror() -> Option<Vec<u8>> {
    let body = base_body()?;
    let units = span_at_path(&body, &FILE0_UNITS)?;
    let unit0 = body.get(units.head_end..units.end)?.to_vec();
    let mut item = canonical_head(MAJOR_ARRAY, 3);
    item.extend_from_slice(&unit0);
    item.extend_from_slice(&mirror_unit_item(1, 0x41, 0, 64));
    item.extend_from_slice(&mirror_unit_item(2, 0x42, 0, 99));
    let mutated = splice_item_at_path(&body, &FILE0_UNITS, &item)?;
    envelope_around(&mutated)
}

/// F40's fixture, in emit order (one).
pub const FIXTURES: &[FormatFixture] = &[FormatFixture {
    id: "body-second-raw-mirror",
    base: "manifest",
    mutation: "grow file 0's unit table to [normal, raw-mirror, raw-mirror], both mirrors fully \
               well-formed",
    surface: Surface::ManifestDecode,
    code: "manifest-multiple-raw-mirrors",
    layer: Some("manifest body"),
    committed: true,
    row: Some("manifest-multiple-raw-mirrors"),
    build: body_second_raw_mirror,
}];

fn row_manifest_multiple_raw_mirrors() -> ActualOutcome {
    exercise_by_id(FIXTURES, "body-second-raw-mirror")
}

/// F40's M0 tamper row. Row ids are permanent handles; see the harness docs
/// ([`super::tamper`]) for the add-a-row procedure and
/// `docs/testing/error-code-contract.md` for why an expected code may never
/// be edited to make a failing run pass.
pub const ROWS: &[TamperRow] = &[TamperRow {
    id: "manifest-multiple-raw-mirrors",
    base: "golden-manifest-ed25519-only",
    mutation: "grow file 0's unit table to [normal, raw-mirror, raw-mirror], both mirrors fully \
               well-formed",
    expected: ExpectedOutcome::ErrorCode("manifest-multiple-raw-mirrors"),
    exercise: row_manifest_multiple_raw_mirrors,
}];

// ---------------------------------------------------------------------------
// the rejecting-direction generator
// ---------------------------------------------------------------------------

use proptest::prelude::{Just, Strategy, any};

use crate::crypto::disclosure::UnitBinding;
use crate::manifest::UnitEntry;

/// A 32-byte constant-pattern digest (fixture material; project rule 6).
fn digest32(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    out
}

/// **Rejecting-direction strategy** (D23 clause 3): a unit table with
/// 1..=3 `Normal` units and **2..=4 raw mirrors**, mirror positions
/// shuffled — the count rule fires on `kind` alone, wherever the mirrors
/// sit — with every *other* rule satisfied: ids are manifest-order
/// ordinals, bindings agree with `fine_tree` and kind (mirrors always
/// non-covered), so `FileEntry::new` must reject on the mirror count and
/// nothing else. Yields `(fine_tree, units, mirror_count)`.
///
/// Deliberately **not** in [`super::strategies`]: the F16 generators are
/// schema-valid by contract (`arb_file` appends `usize::from(mirror)` ≤ 1
/// mirrors, so D23 clause 3 holds there by construction), and a valid
/// corpus must never contain this shape. Invalid shapes live with the
/// tamper rows that pin them.
pub fn arb_two_plus_mirror_units() -> impl Strategy<Value = (bool, Vec<UnitEntry>, u64)> {
    (1usize..=3, 2usize..=4, any::<bool>(), any::<u8>())
        .prop_flat_map(|(normals, mirrors, fine_tree, seed)| {
            let mut kinds: Vec<UnitKind> = Vec::with_capacity(normals + mirrors);
            kinds.extend(core::iter::repeat_n(UnitKind::Normal, normals));
            kinds.extend(core::iter::repeat_n(UnitKind::RawMirror, mirrors));
            (Just((fine_tree, seed, mirrors)), Just(kinds).prop_shuffle())
        })
        .prop_map(|((fine_tree, seed, mirrors), kinds)| {
            let units: Vec<UnitEntry> = kinds
                .into_iter()
                .enumerate()
                .map(|(i, kind)| {
                    let salt = seed.wrapping_add(i as u8);
                    let covered = fine_tree && kind == UnitKind::Normal;
                    let binding = if covered {
                        UnitBinding::FineTreeCovered
                    } else {
                        UnitBinding::NonCovered {
                            unit_commit: digest32(salt),
                        }
                    };
                    UnitEntry::new(
                        i as u64,
                        kind,
                        ByteRange::new(u64::from(salt), 16),
                        16,
                        binding,
                        Nonce24::from_bytes([salt; 24]),
                        ContentAddress::from_bytes(digest32(salt ^ 0x5A)),
                    )
                })
                .collect();
            (fine_tree, units, mirrors as u64)
        })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::super::strategies::proptest_config;
    use super::super::tamper_rows_format::run_surface;
    use super::*;
    use crate::codec::decode::check_canonical;
    use crate::manifest::{CanonMode, FileEntry, FineTree, Manifest, ManifestError};

    /// The fixture produces exactly its declared `(code, layer)` pair. The
    /// committed-bytes half lives in `tests/format_tamper_fixtures.rs`.
    #[test]
    fn the_fixture_produces_its_declared_code_and_layer() {
        for fixture in FIXTURES {
            let bytes = (fixture.build)()
                .unwrap_or_else(|| panic!("fixture `{}` failed to build", fixture.id));
            let observed = run_surface(fixture.surface, &bytes);
            assert_eq!(
                observed.code.as_deref(),
                Some(fixture.code),
                "{}",
                fixture.id
            );
            assert_eq!(observed.layer.as_deref(), fixture.layer, "{}", fixture.id);
        }
    }

    /// **The fixture is perfectly canonical CBOR at both layers** — the
    /// property F14's independent cross-check demands of every schema-level
    /// fixture: only the D23 count rule may reject it, so the row pins the
    /// rule and not an ordering accident.
    #[test]
    fn the_fixture_is_canonical_at_both_layers() {
        let envelope = body_second_raw_mirror().expect("the two-mirror fixture");
        assert_eq!(check_canonical(&envelope), Ok(()), "envelope layer");
        let body = base_body().expect("base body");
        let units = span_at_path(&body, &FILE0_UNITS).expect("units span");
        let unit0 = body.get(units.head_end..units.end).expect("unit 0");
        let mut item = canonical_head(MAJOR_ARRAY, 3);
        item.extend_from_slice(unit0);
        item.extend_from_slice(&mirror_unit_item(1, 0x41, 0, 64));
        item.extend_from_slice(&mirror_unit_item(2, 0x42, 0, 99));
        let mutated = splice_item_at_path(&body, &FILE0_UNITS, &item).expect("mutated body");
        assert_eq!(check_canonical(&mutated), Ok(()), "body layer");
        // The base's own covered unit survives verbatim, and both mirror
        // entries are present — the mutation is the one it claims to be.
        assert!(mutated.windows(unit0.len()).any(|w| w == unit0));
        for mirror in [
            mirror_unit_item(1, 0x41, 0, 64),
            mirror_unit_item(2, 0x42, 0, 99),
        ] {
            assert!(mutated.windows(mirror.len()).any(|w| w == mirror));
        }
    }

    /// The base is a valid manifest before the mutation — a row that
    /// "passed" because its base was already broken would pin nothing.
    #[test]
    fn the_base_is_valid_before_mutation() {
        let base = super::super::tamper_rows_format::base_manifest();
        assert!(Manifest::decode(&base).is_ok());
    }

    proptest! {
        #![proptest_config(proptest_config(0x5EED_F400))]

        /// **Every generated ≥ 2-mirror table is rejected with exactly the
        /// D23 count code**, whatever the mirror positions, the normal
        /// count, or the fine-tree state — and the count in the error is
        /// the real count. This is the rejecting-direction property the
        /// pre-F40 corpus never contained (every valid generator produces
        /// 0 or 1 mirrors).
        #[test]
        fn any_table_with_two_or_more_mirrors_is_rejected(
            (fine_tree, units, mirrors) in arb_two_plus_mirror_units()
        ) {
            let canon = CanonMode::Text {
                canon_commit: digest32(0x66),
                unicode_version: "unicode-17.0.0".to_owned(),
            };
            let tree = if fine_tree {
                FineTree::Present { root: digest32(0x22) }
            } else {
                FineTree::Absent
            };
            let got = FileEntry::new(digest32(0x44), digest32(0x55), canon, 16, tree, units)
                .map(|_| ());
            prop_assert_eq!(got, Err(ManifestError::MultipleRawMirrors { count: mirrors }));
        }
    }
}
