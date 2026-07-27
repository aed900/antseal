//! Structural checks: exact lengths, referential integrity, the tiling
//! invariant, and `path_commit` recomputation (task R3).
//!
//! These are the manifest/bundle-shape invariants of MVP-SPEC.md line 121 —
//! everything a verifier can decide from *structure alone*, before any unit
//! ciphertext is touched. R5 runs this stage ahead of the per-unit evidence
//! stages ([`super::unit_stages`]), which is why [`RevealedUnitInput`]
//! documents range well-formedness as "already validated by R3".
//!
//! Four check groups, executed by [`check_structural`] in this frozen
//! order (D27's deterministic first-error contract —
//! `docs/decisions/D27-verify-error-mode.md`):
//!
//! 1. **Exact lengths** of every disclosed secret-adjacent byte string:
//!    `unit_salt`/`path_salt`/`file_salt` = 16 B, `s_root` and every GGM
//!    covering seed = 32 B, every boundary Merkle node hash = 32 B — one
//!    distinct code per [`LengthField`] class. First because every later
//!    group consumes these values.
//! 2. **Manifest-internal referential integrity**: every unit's `file_id`
//!    exists in the file table.
//! 3. **Bundle → manifest referential integrity**: every revealed
//!    `unit_id` exists and is revealed at most once; every touched-file
//!    entry names an existing `file_id`; covers and boundary paths
//!    reference revealed units only.
//! 4. **Tiling invariant** per file, then **`path_commit`** recomputation
//!    for every touched file (the only group that hashes).
//!
//! # The tiling invariant runs on every reveal shape
//!
//! Tiling is a property of the **manifest unit table**, not of what a
//! bundle discloses: a partial reveal — even one revealing no bytes at all
//! — still carries the full manifest, so a manifest whose unit ranges do
//! not tile its files is rejected regardless (spec line 121; asserted by
//! `tiling_fires_on_a_reveal_with_no_revealed_units`).
//!
//! # Raw mirrors are exempt by `kind`, never by position
//!
//! A raw-mirror unit lives in the **raw** byte domain, which the canonical
//! tiling does not cover, so it is skipped by `kind`
//! ([`UnitKind::RawMirror`]) and by nothing else. D23 froze the *sealer's*
//! placement rule (a mirror is its file's last unit), but this verifier
//! deliberately does not assume it: a hand-built manifest that places a
//! mirror anywhere still tiles correctly here, and is caught — if at all —
//! by the checks that actually bind content
//! (`mirror_exempt_by_kind_not_by_position`).
//!
//! # F seam
//!
//! The view types below ([`ManifestView`], [`BundleView`]) are the minimal
//! structural projection this stage needs, mirroring the F4 registry's
//! shapes without depending on F5's schema types. R5 populates them from
//! the decoded manifest/bundle; the field set is the contract. Every wire
//! quantity is `u64` — adversary-controlled wire values are never `usize`
//! (the R2 convention).

use crate::crypto::commit::{CommitmentDigest, verify_path_commit};
use crate::crypto::error::SaltKind;
use crate::crypto::material::Salt16;

use super::error::{LengthField, TilingViolationKind, VerifyError};

/// Whether a unit carries ordinary content or is a file's raw mirror
/// (MVP-SPEC.md lines 92, 98 — the unit table's `kind` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitKind {
    /// An ordinary unit in the file's tiling domain (canonical bytes for
    /// text, raw bytes for binary).
    Normal,
    /// The file's raw mirror: byte-range `[0, raw_size)` in the **raw**
    /// domain, exempt from tiling and from full-reveal concatenation.
    RawMirror,
}

/// The structural projection of one manifest unit-table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitEntry {
    /// Work-global `unit_id` (LE64 ordinal; spec line 76).
    pub unit_id: u64,
    /// Owning file.
    pub file_id: u64,
    /// Tiling participation is decided by this field alone.
    pub kind: UnitKind,
    /// Byte-range start (inclusive).
    pub range_start: u64,
    /// Byte-range end (exclusive).
    pub range_end: u64,
}

/// The structural projection of one manifest file-table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileEntry {
    /// File id referenced by unit entries and reveal entries.
    pub file_id: u64,
    /// The file's `size` field: the tiling domain width and leaf count
    /// (canonical bytes for text, raw bytes for binary; spec line 98).
    pub size: u64,
    /// `path_commit = SHA-256(0x05 ‖ path_salt ‖ path_utf8)` (spec line 95).
    pub path_commit: CommitmentDigest,
}

/// The manifest side of the structural view.
#[derive(Debug, Clone, Copy)]
pub struct ManifestView<'a> {
    /// File table.
    pub files: &'a [FileEntry],
    /// Unit table, in manifest order (the order tiling is checked in).
    pub units: &'a [UnitEntry],
}

/// One disclosed fixed-length byte string, as a (class, observed length)
/// pair — the input to the exact-length group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisclosedField {
    /// Which spec-mandated length class this value belongs to.
    pub field: LengthField,
    /// Observed length in bytes.
    pub len: u64,
}

/// A file a reveal *touches*: its path plus the `path_salt` that opens the
/// manifest's `path_commit` (spec line 95).
#[derive(Debug, Clone, Copy)]
pub struct TouchedFile<'a> {
    /// The file this entry claims to name.
    pub file_id: u64,
    /// The disclosed UTF-8 path.
    pub path: &'a str,
    /// The disclosed `path_salt`, unvalidated: length-checked by group 1
    /// (and again, defensively, when this group consumes it).
    pub path_salt: &'a [u8],
}

/// The bundle side of the structural view.
#[derive(Debug, Clone, Copy)]
pub struct BundleView<'a> {
    /// `unit_id`s the bundle reveals, in bundle order.
    pub revealed_unit_ids: &'a [u64],
    /// Touched-file entries (path disclosures).
    pub touched_files: &'a [TouchedFile<'a>],
    /// `unit_id`s referenced by GGM covers and boundary paths. These must
    /// name **revealed** units: a proof may only speak about disclosed
    /// bytes.
    pub proof_unit_refs: &'a [u64],
    /// Every disclosed fixed-length byte string in the bundle
    /// (salts, seeds, node hashes), collected by R5.
    pub disclosed_lengths: &'a [DisclosedField],
}

/// Run every structural check in the frozen order (module docs).
///
/// # Errors
///
/// The first violation, per D27's fail-fast contract: a [`LengthField`]
/// class error, [`VerifyError::UnknownFileRef`],
/// [`VerifyError::UnknownUnitRef`], [`VerifyError::DuplicateUnitReveal`],
/// [`VerifyError::TilingViolation`], [`VerifyError::RawMirrorInTilingSet`],
/// or [`VerifyError::PathCommitMismatch`].
pub fn check_structural(
    manifest: &ManifestView<'_>,
    bundle: &BundleView<'_>,
) -> Result<(), VerifyError> {
    check_disclosed_lengths(bundle.disclosed_lengths)?;
    check_manifest_refs(manifest)?;
    check_reveal_refs(manifest, bundle)?;
    check_tiling(manifest)?;
    check_path_commits(manifest, bundle.touched_files)
}

/// Exact-length check for one disclosed field.
///
/// # Errors
///
/// [`VerifyError::WrongLength`] carrying the field class, so each class is
/// its own stable code (spec line 121; tamper row "wrong-length salt").
pub fn check_field_length(field: LengthField, len: u64) -> Result<(), VerifyError> {
    if len == field.spec_len() {
        Ok(())
    } else {
        Err(VerifyError::WrongLength {
            field,
            expected: field.spec_len(),
            actual: len,
        })
    }
}

/// Exact-length check over every disclosed fixed-length byte string.
///
/// # Errors
///
/// The first [`VerifyError::WrongLength`] in input order.
pub fn check_disclosed_lengths(fields: &[DisclosedField]) -> Result<(), VerifyError> {
    for disclosed in fields {
        check_field_length(disclosed.field, disclosed.len)?;
    }
    Ok(())
}

/// Manifest-internal referential integrity: every unit names a file that
/// exists.
///
/// # Errors
///
/// [`VerifyError::UnknownFileRef`] for the first dangling `file_id`.
pub fn check_manifest_refs(manifest: &ManifestView<'_>) -> Result<(), VerifyError> {
    for unit in manifest.units {
        if !file_exists(manifest, unit.file_id) {
            return Err(VerifyError::UnknownFileRef {
                file_id: unit.file_id,
            });
        }
    }
    Ok(())
}

/// Bundle → manifest referential integrity.
///
/// Every revealed `unit_id` exists in the manifest unit table and is
/// revealed at most once; every touched-file entry names an existing
/// `file_id`; every cover/boundary-path reference names a **revealed**
/// unit — a proof that reaches outside the revealed set is rejected with
/// [`VerifyError::UnknownUnitRef`], since no such unit is available for it
/// to speak about.
///
/// # Errors
///
/// [`VerifyError::UnknownUnitRef`], [`VerifyError::DuplicateUnitReveal`],
/// or [`VerifyError::UnknownFileRef`].
pub fn check_reveal_refs(
    manifest: &ManifestView<'_>,
    bundle: &BundleView<'_>,
) -> Result<(), VerifyError> {
    for (index, unit_id) in bundle.revealed_unit_ids.iter().enumerate() {
        if !manifest.units.iter().any(|unit| unit.unit_id == *unit_id) {
            return Err(VerifyError::UnknownUnitRef { unit_id: *unit_id });
        }
        if bundle.revealed_unit_ids[..index].contains(unit_id) {
            return Err(VerifyError::DuplicateUnitReveal { unit_id: *unit_id });
        }
    }

    for touched in bundle.touched_files {
        if !file_exists(manifest, touched.file_id) {
            return Err(VerifyError::UnknownFileRef {
                file_id: touched.file_id,
            });
        }
    }

    for unit_id in bundle.proof_unit_refs {
        if !bundle.revealed_unit_ids.contains(unit_id) {
            return Err(VerifyError::UnknownUnitRef { unit_id: *unit_id });
        }
    }

    Ok(())
}

/// The per-file tiling invariant over the manifest unit table.
///
/// For every file, its **non-mirror** unit byte-ranges must be sorted,
/// non-overlapping, and exactly tile `[0, size)` (spec line 121). Runs for
/// every file on every reveal shape (module docs).
///
/// When the non-mirror ranges fail *but* including the file's raw-mirror
/// ranges would make them tile, the manifest is counting the mirror as part
/// of the tiling — reported as the distinct
/// [`VerifyError::RawMirrorInTilingSet`] rather than a generic violation,
/// because that specific confusion (raw bytes standing in for canonical
/// bytes) is its own tamper row.
///
/// # Errors
///
/// [`VerifyError::TilingViolation`] or [`VerifyError::RawMirrorInTilingSet`].
pub fn check_tiling(manifest: &ManifestView<'_>) -> Result<(), VerifyError> {
    for file in manifest.files {
        let normal: Vec<&UnitEntry> = manifest
            .units
            .iter()
            .filter(|unit| unit.file_id == file.file_id && unit.kind == UnitKind::Normal)
            .collect();

        let Err(kind) = tile(&normal, file.size) else {
            continue;
        };

        let with_mirrors: Vec<&UnitEntry> = manifest
            .units
            .iter()
            .filter(|unit| unit.file_id == file.file_id)
            .collect();
        if tile(&with_mirrors, file.size).is_ok()
            && let Some(mirror) = with_mirrors
                .iter()
                .find(|unit| unit.kind == UnitKind::RawMirror)
        {
            return Err(VerifyError::RawMirrorInTilingSet {
                unit_id: mirror.unit_id,
            });
        }

        return Err(VerifyError::TilingViolation {
            file_id: file.file_id,
            kind,
        });
    }
    Ok(())
}

/// Tile `[0, size)` with `ranges` in manifest order.
///
/// Check order is frozen for first-error determinism and follows the
/// spec's own phrasing — "sorted, non-overlapping, and exactly tiling":
/// sortedness across the whole sequence, then per-range bounds, then the
/// coverage sweep. (Without the sortedness pre-pass, a descending sequence
/// would surface as a gap at the first range, which is true but far less
/// diagnostic.)
fn tile(ranges: &[&UnitEntry], size: u64) -> Result<(), TilingViolationKind> {
    for pair in ranges.windows(2) {
        if pair[1].range_start < pair[0].range_start {
            return Err(TilingViolationKind::Unsorted);
        }
    }

    for range in ranges {
        if range.range_end < range.range_start || range.range_end > size {
            return Err(TilingViolationKind::OutOfBounds);
        }
    }

    let mut cursor = 0u64;
    for range in ranges {
        if range.range_start < cursor {
            return Err(TilingViolationKind::Overlap);
        }
        if range.range_start > cursor {
            return Err(TilingViolationKind::Gap);
        }
        cursor = range.range_end;
    }
    if cursor == size {
        Ok(())
    } else {
        Err(TilingViolationKind::Gap)
    }
}

/// Recompute `path_commit` for every touched file and match the manifest.
///
/// # Errors
///
/// [`VerifyError::WrongLength`] (`path_salt`) if a salt is not 16 B — a
/// defensive re-check, since group 1 already covers it;
/// [`VerifyError::UnknownFileRef`] for a dangling `file_id`;
/// [`VerifyError::PathCommitMismatch`] when the disclosed path and salt do
/// not reproduce the manifest's commitment.
pub fn check_path_commits(
    manifest: &ManifestView<'_>,
    touched_files: &[TouchedFile<'_>],
) -> Result<(), VerifyError> {
    for touched in touched_files {
        let Some(file) = manifest
            .files
            .iter()
            .find(|file| file.file_id == touched.file_id)
        else {
            return Err(VerifyError::UnknownFileRef {
                file_id: touched.file_id,
            });
        };

        let salt = Salt16::try_from_slice(SaltKind::Path, touched.path_salt).map_err(|_| {
            VerifyError::WrongLength {
                field: LengthField::PathSalt,
                expected: LengthField::PathSalt.spec_len(),
                actual: touched.path_salt.len() as u64,
            }
        })?;

        verify_path_commit(&salt, touched.path, &file.path_commit).map_err(|_| {
            VerifyError::PathCommitMismatch {
                file_id: touched.file_id,
            }
        })?;
    }
    Ok(())
}

fn file_exists(manifest: &ManifestView<'_>, file_id: u64) -> bool {
    manifest.files.iter().any(|file| file.file_id == file_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::commit::path_commit;

    /// Fixed, public, NON-SECRET test salt (project rule 6).
    const TEST_PATH_SALT: [u8; 16] = [7u8; 16];

    fn salt() -> Salt16 {
        Salt16::from_bytes(TEST_PATH_SALT)
    }

    fn file(file_id: u64, size: u64, path: &str) -> FileEntry {
        FileEntry {
            file_id,
            size,
            path_commit: path_commit(&salt(), path),
        }
    }

    fn unit(unit_id: u64, file_id: u64, start: u64, end: u64) -> UnitEntry {
        UnitEntry {
            unit_id,
            file_id,
            kind: UnitKind::Normal,
            range_start: start,
            range_end: end,
        }
    }

    fn mirror(unit_id: u64, file_id: u64, end: u64) -> UnitEntry {
        UnitEntry {
            unit_id,
            file_id,
            kind: UnitKind::RawMirror,
            range_start: 0,
            range_end: end,
        }
    }

    fn empty_bundle<'a>() -> BundleView<'a> {
        BundleView {
            revealed_unit_ids: &[],
            touched_files: &[],
            proof_unit_refs: &[],
            disclosed_lengths: &[],
        }
    }

    fn tiling_kind(err: VerifyError) -> TilingViolationKind {
        match err {
            VerifyError::TilingViolation { kind, .. } => kind,
            other => panic!("expected a tiling violation, got {other:?}"),
        }
    }

    // ── group 1: exact lengths ──

    /// Every length class rejects a wrong length as its own distinct code,
    /// and accepts its spec length (spec line 121).
    #[test]
    fn each_length_class_has_its_own_distinct_error() {
        let classes = [
            LengthField::UnitSalt,
            LengthField::PathSalt,
            LengthField::FileSalt,
            LengthField::SRoot,
            LengthField::GgmCoveringSeed,
            LengthField::BoundaryNodeHash,
        ];

        let mut codes = Vec::new();
        for field in classes {
            check_field_length(field, field.spec_len()).expect("the spec length is accepted");

            for bad in [0, field.spec_len() - 1, field.spec_len() + 1, 1024] {
                let err = check_field_length(field, bad).expect_err("a wrong length is rejected");
                assert!(
                    matches!(err, VerifyError::WrongLength { field: got, .. } if got == field),
                    "{field}: wrong-length error names the wrong class: {err:?}"
                );
            }
            codes.push(
                check_field_length(field, 3)
                    .expect_err("wrong length")
                    .code(),
            );
        }

        let mut unique = codes.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            codes.len(),
            "length-class codes must be pairwise distinct: {codes:?}"
        );
    }

    #[test]
    fn disclosed_length_sweep_reports_the_first_offender_in_order() {
        let fields = [
            DisclosedField {
                field: LengthField::UnitSalt,
                len: 16,
            },
            DisclosedField {
                field: LengthField::SRoot,
                len: 31,
            },
            DisclosedField {
                field: LengthField::FileSalt,
                len: 15,
            },
        ];
        let err = check_disclosed_lengths(&fields).expect_err("the 31-byte s_root is rejected");
        assert_eq!(err.code(), "wrong-length-s-root");
    }

    // ── groups 2 and 3: referential integrity ──

    #[test]
    fn manifest_unit_naming_a_missing_file_is_rejected() {
        let files = [file(1, 4, "a.txt")];
        let units = [unit(0, 1, 0, 4), unit(1, 99, 0, 4)];
        let manifest = ManifestView {
            files: &files,
            units: &units,
        };
        assert_eq!(
            check_manifest_refs(&manifest).expect_err("dangling file ref"),
            VerifyError::UnknownFileRef { file_id: 99 }
        );
    }

    #[test]
    fn reveal_of_a_nonexistent_unit_is_rejected() {
        let files = [file(1, 4, "a.txt")];
        let units = [unit(0, 1, 0, 4)];
        let manifest = ManifestView {
            files: &files,
            units: &units,
        };
        let bundle = BundleView {
            revealed_unit_ids: &[7],
            ..empty_bundle()
        };
        assert_eq!(
            check_reveal_refs(&manifest, &bundle).expect_err("dangling unit ref"),
            VerifyError::UnknownUnitRef { unit_id: 7 }
        );
    }

    #[test]
    fn revealing_the_same_unit_twice_is_rejected() {
        let files = [file(1, 4, "a.txt")];
        let units = [unit(0, 1, 0, 4)];
        let manifest = ManifestView {
            files: &files,
            units: &units,
        };
        let bundle = BundleView {
            revealed_unit_ids: &[0, 0],
            ..empty_bundle()
        };
        assert_eq!(
            check_reveal_refs(&manifest, &bundle).expect_err("duplicate reveal"),
            VerifyError::DuplicateUnitReveal { unit_id: 0 }
        );
    }

    #[test]
    fn touched_file_naming_a_missing_file_is_rejected() {
        let files = [file(1, 4, "a.txt")];
        let units = [unit(0, 1, 0, 4)];
        let manifest = ManifestView {
            files: &files,
            units: &units,
        };
        let touched = [TouchedFile {
            file_id: 42,
            path: "a.txt",
            path_salt: &TEST_PATH_SALT,
        }];
        let bundle = BundleView {
            touched_files: &touched,
            ..empty_bundle()
        };
        assert_eq!(
            check_reveal_refs(&manifest, &bundle).expect_err("dangling file ref"),
            VerifyError::UnknownFileRef { file_id: 42 }
        );
    }

    /// A cover or boundary path may only reference units the bundle
    /// actually reveals — reaching outside the revealed set is rejected.
    #[test]
    fn proof_referencing_an_unrevealed_unit_is_rejected() {
        let files = [file(1, 8, "a.txt")];
        let units = [unit(0, 1, 0, 4), unit(1, 1, 4, 8)];
        let manifest = ManifestView {
            files: &files,
            units: &units,
        };
        let bundle = BundleView {
            revealed_unit_ids: &[0],
            proof_unit_refs: &[1],
            ..empty_bundle()
        };
        assert_eq!(
            check_reveal_refs(&manifest, &bundle).expect_err("proof reaches outside the reveal"),
            VerifyError::UnknownUnitRef { unit_id: 1 }
        );
    }

    // ── group 4a: tiling ──

    #[test]
    fn exact_tiling_is_accepted() {
        let files = [file(1, 10, "a.txt")];
        let units = [unit(0, 1, 0, 4), unit(1, 1, 4, 10)];
        check_tiling(&ManifestView {
            files: &files,
            units: &units,
        })
        .expect("contiguous ranges tile exactly");
    }

    #[test]
    fn empty_file_tiles_with_its_single_empty_unit() {
        let files = [file(1, 0, "empty.txt")];
        let units = [unit(0, 1, 0, 0)];
        check_tiling(&ManifestView {
            files: &files,
            units: &units,
        })
        .expect("an empty file's [0,0) unit tiles [0,0)");
    }

    #[test]
    fn each_tiling_violation_class_is_distinguished() {
        let files = [file(1, 10, "a.txt")];

        let unsorted = [unit(0, 1, 4, 10), unit(1, 1, 0, 4)];
        let overlap = [unit(0, 1, 0, 6), unit(1, 1, 4, 10)];
        let gap = [unit(0, 1, 0, 4), unit(1, 1, 6, 10)];
        let out_of_bounds = [unit(0, 1, 0, 4), unit(1, 1, 4, 12)];
        let short = [unit(0, 1, 0, 4)];

        let cases: [(&[UnitEntry], TilingViolationKind); 5] = [
            (&unsorted, TilingViolationKind::Unsorted),
            (&overlap, TilingViolationKind::Overlap),
            (&gap, TilingViolationKind::Gap),
            (&out_of_bounds, TilingViolationKind::OutOfBounds),
            (&short, TilingViolationKind::Gap),
        ];

        for (units, expected) in cases {
            let err = check_tiling(&ManifestView {
                files: &files,
                units,
            })
            .expect_err("the tiling is broken");
            assert_eq!(tiling_kind(err), expected, "units: {units:?}");
        }

        // The four kinds carry four distinct stable codes.
        let mut codes: Vec<&str> = [
            TilingViolationKind::Unsorted,
            TilingViolationKind::Overlap,
            TilingViolationKind::Gap,
            TilingViolationKind::OutOfBounds,
        ]
        .into_iter()
        .map(|kind| VerifyError::TilingViolation { file_id: 1, kind }.code())
        .collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 4, "tiling codes must be pairwise distinct");
    }

    #[test]
    fn inverted_range_is_out_of_bounds_not_a_panic() {
        let files = [file(1, 10, "a.txt")];
        let units = [unit(0, 1, 8, 2)];
        let err = check_tiling(&ManifestView {
            files: &files,
            units: &units,
        })
        .expect_err("an inverted range is rejected");
        assert_eq!(tiling_kind(err), TilingViolationKind::OutOfBounds);
    }

    /// The tiling invariant is a manifest property: it fires even when the
    /// bundle reveals nothing at all (spec line 121; R3 accept).
    #[test]
    fn tiling_fires_on_a_reveal_with_no_revealed_units() {
        let files = [file(1, 10, "a.txt")];
        let units = [unit(0, 1, 0, 4)];
        let manifest = ManifestView {
            files: &files,
            units: &units,
        };
        let err = check_structural(&manifest, &empty_bundle())
            .expect_err("a short tiling is rejected with nothing revealed");
        assert_eq!(err.code(), "tiling-gap");
    }

    /// A raw mirror never participates in the tiling, wherever it sits in
    /// the unit table — exemption is by `kind`, not by D23's placement.
    #[test]
    fn mirror_exempt_by_kind_not_by_position() {
        let files = [file(1, 10, "a.txt")];
        let mirror_last = [unit(0, 1, 0, 4), unit(1, 1, 4, 10), mirror(2, 1, 12)];
        let mirror_first = [mirror(0, 1, 12), unit(1, 1, 0, 4), unit(2, 1, 4, 10)];

        for units in [&mirror_last, &mirror_first] {
            check_tiling(&ManifestView {
                files: &files,
                units,
            })
            .expect("the mirror is exempt regardless of its position");
        }
    }

    /// Counting the mirror to complete a tiling is its own distinct error,
    /// not a generic gap: raw bytes must never stand in for canonical
    /// coverage. Both shapes of the confusion are covered — a file whose
    /// *only* unit is its mirror, and a mirror positioned to fill a hole
    /// the normal units leave.
    #[test]
    fn mirror_used_to_complete_the_tiling_is_its_own_error() {
        let files = [file(1, 10, "a.txt")];
        let mirror_only = [mirror(9, 1, 10)];
        let mirror_fills_hole = [unit(0, 1, 0, 4), mirror(9, 1, 10)];

        for units in [&mirror_only[..], &mirror_fills_hole[..]] {
            // The hole-filling shape needs the mirror to start where the
            // normal units stop, which a legitimate mirror never does
            // (its range is always [0, raw_size)) — that is the point.
            let units: Vec<UnitEntry> = units
                .iter()
                .map(|entry| {
                    if entry.kind == UnitKind::RawMirror && units.len() > 1 {
                        UnitEntry {
                            range_start: 4,
                            ..*entry
                        }
                    } else {
                        *entry
                    }
                })
                .collect();
            let err = check_tiling(&ManifestView {
                files: &files,
                units: &units,
            })
            .expect_err("the mirror is counted in the tiling");
            assert_eq!(
                err,
                VerifyError::RawMirrorInTilingSet { unit_id: 9 },
                "expected the mirror-specific error, got {err:?}"
            );
            assert_eq!(err.code(), "raw-mirror-in-tiling-set");
        }
    }

    // ── group 4b: path_commit ──

    #[test]
    fn correct_path_and_salt_open_the_commitment() {
        let files = [file(1, 4, "docs/a.txt")];
        let units = [unit(0, 1, 0, 4)];
        let touched = [TouchedFile {
            file_id: 1,
            path: "docs/a.txt",
            path_salt: &TEST_PATH_SALT,
        }];
        check_path_commits(
            &ManifestView {
                files: &files,
                units: &units,
            },
            &touched,
        )
        .expect("the disclosed path opens path_commit");
    }

    #[test]
    fn wrong_path_fails_the_commitment_distinctly() {
        let files = [file(1, 4, "docs/a.txt")];
        let units = [unit(0, 1, 0, 4)];
        let touched = [TouchedFile {
            file_id: 1,
            path: "docs/OTHER.txt",
            path_salt: &TEST_PATH_SALT,
        }];
        let err = check_path_commits(
            &ManifestView {
                files: &files,
                units: &units,
            },
            &touched,
        )
        .expect_err("a substituted path does not open path_commit");
        assert_eq!(err, VerifyError::PathCommitMismatch { file_id: 1 });
        assert_eq!(err.code(), "path-commit-mismatch");
    }

    #[test]
    fn wrong_length_path_salt_is_a_length_error_not_a_mismatch() {
        let files = [file(1, 4, "a.txt")];
        let units = [unit(0, 1, 0, 4)];
        let touched = [TouchedFile {
            file_id: 1,
            path: "a.txt",
            path_salt: &[7u8; 15],
        }];
        let err = check_path_commits(
            &ManifestView {
                files: &files,
                units: &units,
            },
            &touched,
        )
        .expect_err("a 15-byte path_salt is rejected");
        assert_eq!(err.code(), "wrong-length-path-salt");
    }

    // ── orchestration ──

    /// The frozen group order is observable: with a length defect *and* a
    /// tiling defect present, the length error wins (D27 determinism).
    #[test]
    fn check_order_is_lengths_then_refs_then_tiling_then_commitments() {
        let files = [file(1, 10, "a.txt")];
        let units = [unit(0, 1, 0, 4)];
        let manifest = ManifestView {
            files: &files,
            units: &units,
        };
        let lengths = [DisclosedField {
            field: LengthField::UnitSalt,
            len: 15,
        }];
        let touched = [TouchedFile {
            file_id: 1,
            path: "WRONG",
            path_salt: &TEST_PATH_SALT,
        }];
        let bundle = BundleView {
            revealed_unit_ids: &[0],
            touched_files: &touched,
            proof_unit_refs: &[],
            disclosed_lengths: &lengths,
        };
        assert_eq!(
            check_structural(&manifest, &bundle)
                .expect_err("the length defect is reported first")
                .code(),
            "wrong-length-unit-salt"
        );
    }

    #[test]
    fn a_well_formed_reveal_passes_every_group() {
        let files = [file(1, 10, "a.txt"), file(2, 0, "empty.bin")];
        let units = [
            unit(0, 1, 0, 4),
            unit(1, 1, 4, 10),
            mirror(2, 1, 11),
            unit(3, 2, 0, 0),
        ];
        let touched = [TouchedFile {
            file_id: 1,
            path: "a.txt",
            path_salt: &TEST_PATH_SALT,
        }];
        let lengths = [
            DisclosedField {
                field: LengthField::UnitSalt,
                len: 16,
            },
            DisclosedField {
                field: LengthField::PathSalt,
                len: 16,
            },
            DisclosedField {
                field: LengthField::BoundaryNodeHash,
                len: 32,
            },
        ];
        let bundle = BundleView {
            revealed_unit_ids: &[0, 2],
            touched_files: &touched,
            proof_unit_refs: &[0],
            disclosed_lengths: &lengths,
        };
        check_structural(
            &ManifestView {
                files: &files,
                units: &units,
            },
            &bundle,
        )
        .expect("a well-formed multi-file reveal passes");
    }
}
