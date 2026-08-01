//! Bundle ↔ manifest coherence: the rules neither layer can decide alone
//! (task R5, the tail of the structural stage).
//!
//! F8's bundle schema is validated **without ever opening the embedded
//! manifest** (decision D78), and F5's manifest schema knows nothing about
//! the bundle that carries it. Both can therefore be perfectly well formed
//! while *disagreeing with each other*. The error-code contract assigns that
//! class to R's unprefixed namespace explicitly:
//!
//! > A bundle that is *well-formed but inconsistent with its manifest* is
//! > neither \[`bundle-` nor `manifest-`\]: it is a verify-pipeline outcome
//! > in R's unprefixed namespace.
//! > — `docs/testing/error-code-contract.md` §2
//!
//! Three such rules exist at M0, and this module owns all three.
//!
//! # The frozen check order
//!
//! Runs immediately after R3's four structural groups
//! ([`check_structural`](super::structural::check_structural)) and before
//! any ciphertext is touched, in this order — frozen, because D27 makes
//! fail-fast the sole normative mode:
//!
//! | # | rule | error |
//! |---|---|---|
//! | 1 | every revealed unit's owning file has a `touched_files` entry | [`VerifyError::RevealedUnitFileNotTouched`] (D80) |
//! | 1b | every `touched_files` entry's file has a revealed unit | [`VerifyError::TouchedFileWithoutRevealedUnit`] (D82) |
//! | 2 | every revealed unit sits in the reveal section its manifest binding requires | [`VerifyError::RevealModeMismatch`] |
//!
//! Group 1 first because it is the direct continuation of R3 group 3
//! (bundle → manifest referential integrity): group 3 proves every reveal
//! *names* something that exists, group 1 proves the disclosure that makes
//! the reveal interpretable to its recipient is also present. Group 1b is
//! that rule's converse and belongs beside it: together they make
//! `touched_files` exactly determined. Group 2 is a step further in — it is
//! about the shape of a unit's proof *material*, and it is what makes R5's
//! per-unit dispatch total.
//!
//! **1b was additive.** It was introduced after 1 and 2 were frozen, and it
//! changes no existing input's reported code: an input violating 1 still
//! reports 1's code (1b runs after), and the only inputs 1b newly rejects
//! were previously *accepted*, never assigned to 2. The one deliberate new
//! precedence is 1b before 2, pinned by
//! `d82_group_order_touched_exactness_before_reveal_section`.
//!
//! Within each group, units are visited in **manifest unit-table order**
//! (D27: "subjects in manifest order"), which is `unit_id` order, since
//! F5 pins each unit's stored id to its manifest ordinal.
//!
//! # Group 1 — D80
//!
//! `{ file_id(u) : u ∈ bundle.revealed } ⊆ touched_files`.
//!
//! MVP-SPEC.md line 95 defines the term at its italicised first use:
//! `path_salt` "ships whenever any reveal *touches* the file (so the
//! recipient can verify the path)". Line 121's rendering taxonomy has
//! exactly two states — revealed content, or an unrevealed file as a
//! committed placeholder with the path withheld — and no third state for
//! "revealed content, path withheld". Full record:
//! `docs/decisions/D80-revealed-unit-touched-file.md`.
//!
//! It is **not** F8's `bundle-full-reveal-without-touched-file`. That rule
//! is `full_reveals ⊆ touched_files`, decidable from the bundle's own two
//! lists (tier `[X]`). D80 is the per-*unit* case: mapping `unit_id →
//! file_id` needs the signed unit table, which D78 keeps out of layer 1.
//! The two are not redundant — a file can be touched by a single-unit
//! reveal without being fully revealed.
//!
//! # Group 1b — D82
//!
//! `touched_files ⊆ { file_id(u) : u ∈ bundle.revealed }`, which with group
//! 1 makes the containment an **equality**:
//!
//! ```text
//! touched_files  ==  { file_id(u) : u ∈ bundle.revealed }
//! ```
//!
//! D80 settled the implication in one direction; D82 closes the converse.
//! Full record: `docs/decisions/D82-touched-file-without-reveal.md`. Its
//! three loads:
//!
//! - **The spec forecloses the shape.** Line 95: bundle recipients see
//!   unrevealed files "**only** as committed placeholders". Line 121's
//!   taxonomy is closed in both directions — an unrevealed file renders as
//!   a placeholder with its **path withheld** — so "unrevealed file, path
//!   disclosed" is a state the spec names the opposite of, not one it
//!   merely omits. Line 95's defining use of *touches* (a reveal touches a
//!   file when it discloses a unit of it, D80) makes `path_salt`'s shipping
//!   condition a biconditional.
//! - **The verifier throws the disclosure away anyway.**
//!   [`reveal_set`](super::pipeline) computes `touched` from `is_revealed`
//!   alone and emits an untouched file as `UnrevealedFilePlaceholder`
//!   (size only). So the permissive branch was never "keep today's
//!   behaviour": delivering the disclosure would need a third `RevealSet`
//!   state, which `report.rs` forbids in terms.
//! - **It is the D74 add-material hole, in this section.** The manifest is
//!   signed; the bundle is not. A relay cannot *invent* a `(path,
//!   path_salt)` pair — that needs a preimage of a signed `path_commit`
//!   under a 16-byte secret salt — but it does not have to:
//!   `path_salt = HKDF(W, "path-salt", file_id)` is a per-work constant, so
//!   anyone holding another bundle of the same work holds the pair verbatim
//!   and can splice it into a bundle whose sealer chose not to disclose
//!   that file. R3's `path_commit` check passes, because the pair is
//!   genuine. Without 1b the sealer's per-bundle, file-scoped disclosure
//!   decision is silently overridden by a third party.
//!
//! One code, not two: the `full_reveals` form of the same mistake is
//! unreachable, because a full reveal reveals every non-mirror unit and F5
//! refuses a file with none (`ManifestError::EmptyContainer`).
//!
//! # Group 2 — reveal mode vs manifest binding
//!
//! MVP-SPEC.md line 94's single-authoritative-commitment rule gives every
//! unit exactly one content binding: `fine_root` (covered) **or**
//! `unit_commit` (non-covered), never both. F5 already ties the manifest
//! side down — [`FileEntry::new`](crate::manifest::body::FileEntry::new)
//! refuses a covered unit carrying a `unit_commit` and a non-covered unit
//! without one — so the manifest is internally consistent by construction.
//!
//! The bundle side is not tied to anything: `covered_reveals` and
//! `noncovered_reveals` are two separate sections and F8, forbidden from
//! reading the manifest, cannot know which one a given `unit_id` belongs
//! in. So a bundle may ship a fine-tree-covered unit as a non-covered
//! reveal — handing the verifier a `unit_salt` for a `unit_commit` that
//! does not exist — or the reverse.
//!
//! Rejecting it here is what lets R5's stage-4 dispatch be **total** on the
//! manifest's binding: by the time a unit reaches
//! [`verify_revealed_unit`](super::unit_stages::verify_revealed_unit), the
//! material it needs is known to be present. R5 keeps a defensive copy of
//! the same two arms at the dispatch site (unreachable after this stage,
//! and yielding the identical codes), mirroring R4's row-6 backstop.

use std::collections::{BTreeMap, BTreeSet};

use super::error::{BindingMode, VerifyError};

/// The manifest-side projection one coherence check needs per unit.
///
/// Deliberately three scalars: this stage decides nothing from ranges,
/// commitments or ciphertext, and a wider view would invite it to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoherenceUnit {
    /// Work-global `unit_id` (MVP-SPEC.md line 76).
    pub unit_id: u64,
    /// Owning file, from the manifest's nested unit table.
    pub file_id: u64,
    /// How the **manifest** binds this unit's content (line 94).
    pub binding: BindingMode,
}

/// How the **bundle** chose to reveal a unit: which of the two reveal
/// sections it put the unit in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealSection {
    /// `covered_reveals` — carries a leaf-exact GGM sub-cover + boundary
    /// path (registry §7.11).
    Covered,
    /// `noncovered_reveals` — carries a `unit_salt` (registry §7.12).
    NonCovered,
}

impl RevealSection {
    /// The manifest binding this section is the correct home for.
    const fn required_binding(self) -> BindingMode {
        match self {
            Self::Covered => BindingMode::FineTreeCovered,
            Self::NonCovered => BindingMode::NonCovered,
        }
    }
}

/// One revealed unit as the bundle presents it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevealedUnitRef {
    /// The `unit_id` the reveal entry names.
    pub unit_id: u64,
    /// Which section it came from.
    pub section: RevealSection,
}

/// The bundle side of the coherence view.
#[derive(Debug, Clone, Copy)]
pub struct CoherenceBundleView<'a> {
    /// Every revealed unit, from both reveal sections. R3 has already
    /// proved each `unit_id` exists in the manifest unit table and is
    /// revealed at most once.
    pub reveals: &'a [RevealedUnitRef],
    /// `file_id`s with a `touched_files` entry. R3 has already proved each
    /// names an existing file and opens its `path_commit`.
    pub touched_file_ids: &'a [u64],
}

/// Run all three coherence groups in the frozen order (module docs).
///
/// `units` is the manifest unit table in manifest order; visiting it (not
/// the bundle's sections) is what makes "first error" deterministic across
/// the two reveal sections.
///
/// # Errors
///
/// [`VerifyError::RevealedUnitFileNotTouched`] (group 1), then
/// [`VerifyError::TouchedFileWithoutRevealedUnit`] (group 1b), then
/// [`VerifyError::RevealModeMismatch`] (group 2).
pub fn check_coherence(
    units: &[CoherenceUnit],
    bundle: &CoherenceBundleView<'_>,
) -> Result<(), VerifyError> {
    check_touched_coverage(units, bundle)?;
    check_touched_exactness(units, bundle)?;
    check_reveal_sections(units, bundle)
}

/// Group 1 (D80): every revealed unit's owning file is disclosed.
///
/// # Errors
///
/// [`VerifyError::RevealedUnitFileNotTouched`] for the first revealed unit
/// in manifest order whose file has no `touched_files` entry.
pub fn check_touched_coverage(
    units: &[CoherenceUnit],
    bundle: &CoherenceBundleView<'_>,
) -> Result<(), VerifyError> {
    // Both memberships as sets, built once (R54): the pre-R54 shape
    // rescanned `reveals` per unit — Θ(|units| × |reveals|) on a fully
    // revealed work. Units are still visited in manifest order, so the
    // first error is unchanged.
    let revealed = revealed_id_set(bundle);
    let touched = touched_id_set(bundle);
    for unit in units {
        if !revealed.contains(&unit.unit_id) {
            continue;
        }
        if !touched.contains(&unit.file_id) {
            return Err(VerifyError::RevealedUnitFileNotTouched {
                unit_id: unit.unit_id,
                file_id: unit.file_id,
            });
        }
    }
    Ok(())
}

/// Group 1b (D82): every disclosed file is one the bundle reveals from.
///
/// # Subject order
///
/// The **manifest** file table, never `touched_files` order — same reason
/// group 1 visits the manifest unit table: "first error" must not depend on
/// bundle layout (D27). No extra view is needed to enumerate it. Every file
/// has at least one unit (F5's `EmptyContainer`: "an empty file still has
/// one empty unit"), so the `file_id`s appearing in `units` — already in
/// manifest order — enumerate the manifest file table by first occurrence.
///
/// Every touched `file_id` is known to name a real file by now: R3's group
/// 3 already rejected a dangling one as `unknown-file-ref`. A `file_id`
/// this loop cannot see is therefore not "touched but unknown", it is
/// unreachable.
///
/// # Errors
///
/// [`VerifyError::TouchedFileWithoutRevealedUnit`] for the lowest-ordinal
/// file in manifest order that has a `touched_files` entry and no revealed
/// unit.
pub fn check_touched_exactness(
    units: &[CoherenceUnit],
    bundle: &CoherenceBundleView<'_>,
) -> Result<(), VerifyError> {
    // Built once (R54): `files_with_a_reveal` answers, per file, exactly
    // the question the pre-R54 shape answered by rescanning the whole unit
    // table (and, inside that, the whole reveal list) for every
    // first-occurrence file — Θ(|files| × |units| × |reveals|) at worst,
    // and quadratic even on a no-reveal bundle through the linear `seen`
    // probe. Subjects are still first-occurrence files in manifest unit
    // order, so the reported file is unchanged.
    let revealed = revealed_id_set(bundle);
    let touched = touched_id_set(bundle);
    let files_with_a_reveal: BTreeSet<u64> = units
        .iter()
        .filter(|unit| revealed.contains(&unit.unit_id))
        .map(|unit| unit.file_id)
        .collect();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for unit in units {
        if !seen.insert(unit.file_id) {
            continue;
        }
        if !touched.contains(&unit.file_id) {
            continue;
        }
        if !files_with_a_reveal.contains(&unit.file_id) {
            return Err(VerifyError::TouchedFileWithoutRevealedUnit {
                file_id: unit.file_id,
            });
        }
    }
    Ok(())
}

/// Group 2: every revealed unit is in the reveal section its manifest
/// binding requires.
///
/// # Errors
///
/// [`VerifyError::RevealModeMismatch`] for the first revealed unit in
/// manifest order whose section contradicts its binding, carrying the
/// **manifest's** binding (the fixed fact; the bundle did the other thing).
pub fn check_reveal_sections(
    units: &[CoherenceUnit],
    bundle: &CoherenceBundleView<'_>,
) -> Result<(), VerifyError> {
    // First-wins by construction (R54): the map keeps the first reveal per
    // `unit_id`, exactly what the pre-R54 per-unit `.find` rescan returned
    // — including on a hand-built view listing one unit in both sections
    // (unreachable through the pipeline: R3 group 3 already rejected the
    // duplicate). Units are still visited in manifest order.
    let mut section_by_id: BTreeMap<u64, RevealSection> = BTreeMap::new();
    for reveal in bundle.reveals {
        section_by_id
            .entry(reveal.unit_id)
            .or_insert(reveal.section);
    }
    for unit in units {
        let Some(section) = section_by_id.get(&unit.unit_id) else {
            continue;
        };
        if section.required_binding() != unit.binding {
            return Err(VerifyError::RevealModeMismatch {
                unit_id: unit.unit_id,
                manifest_binding: unit.binding,
            });
        }
    }
    Ok(())
}

/// Every revealed `unit_id`, as a set (R54).
fn revealed_id_set(bundle: &CoherenceBundleView<'_>) -> BTreeSet<u64> {
    bundle.reveals.iter().map(|reveal| reveal.unit_id).collect()
}

/// Every touched `file_id`, as a set (R54).
fn touched_id_set(bundle: &CoherenceBundleView<'_>) -> BTreeSet<u64> {
    bundle.touched_file_ids.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two files: file 0 has a covered unit 0 and a non-covered mirror
    /// unit 1; file 1 has a non-covered unit 2.
    fn units() -> Vec<CoherenceUnit> {
        vec![
            CoherenceUnit {
                unit_id: 0,
                file_id: 0,
                binding: BindingMode::FineTreeCovered,
            },
            CoherenceUnit {
                unit_id: 1,
                file_id: 0,
                binding: BindingMode::NonCovered,
            },
            CoherenceUnit {
                unit_id: 2,
                file_id: 1,
                binding: BindingMode::NonCovered,
            },
        ]
    }

    fn reveal(unit_id: u64, section: RevealSection) -> RevealedUnitRef {
        RevealedUnitRef { unit_id, section }
    }

    #[test]
    fn a_coherent_bundle_passes() {
        let reveals = [
            reveal(0, RevealSection::Covered),
            reveal(1, RevealSection::NonCovered),
            reveal(2, RevealSection::NonCovered),
        ];
        let touched = [0u64, 1];
        let bundle = CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched,
        };
        assert!(check_coherence(&units(), &bundle).is_ok());
    }

    /// D80: a revealed unit whose file was never disclosed.
    #[test]
    fn d80_revealed_unit_needs_its_file_touched() {
        let reveals = [reveal(2, RevealSection::NonCovered)];
        let touched = [0u64];
        let bundle = CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched,
        };
        let err = check_coherence(&units(), &bundle).expect_err("file 1 is not touched");
        assert_eq!(
            err,
            VerifyError::RevealedUnitFileNotTouched {
                unit_id: 2,
                file_id: 1,
            }
        );
        assert_eq!(err.code(), "revealed-unit-file-not-touched");
    }

    /// D80 applies to a revealed **raw mirror** too — it is a revealed
    /// unit of the file like any other (the decision record's "covered or
    /// non-covered, normal or raw-mirror").
    #[test]
    fn d80_covers_raw_mirror_units() {
        let reveals = [reveal(1, RevealSection::NonCovered)];
        let touched: [u64; 0] = [];
        let bundle = CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched,
        };
        assert_eq!(
            check_coherence(&units(), &bundle).expect_err("file 0 is not touched"),
            VerifyError::RevealedUnitFileNotTouched {
                unit_id: 1,
                file_id: 0,
            }
        );
    }

    /// **D82** (the inverse of what this module asserted before the
    /// decision landed): a path disclosed for a file nothing was revealed
    /// from is now rejected. File 1 is legitimately touched and revealed
    /// from; file 0 is touched with neither of its units revealed.
    #[test]
    fn d82_a_touched_file_with_no_revealed_unit_is_rejected() {
        let reveals = [reveal(2, RevealSection::NonCovered)];
        let touched = [0u64, 1];
        let bundle = CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched,
        };
        let err = check_coherence(&units(), &bundle).expect_err("file 0 has no revealed unit");
        assert_eq!(
            err,
            VerifyError::TouchedFileWithoutRevealedUnit { file_id: 0 }
        );
        assert_eq!(err.code(), "touched-file-without-revealed-unit");
    }

    /// D82 is about the **file**, not its units one at a time: a file with
    /// two units is disclosed legitimately when *either* is revealed.
    #[test]
    fn d82_one_revealed_unit_is_enough_to_justify_the_entry() {
        for revealed_unit in [0, 1] {
            let section = if revealed_unit == 0 {
                RevealSection::Covered
            } else {
                RevealSection::NonCovered
            };
            let reveals = [reveal(revealed_unit, section)];
            let touched = [0u64];
            let bundle = CoherenceBundleView {
                reveals: &reveals,
                touched_file_ids: &touched,
            };
            assert!(
                check_coherence(&units(), &bundle).is_ok(),
                "unit {revealed_unit} of file 0 justifies file 0's entry"
            );
        }
    }

    /// D82's subject order is **manifest file-table order**, not
    /// `touched_files` order: with both files wrongly touched and the
    /// bundle listing file 1 first, file 0 is still the reported subject.
    #[test]
    fn d82_subjects_are_visited_in_manifest_file_order() {
        let reveals: [RevealedUnitRef; 0] = [];
        let touched = [1u64, 0];
        let bundle = CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched,
        };
        assert_eq!(
            check_coherence(&units(), &bundle).expect_err("neither file has a revealed unit"),
            VerifyError::TouchedFileWithoutRevealedUnit { file_id: 0 }
        );
    }

    /// The new precedence D82 introduces: **1b before group 2**. Unit 0 is
    /// covered but revealed as non-covered (a group-2 violation), while
    /// file 1 is touched with nothing revealed from it (a 1b violation).
    /// 1b's code is the reported one.
    #[test]
    fn d82_group_order_touched_exactness_before_reveal_section() {
        let reveals = [reveal(0, RevealSection::NonCovered)];
        let touched = [0u64, 1];
        let bundle = CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched,
        };
        assert_eq!(
            check_coherence(&units(), &bundle)
                .expect_err("both 1b and group 2 are violated")
                .code(),
            "touched-file-without-revealed-unit"
        );
    }

    /// And the older precedence is unchanged by 1b's arrival: **group 1
    /// before 1b**. Unit 2's file 1 is not touched (group 1), and file 0 is
    /// touched with nothing revealed from it (1b).
    #[test]
    fn d82_group_order_touched_coverage_before_touched_exactness() {
        let reveals = [reveal(2, RevealSection::NonCovered)];
        let touched = [0u64];
        let bundle = CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched,
        };
        assert_eq!(
            check_coherence(&units(), &bundle)
                .expect_err("both group 1 and 1b are violated")
                .code(),
            "revealed-unit-file-not-touched"
        );
    }

    /// A covered unit shipped in `noncovered_reveals`.
    #[test]
    fn covered_unit_revealed_as_non_covered_is_rejected() {
        let reveals = [reveal(0, RevealSection::NonCovered)];
        let touched = [0u64];
        let bundle = CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched,
        };
        let err = check_coherence(&units(), &bundle).expect_err("unit 0 is covered");
        assert_eq!(
            err,
            VerifyError::RevealModeMismatch {
                unit_id: 0,
                manifest_binding: BindingMode::FineTreeCovered,
            }
        );
        assert_eq!(err.code(), "covered-unit-revealed-as-non-covered");
    }

    /// A non-covered unit shipped in `covered_reveals`.
    #[test]
    fn non_covered_unit_revealed_as_covered_is_rejected() {
        let reveals = [reveal(2, RevealSection::Covered)];
        let touched = [1u64];
        let bundle = CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched,
        };
        let err = check_coherence(&units(), &bundle).expect_err("unit 2 is not covered");
        assert_eq!(
            err,
            VerifyError::RevealModeMismatch {
                unit_id: 2,
                manifest_binding: BindingMode::NonCovered,
            }
        );
        assert_eq!(err.code(), "non-covered-unit-revealed-as-covered");
    }

    /// The frozen group order: with **both** rules violated, D80's is the
    /// reported first error.
    #[test]
    fn group_order_is_frozen_touched_coverage_before_reveal_section() {
        let reveals = [reveal(0, RevealSection::NonCovered)];
        let touched: [u64; 0] = [];
        let bundle = CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched,
        };
        assert_eq!(
            check_coherence(&units(), &bundle)
                .expect_err("both rules are violated")
                .code(),
            "revealed-unit-file-not-touched"
        );
    }

    /// Subjects are visited in manifest order, not bundle order: with two
    /// offending units revealed, the lower `unit_id` is reported even when
    /// the bundle lists it second (D27's determinism requirement).
    #[test]
    fn subjects_are_visited_in_manifest_order() {
        let reveals = [
            reveal(2, RevealSection::NonCovered),
            reveal(1, RevealSection::NonCovered),
        ];
        let touched: [u64; 0] = [];
        let bundle = CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched,
        };
        assert_eq!(
            check_coherence(&units(), &bundle).expect_err("neither file is touched"),
            VerifyError::RevealedUnitFileNotTouched {
                unit_id: 1,
                file_id: 0,
            }
        );
    }

    /// An unrevealed unit is not subject to either rule.
    #[test]
    fn unrevealed_units_are_not_checked() {
        let reveals: [RevealedUnitRef; 0] = [];
        let touched: [u64; 0] = [];
        let bundle = CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched,
        };
        assert!(check_coherence(&units(), &bundle).is_ok());
    }
}
