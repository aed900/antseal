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
//! Two such rules exist at M0, and this module owns both.
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
//! | 2 | every revealed unit sits in the reveal section its manifest binding requires | [`VerifyError::RevealModeMismatch`] |
//!
//! Group 1 first because it is the direct continuation of R3 group 3
//! (bundle → manifest referential integrity): group 3 proves every reveal
//! *names* something that exists, group 1 proves the disclosure that makes
//! the reveal interpretable to its recipient is also present. Group 2 is a
//! step further in — it is about the shape of a unit's proof *material*, and
//! it is what makes R5's per-unit dispatch total.
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
//! The **converse** direction — a `touched_files` entry for a file with no
//! revealed unit — is deliberately *not* rejected here. D80 settled the
//! implication in one direction only, the spec does not forbid disclosing a
//! path without content, and R3 already proves such a path against
//! `path_commit`. R5 renders that file as a committed placeholder (size
//! only), so the extra disclosure buys the sealer nothing and costs the
//! recipient nothing. Turning it into a rejection would mint a permanent
//! code for a rule no decision has taken.
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

/// Run both coherence groups in the frozen order (module docs).
///
/// `units` is the manifest unit table in manifest order; visiting it (not
/// the bundle's sections) is what makes "first error" deterministic across
/// the two reveal sections.
///
/// # Errors
///
/// [`VerifyError::RevealedUnitFileNotTouched`] (group 1), then
/// [`VerifyError::RevealModeMismatch`] (group 2).
pub fn check_coherence(
    units: &[CoherenceUnit],
    bundle: &CoherenceBundleView<'_>,
) -> Result<(), VerifyError> {
    check_touched_coverage(units, bundle)?;
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
    for unit in units {
        if !is_revealed(bundle, unit.unit_id) {
            continue;
        }
        if !bundle.touched_file_ids.contains(&unit.file_id) {
            return Err(VerifyError::RevealedUnitFileNotTouched {
                unit_id: unit.unit_id,
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
    for unit in units {
        let Some(reveal) = bundle
            .reveals
            .iter()
            .find(|reveal| reveal.unit_id == unit.unit_id)
        else {
            continue;
        };
        if reveal.section.required_binding() != unit.binding {
            return Err(VerifyError::RevealModeMismatch {
                unit_id: unit.unit_id,
                manifest_binding: unit.binding,
            });
        }
    }
    Ok(())
}

fn is_revealed(bundle: &CoherenceBundleView<'_>, unit_id: u64) -> bool {
    bundle
        .reveals
        .iter()
        .any(|reveal| reveal.unit_id == unit_id)
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

    /// The converse is deliberately allowed: a path disclosed for a file
    /// nothing was revealed from (module docs).
    #[test]
    fn a_touched_file_with_no_revealed_unit_is_allowed() {
        let reveals = [reveal(2, RevealSection::NonCovered)];
        let touched = [0u64, 1, 7];
        let bundle = CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched,
        };
        assert!(check_coherence(&units(), &bundle).is_ok());
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
