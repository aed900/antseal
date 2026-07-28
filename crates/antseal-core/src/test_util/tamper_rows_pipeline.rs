//! **R's registry slice for the pipeline-integration rows** (task R8):
//! mutations of a bundle's *contents* — ciphertext, keys, salts, and signed
//! manifest fields — driven end to end through `verify_bundle` and pinned to
//! the distinct error each must produce (MVP-SPEC.md line 168).
//!
//! R7 owns the *structural* rows: everything a verifier decides from the
//! shape of a bundle and its manifest, before any ciphertext is opened. This
//! slice starts where that one stops. Primitive-level reject tests for the
//! AEAD, the commitments and the signatures remain C's and G's; what these
//! rows prove is that those failures surface **distinctly through the whole
//! pipeline**, at the stage the frozen order says they should.
//!
//! Harness: [`super::tamper`]. Code contract:
//! `docs/testing/error-code-contract.md`. Like R7, **this slice mints
//! nothing** — every code it binds already existed in R1–R5's taxonomy.
//!
//! # Two rows, three demoted mutations, and why that is the honest count
//!
//! R8's task text names six mutations. Two are rows here; one is R7's
//! already; one is G19's; and **three are recorded non-rows**, because they
//! are observationally identical to a row that already claims the outcome.
//! That is not a gap — it is the tamper matrix's own distinctness rule
//! working (`check_registry` would refuse the pair), and each demotion is
//! recorded in `testdata/tamper/MATRIX.json` with the argument and with the
//! named test that asserts it instead.
//!
//! | R8 mutation | where it lives | why |
//! | --- | --- | --- |
//! | flipped ciphertext byte | **row** [`ROWS`] | `unit-decrypt-failed` |
//! | altered manifest field, **non-covered** unit fails `unit_commit` | **row** [`ROWS`] | `unit-commit-mismatch` |
//! | altered manifest field, **covered** unit fails `fine_root` | **G19's row** | R's wrapper arms surface the inner code unchanged (contract §2), so a G-level and an R-level row would claim one outcome. One row, one owner. |
//! | wrong `path_salt`/path → `path_commit` mismatch | **R7/Q7's row** `verify-path-commit-mismatch` | already implemented; a second row would collide |
//! | swapped unit | **non-row** `swapped-unit-ciphertext` | decision D81 |
//! | wrong `k_u` | **non-row** `pipeline-level-wrong-unit-key` | decision D81 |
//! | wrong `unit_salt` → `unit_commit` mismatch | **non-row** `pipeline-level-wrong-unit-salt` | found at R8; decision **D85** |
//!
//! ## The AEAD collapse (decision D81)
//!
//! Flipped ciphertext, swapped unit and wrong `k_u` all reach
//! `VerifyError::UnitDecryptFailed`, which carries no cause. That is not an
//! oversight to fix with a discriminator: **an AEAD authentication failure
//! is one bit by construction** — a single Poly1305 tag comparison covers
//! the key, the nonce, the AAD, the ciphertext and the lengths — and
//! outside the AEAD the verifier holds nothing that separates the three. It
//! never holds `W`, so a bundle-supplied `k_u` is unverifiable; the AAD's
//! `unit_id` binding is an *input* to the failing check, not an output of
//! it; ciphertext length separates only swaps across 256-byte padding
//! buckets, which makes the outcome a function of which two units the
//! fixture picked; and the commitments that would tell them apart need a
//! plaintext that does not exist. D81 evaluates and rejects the
//! address-recompute and speculative-re-decryption discriminators too.
//!
//! So one row is kept — the flip, which line 168 lists first and which is
//! fixture-independent in the strongest sense — and the other two are
//! asserted by name here plus an R10 property. C made the identical
//! collapse one layer down: `crypto-unit-aead-wrong-key` is its single row
//! for the whole wrong-key/nonce/AAD/flip family.
//!
//! ## The commitment collapse (found at R8, same shape one layer up)
//!
//! `unit_commit` is a **salted commitment opening**, and an opening failure
//! is one bit for exactly the reason an AEAD failure is: the verifier
//! recomputes `SHA-256(0x02 ‖ unit_salt ‖ bytes)` and compares it with the
//! manifest's stored value. A mismatch says the *triple* is inconsistent —
//! it cannot say whether the bundle's salt was substituted or the
//! manifest's commit was altered, because both are inputs to the one
//! comparison. So R8's `wrong unit_salt` mutation and its `altered manifest
//! field, non-covered unit` mutation are one observable failure, and the
//! spec's own `wrong-salt/unit-commit` case is in any event already
//! discharged by C's primitive-level row. The manifest-alteration keeps the
//! row, because that is the mutation the spec case names; the salt
//! substitution is a recorded non-row plus
//! [`the_wrong_unit_salt_route_reaches_the_same_code`].
//!
//! Ratified as **decision D85**
//! (`docs/decisions/D85-unit-commit-cause.md`), which also answers the
//! objection this collapse invites and D81's did not: the manifest is
//! signed, so a signature-first verifier *looks* able to attribute the
//! fault to a side. It cannot — "signature valid" leaves two bundle-side
//! candidates (the salt and the plaintext, since a bundle holder can
//! re-encrypt under the supplied `k_u`), and "signature invalid" names no
//! field. D85 extends the rule to `path_commit`, `canon_commit` and
//! `raw_commit`; the named salt-route tests that would assert it at those
//! three sites are task **R51**, not part of the ratification.
//!
//! # What the `unit_commit` row proves about the stage order
//!
//! Its mutation alters a **signed** manifest field, so the bundle's
//! signature no longer verifies either. The row asserts
//! `unit-commit-mismatch`, not a signature code — which is the frozen
//! order's "Files before Signatures" working as designed: a bundle whose
//! content contradicts its manifest is reported as a *content* failure,
//! which is the more useful verdict than "the signature over this manifest
//! is broken". [`the_unit_commit_row_beats_the_signature_stage`] pins that
//! explicitly rather than leaving it implied by the row's expected code.
//!
//! [`Tweak`]: super::bundle_fixtures::Tweak

use crate::verify::{VerifyError, VerifyOptions, verify_bundle};

use super::bundle_fixtures::{BuiltFixture, Selection, Tweak, build_tweaked, shapes};
use super::tamper::{ActualOutcome, ExpectedOutcome, TamperRow};

// ---------------------------------------------------------------------------
// the shared base fixtures
// ---------------------------------------------------------------------------

/// R6's three-file work under the mixed selection: file 0 fully revealed
/// (text + raw mirror + fine tree), file 1 partially revealed (binary,
/// `--split` into three units, middle unit shown), file 2 untouched.
///
/// Revealed units are 0 (file 0's covered normal unit), 1 (its non-covered
/// raw mirror) and 3 (file 1's covered middle unit).
fn mixed(tweak: &Tweak) -> BuiltFixture {
    build_tweaked(
        &shapes::multi_file(),
        &shapes::multi_file_mixed_selection(),
        tweak,
    )
}

/// The same work with **everything** revealed, which is what puts unit 5 —
/// file 2's plain non-covered normal unit, its file carrying no fine tree —
/// in the bundle. That is the cleanest possible subject for a `unit_commit`
/// row: no mirror exemption, no fine tree, one authoritative commitment.
fn all_revealed(tweak: &Tweak) -> BuiltFixture {
    build_tweaked(&shapes::multi_file(), &Selection::all(3), tweak)
}

/// Run a built fixture through the pipeline and report its first error.
fn pipeline(built: &BuiltFixture) -> ActualOutcome {
    ActualOutcome::from_result(
        verify_bundle(&built.bytes, &VerifyOptions::new()),
        VerifyError::code,
    )
}

/// The code `verify_bundle` reports for a tweaked fixture. Used by the
/// named tests that stand in for the demoted mutations, which assert a code
/// directly rather than through the row harness.
#[cfg(test)]
fn code_of(built: &BuiltFixture) -> &'static str {
    verify_bundle(&built.bytes, &VerifyOptions::new())
        .expect_err("the tweaked fixture must not verify")
        .code()
}

// ---------------------------------------------------------------------------
// the rows
// ---------------------------------------------------------------------------

/// Flip one byte of a revealed unit's embedded ciphertext.
///
/// Body or tag — the same outcome either way, which is the point: the tag
/// covers both, so there is nothing for the verifier to distinguish. Unit 3
/// is file 1's middle unit, revealed on its own, so no whole-file check can
/// claim the verdict ahead of the AEAD.
fn flipped_ciphertext_byte() -> ActualOutcome {
    pipeline(&mixed(&Tweak {
        corrupt_ciphertext: Some(3),
        ..Tweak::default()
    }))
}

/// Flip a bit of unit 5's manifest `unit_commit`, leaving its bytes, its
/// salt and every other field alone.
///
/// Unit 5 is file 2's only normal unit and file 2 has no fine tree, so
/// `unit_commit` is its **single authoritative commitment** (spec line 94)
/// and there is no second binding that could catch the alteration first.
fn non_covered_unit_commit_mismatch() -> ActualOutcome {
    pipeline(&all_revealed(&Tweak {
        corrupt_unit_commit: Some(5),
        ..Tweak::default()
    }))
}

// ---------------------------------------------------------------------------
// the registry slice
// ---------------------------------------------------------------------------

/// R's M0 pipeline-integration rows. Ids are permanent; see
/// [`super::tamper`]'s module docs for the add-a-row procedure and
/// `docs/testing/error-code-contract.md` for why none may be edited.
pub const ROWS: &[TamperRow] = &[
    TamperRow {
        id: "verify-flipped-ciphertext-byte",
        base: "r6-multi-file-mixed",
        mutation: "flip one byte of a revealed unit's embedded ciphertext",
        expected: ExpectedOutcome::ErrorCode("unit-decrypt-failed"),
        exercise: flipped_ciphertext_byte,
    },
    TamperRow {
        id: "verify-non-covered-unit-commit-mismatch",
        base: "r6-multi-file-all-revealed",
        mutation: "flip a bit of a non-covered unit's manifest unit_commit",
        expected: ExpectedOutcome::ErrorCode("unit-commit-mismatch"),
        exercise: non_covered_unit_commit_mismatch,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// A row that "passes" against a broken base would prove nothing.
    #[test]
    fn every_base_fixture_verifies_before_it_is_mutated() {
        for built in [mixed(&Tweak::default()), all_revealed(&Tweak::default())] {
            assert!(
                verify_bundle(&built.bytes, &VerifyOptions::new())
                    .expect("a row's base must verify")
                    .evidence
                    .passed
            );
        }
    }

    // -----------------------------------------------------------------
    // D81's demoted mutations — asserted by name, since they cannot be rows
    // -----------------------------------------------------------------

    /// **The swapped unit** (recorded non-row `swapped-unit-ciphertext`):
    /// present unit 0's ciphertext under unit 3's bundle entry, keeping
    /// unit 3's key, nonce and `unit_id`.
    ///
    /// What rejects it is the **AAD's `unit_id` binding**, not a
    /// commitment: `AAD = seal_id ‖ LE64(unit_id)`, so opening unit 0's
    /// ciphertext against unit 3's AAD fails the tag comparison at stage 1
    /// of the per-unit pipeline, long before any content binding is
    /// consulted. The C-level
    /// `aad_unit_id_binding_rejects_a_foreign_unit_id`
    /// (`crate::crypto::unit_aead`) proves *that* claim in isolation, by
    /// varying the `unit_id` alone while holding the key fixed — which only
    /// `decrypt_unit_with_key` makes possible.
    ///
    /// Worth noting the two units are in the same 256-byte padding bucket,
    /// so no length check could have claimed this first even if one existed
    /// — which is exactly D81's argument against making ciphertext length a
    /// cause discriminator.
    #[test]
    fn r8_swapped_unit_ciphertext_is_rejected() {
        assert_eq!(
            code_of(&mixed(&Tweak {
                swap_ciphertext_into: Some((0, 3)),
                ..Tweak::default()
            })),
            "unit-decrypt-failed"
        );
    }

    /// **Pipeline-level wrong `k_u`** (recorded non-row
    /// `pipeline-level-wrong-unit-key`): unit 3's entry carries unit 0's
    /// genuinely derived key.
    ///
    /// The verifier never holds `W`, so it cannot establish that a
    /// bundle-supplied `k_u` *is* that unit's key; all it can observe is
    /// that the tag does not verify. Hence the same code as the flip, and
    /// hence a non-row. The spec's `wrong key` family is separately
    /// discharged by C's primitive-level row.
    #[test]
    fn r8_pipeline_level_wrong_unit_key_is_rejected() {
        assert_eq!(
            code_of(&mixed(&Tweak {
                wrong_unit_key: Some((3, 0)),
                ..Tweak::default()
            })),
            "unit-decrypt-failed"
        );
    }

    /// All three AEAD mutations produce the **same** code from the **same**
    /// base — the collision D81 is about, pinned as a fact rather than
    /// asserted in prose.
    ///
    /// If a future change ever made one of them distinguishable, this test
    /// goes red and the demotion is up for review. That is the intended
    /// behaviour: D81's conclusion is contingent on the construction, and
    /// this is where the contingency is checked.
    #[test]
    fn the_three_aead_mutations_are_one_observable_failure() {
        let codes = [
            code_of(&mixed(&Tweak {
                corrupt_ciphertext: Some(3),
                ..Tweak::default()
            })),
            code_of(&mixed(&Tweak {
                swap_ciphertext_into: Some((0, 3)),
                ..Tweak::default()
            })),
            code_of(&mixed(&Tweak {
                wrong_unit_key: Some((3, 0)),
                ..Tweak::default()
            })),
        ];
        assert!(
            codes.iter().all(|code| *code == "unit-decrypt-failed"),
            "D81 rests on these three being indistinguishable; got {codes:?}"
        );
    }

    // -----------------------------------------------------------------
    // the commitment collapse found at R8
    // -----------------------------------------------------------------

    /// **Wrong `unit_salt`** (recorded non-row
    /// `pipeline-level-wrong-unit-salt`): unit 5's entry carries unit 1's
    /// genuinely derived, correctly sized salt.
    ///
    /// It reaches `unit-commit-mismatch` — the code the manifest-alteration
    /// row above claims — because a commitment opening is one bit in the
    /// same way an AEAD tag is: the verifier recomputes
    /// `SHA-256(0x02 ‖ unit_salt ‖ bytes)` and compares, and a mismatch
    /// cannot attribute itself to the salt rather than to the stored
    /// commit. Both are inputs to the single comparison.
    #[test]
    fn the_wrong_unit_salt_route_reaches_the_same_code() {
        assert_eq!(
            code_of(&all_revealed(&Tweak {
                wrong_unit_salt: Some((5, 1)),
                ..Tweak::default()
            })),
            "unit-commit-mismatch"
        );
    }

    /// The `unit_commit` row alters a **signed** field, so the signature is
    /// broken too — and the row still reports the content failure, because
    /// Files (stage 4) run before Signatures (stage 5).
    ///
    /// Pinned separately from the row so the row's expected code is not
    /// silently doing double duty: if the stage order were ever inverted,
    /// the row would go red for a reason its own description does not
    /// mention, whereas this test names it.
    #[test]
    fn the_unit_commit_row_beats_the_signature_stage() {
        let code = code_of(&all_revealed(&Tweak {
            corrupt_unit_commit: Some(5),
            ..Tweak::default()
        }));
        assert_eq!(code, "unit-commit-mismatch");
        assert!(
            !code.starts_with("crypto-sig"),
            "a content failure must not be reported as a signature failure"
        );
    }

    // -----------------------------------------------------------------
    // ownership boundaries
    // -----------------------------------------------------------------

    /// The rows this slice must NOT contain, each with the owner it would
    /// collide with. `check_registry` would refuse every pair; naming them
    /// here means a future addition fails against a reason rather than
    /// against a bare assertion.
    #[test]
    fn codes_owned_by_other_slices_stay_out_of_this_one() {
        for (code, owner) in [
            ("fine-root-binding-failed", "G19"),
            ("fine-root-over-broad-cover", "G19"),
            ("path-commit-mismatch", "the Q7 seed rows"),
            ("revealed-unit-file-not-touched", "R7"),
            ("touched-file-without-revealed-unit", "R7"),
        ] {
            assert!(
                !ROWS
                    .iter()
                    .any(|row| row.expected == ExpectedOutcome::ErrorCode(code)),
                "`{code}` belongs to {owner}; a second row here would collide"
            );
        }
    }

    /// Every code this slice binds already existed — R8 mints nothing
    /// (module docs; contract §3).
    #[test]
    fn every_expected_code_is_a_real_verify_error_code() {
        let universe: Vec<&'static str> = crate::verify::error::all_error_exemplars()
            .iter()
            .map(VerifyError::code)
            .collect();
        for row in ROWS {
            let ExpectedOutcome::ErrorCode(code) = row.expected else {
                panic!("row `{}` is not an error-code row", row.id);
            };
            assert!(
                universe.contains(&code),
                "row `{}` binds `{code}`, which no VerifyError variant emits",
                row.id
            );
        }
    }

    /// The slice's own codes are pairwise distinct (contract §4 layer 1).
    #[test]
    fn the_slice_is_internally_distinct() {
        let mut seen: Vec<String> = Vec::new();
        for row in ROWS {
            let key = row.expected.key();
            assert!(
                !seen.contains(&key),
                "row `{}` re-claims outcome `{key}`",
                row.id
            );
            seen.push(key);
        }
    }
}
