//! D83 end-to-end: a real `.sealproof` carrying a non-canonical leaf-level
//! GGM payload is rejected by `verify_bundle`, from **both** sites, with one
//! code — and the honest bundle still verifies.
//!
//! The unit-level tests elsewhere drive the two checks directly
//! (`content::fine_tree::verify` for the cover entry,
//! `verify::file_stages` for `s_root`). This file is the *whole pipeline*
//! statement, because that is what a third-party verifier actually runs and
//! because only here can the two sites be shown to be reachable, distinct as
//! variants, and identical as codes.
//!
//! # Why the `n == 1` file carries most of the cases
//!
//! D83's incidence rule is `d == 0 ∨ a odd ∨ (b odd ∧ b < n)`, and until R37
//! every R6 work had even unit boundaries — `CRLF_TEXT` -> 34, `blob.bin` 30
//! split 10/10/10, `split.md` 34 split 12/12/10 — while a whole-file cover
//! `[0, n)` is always the single root node. At `n == 1`, though, `d == 0`:
//! the grid root **is** the leaf, so the file's cover entry *and* its
//! `full_reveal.s_root` are both leaf-level disclosures of the same 32 bytes.
//! One shape, both sites, which is what makes it the right subject for the
//! two-sites-one-code statement.
//!
//! # The G-site case over a larger file (G24)
//!
//! R37 landed the odd-boundary fixture this file's first version asked for,
//! so [`a_dirty_cover_tail_is_rejected_at_depth_three`] now drives the cover
//! site at `d = 3` rather than only at the `d == 0` degeneracy. That matters
//! because `check_leaf_level_payload` is a no-op unless `level == depth`, and
//! at `n == 1` **every** node satisfies that trivially: a bug that compared
//! the wrong quantity — `level == 0`, say, or `index == 0` — would have been
//! invisible in a corpus of one-byte files. The `(3, 2)` case is where the
//! predicate is actually discriminating.

use antseal_core::content::fine_tree::FineTreeError;
use antseal_core::test_util::bundle_fixtures::{
    FileSelection, Selection, Tweak, build, build_tweaked, shapes,
};
use antseal_core::verify::{VerifyError, VerifyOptions, verify_bundle};

/// `Tweak` is `#[non_exhaustive]`, so it is built field by field rather than
/// with a struct literal.
fn tweak(set: impl FnOnce(&mut Tweak)) -> Tweak {
    let mut t = Tweak::default();
    set(&mut t);
    t
}

/// The `n == 1` work, fully revealed: one covered unit, one `full_reveals`
/// entry, both carrying leaf-level material.
fn one_byte_bundle(set: impl FnOnce(&mut Tweak)) -> Vec<u8> {
    build_tweaked(&shapes::one_byte_file(), &Selection::all(1), &tweak(set)).bytes
}

/// The control. Without this the two rejections below would prove nothing:
/// a fixture that never verified would "fail" for free.
#[test]
fn the_honest_one_byte_bundle_verifies() {
    let bytes = build(&shapes::one_byte_file(), &Selection::all(1)).bytes;
    let report = verify_bundle(&bytes, &VerifyOptions::new())
        .expect("the honest one-byte bundle must verify");
    // The bundle carries no anchors (line 153's UNANCHORED shape), so the
    // evidence layer — the one that carries the verdict (line 118) — is what
    // this control is about.
    assert!(report.anchors.is_empty());
    assert!(report.evidence.passed, "the evidence layer must pass");
    assert_eq!(
        report.evidence.units_verified, 1,
        "the one-byte file's single covered unit is verified, so its \
         leaf-level cover payload and its s_root really were both checked"
    );
}

/// **Site 1 — the cover entry** (`docs/format/registry-v1.md` §7.11 key 3).
///
/// One bit of byte 16 of the unit's `level == d` cover payload; address,
/// salt half, boundary path, ciphertext and `s_root` all honest. It surfaces
/// through G's seam arm, so the variant names the *unit*.
#[test]
fn a_dirty_cover_tail_is_rejected_through_the_fine_tree_site() {
    let bytes = one_byte_bundle(|t| t.corrupt_leaf_cover_tail = Some(0));
    let err = verify_bundle(&bytes, &VerifyOptions::new())
        .expect_err("a non-canonical cover payload must not verify");

    assert_eq!(err.code(), "fine-root-leaf-seed-tail-not-zero");
    assert_eq!(
        err,
        VerifyError::FineRootBindingFailed {
            unit_id: 0,
            source: FineTreeError::LeafSeedTailNotZero { level: 0, index: 0 },
        },
        "the fine-tree site wraps G's class and names the unit"
    );
}

/// **Site 2 — `full_reveal.s_root`** (§7.14 key 2), the binding the original
/// D83 record missed.
///
/// One bit of byte 16 of the disclosed `s_root`, cover left honest. It
/// surfaces through R's delegating arm, so the variant names the *file* —
/// and returns the very same code, which is the whole point: a code names a
/// rejection class, never a site.
#[test]
fn a_dirty_s_root_tail_is_rejected_through_the_r_site() {
    let bytes = one_byte_bundle(|t| t.corrupt_s_root_tail = Some(0));
    let err = verify_bundle(&bytes, &VerifyOptions::new())
        .expect_err("a non-canonical s_root must not verify");

    assert_eq!(err.code(), "fine-root-leaf-seed-tail-not-zero");
    assert_eq!(
        err,
        VerifyError::FineRootSeedTailNotCanonical {
            file_id: 0,
            source: FineTreeError::LeafSeedTailNotZero { level: 0, index: 0 },
        },
        "the R site delegates G's class and names the file"
    );
}

/// The two sites are **distinct variants** carrying the **same code** — the
/// `(code, layer)` separation the error-code contract mandates, asserted as
/// one statement rather than inferred from the two tests above.
#[test]
fn the_two_sites_share_one_code_and_differ_only_in_layer() {
    let cover_side = verify_bundle(
        &one_byte_bundle(|t| t.corrupt_leaf_cover_tail = Some(0)),
        &VerifyOptions::new(),
    )
    .expect_err("site 1 rejects");
    let s_root_side = verify_bundle(
        &one_byte_bundle(|t| t.corrupt_s_root_tail = Some(0)),
        &VerifyOptions::new(),
    )
    .expect_err("site 2 rejects");

    assert_eq!(cover_side.code(), s_root_side.code());
    assert_ne!(
        core::mem::discriminant(&cover_side),
        core::mem::discriminant(&s_root_side),
        "one code, two layers"
    );
    assert_ne!(
        cover_side.to_string(),
        s_root_side.to_string(),
        "the Display must still say which field was wrong"
    );
}

/// The mutation is confined to the tail: flipping the **salt** half of the
/// same field is a different class at both sites, so neither case above is
/// passing because "any change to these bytes fails".
#[test]
fn the_salt_half_is_a_different_class_at_both_sites() {
    let s_root_salt = verify_bundle(
        &one_byte_bundle(|t| t.corrupt_disclosed_s_root = Some(0)),
        &VerifyOptions::new(),
    )
    .expect_err("a wrong salt_0 must not verify");
    assert_ne!(s_root_salt.code(), "fine-root-leaf-seed-tail-not-zero");
    assert_eq!(s_root_salt.code(), "fine-root-rebuild-mismatch");

    let cover_salt = verify_bundle(
        &one_byte_bundle(|t| t.corrupt_leaf_cover_salt = Some(0)),
        &VerifyOptions::new(),
    )
    .expect_err("a wrong cover salt must not verify");
    assert_ne!(cover_salt.code(), "fine-root-leaf-seed-tail-not-zero");
    assert_eq!(cover_salt.code(), "fine-root-binding-failed");
}

/// **G24 — the cover site at `d = 3`, in a real bundle.**
///
/// `unbalanced-n6-odd-split`, reveal unit 1: leaves `[2, 3)`, cover exactly
/// `(3, 2)`. Flipping one bit of byte 16 of that entry's payload is the
/// mutation D83's tamper row describes, driven here through the **whole
/// pipeline** rather than through `verify_range` alone — which is what G24's
/// Accept asks for, since a third-party verifier runs `verify_bundle` and
/// nothing else.
///
/// The address `(3, 2)` in the error payload is the load-bearing part: it is
/// a node at depth 3 of a `d = 3` grid, so the check is discriminating on
/// `level == depth` rather than passing trivially the way it must at
/// `n == 1`.
#[test]
fn a_dirty_cover_tail_is_rejected_at_depth_three() {
    // Unit 1 of file 0 — the lone leaf [2, 3). Work-global ids are assigned
    // in order, so the file's second unit is unit_id 1.
    let selection = Selection(vec![FileSelection::Units(vec![1])]);
    let honest = build(&shapes::unbalanced_n6_odd_split(), &selection).bytes;
    let dirty = build_tweaked(
        &shapes::unbalanced_n6_odd_split(),
        &selection,
        &tweak(|t| t.corrupt_leaf_cover_tail = Some(1)),
    )
    .bytes;

    // The knob is a no-op when the unit's cover has no leaf-level node, so
    // the first thing to establish is that the mutation LANDED.
    assert_ne!(
        honest, dirty,
        "the leaf-level tail knob did nothing — this reveal's cover has no level == d node, so \
         the case below would be green for the wrong reason"
    );
    verify_bundle(&honest, &VerifyOptions::new()).expect("the honest odd-split bundle verifies");

    let err = verify_bundle(&dirty, &VerifyOptions::new())
        .expect_err("a non-canonical cover payload must not verify");
    assert_eq!(err.code(), "fine-root-leaf-seed-tail-not-zero");
    assert_eq!(
        err,
        VerifyError::FineRootBindingFailed {
            unit_id: 1,
            source: FineTreeError::LeafSeedTailNotZero { level: 3, index: 2 },
        },
        "the node is (3, 2) at d = 3 — G11's normative KAT, so the check is discriminating on \
         level == depth and not passing vacuously"
    );
}

/// The same bundle's **salt** half is a different class, at `d = 3` too.
///
/// The `n == 1` twin of this
/// ([`the_salt_half_is_a_different_class_at_both_sites`]) cannot distinguish
/// "the tail rule fired" from "any change to a 32-byte root fails", because
/// at `n == 1` the cover payload is the whole fine tree. Here the file has
/// six leaves and a real boundary path, so the two halves genuinely take
/// different routes.
#[test]
fn at_depth_three_the_salt_half_is_still_a_different_class() {
    let selection = Selection(vec![FileSelection::Units(vec![1])]);
    let err = verify_bundle(
        &build_tweaked(
            &shapes::unbalanced_n6_odd_split(),
            &selection,
            &tweak(|t| t.corrupt_leaf_cover_salt = Some(1)),
        )
        .bytes,
        &VerifyOptions::new(),
    )
    .expect_err("a wrong cover salt must not verify");
    assert_ne!(err.code(), "fine-root-leaf-seed-tail-not-zero");
    assert_eq!(err.code(), "fine-root-binding-failed");
}

/// At every larger `n` the rule idles: the same 32-byte `s_root` field
/// carries a real seed whose tail is meaningful, so a tail flip there is a
/// rebuild mismatch, not a canonicality rejection. This is the asymmetry
/// D83 turns on, stated as a test so it cannot be "tidied" into symmetry.
#[test]
fn above_one_leaf_the_s_root_tail_is_not_a_canonicality_question() {
    let bytes = build_tweaked(
        &shapes::unbalanced_n6(),
        &Selection::all(1),
        &tweak(|t| t.corrupt_s_root_tail = Some(0)),
    )
    .bytes;
    let err = verify_bundle(&bytes, &VerifyOptions::new()).expect_err("a wrong s_root fails");
    assert_ne!(
        err.code(),
        "fine-root-leaf-seed-tail-not-zero",
        "at n = 6 the grid root is not a leaf, so its tail is real seed material"
    );
}
