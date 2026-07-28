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
//! # Why every case is a one-byte file
//!
//! It is the only committed R6 shape that produces a `level == d` node at
//! all. D83's incidence rule is `d == 0 ∨ a odd ∨ (b odd ∧ b < n)`, and
//! every other R6 work has even unit boundaries — `CRLF_TEXT` -> 34,
//! `blob.bin` 30 split 10/10/10, `split.md` 34 split 12/12/10 — while a
//! whole-file cover `[0, n)` is always the single root node. At `n == 1`,
//! though, `d == 0`: the grid root **is** the leaf, so the file's cover
//! entry *and* its `full_reveal.s_root` are both leaf-level disclosures of
//! the same 32 bytes. One shape, both sites, which is exactly what makes it
//! the right subject.
//!
//! If R36/R37 ever add an odd-boundary fixture, a second G-site case over a
//! larger file belongs here.

use antseal_core::content::fine_tree::FineTreeError;
use antseal_core::test_util::bundle_fixtures::{Selection, Tweak, build, build_tweaked, shapes};
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
