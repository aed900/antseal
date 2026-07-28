//! G19 — the fine-tree tamper rows, their meta-tests, and the evidence that
//! each one is a genuine mutation of a genuinely-good opening.
//!
//! The rows themselves live in
//! `antseal_core::test_util::tamper_rows_fine_tree` (in the library, so the
//! whole registry can be assembled in one place for the cross-domain
//! distinctness sweep). This file:
//!
//! 1. runs G's slice through the Q7 harness on its own, for fast
//!    domain-local feedback;
//! 2. asserts **error identity, not merely failure** — each mutation yields
//!    its exact [`FineTreeError`] variant — and distinctness **across the
//!    full G13 error enum**, not just across the two rows;
//! 3. proves each row is a real mutation: the unmutated base opening
//!    *verifies*, so neither row can be green because its fixture was broken
//!    to begin with;
//! 4. pins the properties of the over-broad-cover construction helper the R
//!    lane consumes — that what it builds is dyadically **valid** (so the
//!    rejection is about leaf-exactness, not about a malformed address) and
//!    genuinely **over-broad** (its real-leaf span escapes the reveal).
//!
//! Whole-registry (cross-domain) distinctness lives in `tamper_matrix.rs`,
//! which merges this slice with the seed rows and C's.

use std::collections::BTreeSet;

use antseal_core::content::fine_tree::error::all_code_exemplars;
use antseal_core::content::{
    ByteRange, FineTreeError, RangeProofView, WireNode, prove_range, rebuild_fine_root,
    verify_range,
};
use antseal_core::crypto::material::Seed32;
use antseal_core::test_util::TEST_MASTER_SECRET_W;
use antseal_core::test_util::tamper::{
    ActualOutcome, ExpectedOutcome, TamperRow, check_registry, render_failures,
};
use antseal_core::test_util::tamper_rows_fine_tree::{
    D83_LEAF_COUNT, D83_RANGE, FIXTURE_LEAF_COUNT, FIXTURE_OVER_BROAD_RANGE, FIXTURE_UNIT_RANGE,
    OpeningFixture, ROWS, canonical_s_root_at_one_leaf_is_accepted, leaf_level_s_root_tail_flipped,
    over_broad_cover,
};

fn expected_codes() -> Vec<&'static str> {
    ROWS.iter()
        .map(|row| match row.expected {
            ExpectedOutcome::ErrorCode(code) => code,
            ExpectedOutcome::VerdictState(state) => state,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// the harness
// ---------------------------------------------------------------------------

/// G's slice on its own: every row produces exactly its expected outcome,
/// outcomes are pairwise distinct, and nothing panics.
#[test]
fn fine_tree_rows_are_green() {
    match check_registry(ROWS) {
        Ok(count) => assert_eq!(count, ROWS.len()),
        Err(failures) => panic!("{}", render_failures(&failures)),
    }
}

/// The slice is exactly the rows G owns — a fourth arriving here without a
/// Q8 registry entry is a review event, not a silent addition. The third is
/// D83's, a **project addition** rather than a spec-line-168 family.
#[test]
fn the_slice_is_the_g19_rows_plus_d83() {
    let ids: Vec<&str> = ROWS.iter().map(|row: &TamperRow| row.id).collect();
    assert_eq!(
        ids,
        vec![
            "content-fine-root-binding-failed",
            "content-fine-root-over-broad-cover",
            "content-fine-root-leaf-seed-tail-not-zero",
        ]
    );
    assert_eq!(
        expected_codes(),
        vec![
            "fine-root-binding-failed",
            "fine-root-over-broad-cover",
            "fine-root-leaf-seed-tail-not-zero",
        ]
    );
}

// ---------------------------------------------------------------------------
// D83 — the canonical leaf-level payload row and its second fixture
// ---------------------------------------------------------------------------

/// **The row is a real mutation of a genuinely good opening**, and it is the
/// mutation D83 names: the base is G11's normative KAT (`n = 6`, reveal
/// `{2}`, node `(3, 2)`), its honest wire form carries `salt_2 ‖ 0x00·16`,
/// and flipping any single tail byte is rejected with the row's own code.
#[test]
fn the_d83_row_mutates_a_verifying_leaf_level_opening() {
    let s_root = Seed32::from_bytes(TEST_MASTER_SECRET_W);
    let content = b"abcdef";
    let fine_root = rebuild_fine_root(&s_root, content).expect("n = 6 has a tree");
    let proof = prove_range(&s_root, content, D83_RANGE, D83_LEAF_COUNT).expect("in bounds");
    let revealed = &content[2..3];

    // Unmutated: it verifies, and its single cover node really is at the
    // grid's leaf level carrying the canonical payload.
    assert_eq!(proof.verify(revealed, &fine_root), Ok(()));
    assert_eq!(proof.depth(), 3);
    let honest: Vec<(u8, u64, Vec<u8>)> = proof
        .wire_cover()
        .into_iter()
        .map(|n| (n.level, n.index, n.bytes.to_vec()))
        .collect();
    assert_eq!(honest.len(), 1);
    assert_eq!((honest[0].0, honest[0].1), (3, 2));
    assert_eq!(&honest[0].2[16..], &[0u8; 16]);

    // Every tail byte, not one lucky position.
    let boundary = proof.wire_boundary();
    for index in 16..32 {
        let mut bytes = honest[0].2.clone();
        bytes[index] ^= 0x01;
        let cover = [WireNode {
            level: 3,
            index: 2,
            bytes: &bytes,
        }];
        let error = verify_range(
            &RangeProofView {
                range: D83_RANGE,
                cover: &cover,
                boundary: &boundary,
            },
            revealed,
            D83_LEAF_COUNT,
            &fine_root,
        )
        .expect_err("a non-canonical tail must not verify");
        assert_eq!(
            error,
            FineTreeError::LeafSeedTailNotZero { level: 3, index: 2 },
            "tail byte {index}"
        );
        assert_eq!(error.code(), "fine-root-leaf-seed-tail-not-zero");
    }
}

/// **The second fixture, same row, other site** (D83 §7): the rule also
/// binds `full_reveal.s_root` at `n == 1`. The honest disclosure passes, the
/// mutated one fails with the *same* code — which is the point: a code names
/// a rejection class, and the two sites are separated by layer, not by a
/// second string.
#[test]
fn the_d83_second_fixture_covers_the_s_root_site_with_the_same_code() {
    assert_eq!(canonical_s_root_at_one_leaf_is_accepted(), Ok(()));
    assert_eq!(
        leaf_level_s_root_tail_flipped(),
        ActualOutcome::ErrorCode("fine-root-leaf-seed-tail-not-zero".to_owned())
    );
    // Same code from both sites — asserted against the row itself rather
    // than a literal, so a rename could never leave the two out of step.
    let row = ROWS
        .iter()
        .find(|row| row.id == "content-fine-root-leaf-seed-tail-not-zero")
        .expect("D83's row is registered");
    let ExpectedOutcome::ErrorCode(code) = row.expected else {
        panic!("D83's row expects an error code");
    };
    assert_eq!(
        leaf_level_s_root_tail_flipped(),
        ActualOutcome::ErrorCode(code.to_owned())
    );
}

/// The class is reachable from the **real corpus**, not only from D83's
/// private base: G14's golden work, opened at the same range row 1 uses,
/// carries a `level == d` cover node — the incidence rule (`d == 0 ∨ a odd ∨
/// (b odd ∧ b < n)`) showing up in a committed artifact. If a future fixture
/// edit made every golden boundary even, this test says so.
#[test]
fn the_golden_work_also_carries_a_leaf_level_node() {
    let fixture = OpeningFixture::new();
    let proof = fixture
        .open(FIXTURE_UNIT_RANGE)
        .expect("the fixture unit range opens");
    let depth = proof.depth();
    let leaf_level: Vec<_> = proof
        .wire_cover()
        .into_iter()
        .filter(|node| node.level == depth)
        .map(|node| (node.index, node.bytes.to_vec()))
        .collect();
    assert!(
        !leaf_level.is_empty(),
        "the golden opening [{}, {}) of an n = {} file must carry a level-{depth} node",
        FIXTURE_UNIT_RANGE.start(),
        FIXTURE_UNIT_RANGE.end().expect("in bounds"),
        FIXTURE_LEAF_COUNT,
    );
    for (index, bytes) in leaf_level {
        assert_eq!(
            &bytes[16..],
            &[0u8; 16],
            "the golden work's own level-{depth} node {index} must be canonical"
        );
    }
}

// ---------------------------------------------------------------------------
// error identity and enum-wide distinctness
// ---------------------------------------------------------------------------

/// **Identity, not merely failure.** Each row's mutation yields its exact
/// [`FineTreeError`] variant — asserted on the variant itself, so a future
/// change that made both mutations fail with the *same* class would break
/// here even if both codes happened to stay `fine-root-`-prefixed.
#[test]
fn each_row_yields_its_exact_error_variant() {
    let fixture = OpeningFixture::new();

    // Row 1 — flipped covered-unit content.
    let proof = fixture
        .open(FIXTURE_UNIT_RANGE)
        .expect("the fixture unit range opens");
    let mut revealed = fixture.revealed(FIXTURE_UNIT_RANGE).to_vec();
    revealed[0] ^= 0x01;
    let error = proof
        .verify(&revealed, fixture.fine_root())
        .expect_err("flipped content must not verify");
    assert_eq!(error, FineTreeError::RootMismatch);
    assert_eq!(error.code(), "fine-root-binding-failed");

    // Row 2 — over-broad cover.
    let range = FIXTURE_OVER_BROAD_RANGE;
    let honest = fixture.open(range).expect("the fixture range opens");
    let over_broad = over_broad_cover(fixture.s_root(), range, fixture.leaf_count())
        .expect("an over-broad ancestor exists for a partial range");
    let cover = [over_broad.wire_node()];
    let boundary = honest.wire_boundary();
    let error = verify_range(
        &RangeProofView {
            range,
            cover: &cover,
            boundary: &boundary,
        },
        fixture.revealed(range),
        fixture.leaf_count(),
        fixture.fine_root(),
    )
    .expect_err("an over-broad cover must not verify");
    assert_eq!(error, FineTreeError::OverBroadCover);
    assert_eq!(error.code(), "fine-root-over-broad-cover");

    // And the two are different classes, not two spellings of one.
    assert_ne!(FineTreeError::RootMismatch, FineTreeError::OverBroadCover);
}

/// Distinctness **across the full G13 error enum** (G19 accept), not merely
/// between the two rows: every variant has its own code, the rows' codes are
/// among them, and no other variant shares either.
#[test]
fn row_codes_are_distinct_across_the_whole_fine_tree_enum() {
    let exemplars = all_code_exemplars();
    let codes: Vec<&'static str> = exemplars.iter().map(FineTreeError::code).collect();
    let unique: BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(
        unique.len(),
        codes.len(),
        "the fine-tree taxonomy must be pairwise distinct: {codes:?}"
    );
    assert_eq!(codes.len(), 8, "G13's seven classes plus D83's");

    for code in expected_codes() {
        assert!(
            unique.contains(code),
            "row code {code} is not emitted by any FineTreeError variant"
        );
        assert!(
            code.starts_with("fine-root-"),
            "row code {code} must use the recorded D30 `fine-root-` family"
        );
        // Exactly one variant claims it.
        assert_eq!(
            codes.iter().filter(|other| **other == code).count(),
            1,
            "code {code} is claimed by more than one variant"
        );
    }

    // The five codes G does NOT claim are the ones Q8 assigns to R7/R8;
    // asserting the complement keeps the ownership split honest.
    let claimed: BTreeSet<&str> = expected_codes().into_iter().collect();
    let unclaimed: BTreeSet<&str> = unique.difference(&claimed).copied().collect();
    assert_eq!(
        unclaimed,
        BTreeSet::from([
            "fine-root-bad-node-hash-length",
            "fine-root-bad-seed-length",
            "fine-root-byte-len-mismatch",
            "fine-root-range-out-of-bounds",
            "fine-root-wrong-cover-shape",
        ])
    );
}

// ---------------------------------------------------------------------------
// the base fixture is genuinely good
// ---------------------------------------------------------------------------

/// Neither row can be green because its fixture was already broken: the
/// **unmutated** openings both verify against the model-committed
/// `fine_root`.
#[test]
fn the_unmutated_openings_verify() {
    let fixture = OpeningFixture::new();
    assert_eq!(fixture.leaf_count(), FIXTURE_LEAF_COUNT);

    for range in [FIXTURE_UNIT_RANGE, FIXTURE_OVER_BROAD_RANGE] {
        let proof = fixture.open(range).expect("the fixture range opens");
        proof
            .verify(fixture.revealed(range), fixture.fine_root())
            .expect("the honest opening must verify — otherwise the rows prove nothing");
    }
}

/// Row 1's mutation is minimal and total: flipping **any** single bit of
/// **any** revealed byte gives the same class, so the row is not resting on
/// one lucky byte position.
#[test]
fn flipping_any_revealed_byte_gives_the_same_class() {
    let fixture = OpeningFixture::new();
    let proof = fixture
        .open(FIXTURE_UNIT_RANGE)
        .expect("the fixture unit range opens");
    let honest = fixture.revealed(FIXTURE_UNIT_RANGE);

    for index in 0..honest.len() {
        for bit in 0..8u32 {
            let mut revealed = honest.to_vec();
            revealed[index] ^= 1u8 << bit;
            assert_eq!(
                proof.verify(&revealed, fixture.fine_root()),
                Err(FineTreeError::RootMismatch),
                "byte {index}, bit {bit}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// the over-broad-cover helper (the R-lane seam)
// ---------------------------------------------------------------------------

/// What the helper builds really is **dyadically valid** — its address is a
/// well-formed node of this tree's grid — and really is **over-broad** — its
/// real-leaf span escapes the revealed range. Both halves matter: if the
/// address were malformed, G13 would reject it as
/// `fine-root-wrong-cover-shape` and the row would be testing the wrong rule.
#[test]
fn the_helper_builds_a_valid_but_over_broad_node() {
    let fixture = OpeningFixture::new();
    let range = FIXTURE_OVER_BROAD_RANGE;
    let node = over_broad_cover(fixture.s_root(), range, fixture.leaf_count())
        .expect("an over-broad ancestor exists");

    // Dyadically valid: level 2 of the depth-6 grid (n = 34 -> 64 slots),
    // index 1, spanning slots [16, 32) and truncated to real leaves [16, 32).
    let depth = 6u8;
    assert_eq!(node.address().level(), 2);
    assert_eq!(node.address().index(), 1);
    assert!(node.address().validate_in_tree(depth).is_ok());
    assert_eq!(node.address().first_slot(depth), Ok(16));
    assert_eq!(node.address().slot_width(depth), Ok(16));

    // Over-broad: the span reaches leaf 31, but the reveal stops at 23.
    assert_eq!(node.real_span(), (16, 32));
    let range_end = range.end().expect("no overflow");
    assert_eq!(range_end, 24);
    assert!(
        node.real_span().1 > range_end,
        "the node must commit at least one leaf the reveal does not show"
    );

    // And the wire form carries a full-length seed, so the rejection cannot
    // be attributed to a length fault (G13 precedence stage 3).
    assert_eq!(node.wire_node().bytes.len(), 32);
    assert_eq!(node.wire_node().level, 2);
    assert_eq!(node.wire_node().index, 1);
}

/// The helper is honest about when no such node exists — it returns `None`
/// rather than inventing one. Two cases matter, for opposite reasons.
#[test]
fn the_helper_declines_where_over_broadness_is_unreachable() {
    let fixture = OpeningFixture::new();
    let n = fixture.leaf_count();

    // A full reveal's cover IS `s_root` (D75), which has no ancestor.
    assert!(over_broad_cover(fixture.s_root(), ByteRange::new(0, n), n).is_none());

    // An invalid range has no honest cover to take an ancestor of.
    assert!(over_broad_cover(fixture.s_root(), ByteRange::new(0, 0), n).is_none());
    assert!(over_broad_cover(fixture.s_root(), ByteRange::new(n, 1), n).is_none());
}

/// The helper works across the range space, not just at the fixture's range:
/// for every partial range of the fixture file it either declines or returns
/// a node that G13 rejects as `OverBroadCover` — never as a shape fault, and
/// never accepted.
#[test]
fn every_partial_range_is_rejected_as_over_broad_or_declined() {
    let fixture = OpeningFixture::new();
    let n = fixture.leaf_count();
    let mut built = 0;

    for start in 0..n {
        for length in 1..=(n - start) {
            let range = ByteRange::new(start, length);
            let Some(node) = over_broad_cover(fixture.s_root(), range, n) else {
                continue;
            };
            built += 1;
            let honest = fixture.open(range).expect("a valid range opens");
            let cover = [node.wire_node()];
            let boundary = honest.wire_boundary();
            assert_eq!(
                verify_range(
                    &RangeProofView {
                        range,
                        cover: &cover,
                        boundary: &boundary,
                    },
                    fixture.revealed(range),
                    n,
                    fixture.fine_root(),
                ),
                Err(FineTreeError::OverBroadCover),
                "range [{start}, {})",
                start + length
            );
        }
    }

    assert!(
        built > 100,
        "the sweep should exercise many ranges, built {built}"
    );
}
