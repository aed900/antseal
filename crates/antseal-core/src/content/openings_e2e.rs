//! End-to-end opening test (tasks/G.md G17): G14's pipeline → `prove_unit`
//! and `prove_range` → G13 verification against the **manifest-committed**
//! `fine_root`.
//!
//! This is the composition the spec's M0 milestone names (line 153) and the
//! one the verifier executes (line 169). It is deliberately in the library's
//! `cfg(test)` tree rather than in `tests/`, because the wasm32 lane runs
//! `--lib` unit tests only (P14, `docs/wasm-toolchain.md`) and G17's accept
//! criteria require both opening kinds green on native **and** wasm32.
//!
//! # What it demonstrates that the layer tests cannot
//!
//! The layers each verify themselves: G12 already asserts that `prove_unit`
//! *is* `prove_range` byte-identically
//! (`prove_unit_is_byte_identical_to_prove_range`), and G13 verifies proofs
//! against roots it was handed. What no layer test can see is whether the
//! four things that must line up actually do:
//!
//! 1. the `s_root` the model used to build `fine_root`,
//! 2. the byte **domain** the model chose (canonical for text, raw for
//!    binary — MVP-SPEC.md line 85),
//! 3. the `leaf_count` the model recorded as the file's `size` (line 98),
//! 4. the unit ranges the model assigned.
//!
//! A disagreement in any one of them produces a proof that verifies against
//! *some* root but not the committed one — which is exactly the failure this
//! test exists to catch, and why every `fine_root` here is read back out of
//! the model instead of being recomputed locally.
//!
//! # The sole-commitment rule, demonstrated rather than asserted
//!
//! A range spanning a unit boundary verifies against `fine_root` with no
//! per-unit commitment involved anywhere — which is only possible because
//! covered units carry **no** `unit_commit` (lines 94, 96). The test asserts
//! both halves: the cross-boundary opening verifies, and every covered unit
//! in the fixture is `unit_commit`-free.

use super::descriptor::CanonDescriptor;
use super::fine_tree::{CoveredUnit, FineRoot, RangeProof, prove_range, prove_unit};
use super::fixtures::{
    GOLDEN_FILE_BINARY, GOLDEN_FILE_EMPTY, GOLDEN_FILE_NO_FINE_TREE, GOLDEN_FILE_TEXT_SPLIT,
    SYNTHETIC_FINE_SEEDS, golden_model,
};
use super::unit::{ByteRange, Unit, requires_unit_commit};
use super::{ContentModel, FineSeedSource};
use crate::crypto::hkdf::FileId;
use crate::crypto::material::Seed32;

/// Everything one file of the golden work contributes to an opening: the seed
/// the model derived its `fine_root` from, the byte domain, the leaf count,
/// and the committed root itself.
struct Opening<'a> {
    s_root: Seed32,
    domain: &'a [u8],
    leaf_count: u64,
    fine_root: &'a FineRoot,
    descriptor: &'a CanonDescriptor,
    units: &'a [Unit],
}

/// Assemble the golden work and pull out one file's opening context —
/// reading `fine_root` **from the model**, so every proof below is checked
/// against the value a manifest would carry, not a locally recomputed one.
fn opening_of<'a>(model: &'a ContentModel<'a>, file_id: u64) -> Opening<'a> {
    let file = model.file(file_id).expect("golden file");
    Opening {
        // The identical supplier the model was assembled with (G14's fixture).
        s_root: SYNTHETIC_FINE_SEEDS.fine_seed(FileId(file_id)),
        domain: file.domain_bytes(),
        leaf_count: file.size(),
        fine_root: file.fine_root().expect("fine-tree-covered file"),
        descriptor: file.descriptor(),
        units: model.units_of(file_id),
    }
}

impl Opening<'_> {
    /// Open an arbitrary byte range and verify it against the committed root.
    fn open_range(&self, range: ByteRange) -> RangeProof {
        let proof = prove_range(&self.s_root, self.domain, range, self.leaf_count)
            .expect("range lies inside the file");
        proof
            .verify(self.revealed(range), self.fine_root)
            .expect("an honest opening must verify against the committed root");
        proof
    }

    /// The revealed bytes of `range` in this file's own byte domain.
    fn revealed(&self, range: ByteRange) -> &[u8] {
        let start = usize::try_from(range.start()).expect("fits usize");
        let end = usize::try_from(range.end().expect("no overflow")).expect("fits usize");
        &self.domain[start..end]
    }

    /// The wire form of a proof — the bytes a bundle would actually carry,
    /// and therefore the right granularity for "byte-identical".
    fn wire(proof: &RangeProof) -> WireForm {
        let nodes = |wire: Vec<super::fine_tree::WireNode<'_>>| {
            wire.into_iter()
                .map(|node| (node.level, node.index, node.bytes.to_vec()))
                .collect::<Vec<_>>()
        };
        WireForm {
            range: proof.range(),
            leaf_count: proof.leaf_count(),
            depth: proof.depth(),
            cover: nodes(proof.wire_cover()),
            boundary: nodes(proof.wire_boundary()),
        }
    }
}

/// One proof node exactly as F would encode it: `(level, index, bytes)`.
type WireTriple = (u8, u64, Vec<u8>);

/// Everything a bundle carries for one opening, in comparable form —
/// deliberately owned and structural, so equality is over the *content* of
/// the proof rather than over a struct that does not implement `PartialEq`.
#[derive(Debug, PartialEq, Eq)]
struct WireForm {
    range: ByteRange,
    leaf_count: u64,
    depth: u8,
    cover: Vec<WireTriple>,
    boundary: Vec<WireTriple>,
}

/// (a) Every covered unit of the golden work opens as a leaf-aligned range
/// and verifies against its file's committed `fine_root` — the text file's
/// three `--split` paragraphs and the binary file's whole-file unit, i.e.
/// both byte domains.
#[test]
fn per_unit_openings_verify_against_the_committed_fine_root() {
    let model = golden_model();
    let mut opened = 0;

    for file_id in [GOLDEN_FILE_TEXT_SPLIT, GOLDEN_FILE_BINARY] {
        let file = opening_of(&model, file_id);
        for unit in file.units {
            let Some(covered) = CoveredUnit::of(unit, file.descriptor) else {
                // The text file's raw mirror: not covered, so `prove_unit`
                // cannot even be called on it (spec lines 92, 94).
                assert!(requires_unit_commit(unit, file.descriptor));
                continue;
            };
            assert_eq!(covered.leaf_range(), unit.byte_range());

            let proof = prove_unit(&file.s_root, file.domain, covered, file.leaf_count)
                .expect("a covered unit is always in bounds");
            proof
                .verify(file.revealed(unit.byte_range()), file.fine_root)
                .expect("per-unit opening must verify");
            opened += 1;
        }
    }

    assert_eq!(opened, 4, "3 paragraphs + 1 whole binary file");
}

/// (b) Arbitrary, non-unit-aligned byte ranges open and verify — including
/// ranges **spanning a unit boundary**, which is the case that could only
/// work if `fine_root` alone commits the bytes.
///
/// The golden text file's units are `[0, 21)`, `[21, 28)`, `[28, 34)`, so the
/// ranges below are chosen relative to those two interior boundaries.
#[test]
fn arbitrary_byte_ranges_verify_including_across_unit_boundaries() {
    let model = golden_model();
    let text = opening_of(&model, GOLDEN_FILE_TEXT_SPLIT);
    assert_eq!(text.leaf_count, 34);
    let boundaries: Vec<u64> = text
        .units
        .iter()
        .filter_map(|unit: &Unit| unit.byte_range().end())
        .take(2)
        .collect();
    assert_eq!(boundaries, vec![21, 28], "the two interior unit boundaries");

    // Wholly inside one unit, aligned to nothing.
    text.open_range(ByteRange::new(5, 4));
    // Spanning the first boundary (21) — starts in unit 0, ends in unit 1.
    text.open_range(ByteRange::new(18, 7));
    // Spanning the second boundary (28).
    text.open_range(ByteRange::new(25, 6));
    // Spanning BOTH boundaries in one opening.
    text.open_range(ByteRange::new(19, 12));
    // Degenerate but legal: one byte, and one byte sitting exactly on a
    // boundary.
    text.open_range(ByteRange::new(0, 1));
    text.open_range(ByteRange::new(21, 1));
    text.open_range(ByteRange::new(33, 1));
    // The whole file — the full-reveal shape, where the cover is `s_root`.
    text.open_range(ByteRange::new(0, 34));

    // The binary file, in the raw domain, likewise opens at arbitrary offsets
    // even though it has exactly one unit.
    let binary = opening_of(&model, GOLDEN_FILE_BINARY);
    assert_eq!(binary.leaf_count, 9);
    binary.open_range(ByteRange::new(3, 2));
    binary.open_range(ByteRange::new(0, 9));
}

/// The per-unit opening and the byte-range opening over the **same span** are
/// the same object, wire byte for wire byte — one machinery, not two.
///
/// G12 already pins this at the primitive level
/// (`prove_unit_is_byte_identical_to_prove_range`); what is added here is
/// that it still holds when the span, seed, domain and leaf count all come
/// from an assembled model rather than from hand-written arguments.
#[test]
fn per_unit_and_byte_range_openings_are_identical_on_the_same_span() {
    let model = golden_model();

    for file_id in [GOLDEN_FILE_TEXT_SPLIT, GOLDEN_FILE_BINARY] {
        let file = opening_of(&model, file_id);
        for unit in file.units {
            let Some(covered) = CoveredUnit::of(unit, file.descriptor) else {
                continue;
            };
            let by_unit =
                prove_unit(&file.s_root, file.domain, covered, file.leaf_count).expect("in bounds");
            let by_range = file.open_range(unit.byte_range());

            assert_eq!(
                Opening::wire(&by_unit),
                Opening::wire(&by_range),
                "unit {} of file {file_id}",
                unit.unit_id()
            );
            // And both verdicts are Ok against the same committed root.
            by_unit
                .verify(file.revealed(unit.byte_range()), file.fine_root)
                .expect("per-unit verdict");
        }
    }
}

/// The model assertion G17 requires: **no covered unit carries a
/// `unit_commit`** — `fine_root` is the sole content commitment of covered
/// bytes (MVP-SPEC.md lines 94, 96).
///
/// Stated over the whole golden work, so the uncovered units (the raw mirror,
/// the `--no-fine-tree` file, the empty file) are asserted to be the *only*
/// commitment-carrying ones.
#[test]
fn no_covered_unit_carries_a_unit_commit() {
    let model = golden_model();
    let mut covered = 0;
    let mut committing = Vec::new();

    for unit in model.units() {
        let file = model.file(unit.file_id()).expect("unit belongs to a file");
        let needs_commit = requires_unit_commit(unit, file.descriptor());
        assert_ne!(
            needs_commit,
            model.is_covered(unit),
            "unit {} — presence must be exactly the negation of coverage",
            unit.unit_id()
        );
        if model.is_covered(unit) {
            covered += 1;
            assert!(
                file.fine_root().is_some(),
                "unit {} is covered, so its file must commit a fine_root",
                unit.unit_id()
            );
        } else {
            committing.push(unit.unit_id());
        }
    }

    assert_eq!(
        covered, 4,
        "3 paragraphs + the binary file's whole-file unit"
    );
    assert_eq!(
        committing,
        vec![3, 5, 6],
        "only the raw mirror, the --no-fine-tree file and the empty file"
    );
    // And those three files are exactly the ones with no fine tree to be the
    // sole commitment (the empty and opted-out files); the mirror's file has
    // one, but the mirror lives in the other byte domain.
    for file_id in [GOLDEN_FILE_NO_FINE_TREE, GOLDEN_FILE_EMPTY] {
        assert_eq!(model.file(file_id).expect("golden file").fine_root(), None);
    }
}

/// Negative controls — without these the tests above would pass on a
/// verifier that returned `Ok` unconditionally.
#[test]
fn openings_do_not_verify_against_the_wrong_bytes_or_the_wrong_root() {
    let model = golden_model();
    let text = opening_of(&model, GOLDEN_FILE_TEXT_SPLIT);
    let binary = opening_of(&model, GOLDEN_FILE_BINARY);

    let range = ByteRange::new(18, 7);
    let proof = text.open_range(range);

    // Wrong revealed bytes for the right range.
    let mut mutated = text.revealed(range).to_vec();
    mutated[0] ^= 0x01;
    assert!(
        proof.verify(&mutated, text.fine_root).is_err(),
        "flipped content must not verify"
    );

    // Right bytes, wrong file's root.
    assert!(
        proof
            .verify(text.revealed(range), binary.fine_root)
            .is_err(),
        "a proof must not verify against another file's fine_root"
    );

    // Right bytes and root, wrong length claim.
    assert!(
        proof
            .verify(&text.revealed(range)[..6], text.fine_root)
            .is_err(),
        "a short reveal must not verify"
    );
}
