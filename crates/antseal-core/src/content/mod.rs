//! The content model (tasks/G.md) — how a work's files are described,
//! divided into units, and salted for byte-range commitment.
//!
//! Everything here is pure, deterministic, allocation-bounded, and WASM-safe:
//! no I/O, no clocks, no randomness. Bytes arrive from the caller (S reads
//! files; R reads bundles), decisions come back.
//!
//! Module layout:
//!
//! - [`descriptor`] (G4) — the per-file canonicalization descriptor: kind,
//!   fine-tree presence, its byte domain, and the frozen Unicode data version
//!   (MVP-SPEC.md line 83), with the seal-time decision logic and the
//!   decode-time cross-field validation predicate.
//! - [`unit`](mod@unit) (G5) — the unit model: work-global `unit_id` assignment in
//!   manifest order (MVP-SPEC.md line 76), the file-table `size` semantics
//!   (line 98), and the `is_fine_tree_covered` predicate that decides whether a
//!   unit carries its own `unit_commit` (line 94).
//! - [`split`] (G6, decision D22) — `--split blank-lines`: the frozen
//!   blank-line paragraph-boundary semantics, over canonical bytes so the
//!   result is platform-stable (MVP-SPEC.md line 84).
//! - [`mirror`] (G7, decision D23) — the raw mirror: when a text file needs
//!   one, how its entry is built, the `kind`-based tiling/concatenation
//!   exemptions, and the rule that a mirror is never selectable by a bare
//!   `--units` id (MVP-SPEC.md line 92).
//! - [`ggm`] (G8) — the GGM salt tree: `s_root` → per-leaf 16-byte salts over a
//!   complete depth-`d` dyadic grid, with the canonical node-address type
//!   shared by covers and boundary paths (MVP-SPEC.md line 96).
//! - [`error`] — the `content-`-coded error taxonomy these share.
//!
//! # Where the boundaries are
//!
//! - **C** supplies the inputs: `s_root = HKDF(W, "fine-seed", file_id)`, the
//!   `0x06` domain tag, and the SHA-256 primitive. This module never derives
//!   from `W` itself.
//! - **F** owns every wire encoding. The semantic field sets and their legality
//!   rules live here; the CBOR spellings live in
//!   `docs/format/registry-v1.md`.
//! - **R** owns verdicts. This module supplies predicates and distinct errors;
//!   it never decides that a bundle is invalid.

pub mod descriptor;
pub mod error;
pub mod ggm;
pub mod mirror;
pub mod split;
pub mod unit;

pub use descriptor::{CanonDescriptor, ContentKind, FileKind, FineTreeDomain, FineTreeOptOut};
pub use error::ContentError;
pub use ggm::{ChildBit, NodeAddress, SaltTree, child_seed, depth_for_leaf_count};
pub use mirror::{
    RevealSelection, full_reveal_concat_exempt, mirror_selectable, needs_mirror, tiling_exempt,
    unit_selectable, with_raw_mirror_if_needed,
};
pub use split::{is_blank_line, plan_blank_line_split, split_blank_lines};
pub use unit::{
    ByteRange, FileLengths, FileUnitPlan, SplitEligibleText, Unit, UnitKind, assign_unit_ids,
    is_fine_tree_covered, requires_unit_commit,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::{TextMode, UnicodeVersion, canonicalize};
    use crate::crypto::hkdf::{FileId, derive_fine_seed};
    use crate::crypto::material::MasterSecretRef;
    use crate::test_util::TEST_MASTER_SECRET_W;

    /// Worked example pinning how G2 → G4 → G5 → G8 compose for a real
    /// two-file work — the sequence G14's assembly performs. It exists to
    /// catch drift *between* the three layers, which their own unit tests
    /// cannot see.
    ///
    /// File 0: CRLF text (raw != canonical, so it gets a raw mirror).
    /// File 1: binary.
    #[test]
    fn worked_example_text_with_mirror_plus_binary() {
        // ── G2: canonicalize the text file ──────────────────────────────
        let raw_text = b"a\r\nb\r\n";
        let canonical = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, raw_text)
            .expect("valid UTF-8");
        assert_eq!(canonical.as_str(), "a\nb\n");

        let text_lengths = FileLengths::Text {
            canonical: u64::try_from(canonical.len()).expect("fits u64"),
            raw: u64::try_from(raw_text.len()).expect("fits u64"),
        };
        let binary_lengths = FileLengths::Binary { raw: 9 };

        // ── G5: the `size` field is stated in each file's own domain ────
        assert_eq!(text_lengths.size_field(), 4, "canonical count, not 6");
        assert_eq!(text_lengths.raw(), 6);
        assert_eq!(binary_lengths.size_field(), 9);

        // ── G4: descriptors ─────────────────────────────────────────────
        let text_desc = CanonDescriptor::describe_file(
            ContentKind::Text(UnicodeVersion::CURRENT),
            text_lengths.size_field(),
            FineTreeOptOut::NotRequested,
        );
        let binary_desc = CanonDescriptor::describe_file(
            ContentKind::Binary,
            binary_lengths.size_field(),
            FineTreeOptOut::NotRequested,
        );
        assert_eq!(
            text_desc.validate_with_size(text_lengths.size_field()),
            Ok(())
        );
        assert_eq!(
            binary_desc.validate_with_size(binary_lengths.size_field()),
            Ok(())
        );
        assert_eq!(
            text_desc.fine_tree_domain(),
            Some(FineTreeDomain::Canonical)
        );
        assert_eq!(binary_desc.fine_tree_domain(), Some(FineTreeDomain::Raw));
        assert_eq!(
            text_desc.resolve_unicode_version(),
            Ok(Some(UnicodeVersion::CURRENT))
        );
        assert_eq!(binary_desc.resolve_unicode_version(), Ok(None));

        // ── G5: units, work-global ids, mirror last (D23) ───────────────
        let raw_differs = canonical.as_bytes() != raw_text.as_slice();
        assert!(raw_differs, "CRLF text needs a mirror (G7's predicate)");
        let plans = [
            FileUnitPlan::whole_file(text_lengths.size_field()).with_raw_mirror(text_lengths.raw()),
            FileUnitPlan::whole_file(binary_lengths.size_field()),
        ];
        let units = assign_unit_ids(&plans);
        assert_eq!(units.len(), 3);

        // unit 0: the text file's canonical-domain content unit.
        assert_eq!(units[0].unit_id(), 0);
        assert_eq!(units[0].file_id(), 0);
        assert_eq!(units[0].kind(), UnitKind::Normal);
        assert_eq!(units[0].byte_range(), ByteRange::new(0, 4));
        assert!(is_fine_tree_covered(&units[0], &text_desc));
        assert!(!requires_unit_commit(&units[0], &text_desc));

        // unit 1: the raw mirror — file 0's LAST unit, raw domain, and never
        // covered, so it carries a unit_commit (spec lines 92, 94).
        assert_eq!(units[1].unit_id(), 1);
        assert_eq!(units[1].file_id(), 0);
        assert_eq!(units[1].kind(), UnitKind::RawMirror);
        assert_eq!(units[1].byte_range(), ByteRange::new(0, 6));
        assert_eq!(units[1].true_length(), 6, "the raw byte count lives here");
        assert!(!is_fine_tree_covered(&units[1], &text_desc));
        assert!(requires_unit_commit(&units[1], &text_desc));

        // unit 2: the binary file — the counter did NOT restart (spec line 76).
        assert_eq!(units[2].unit_id(), 2);
        assert_eq!(units[2].file_id(), 1);
        assert_eq!(units[2].byte_range(), ByteRange::new(0, 9));
        assert!(is_fine_tree_covered(&units[2], &binary_desc));

        // ── G8: the salt tree spans the `size` field, not the raw bytes ──
        let w = MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W);
        let s_root = derive_fine_seed(w, FileId(0));
        let tree = SaltTree::new(&s_root, text_lengths.size_field()).expect("n = 4");
        assert_eq!(tree.leaf_count(), 4, "canonical bytes are the leaves");
        assert_eq!(tree.depth(), 2);
        assert!(
            tree.salt(3).is_some() && tree.salt(4).is_none(),
            "the tree stops at the canonical length, not the raw length"
        );

        // Per-byte salts are all distinct — one salt per canonical byte.
        let salts: std::collections::BTreeSet<[u8; 16]> = (0..tree.leaf_count())
            .map(|i| *tree.salt(i).expect("in range").as_bytes())
            .collect();
        assert_eq!(salts.len(), 4);
    }

    /// A `--no-fine-tree` file composes to exactly one whole-file unit that
    /// carries a `unit_commit`, with no salt tree at all — the "permanently
    /// whole-file-reveal-only" shape (MVP-SPEC.md lines 85, 94) without any
    /// extra predicate.
    #[test]
    fn worked_example_no_fine_tree_file() {
        let descriptor = CanonDescriptor::describe_file(
            ContentKind::Text(UnicodeVersion::CURRENT),
            1_000,
            FineTreeOptOut::Requested,
        );
        assert!(!descriptor.fine_tree_present());
        assert!(
            SplitEligibleText::of(&descriptor).is_none(),
            "no split path"
        );

        let units = assign_unit_ids(&[FileUnitPlan::whole_file(1_000)]);
        assert_eq!(units.len(), 1);
        assert!(requires_unit_commit(&units[0], &descriptor));

        // No fine tree ⇒ nothing derives a salt for it; the file's `s_root`
        // is simply never used.
        assert_eq!(depth_for_leaf_count(0), None);
    }
}
