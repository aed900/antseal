//! The unit model (tasks/G.md G5) — reveal granularity, work-global
//! `unit_id` assignment, file-table `size` semantics, and the predicate that
//! decides which units carry their own `unit_commit`.
//!
//! A **unit** is the MVP's reveal granularity (MVP-SPEC.md line 84): by default
//! one unit per file, `--split blank-lines` splits text files on paragraph
//! boundaries (G6), and binary files are always single-unit. A file whose raw
//! bytes differ from its canonical rendition additionally carries a
//! **raw-mirror** unit (G7; MVP-SPEC.md line 92).
//!
//! # Work-global ids (MVP-SPEC.md line 76)
//!
//! `unit_id` is a **work-global LE64 ordinal in manifest order** — not
//! file-scoped. This is security-critical, not cosmetic: `k_u`, `unit_salt`,
//! and the AEAD AAD all derive from `unit_id`, so file-scoped numbering would
//! silently derive **identical keys and salts** for the first unit of every
//! file. [`assign_unit_ids`] is the single implementation of that numbering.
//!
//! # Per-file order is frozen (decision D23)
//!
//! Within each file: all normal units first in ascending byte-range order (so
//! id order and range order agree), then the raw-mirror entry — if present —
//! **last**. At most one mirror per file. The global counter walks files in
//! manifest order and units in that per-file order, assigning strictly
//! increasing ordinals with no gaps.
//!
//! # `--no-fine-tree` x `--split` is unrepresentable (decision D24)
//!
//! A `--no-fine-tree` file is permanently whole-file-reveal-only, hence exactly
//! one unit. The model does not *check* that a `--no-fine-tree` file was not
//! split — it cannot express it: sub-file ranges are reachable only through
//! [`FileUnitPlan::split`], which requires a [`SplitEligibleText`] witness that
//! only a fine-tree-covered **text** descriptor can produce. The matching hard
//! CLI error (naming the file and both flags) is U's, per D24.
//!
//! # Byte domains and `size`
//!
//! Byte ranges are offsets into the file's own tiling domain: **canonical**
//! bytes for text, **raw** bytes for binary (MVP-SPEC.md line 83). The
//! file-table `size` field is the leaf count in that same domain — the
//! canonical byte count for text, the raw byte count for binary
//! ([`FileLengths::size_field`]; line 98). A text file's *raw* byte count is
//! deliberately **not** a file-table field: it travels only as its raw-mirror
//! unit's `true_length` (lines 92, 98).
//!
//! Every wire-facing quantity here is a `u64`, matching the `uint` encodings F
//! registers.

use super::descriptor::{CanonDescriptor, FileKind, FineTreeDomain};

/// A unit's byte range in its file's byte domain, as `[start, length)`
/// (`docs/format/registry-v1.md` §4).
///
/// Stored as start + **length**, not start + end: every consumer wants the
/// width (`true_length`, the `padded_length` input, the covered leaf count), so
/// width is a field rather than a subtraction, and the degenerate `end < start`
/// state cannot be written at all.
///
/// The [`Ord`] derive is lexicographic on `(start, length)` — the ascending
/// order [`assign_unit_ids`] puts normal units in (D23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ByteRange {
    start: u64,
    length: u64,
}

impl ByteRange {
    /// A range of `length` bytes starting at `start`.
    #[must_use]
    pub const fn new(start: u64, length: u64) -> Self {
        Self { start, length }
    }

    /// The empty range at offset 0 — the sole unit of an empty file
    /// (MVP-SPEC.md line 78).
    #[must_use]
    pub const fn empty() -> Self {
        Self::new(0, 0)
    }

    /// First byte offset covered.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Width in bytes — a normal unit's `true_length` (MVP-SPEC.md line 121).
    #[must_use]
    pub const fn length(self) -> u64 {
        self.length
    }

    /// Exclusive end offset, `None` on `u64` overflow.
    ///
    /// Overflow is only reachable from hostile wire values (a real file cannot
    /// span past `u64::MAX`), and the registry records the checked-arithmetic
    /// requirement wherever the exclusive end is formed
    /// (`docs/format/registry-v1.md` §4). Returning `Option` keeps R's tiling
    /// check and G's cover derivation panic-free by construction.
    #[must_use]
    pub const fn end(self) -> Option<u64> {
        self.start.checked_add(self.length)
    }

    /// `true` for a zero-width range.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.length == 0
    }
}

/// A unit's kind (MVP-SPEC.md lines 92, 98).
///
/// Raw-mirror units are ordinary unit-table entries distinguished **only** by
/// this field — there is no separate link field — and it is their *kind*, not
/// their position, that exempts them from the per-file tiling invariant and
/// from full-reveal concatenation (G7 owns those predicates).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnitKind {
    /// A normal content unit, in the file's tiling domain (canonical bytes for
    /// text, raw bytes for binary).
    Normal,
    /// The raw mirror: the whole original file in the **raw** byte domain,
    /// carried so a text file's exact original bytes reach storage and
    /// `raw_commit` stays openable (MVP-SPEC.md line 92).
    RawMirror,
}

impl UnitKind {
    /// Both kinds, for truth-table tests.
    pub const ALL: [Self; 2] = [Self::Normal, Self::RawMirror];
}

/// One unit-table entry's structural fields (MVP-SPEC.md line 98).
///
/// Deliberately carries **only** the model's own quantities. The cryptographic
/// fields of the wire entry — `unit_commit`, nonce, ciphertext address — belong
/// to C/S and are attached at assembly (G14); keeping them out of this type is
/// what lets the whole unit model be tested with no key material in sight
/// (project rule 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Unit {
    unit_id: u64,
    file_id: u64,
    kind: UnitKind,
    byte_range: ByteRange,
    true_length: u64,
}

impl Unit {
    /// **Seal side.** A unit whose `true_length` is its byte-range width — the
    /// model rule for every unit, mirror included (MVP-SPEC.md lines 98, 121;
    /// `docs/format/registry-v1.md` §4).
    #[must_use]
    pub const fn new(unit_id: u64, file_id: u64, kind: UnitKind, byte_range: ByteRange) -> Self {
        Self {
            unit_id,
            file_id,
            kind,
            byte_range,
            true_length: byte_range.length(),
        }
    }

    /// **Decode side.** A unit with `true_length` taken as received, so a
    /// manifest whose `true_length` disagrees with its byte-range width is
    /// *representable* — that mismatch is a required tamper-matrix row
    /// (MVP-SPEC.md line 168) and R must be able to see it and reject it with
    /// its own error. Check it with [`Self::true_length_matches_range`].
    #[must_use]
    pub const fn from_wire_fields(
        unit_id: u64,
        file_id: u64,
        kind: UnitKind,
        byte_range: ByteRange,
        true_length: u64,
    ) -> Self {
        Self {
            unit_id,
            file_id,
            kind,
            byte_range,
            true_length,
        }
    }

    /// Work-global ordinal in manifest order (MVP-SPEC.md line 76) — the id
    /// `k_u`/`unit_salt`/AAD derive from and the id `reveal --units` takes.
    #[must_use]
    pub const fn unit_id(self) -> u64 {
        self.unit_id
    }

    /// Index of the owning file in the manifest file table (MVP-SPEC.md
    /// line 76).
    #[must_use]
    pub const fn file_id(self) -> u64 {
        self.file_id
    }

    /// Normal or raw-mirror (MVP-SPEC.md line 92).
    #[must_use]
    pub const fn kind(self) -> UnitKind {
        self.kind
    }

    /// The unit's byte range in its domain.
    #[must_use]
    pub const fn byte_range(self) -> ByteRange {
        self.byte_range
    }

    /// Pre-padding plaintext length (MVP-SPEC.md lines 91, 98).
    #[must_use]
    pub const fn true_length(self) -> u64 {
        self.true_length
    }

    /// Whether `true_length` equals the byte-range width — R's structural
    /// invariant (MVP-SPEC.md line 121), true by construction for units built
    /// with [`Self::new`].
    #[must_use]
    pub const fn true_length_matches_range(self) -> bool {
        self.true_length == self.byte_range.length()
    }
}

/// A source file's byte counts in both domains, and the rule that picks the
/// file-table `size` field from them (MVP-SPEC.md line 98).
///
/// The `size` field is the file's **leaf count** and the bound of its unit
/// tiling, so it must be stated in exactly one domain. This type is that
/// statement: a text file's raw byte count exists here for the raw-mirror
/// entry's `true_length` and is *not* what `size` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileLengths {
    /// A text file: the canonical rendition's byte count (its tiling and leaf
    /// domain) plus the original raw byte count.
    Text {
        /// Byte length of the canonical rendition — the `size` field.
        canonical: u64,
        /// Byte length of the original file — carried by the raw mirror, if
        /// one exists (MVP-SPEC.md line 92).
        raw: u64,
    },
    /// A binary file: raw bytes only — there is no canonical rendition
    /// (MVP-SPEC.md line 83).
    Binary {
        /// Byte length of the file — the `size` field.
        raw: u64,
    },
}

impl FileLengths {
    /// The file-table `size` field: **canonical** byte count for text,
    /// **raw** byte count for binary (MVP-SPEC.md line 98). Also the fine
    /// tree's leaf count `n` and the exclusive bound of the file's unit tiling.
    #[must_use]
    pub const fn size_field(self) -> u64 {
        match self {
            Self::Text { canonical, .. } => canonical,
            Self::Binary { raw } => raw,
        }
    }

    /// The original file's byte count. For text this is *not* the `size` field:
    /// it reaches the manifest only as the raw-mirror unit's `true_length`
    /// (MVP-SPEC.md lines 92, 98).
    #[must_use]
    pub const fn raw(self) -> u64 {
        match self {
            Self::Text { raw, .. } | Self::Binary { raw } => raw,
        }
    }

    /// The descriptor kind these lengths belong to.
    #[must_use]
    pub const fn file_kind(self) -> FileKind {
        match self {
            Self::Text { .. } => FileKind::Text,
            Self::Binary { .. } => FileKind::Binary,
        }
    }

    /// The byte domain `size` and every unit range of this file are stated in
    /// (MVP-SPEC.md line 83).
    #[must_use]
    pub const fn tiling_domain(self) -> FineTreeDomain {
        self.file_kind().fine_tree_domain()
    }
}

/// Witness that a file may carry **sub-file units**: its descriptor says
/// `kind = text` *and* a fine tree is present.
///
/// This type is how decision D24 becomes structural. [`FileUnitPlan::split`]
/// takes it by value, so there is no code path anywhere that splits a
/// `--no-fine-tree` file (or a binary file, which is always single-unit —
/// MVP-SPEC.md line 84): the contradiction is not rejected at runtime, it
/// cannot be written. The corresponding user-facing hard error at
/// `--no-fine-tree` x `--split` is U's, by the same decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitEligibleText(());

impl SplitEligibleText {
    /// `Some` iff `descriptor` is text **and** fine-tree-covered.
    ///
    /// `None` is not an error: it is the ordinary answer for binary files and
    /// for `--no-fine-tree` files, both of which are single-unit by the model
    /// (MVP-SPEC.md lines 84, 85).
    #[must_use]
    pub const fn of(descriptor: &CanonDescriptor) -> Option<Self> {
        if descriptor.fine_tree_present() && matches!(descriptor.kind(), FileKind::Text) {
            Some(Self(()))
        } else {
            None
        }
    }
}

/// One file's unit layout, in the frozen D23 order: normal units, then the
/// raw mirror if present.
///
/// Built seal-side and consumed by [`assign_unit_ids`]. The normal-unit list is
/// never empty — an empty file is one empty unit (MVP-SPEC.md line 78).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileUnitPlan {
    /// Never empty. Sorted ascending by [`assign_unit_ids`], so callers need
    /// not pre-sort.
    normal: Vec<ByteRange>,
    /// `Some(raw_size)` iff this file has a raw mirror (G7's `needs_mirror`).
    mirror_raw_size: Option<u64>,
}

impl FileUnitPlan {
    /// The default layout: exactly one unit spanning `[0, size)`
    /// (MVP-SPEC.md line 84).
    ///
    /// This is also the **only** layout available to binary files (line 84) and
    /// to `--no-fine-tree` files (line 85 / D24), and the empty-file layout —
    /// `whole_file(0)` is the single `[0, 0)` unit of line 78.
    #[must_use]
    pub fn whole_file(size: u64) -> Self {
        Self {
            normal: vec![ByteRange::new(0, size)],
            mirror_raw_size: None,
        }
    }

    /// Sub-file units from `--split blank-lines` (G6).
    ///
    /// Requires a [`SplitEligibleText`] witness — see that type for why (D24).
    /// `ranges` are G6's output: sorted, non-overlapping, exactly tiling
    /// `[0, canonical_len)`; [`assign_unit_ids`] sorts them regardless so id
    /// order always equals range order (D23), and R re-checks the tiling
    /// itself (MVP-SPEC.md line 121).
    ///
    /// An empty `ranges` list yields the single empty unit of MVP-SPEC.md
    /// line 78 rather than a unit-less file, which the format does not allow.
    #[must_use]
    pub fn split(_eligible: SplitEligibleText, ranges: Vec<ByteRange>) -> Self {
        let normal = if ranges.is_empty() {
            vec![ByteRange::empty()]
        } else {
            ranges
        };
        Self {
            normal,
            mirror_raw_size: None,
        }
    }

    /// Attach this file's raw mirror, spanning `[0, raw_size)` in the **raw**
    /// byte domain with `true_length = raw_size` (MVP-SPEC.md line 92).
    ///
    /// The mirror becomes the file's **last** unit (D23). Calling this twice
    /// replaces the previous mirror — at most one mirror per file, by
    /// construction.
    #[must_use]
    pub fn with_raw_mirror(mut self, raw_size: u64) -> Self {
        self.mirror_raw_size = Some(raw_size);
        self
    }

    /// The file's normal (non-mirror) unit ranges, as supplied.
    #[must_use]
    pub fn normal_ranges(&self) -> &[ByteRange] {
        &self.normal
    }

    /// The raw mirror's size, if this file has one.
    #[must_use]
    pub const fn mirror_raw_size(&self) -> Option<u64> {
        self.mirror_raw_size
    }

    /// Total units this file contributes, mirror included.
    #[must_use]
    pub const fn unit_count(&self) -> usize {
        self.normal.len() + if self.mirror_raw_size.is_some() { 1 } else { 0 }
    }
}

/// Assign work-global `unit_id`s across a work's files (MVP-SPEC.md line 76;
/// decision D23).
///
/// `plans[i]` is the plan for the file at file-table index `i`, so `file_id`
/// comes from position and cannot be mis-stated. One counter walks:
///
/// 1. files in manifest order;
/// 2. within a file, normal units **ascending by byte range** (the list is
///    sorted here, so id order equals range order however the caller supplied
///    it);
/// 3. then the raw mirror, if any, **last** (D23).
///
/// Ids are strictly increasing with no gaps, starting at 0. Every returned unit
/// has `true_length` equal to its range width ([`Unit::new`]).
///
/// The counter cannot overflow: each increment corresponds to one `Unit` in the
/// returned `Vec`, so the count is bounded by `usize::MAX`, and allocation
/// fails long before `u64::MAX` units exist.
#[must_use]
pub fn assign_unit_ids(plans: &[FileUnitPlan]) -> Vec<Unit> {
    let total: usize = plans.iter().map(FileUnitPlan::unit_count).sum();
    let mut units = Vec::with_capacity(total);
    let mut next_id: u64 = 0;

    // `file_id` is the plan's position in the file table (spec line 76), so it
    // is counted alongside rather than passed in.
    for (file_id, plan) in (0u64..).zip(plans) {
        // D23 step 2: id order == range order, established here rather than
        // assumed of the caller.
        let mut ranges = plan.normal.clone();
        ranges.sort_unstable();
        for range in ranges {
            units.push(Unit::new(next_id, file_id, UnitKind::Normal, range));
            next_id += 1;
        }
        // D23 step 3: the mirror is the file's last unit, in the raw domain.
        if let Some(raw_size) = plan.mirror_raw_size {
            units.push(Unit::new(
                next_id,
                file_id,
                UnitKind::RawMirror,
                ByteRange::new(0, raw_size),
            ));
            next_id += 1;
        }
    }

    debug_assert_eq!(units.len(), total, "unit count must match the plans");
    units
}

/// Whether a unit's bytes are committed by its file's `fine_root`
/// (MVP-SPEC.md lines 94, 96): `true` iff the file has a fine tree **and** the
/// unit is a normal unit.
///
/// A raw mirror is never covered — the canonical fine tree does not reach the
/// raw byte domain (MVP-SPEC.md line 92) — and a `--no-fine-tree` file has no
/// tree at all.
///
/// This predicate drives the normative presence rule for `unit_commit`; see
/// [`requires_unit_commit`].
#[must_use]
pub const fn is_fine_tree_covered(unit: &Unit, descriptor: &CanonDescriptor) -> bool {
    descriptor.fine_tree_present() && matches!(unit.kind(), UnitKind::Normal)
}

/// Whether a unit carries its own `unit_commit`: **present iff the unit is NOT
/// fine-tree-covered** (MVP-SPEC.md line 94) — i.e. exactly the negation of
/// [`is_fine_tree_covered`].
///
/// The rule is a security property, not bookkeeping. For a covered unit,
/// `fine_root` is the *sole* content commitment: committing the same bytes
/// under two independent salted hashes would let a malicious sealer open byte
/// `i` to X via `unit_commit` for one counterparty and to Y != X via a range
/// proof for another, under one anchored `work_id` — a break of "proof it
/// belongs to what you sealed", frozen unfixably at M0 (MVP-SPEC.md line 94).
#[must_use]
pub const fn requires_unit_commit(unit: &Unit, descriptor: &CanonDescriptor) -> bool {
    !is_fine_tree_covered(unit, descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::UnicodeVersion;
    use crate::content::descriptor::{ContentKind, FineTreeOptOut};
    use crate::test_util::strategies::proptest_config;
    use proptest::prelude::*;

    fn text_desc(size: u64, opt_out: FineTreeOptOut) -> CanonDescriptor {
        CanonDescriptor::describe_file(ContentKind::Text(UnicodeVersion::CURRENT), size, opt_out)
    }

    fn binary_desc(size: u64, opt_out: FineTreeOptOut) -> CanonDescriptor {
        CanonDescriptor::describe_file(ContentKind::Binary, size, opt_out)
    }

    fn ranges(spans: &[(u64, u64)]) -> Vec<ByteRange> {
        spans
            .iter()
            .map(|&(start, length)| ByteRange::new(start, length))
            .collect()
    }

    /// Build a split plan for a text file, asserting the witness exists.
    fn split_plan(size: u64, spans: &[(u64, u64)]) -> FileUnitPlan {
        let descriptor = text_desc(size, FineTreeOptOut::NotRequested);
        let eligible =
            SplitEligibleText::of(&descriptor).expect("covered text file is split-eligible");
        FileUnitPlan::split(eligible, ranges(spans))
    }

    // ── Work-global id assignment (G5 accept) ───────────────────────────

    /// G5 accept, the file-scoped-numbering hazard (MVP-SPEC.md line 76): two
    /// files each with multiple units get globally unique, strictly increasing
    /// `unit_id`s **across** files. File-scoped numbering would restart at 0
    /// per file and derive identical `k_u`/`unit_salt` for each file's first
    /// unit — this test is the regression guard for that.
    #[test]
    fn unit_ids_are_work_global_and_strictly_increasing_across_files() {
        let plans = [
            split_plan(30, &[(0, 10), (10, 10), (20, 10)]),
            split_plan(25, &[(0, 5), (5, 20)]),
        ];
        let units = assign_unit_ids(&plans);

        assert_eq!(units.len(), 5);
        let ids: Vec<u64> = units.iter().map(|u| u.unit_id()).collect();
        assert_eq!(ids, [0, 1, 2, 3, 4], "no restart at the file boundary");
        let file_ids: Vec<u64> = units.iter().map(|u| u.file_id()).collect();
        assert_eq!(file_ids, [0, 0, 0, 1, 1]);

        // Strictly increasing, no gaps, globally unique.
        for pair in ids.windows(2) {
            assert!(pair[1] > pair[0], "ids must strictly increase: {ids:?}");
        }
        let unique: std::collections::BTreeSet<u64> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len());
    }

    /// D23: within a file, normal units come first in ascending range order and
    /// the raw mirror is the file's **last** unit; the global counter then
    /// continues into the next file's units.
    #[test]
    fn raw_mirror_is_the_files_last_unit_and_ids_interleave() {
        let plans = [
            split_plan(20, &[(0, 8), (8, 12)]).with_raw_mirror(22),
            FileUnitPlan::whole_file(7),
            split_plan(9, &[(0, 4), (4, 5)]).with_raw_mirror(11),
        ];
        let units = assign_unit_ids(&plans);

        let shape: Vec<(u64, u64, UnitKind, u64, u64, u64)> = units
            .iter()
            .map(|u| {
                (
                    u.unit_id(),
                    u.file_id(),
                    u.kind(),
                    u.byte_range().start(),
                    u.byte_range().length(),
                    u.true_length(),
                )
            })
            .collect();
        assert_eq!(
            shape,
            vec![
                (0, 0, UnitKind::Normal, 0, 8, 8),
                (1, 0, UnitKind::Normal, 8, 12, 12),
                (2, 0, UnitKind::RawMirror, 0, 22, 22), // mirror last in file 0
                (3, 1, UnitKind::Normal, 0, 7, 7),
                (4, 2, UnitKind::Normal, 0, 4, 4),
                (5, 2, UnitKind::Normal, 4, 5, 5),
                (6, 2, UnitKind::RawMirror, 0, 11, 11), // mirror last in file 2
            ]
        );
    }

    /// Id order equals range order even if the caller supplies ranges out of
    /// order (D23 rule 1 is established by the assignment, not assumed).
    #[test]
    fn normal_units_are_ordered_by_range_regardless_of_input_order() {
        let plan = split_plan(30, &[(20, 10), (0, 10), (10, 10)]);
        let units = assign_unit_ids(&[plan]);
        let starts: Vec<u64> = units.iter().map(|u| u.byte_range().start()).collect();
        assert_eq!(starts, [0, 10, 20]);
        let ids: Vec<u64> = units.iter().map(|u| u.unit_id()).collect();
        assert_eq!(ids, [0, 1, 2]);
    }

    /// An empty work (no files) assigns nothing; a work of empty files still
    /// numbers one unit each.
    #[test]
    fn assignment_edge_cases() {
        assert!(assign_unit_ids(&[]).is_empty());
        let units = assign_unit_ids(&[FileUnitPlan::whole_file(0), FileUnitPlan::whole_file(0)]);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].unit_id(), 0);
        assert_eq!(units[1].unit_id(), 1);
        assert_eq!(units[1].file_id(), 1);
    }

    // ── Model rules (G5 accept) ─────────────────────────────────────────

    /// G5 accept: an empty file is exactly one unit, `[0, 0)`, `true_length` 0
    /// (MVP-SPEC.md line 78).
    #[test]
    fn empty_file_is_one_empty_unit() {
        let units = assign_unit_ids(&[FileUnitPlan::whole_file(0)]);
        assert_eq!(units.len(), 1);
        let unit = units[0];
        assert_eq!(unit.kind(), UnitKind::Normal);
        assert_eq!(unit.byte_range(), ByteRange::new(0, 0));
        assert_eq!(unit.byte_range().start(), 0);
        assert_eq!(unit.byte_range().length(), 0);
        assert_eq!(unit.byte_range().end(), Some(0));
        assert!(unit.byte_range().is_empty());
        assert_eq!(unit.true_length(), 0);
        assert!(unit.true_length_matches_range());
    }

    /// The default is one unit per file, and it spans the whole file
    /// (MVP-SPEC.md line 84) — the shape binary files and `--no-fine-tree`
    /// files are restricted to.
    #[test]
    fn default_layout_is_one_whole_file_unit() {
        let plan = FileUnitPlan::whole_file(1234);
        assert_eq!(plan.unit_count(), 1);
        assert_eq!(plan.normal_ranges(), &[ByteRange::new(0, 1234)]);
        assert_eq!(plan.mirror_raw_size(), None);
    }

    /// D24, structural: binary files and `--no-fine-tree` files cannot produce
    /// a split witness, so no split path exists for them. (The compile-time
    /// half is that [`FileUnitPlan::split`] takes the witness by value; the
    /// runtime half is this: the witness is unobtainable.)
    #[test]
    fn only_covered_text_files_are_split_eligible() {
        // Covered text: eligible.
        assert!(SplitEligibleText::of(&text_desc(100, FineTreeOptOut::NotRequested)).is_some());
        // Binary, even with a fine tree: never split (MVP-SPEC.md line 84).
        assert!(SplitEligibleText::of(&binary_desc(100, FineTreeOptOut::NotRequested)).is_none());
        // `--no-fine-tree` text: no tree, hence whole-file only (D24).
        assert!(SplitEligibleText::of(&text_desc(100, FineTreeOptOut::Requested)).is_none());
        // Empty text file: no tree either, hence one whole-file unit.
        assert!(SplitEligibleText::of(&text_desc(0, FineTreeOptOut::NotRequested)).is_none());
        // Binary + opt-out: still none.
        assert!(SplitEligibleText::of(&binary_desc(100, FineTreeOptOut::Requested)).is_none());
    }

    /// A `--no-fine-tree` file is exactly one whole-file unit, which is what
    /// makes it "permanently whole-file-reveal-only" with no extra predicate
    /// (MVP-SPEC.md line 85).
    #[test]
    fn no_fine_tree_file_is_a_single_whole_file_unit() {
        let descriptor = text_desc(500, FineTreeOptOut::Requested);
        assert!(!descriptor.fine_tree_present());
        let units = assign_unit_ids(&[FileUnitPlan::whole_file(500)]);
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].byte_range(), ByteRange::new(0, 500));
        // Its one unit is not covered, so it carries a unit_commit.
        assert!(!is_fine_tree_covered(&units[0], &descriptor));
        assert!(requires_unit_commit(&units[0], &descriptor));
    }

    /// An empty split list still yields the one empty unit the format requires
    /// (MVP-SPEC.md line 78) — a unit-less file is unrepresentable.
    #[test]
    fn split_never_yields_a_unitless_file() {
        // The witness needs a covered (hence non-empty) text file; the empty
        // range list is the defensive case G6 never actually produces.
        let plan = split_plan(10, &[]);
        assert_eq!(plan.unit_count(), 1);
        assert_eq!(plan.normal_ranges(), &[ByteRange::empty()]);
    }

    /// `with_raw_mirror` twice keeps one mirror (at most one per file, D23).
    #[test]
    fn at_most_one_mirror_per_file() {
        let plan = FileUnitPlan::whole_file(10)
            .with_raw_mirror(12)
            .with_raw_mirror(14);
        assert_eq!(plan.mirror_raw_size(), Some(14));
        assert_eq!(plan.unit_count(), 2);
        let units = assign_unit_ids(&[plan]);
        assert_eq!(
            units
                .iter()
                .filter(|u| u.kind() == UnitKind::RawMirror)
                .count(),
            1
        );
    }

    /// The mirror's fields are exactly the spec's: raw domain, `[0, raw_size)`,
    /// `true_length = raw_size` (MVP-SPEC.md line 92).
    #[test]
    fn mirror_entry_fields_match_the_spec() {
        let units = assign_unit_ids(&[FileUnitPlan::whole_file(40).with_raw_mirror(43)]);
        let mirror = units.last().copied().expect("mirror exists");
        assert_eq!(mirror.kind(), UnitKind::RawMirror);
        assert_eq!(mirror.byte_range(), ByteRange::new(0, 43));
        assert_eq!(mirror.true_length(), 43);
        assert!(mirror.true_length_matches_range());
    }

    // ── unit_commit presence truth table (G5 accept) ────────────────────

    /// G5 accept: the full truth table for `is_fine_tree_covered`, with the
    /// `unit_commit`-presence consequence spelled out per row
    /// (MVP-SPEC.md line 94).
    #[test]
    fn fine_tree_coverage_truth_table() {
        let covered = text_desc(100, FineTreeOptOut::NotRequested);
        let opted_out = text_desc(100, FineTreeOptOut::Requested);
        let empty = text_desc(0, FineTreeOptOut::NotRequested);
        let binary = binary_desc(100, FineTreeOptOut::NotRequested);

        let normal = Unit::new(0, 0, UnitKind::Normal, ByteRange::new(0, 100));
        let mirror = Unit::new(1, 0, UnitKind::RawMirror, ByteRange::new(0, 104));
        let empty_unit = Unit::new(0, 0, UnitKind::Normal, ByteRange::empty());

        // (descriptor, unit, covered?) — `unit_commit` present iff NOT covered.
        let rows: [(&str, &CanonDescriptor, Unit, bool); 5] = [
            ("covered normal unit", &covered, normal, true),
            ("covered binary unit", &binary, normal, true),
            ("--no-fine-tree whole-file unit", &opted_out, normal, false),
            ("raw mirror (never covered)", &covered, mirror, false),
            ("empty-file unit", &empty, empty_unit, false),
        ];

        for (name, descriptor, unit, want_covered) in rows {
            assert_eq!(
                is_fine_tree_covered(&unit, descriptor),
                want_covered,
                "coverage: {name}"
            );
            assert_eq!(
                requires_unit_commit(&unit, descriptor),
                !want_covered,
                "unit_commit presence: {name}"
            );
        }
    }

    /// A raw mirror is never covered, under **any** descriptor — the canonical
    /// fine tree does not reach the raw byte domain (MVP-SPEC.md line 92).
    #[test]
    fn raw_mirror_is_never_fine_tree_covered() {
        let mirror = Unit::new(7, 3, UnitKind::RawMirror, ByteRange::new(0, 64));
        for size in [0u64, 1, 100] {
            for opt_out in FineTreeOptOut::ALL {
                for descriptor in [text_desc(size, opt_out), binary_desc(size, opt_out)] {
                    assert!(!is_fine_tree_covered(&mirror, &descriptor));
                    assert!(requires_unit_commit(&mirror, &descriptor));
                }
            }
        }
    }

    // ── `size` semantics (G5 accept) ────────────────────────────────────

    /// G5 accept: the file-table `size` field is the canonical byte count for
    /// text and the raw byte count for binary; a text file's raw count is
    /// carried only by its mirror's `true_length` (MVP-SPEC.md line 98).
    #[test]
    fn size_field_semantics_per_kind() {
        // Text with CRLF line endings: raw is longer than canonical.
        let text = FileLengths::Text {
            canonical: 100,
            raw: 107,
        };
        assert_eq!(text.size_field(), 100, "text size = canonical byte count");
        assert_eq!(text.raw(), 107);
        assert_eq!(text.file_kind(), FileKind::Text);
        assert_eq!(text.tiling_domain(), FineTreeDomain::Canonical);

        let binary = FileLengths::Binary { raw: 4096 };
        assert_eq!(binary.size_field(), 4096, "binary size = raw byte count");
        assert_eq!(binary.raw(), 4096);
        assert_eq!(binary.file_kind(), FileKind::Binary);
        assert_eq!(binary.tiling_domain(), FineTreeDomain::Raw);

        // The raw count reaches the manifest only through the mirror's
        // true_length — never through `size`.
        let units = assign_unit_ids(&[
            FileUnitPlan::whole_file(text.size_field()).with_raw_mirror(text.raw())
        ]);
        assert_eq!(units[0].true_length(), 100);
        assert_eq!(units[1].kind(), UnitKind::RawMirror);
        assert_eq!(units[1].true_length(), 107);
    }

    /// A text file whose raw bytes already are its canonical rendition has
    /// equal counts and (per G7) no mirror — `size` is then both, but it is
    /// still *defined* as the canonical count.
    #[test]
    fn size_field_when_raw_equals_canonical() {
        let lengths = FileLengths::Text {
            canonical: 64,
            raw: 64,
        };
        assert_eq!(lengths.size_field(), 64);
        assert_eq!(lengths.raw(), 64);
    }

    // ── Range arithmetic is panic-free on hostile values ────────────────

    #[test]
    fn byte_range_end_is_overflow_checked() {
        assert_eq!(ByteRange::new(10, 5).end(), Some(15));
        assert_eq!(ByteRange::new(u64::MAX, 0).end(), Some(u64::MAX));
        assert_eq!(ByteRange::new(u64::MAX, 1).end(), None);
        assert_eq!(ByteRange::new(1, u64::MAX).end(), None);
    }

    #[test]
    fn byte_ranges_sort_by_start_then_length() {
        let mut spans = ranges(&[(10, 1), (0, 5), (10, 0), (5, 5)]);
        spans.sort_unstable();
        assert_eq!(spans, ranges(&[(0, 5), (5, 5), (10, 0), (10, 1)]));
    }

    /// Decode-side units keep a mismatched `true_length` so R can reject it
    /// (MVP-SPEC.md lines 121, 168) — the mismatch must be representable.
    #[test]
    fn wire_units_preserve_a_mismatched_true_length() {
        let honest = Unit::new(1, 0, UnitKind::Normal, ByteRange::new(0, 10));
        assert!(honest.true_length_matches_range());
        let tampered = Unit::from_wire_fields(1, 0, UnitKind::Normal, ByteRange::new(0, 10), 11);
        assert!(!tampered.true_length_matches_range());
        assert_eq!(tampered.true_length(), 11);
        assert_eq!(tampered.byte_range().length(), 10);
    }

    // ── Property tests ──────────────────────────────────────────────────

    /// Plans of 1..=4 files, each 1..=4 normal units of 0..=64 bytes, some
    /// with mirrors.
    fn plans() -> impl Strategy<Value = Vec<FileUnitPlan>> {
        let file = (
            proptest::collection::vec(0u64..=64, 1..=4),
            proptest::option::of(0u64..=128),
        )
            .prop_map(|(widths, mirror)| {
                let mut start = 0u64;
                let mut spans = Vec::with_capacity(widths.len());
                for width in widths {
                    spans.push(ByteRange::new(start, width));
                    start += width;
                }
                let plan = FileUnitPlan {
                    normal: spans,
                    mirror_raw_size: None,
                };
                match mirror {
                    Some(raw_size) => plan.with_raw_mirror(raw_size),
                    None => plan,
                }
            });
        proptest::collection::vec(file, 1..=4)
    }

    proptest! {
        #![proptest_config(proptest_config(0x0064_0002))]

        /// The assignment invariants, over arbitrary multi-file works: ids are
        /// `0..N` with no gaps or repeats; `file_id` is the plan's index; each
        /// file's normal units are ascending with the mirror last (D23);
        /// `true_length` always equals the range width.
        #[test]
        fn assignment_invariants(plans in plans()) {
            let units = assign_unit_ids(&plans);
            let total: usize = plans.iter().map(FileUnitPlan::unit_count).sum();
            prop_assert_eq!(units.len(), total);

            for (position, unit) in units.iter().enumerate() {
                prop_assert_eq!(u64::try_from(position), Ok(unit.unit_id()));
                prop_assert!(unit.true_length_matches_range());
            }

            let mut seen = 0usize;
            for (file_index, plan) in plans.iter().enumerate() {
                let file_units = &units[seen..seen + plan.unit_count()];
                seen += plan.unit_count();

                for unit in file_units {
                    prop_assert_eq!(u64::try_from(file_index), Ok(unit.file_id()));
                }

                let normal: Vec<&Unit> = file_units
                    .iter()
                    .filter(|u| u.kind() == UnitKind::Normal)
                    .collect();
                let mirrors: Vec<&Unit> = file_units
                    .iter()
                    .filter(|u| u.kind() == UnitKind::RawMirror)
                    .collect();
                prop_assert_eq!(normal.len(), plan.normal_ranges().len());
                prop_assert!(mirrors.len() <= 1);

                // Normal units ascend by range and come first.
                for pair in normal.windows(2) {
                    prop_assert!(pair[0].byte_range() <= pair[1].byte_range());
                }
                if let Some(mirror) = mirrors.first() {
                    prop_assert_eq!(mirror.unit_id(), file_units[file_units.len() - 1].unit_id());
                    prop_assert_eq!(mirror.byte_range().start(), 0);
                }
            }
        }

        /// Coverage is exactly `fine_tree_present && kind == Normal`, and
        /// `unit_commit` presence is exactly its negation — over every
        /// descriptor shape and both unit kinds.
        #[test]
        fn coverage_matches_its_definition(
            is_text in any::<bool>(),
            size in 0u64..=4096,
            opt_out_requested in any::<bool>(),
            is_mirror in any::<bool>(),
        ) {
            let opt_out = if opt_out_requested {
                FineTreeOptOut::Requested
            } else {
                FineTreeOptOut::NotRequested
            };
            let descriptor = if is_text {
                text_desc(size, opt_out)
            } else {
                binary_desc(size, opt_out)
            };
            let kind = if is_mirror { UnitKind::RawMirror } else { UnitKind::Normal };
            let unit = Unit::new(0, 0, kind, ByteRange::new(0, size));

            let expected = descriptor.fine_tree_present() && !is_mirror;
            prop_assert_eq!(is_fine_tree_covered(&unit, &descriptor), expected);
            prop_assert_eq!(requires_unit_commit(&unit, &descriptor), !expected);
        }
    }
}
