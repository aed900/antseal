//! Seal-side content-model assembly (tasks/G.md G14) — the **one** place the
//! content rules are applied.
//!
//! [`assemble_content_model`] is the single entry point from a work's raw
//! file bytes plus per-file flags to the finished [`ContentModel`]: the
//! per-file descriptor, canonical rendition, unit table with work-global ids,
//! and `fine_root`. Everything downstream — F building the manifest body, S
//! staging the seal journal, U printing what will be sealed — consumes this
//! value rather than re-deriving any of it, so there is exactly one
//! implementation of "what the content model of this work is".
//!
//! # The rules it enforces, in spec order
//!
//! | rule | MVP-SPEC.md | how |
//! | --- | --- | --- |
//! | text detection is strict UTF-8 validity, or `--force-text` | 83, 149 | [`is_text`] ∨ `force_text` |
//! | text files get a canonical rendition; binary files have none | 83 | [`canonicalize_forced`], text kinds only |
//! | fine tree by default; not for `--no-fine-tree`, not for empty | 85, 78 | [`CanonDescriptor::describe_file`] |
//! | fine-tree domain: canonical for text, raw for binary | 83, 85 | [`FileKind::fine_tree_domain`] |
//! | one whole-file unit by default | 84 | [`FileUnitPlan::whole_file`] |
//! | `--split blank-lines` cuts on blank lines, over canonical bytes | 84 | [`plan_blank_line_split`] |
//! | `--no-fine-tree` (and binary) can never split | 85 (D24) | [`SplitEligibleText`] witness |
//! | empty file → exactly one empty unit, no tree | 78 | `whole_file(0)`, no `fine_root` |
//! | raw mirror iff `raw != canonical`, appended last | 92 (D23) | [`with_raw_mirror_if_needed`] |
//! | `unit_id` is work-global, in manifest order | 76 (D23) | [`assign_unit_ids`], one call |
//! | `size` is stated in the file's own domain | 98 | [`FileLengths::size_field`] |
//! | `fine_root` is the sole content commitment of covered bytes | 94, 96 | [`is_fine_tree_covered`] |
//!
//! # Why this is total (no error type)
//!
//! Assembly cannot fail. That is a design property, not an omission:
//!
//! - **Canonicalization runs in forced mode, always**, through its total
//!   entry point [`canonicalize_forced`]. Forced mode is total over arbitrary
//!   bytes (decision D20), and on valid UTF-8 it is byte-identical to
//!   detected mode — so nothing is lost — while being *the same mode the
//!   verifier recomputes a raw mirror in* (MVP-SPEC.md line 121, D20). Seal
//!   and verify therefore execute the identical transform, making
//!   `canonicalize(raw) == canonical` true by construction rather than by a
//!   mode-agreement lemma. (Detected mode exists for callers that read a
//!   file, establish validity, and canonicalize *later*, where a file mutated
//!   in between is a real hazard. Here detection and canonicalization see one
//!   immutable `&[u8]`, so that window does not exist — and
//!   `detected_mode_agrees_on_the_golden_work` keeps the equivalence
//!   asserted anyway.)
//! - **The Unicode version is [`UnicodeVersion::CURRENT`]**, resolved at
//!   compile time; a seal never names a table this build does not ship.
//!   ("Verifier too old" is a *verify*-side condition — G1/D25.)
//! - **`fine_root` absence flows through as `None`**, never an unwrap: it is
//!   `None` exactly when the descriptor says there is no tree.
//!
//! # Determinism
//!
//! Identical inputs produce a bit-identical model: no I/O, no clock, no
//! randomness, no iteration over an unordered collection, no float. The only
//! injected value is the per-file `s_root`, supplied by [`FineSeedSource`],
//! which C derives deterministically as `HKDF(W, "fine-seed", file_id)`.
//!
//! [`FileKind::fine_tree_domain`]: super::descriptor::FileKind::fine_tree_domain

use crate::canon::{CanonicalBytes, UnicodeVersion, canonicalize_forced, is_text};
use crate::crypto::hkdf::FileId;
use crate::crypto::material::Seed32;

use super::descriptor::{CanonDescriptor, ContentKind, FineTreeOptOut};
use super::fine_tree::{FineRoot, rebuild_fine_root};
use super::mirror::with_raw_mirror_if_needed;
use super::split::plan_blank_line_split;
use super::unit::{
    FileLengths, FileUnitPlan, SplitEligibleText, Unit, UnitKind, assign_unit_ids,
    is_fine_tree_covered,
};

/// How a file was asked to be divided into units (MVP-SPEC.md line 84).
///
/// Exhaustive on purpose, for the reason [`TextMode`](crate::canon::TextMode)
/// is: the unit-division modes are part of what the manifest's unit table
/// means, so a new one is a format-level event to be co-frozen with F, not a
/// quiet API addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SplitMode {
    /// `--split blank-lines` — paragraph units cut at blank-line runs, with
    /// the frozen D22 separator-attachment semantics, computed over the
    /// **canonical** bytes so the result is platform-stable.
    BlankLines,
}

/// The per-file seal flags that reach the content model (MVP-SPEC.md line
/// 149) — U's CLI surface in semantic form.
///
/// `split` is `Option<SplitMode>` rather than a bool because the flag names a
/// mode; `no_fine_tree_matched` is already-resolved glob matching (U owns the
/// glob, G owns what a match means).
///
/// A request is not an outcome. Both `split` and `no_fine_tree_matched` are
/// *requests*, and the model reconciles them: a `--no-fine-tree` file (or a
/// binary one, or an empty one) is single-unit whatever `split` says, and the
/// reconciliation is structural — see [`SplitEligibleText`] and decision D24.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FileFlags {
    force_text: bool,
    split: Option<SplitMode>,
    no_fine_tree_matched: bool,
}

impl FileFlags {
    /// No flags: detected kind, whole-file unit, fine tree present.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            force_text: false,
            split: None,
            no_fine_tree_matched: false,
        }
    }

    /// `--force-text` (MVP-SPEC.md line 149): treat this file as text even if
    /// it is not valid UTF-8. On a file that *is* valid UTF-8 the flag has no
    /// effect — [`is_text`] already says text.
    #[must_use]
    pub const fn with_force_text(mut self) -> Self {
        self.force_text = true;
        self
    }

    /// `--split <mode>` (MVP-SPEC.md line 84). Honoured only where the model
    /// permits sub-file units at all (D24).
    #[must_use]
    pub const fn with_split(mut self, mode: SplitMode) -> Self {
        self.split = Some(mode);
        self
    }

    /// This file matched a `--no-fine-tree` glob (MVP-SPEC.md line 85):
    /// permanently whole-file-reveal-only.
    #[must_use]
    pub const fn with_no_fine_tree(mut self) -> Self {
        self.no_fine_tree_matched = true;
        self
    }

    /// Whether `--force-text` was given for this file.
    #[must_use]
    pub const fn force_text(self) -> bool {
        self.force_text
    }

    /// The requested split mode, if any.
    #[must_use]
    pub const fn split(self) -> Option<SplitMode> {
        self.split
    }

    /// Whether a `--no-fine-tree` glob matched this file.
    #[must_use]
    pub const fn no_fine_tree_matched(self) -> bool {
        self.no_fine_tree_matched
    }
}

/// One file of the work, as handed to assembly: its raw bytes and its flags.
///
/// Bytes are borrowed — S reads the file, this module never does (no I/O) —
/// and the resulting [`ContentModel`] borrows them onward, so a file's bytes
/// exist exactly once in memory no matter how many units reference them.
#[derive(Debug, Clone, Copy)]
pub struct FileInput<'a> {
    raw: &'a [u8],
    flags: FileFlags,
}

impl<'a> FileInput<'a> {
    /// A file's raw bytes with its flags. Position in the input slice is the
    /// file's `file_id` (MVP-SPEC.md line 76), so ids cannot be mis-stated.
    #[must_use]
    pub const fn new(raw: &'a [u8], flags: FileFlags) -> Self {
        Self { raw, flags }
    }

    /// A file with no flags — the common case.
    #[must_use]
    pub const fn plain(raw: &'a [u8]) -> Self {
        Self::new(raw, FileFlags::new())
    }

    /// The file's raw bytes, exactly as read.
    #[must_use]
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// The file's flags.
    #[must_use]
    pub const fn flags(&self) -> FileFlags {
        self.flags
    }
}

/// Supplies each file's fine-tree root seed `s_root`.
///
/// C owns the derivation — `s_root = HKDF(W, "fine-seed", file_id)`
/// ([`derive_fine_seed`](crate::crypto::hkdf::derive_fine_seed), MVP-SPEC.md
/// line 90) — and this module never touches the master secret `W`. Injecting
/// it as a trait is what keeps assembly pure and lets tests drive it from a
/// clearly-labelled synthetic supplier instead of vault material (project
/// rule 6).
///
/// Assembly calls this **only for files that actually have a fine tree**, and
/// **exactly once** per such file, so a supplier may account for what it
/// released. Files with no tree (empty, or `--no-fine-tree`) never have their
/// seed derived at all.
///
/// The blanket `Fn(FileId) -> Seed32` implementation means a closure is a
/// supplier: `assemble_content_model(&files, &|id| derive_fine_seed(w, id))`.
pub trait FineSeedSource {
    /// The `s_root` for the file at `file_id`.
    fn fine_seed(&self, file_id: FileId) -> Seed32;
}

impl<F> FineSeedSource for F
where
    F: Fn(FileId) -> Seed32,
{
    fn fine_seed(&self, file_id: FileId) -> Seed32 {
        self(file_id)
    }
}

/// One file's place in the content model — everything the manifest's file
/// table and unit table are built from (MVP-SPEC.md line 98).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileModel<'a> {
    file_id: u64,
    raw: &'a [u8],
    /// `Some` iff the file is text (MVP-SPEC.md line 83): binary files have
    /// no canonical rendition, and giving them an identity one would hand the
    /// raw domain a second name.
    canonical: Option<CanonicalBytes>,
    descriptor: CanonDescriptor,
    lengths: FileLengths,
    /// This file's slice of the work-global unit table: `[start, start + len)`
    /// in [`ContentModel::units`]. Contiguous because [`assign_unit_ids`]
    /// emits files in order (D23).
    unit_start: usize,
    unit_len: usize,
    /// `Some` iff the file has a fine tree — equivalently, iff
    /// [`CanonDescriptor::fine_tree_present`].
    fine_root: Option<FineRoot>,
}

impl<'a> FileModel<'a> {
    /// This file's `file_id`: its index in the work's file table
    /// (MVP-SPEC.md line 76).
    #[must_use]
    pub const fn file_id(&self) -> u64 {
        self.file_id
    }

    /// The file's raw bytes — the raw mirror's domain, and (for binary files)
    /// the tiling and fine-tree domain too.
    #[must_use]
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// The canonical rendition, `Some` iff the file is text (line 83).
    #[must_use]
    pub const fn canonical(&self) -> Option<&CanonicalBytes> {
        self.canonical.as_ref()
    }

    /// The file's canonicalization descriptor (G4; line 83).
    #[must_use]
    pub const fn descriptor(&self) -> &CanonDescriptor {
        &self.descriptor
    }

    /// The file's lengths in both domains; [`FileLengths::size_field`] is the
    /// manifest's `size` (line 98).
    #[must_use]
    pub const fn lengths(&self) -> FileLengths {
        self.lengths
    }

    /// The file's `size` field: canonical byte count for text, raw byte count
    /// for binary (line 98). This is the fine tree's leaf count `n` and the
    /// upper bound of every non-mirror unit's byte range.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.lengths.size_field()
    }

    /// `fine_root`, present iff the file has a fine tree (lines 85, 98).
    #[must_use]
    pub const fn fine_root(&self) -> Option<&FineRoot> {
        self.fine_root.as_ref()
    }

    /// The bytes non-mirror units index into and the fine tree is built over:
    /// the **canonical** rendition for text, the **raw** bytes for binary
    /// (MVP-SPEC.md lines 83, 85).
    ///
    /// Its length is always [`Self::size`], so `[0, size)` addresses it
    /// exactly.
    #[must_use]
    pub fn domain_bytes(&self) -> &[u8] {
        match self.canonical.as_ref() {
            Some(canonical) => canonical.as_bytes(),
            None => self.raw,
        }
    }

    /// The bytes of `unit`, resolved in that unit's own domain: raw for a
    /// [`UnitKind::RawMirror`], [`Self::domain_bytes`] for a normal unit.
    ///
    /// `None` if `unit` belongs to a different file or its range does not lie
    /// within that domain — neither is reachable for a unit taken from this
    /// model, and returning `None` rather than panicking keeps the accessor
    /// safe for units that arrived from a bundle.
    #[must_use]
    pub fn unit_bytes(&self, unit: &Unit) -> Option<&[u8]> {
        if unit.file_id() != self.file_id {
            return None;
        }
        let domain = match unit.kind() {
            UnitKind::RawMirror => self.raw,
            UnitKind::Normal => self.domain_bytes(),
        };
        let start = usize::try_from(unit.byte_range().start()).ok()?;
        let end = usize::try_from(unit.byte_range().end()?).ok()?;
        domain.get(start..end)
    }
}

/// A work's complete content model: every file's descriptor, rendition,
/// units and `fine_root`, with work-global unit ids assigned once
/// (MVP-SPEC.md lines 76, 98).
///
/// Borrows the input file bytes for `'a`; the canonical renditions are the
/// only bytes it owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentModel<'a> {
    files: Vec<FileModel<'a>>,
    /// The work-global unit table in `unit_id` order — ids are dense from 0,
    /// so `units[i].unit_id() == i` (asserted by `unit_ids_are_dense`).
    units: Vec<Unit>,
}

impl<'a> ContentModel<'a> {
    /// Every file, in file-table order (`files()[i].file_id() == i`).
    #[must_use]
    pub fn files(&self) -> &[FileModel<'a>] {
        &self.files
    }

    /// The work-global unit table in `unit_id` order (MVP-SPEC.md line 76).
    #[must_use]
    pub fn units(&self) -> &[Unit] {
        &self.units
    }

    /// The file with this `file_id`.
    #[must_use]
    pub fn file(&self, file_id: u64) -> Option<&FileModel<'a>> {
        self.files.get(usize::try_from(file_id).ok()?)
    }

    /// The unit with this `unit_id` (ids are dense from 0).
    #[must_use]
    pub fn unit(&self, unit_id: u64) -> Option<&Unit> {
        self.units.get(usize::try_from(unit_id).ok()?)
    }

    /// This file's units, in id order: normal units ascending by byte range,
    /// then the raw mirror last if present (D23).
    #[must_use]
    pub fn units_of(&self, file_id: u64) -> &[Unit] {
        match self.file(file_id) {
            Some(file) => {
                let end = file.unit_start.saturating_add(file.unit_len);
                self.units.get(file.unit_start..end).unwrap_or(&[])
            }
            None => &[],
        }
    }

    /// The bytes of `unit`, resolved through its own file — the work-level
    /// form of [`FileModel::unit_bytes`].
    #[must_use]
    pub fn unit_bytes(&self, unit: &Unit) -> Option<&[u8]> {
        self.file(unit.file_id())?.unit_bytes(unit)
    }

    /// Whether `unit`'s bytes are committed by its file's `fine_root`, and so
    /// carry **no** `unit_commit` of their own (MVP-SPEC.md line 94).
    ///
    /// `false` for a unit not in this model.
    #[must_use]
    pub fn is_covered(&self, unit: &Unit) -> bool {
        match self.file(unit.file_id()) {
            Some(file) => is_fine_tree_covered(unit, &file.descriptor),
            None => false,
        }
    }
}

/// **The** seal-side content-model entry point (tasks/G.md G14): a work's
/// raw file bytes plus flags, in, the finished [`ContentModel`] out.
///
/// `files[i]` becomes the file with `file_id == i` (MVP-SPEC.md line 76).
/// `seeds` supplies each fine-tree-bearing file's `s_root` (see
/// [`FineSeedSource`]).
///
/// Total, pure and deterministic — module docs explain why each of those
/// holds. Every content rule the model has is applied here and nowhere else,
/// so U's CLI and S's seal flow never re-decide any of them.
///
/// # Examples
///
/// ```
/// use antseal_core::content::{FileFlags, FileInput, SplitMode, assemble_content_model};
/// use antseal_core::crypto::hkdf::FileId;
/// use antseal_core::crypto::material::Seed32;
///
/// // A CRLF text file, split into paragraphs, plus a binary file.
/// let text = b"alpha\r\n\r\nbeta\r\n";
/// let binary = b"\x00\x01\x02\xff";
/// let files = [
///     FileInput::new(text, FileFlags::new().with_split(SplitMode::BlankLines)),
///     FileInput::plain(binary),
/// ];
///
/// // A synthetic seed supplier stands in for C's HKDF derivation here.
/// let model = assemble_content_model(&files, &|id: FileId| {
///     Seed32::from_bytes([u8::try_from(id.0).unwrap_or(0); 32])
/// });
///
/// // Two paragraph units + the raw mirror (CRLF != LF), then the binary file.
/// assert_eq!(model.units().len(), 4);
/// assert_eq!(model.units_of(0).len(), 3);
/// let text_file = model.file(0).expect("file 0");
/// let binary_file = model.file(1).expect("file 1");
/// assert_eq!(text_file.size(), 12); // canonical bytes
/// assert_eq!(binary_file.size(), 4); // raw bytes
/// // Covered units carry no `unit_commit`: `fine_root` is the sole commitment.
/// assert!(model.is_covered(&model.units()[0]));
/// ```
#[must_use]
pub fn assemble_content_model<'a, S>(files: &[FileInput<'a>], seeds: &S) -> ContentModel<'a>
where
    S: FineSeedSource + ?Sized,
{
    // ── Pass 1: per-file kind, rendition, descriptor, unit plan ─────────
    //
    // Plans are collected before any id is assigned, because ids are
    // work-global: they cannot be handed out one file at a time (line 76).
    let mut parts: Vec<FilePart<'a>> = Vec::with_capacity(files.len());
    let mut plans: Vec<FileUnitPlan> = Vec::with_capacity(files.len());
    for input in files {
        let part = plan_file(*input);
        plans.push(part.plan.clone());
        parts.push(part);
    }

    // ── Pass 2: one work-global id assignment (D23) ─────────────────────
    let units = assign_unit_ids(&plans);

    // ── Pass 3: fine roots, over each file's own domain ─────────────────
    let mut models: Vec<FileModel<'a>> = Vec::with_capacity(parts.len());
    let mut unit_start = 0usize;
    for (file_id, part) in (0u64..).zip(parts) {
        let unit_len = part.plan.unit_count();
        // `fine_root` is derived iff the descriptor says there is a tree, so
        // the seed of a tree-less file is never requested — and the `Option`
        // reaching the model is the descriptor's own answer, never an unwrap.
        let fine_root = if part.descriptor.fine_tree_present() {
            let s_root = seeds.fine_seed(FileId(file_id));
            rebuild_fine_root(&s_root, part.domain_bytes())
        } else {
            None
        };
        debug_assert_eq!(
            fine_root.is_some(),
            part.descriptor.fine_tree_present(),
            "fine_root presence must equal the descriptor's claim"
        );
        models.push(FileModel {
            file_id,
            raw: part.raw,
            canonical: part.canonical,
            descriptor: part.descriptor,
            lengths: part.lengths,
            unit_start,
            unit_len,
            fine_root,
        });
        unit_start = unit_start.saturating_add(unit_len);
    }

    debug_assert_eq!(unit_start, units.len(), "unit spans must cover the table");
    ContentModel {
        files: models,
        units,
    }
}

/// Pass-1 intermediate: one file decided, but not yet id-assigned.
struct FilePart<'a> {
    raw: &'a [u8],
    canonical: Option<CanonicalBytes>,
    descriptor: CanonDescriptor,
    lengths: FileLengths,
    plan: FileUnitPlan,
}

impl FilePart<'_> {
    /// The tiling / fine-tree domain — canonical for text, raw for binary.
    fn domain_bytes(&self) -> &[u8] {
        match self.canonical.as_ref() {
            Some(canonical) => canonical.as_bytes(),
            None => self.raw,
        }
    }
}

/// Decide one file: kind, rendition, lengths, descriptor, unit plan.
///
/// The whole content-rule cascade lives in this function; `assemble_content_model`
/// only sequences it and assigns ids.
fn plan_file(input: FileInput<'_>) -> FilePart<'_> {
    let raw = input.raw();
    let flags = input.flags();

    // Detection (line 83): text iff valid UTF-8, or forced. `--force-text` on
    // a file that is already valid UTF-8 changes nothing.
    let is_text_file = is_text(raw) || flags.force_text();

    // Canonicalization — Forced mode always, through its total entry point, so
    // there is no error arm to discharge. See the module docs for why forcing
    // is both safe and the *right* mode here.
    let canonical = is_text_file.then(|| canonicalize_forced(UnicodeVersion::CURRENT, raw));

    // `size` is stated in the file's own domain (line 98). `usize -> u64` is
    // lossless on every supported target (64-bit native, 32-bit wasm32).
    let raw_len = u64::try_from(raw.len()).unwrap_or(u64::MAX);
    let lengths = match canonical.as_ref() {
        Some(canonical) => FileLengths::Text {
            canonical: u64::try_from(canonical.len()).unwrap_or(u64::MAX),
            raw: raw_len,
        },
        None => FileLengths::Binary { raw: raw_len },
    };

    // Descriptor (G4): kind, fine-tree presence (default on; off for
    // `--no-fine-tree` and for empty files), domain, Unicode version.
    let kind = if canonical.is_some() {
        ContentKind::Text(UnicodeVersion::CURRENT)
    } else {
        ContentKind::Binary
    };
    let opt_out = if flags.no_fine_tree_matched() {
        FineTreeOptOut::Requested
    } else {
        FineTreeOptOut::NotRequested
    };
    let descriptor = CanonDescriptor::describe_file(kind, lengths.size_field(), opt_out);

    // Units. `SplitEligibleText::of` is the D24 gate: it yields a witness only
    // for a fine-tree-covered text file, so a binary, `--no-fine-tree` or
    // empty file cannot reach the split constructor at all — the conflict is
    // unwritable rather than rejected.
    let plan = match (
        flags.split(),
        canonical.as_ref(),
        SplitEligibleText::of(&descriptor),
    ) {
        (Some(SplitMode::BlankLines), Some(canonical), Some(eligible)) => {
            plan_blank_line_split(eligible, canonical)
        }
        _ => FileUnitPlan::whole_file(lengths.size_field()),
    };

    // The raw mirror (line 92, D23): text files only — a binary file's units
    // already are its raw bytes — and only when the renditions differ.
    let plan = match canonical.as_ref() {
        Some(canonical) => with_raw_mirror_if_needed(plan, raw, canonical),
        None => plan,
    };

    FilePart {
        raw,
        canonical,
        descriptor,
        lengths,
        plan,
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::super::descriptor::{FileKind, FineTreeDomain};
    use super::super::fixtures::{
        GOLDEN_BINARY_RAW, GOLDEN_EMPTY_RAW, GOLDEN_FILE_BINARY, GOLDEN_FILE_EMPTY,
        GOLDEN_FILE_NO_FINE_TREE, GOLDEN_FILE_TEXT_SPLIT, GOLDEN_NO_FINE_TREE_RAW,
        GOLDEN_TEXT_SPLIT_RAW, SyntheticFineSeeds, golden_inputs, golden_model,
        model_invariant_violations,
    };
    use super::super::unit::{ByteRange, requires_unit_commit};
    use super::*;
    use crate::canon::{TextMode, canonicalize};
    #[cfg(feature = "test-util")]
    use crate::test_util::strategies::proptest_config;
    #[cfg(feature = "test-util")]
    use proptest::prelude::*;

    /// A constant seed supplier for the small targeted models below — never a
    /// vault derivation (project rule 6).
    fn flat_seeds(byte: u8) -> impl FineSeedSource {
        move |_: FileId| Seed32::from_bytes([byte; 32])
    }

    fn model_of<'a>(files: &[FileInput<'a>]) -> ContentModel<'a> {
        assemble_content_model(files, &flat_seeds(0x5A))
    }

    fn assert_clean(model: &ContentModel<'_>) {
        let violations = model_invariant_violations(model);
        assert!(
            violations.is_empty(),
            "invariant violations: {violations:#?}"
        );
    }

    // ── The golden end-to-end fixture (G14 accept) ──────────────────────

    /// The full expected [`ContentModel`] of the golden multi-file work,
    /// pinned field by field: descriptors, sizes, unit ids/kinds/ranges, the
    /// commit-presence rule, and both `fine_root`s.
    ///
    /// Any change to detection, canonicalization, splitting, mirror
    /// placement, id assignment or tree construction moves at least one of
    /// these numbers, which is the point.
    #[test]
    fn golden_content_model_is_pinned() {
        let model = golden_model();
        assert_clean(&model);
        assert_eq!(model.files().len(), 4);
        assert_eq!(model.units().len(), 7);

        // ── file 0: CRLF text, --split blank-lines, raw mirror ──────────
        let text = model.file(GOLDEN_FILE_TEXT_SPLIT).expect("file 0");
        assert_eq!(text.descriptor().kind(), FileKind::Text);
        assert!(text.descriptor().fine_tree_present());
        assert_eq!(
            text.descriptor().fine_tree_domain(),
            Some(FineTreeDomain::Canonical)
        );
        assert_eq!(text.descriptor().unicode_version(), Some("unicode-17.0.0"));
        assert_eq!(text.raw().len(), 41);
        assert_eq!(text.size(), 34, "canonical byte count, not raw");
        assert_eq!(
            text.canonical().expect("text file").as_str(),
            "alpha one\nalpha two\n\nbeta\n\n\ngamma\n"
        );
        assert_eq!(
            text.fine_root().expect("covered file").as_bytes(),
            &hex32("4d0d8a1be8aa24d4317db1532d016170e041d47736a3dca4854a9a05b2180781")
        );

        // Three paragraph units — the blank runs ride with the preceding
        // unit (D22) — then the mirror, last (D23).
        let text_units = model.units_of(GOLDEN_FILE_TEXT_SPLIT);
        assert_eq!(text_units.len(), 4);
        let expected: [(u64, UnitKind, ByteRange); 4] = [
            (0, UnitKind::Normal, ByteRange::new(0, 21)),
            (1, UnitKind::Normal, ByteRange::new(21, 7)),
            (2, UnitKind::Normal, ByteRange::new(28, 6)),
            (3, UnitKind::RawMirror, ByteRange::new(0, 41)),
        ];
        for (unit, (id, kind, range)) in text_units.iter().zip(expected) {
            assert_eq!(unit.unit_id(), id);
            assert_eq!(unit.file_id(), GOLDEN_FILE_TEXT_SPLIT);
            assert_eq!(unit.kind(), kind);
            assert_eq!(unit.byte_range(), range);
            assert_eq!(unit.true_length(), range.length());
        }
        // The sole-commitment rule: covered paragraphs carry no unit_commit;
        // the mirror, uncovered, carries one (spec lines 92, 94).
        for unit in &text_units[..3] {
            assert!(model.is_covered(unit));
            assert!(!requires_unit_commit(unit, text.descriptor()));
        }
        assert!(!model.is_covered(&text_units[3]));
        assert!(requires_unit_commit(&text_units[3], text.descriptor()));
        assert_eq!(
            model.unit_bytes(&text_units[0]),
            Some(b"alpha one\nalpha two\n\n".as_slice())
        );
        assert_eq!(
            model.unit_bytes(&text_units[3]),
            Some(GOLDEN_TEXT_SPLIT_RAW)
        );

        // ── file 1: binary — raw domain, one unit, no mirror ────────────
        let binary = model.file(GOLDEN_FILE_BINARY).expect("file 1");
        assert_eq!(binary.descriptor().kind(), FileKind::Binary);
        assert_eq!(binary.descriptor().unicode_version(), None);
        assert_eq!(
            binary.descriptor().fine_tree_domain(),
            Some(FineTreeDomain::Raw)
        );
        assert!(binary.canonical().is_none(), "binary has no rendition");
        assert_eq!(binary.size(), 9);
        assert_eq!(binary.domain_bytes(), GOLDEN_BINARY_RAW);
        assert_eq!(
            binary.fine_root().expect("covered file").as_bytes(),
            &hex32("5ec9e19c79d2fede175e4bdbe983d13d7c130c152ef2cf781350b14b455cd6ee")
        );
        let binary_units = model.units_of(GOLDEN_FILE_BINARY);
        assert_eq!(binary_units.len(), 1);
        assert_eq!(binary_units[0].unit_id(), 4);
        assert_eq!(binary_units[0].byte_range(), ByteRange::new(0, 9));
        assert!(model.is_covered(&binary_units[0]));

        // ── file 2: --no-fine-tree — single unit, unit_commit, no tree ──
        let opted_out = model.file(GOLDEN_FILE_NO_FINE_TREE).expect("file 2");
        assert!(!opted_out.descriptor().fine_tree_present());
        assert_eq!(opted_out.descriptor().fine_tree_domain(), None);
        assert_eq!(opted_out.fine_root(), None);
        assert_eq!(opted_out.size(), 19);
        let opted_units = model.units_of(GOLDEN_FILE_NO_FINE_TREE);
        assert_eq!(opted_units.len(), 1, "single unit despite a blank line");
        assert_eq!(opted_units[0].unit_id(), 5);
        assert_eq!(opted_units[0].byte_range(), ByteRange::new(0, 19));
        assert!(!model.is_covered(&opted_units[0]));
        assert!(requires_unit_commit(
            &opted_units[0],
            opted_out.descriptor()
        ));

        // ── file 3: empty — one empty unit, no tree, no mirror ──────────
        let empty = model.file(GOLDEN_FILE_EMPTY).expect("file 3");
        assert_eq!(empty.size(), 0);
        assert!(!empty.descriptor().fine_tree_present());
        assert_eq!(empty.fine_root(), None);
        let empty_units = model.units_of(GOLDEN_FILE_EMPTY);
        assert_eq!(empty_units.len(), 1);
        assert_eq!(empty_units[0].unit_id(), 6);
        assert_eq!(empty_units[0].byte_range(), ByteRange::empty());
        assert!(empty_units[0].byte_range().is_empty());
        assert_eq!(model.unit_bytes(&empty_units[0]), Some(b"".as_slice()));
        assert!(requires_unit_commit(&empty_units[0], empty.descriptor()));

        // ── work-global ids never restarted (spec line 76) ──────────────
        let ids: Vec<u64> = model.units().iter().map(|unit| unit.unit_id()).collect();
        assert_eq!(ids, (0..7).collect::<Vec<u64>>());
        let files: Vec<u64> = model.units().iter().map(|unit| unit.file_id()).collect();
        assert_eq!(files, vec![0, 0, 0, 0, 1, 2, 3]);
    }

    /// Determinism (G14 accept): two independent runs are bit-identical.
    #[test]
    fn assembly_is_deterministic() {
        let first = golden_model();
        let second = golden_model();
        assert_eq!(first, second);
        // Equality is derived, so spell out the bytes that matter most.
        for (a, b) in first.files().iter().zip(second.files()) {
            assert_eq!(a.fine_root(), b.fine_root());
            assert_eq!(a.domain_bytes(), b.domain_bytes());
        }
        assert_eq!(first.units(), second.units());
        // And a freshly built input array assembles to the same value.
        let third = assemble_content_model(&golden_inputs(), &SyntheticFineSeeds);
        assert_eq!(first, third);
    }

    /// The forced-mode choice loses nothing: on every text file of the golden
    /// work whose bytes are valid UTF-8, detected mode agrees byte-for-byte
    /// (decision D20). Keeps the module docs' claim under test.
    #[test]
    fn detected_mode_agrees_on_the_golden_work() {
        let model = golden_model();
        let mut checked = 0;
        for file in model.files() {
            if let Some(canonical) = file.canonical()
                && is_text(file.raw())
            {
                let detected =
                    canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, file.raw())
                        .expect("valid UTF-8");
                assert_eq!(&detected, canonical, "file {}", file.file_id());
                checked += 1;
            }
        }
        assert_eq!(checked, 3, "files 0, 2 and 3 are valid UTF-8 text");
    }

    // ── Targeted rule tests ─────────────────────────────────────────────

    /// The empty-file rule (MVP-SPEC.md line 78): one empty unit, no tree —
    /// and the unit still carries a `unit_commit`, because nothing covers it.
    #[test]
    fn empty_file_is_one_empty_unit_with_no_tree() {
        let files = [FileInput::plain(GOLDEN_EMPTY_RAW)];
        let model = model_of(&files);
        assert_clean(&model);
        let file = model.file(0).expect("file 0");
        assert_eq!(file.size(), 0);
        assert!(!file.descriptor().fine_tree_present());
        assert_eq!(file.fine_root(), None);
        assert_eq!(model.units().len(), 1);
        assert!(model.units()[0].byte_range().is_empty());
        assert!(requires_unit_commit(&model.units()[0], file.descriptor()));
    }

    /// D24: a `--no-fine-tree` file is single-unit **whatever** `--split`
    /// says. The reconciliation is structural — `SplitEligibleText::of`
    /// refuses the witness — so no runtime rejection is involved. (U's
    /// user-facing hard error on the flag combination is U's, by the same
    /// decision.)
    #[test]
    fn no_fine_tree_file_is_single_unit_even_when_split_is_requested() {
        let flags = FileFlags::new()
            .with_no_fine_tree()
            .with_split(SplitMode::BlankLines);
        let files = [FileInput::new(GOLDEN_NO_FINE_TREE_RAW, flags)];
        let model = model_of(&files);
        assert_clean(&model);
        assert_eq!(model.units().len(), 1, "split request cannot apply");
        assert_eq!(model.units()[0].byte_range(), ByteRange::new(0, 19));
        assert_eq!(model.file(0).expect("file 0").fine_root(), None);

        // Without --no-fine-tree the same bytes DO split, so the assertion
        // above is about the flag, not about the content.
        let split_only = [FileInput::new(
            GOLDEN_NO_FINE_TREE_RAW,
            FileFlags::new().with_split(SplitMode::BlankLines),
        )];
        let split_model = model_of(&split_only);
        assert_clean(&split_model);
        assert_eq!(split_model.units().len(), 2);
    }

    /// A binary file cannot split either (same witness), never gets a mirror,
    /// and tiles its raw bytes.
    #[test]
    fn binary_file_is_single_unit_over_raw_bytes_with_no_mirror() {
        let files = [FileInput::new(
            GOLDEN_BINARY_RAW,
            FileFlags::new().with_split(SplitMode::BlankLines),
        )];
        let model = model_of(&files);
        assert_clean(&model);
        assert_eq!(model.units().len(), 1);
        assert_eq!(model.units()[0].kind(), UnitKind::Normal);
        let file = model.file(0).expect("file 0");
        assert_eq!(file.domain_bytes(), GOLDEN_BINARY_RAW);
        assert!(file.canonical().is_none());
    }

    /// `--force-text` opts invalid UTF-8 into text treatment, with D20's
    /// lossy U+FFFD decode; without it the same bytes are binary. The two
    /// models differ in kind, domain, size and mirror presence.
    #[test]
    fn force_text_changes_kind_domain_and_mirror() {
        let raw = b"caf\xC3 \r\n";
        let forced = model_of(&[FileInput::new(raw, FileFlags::new().with_force_text())]);
        assert_clean(&forced);
        let file = forced.file(0).expect("file 0");
        assert_eq!(file.descriptor().kind(), FileKind::Text);
        assert_eq!(
            file.canonical().expect("text").as_str(),
            "caf\u{FFFD} \n",
            "maximal-subparts replacement, then CRLF -> LF"
        );
        assert_eq!(
            file.size(),
            8,
            "\"caf\" 3 + U+FFFD 3 + space 1 + LF 1 — one canonical byte MORE \
             than the 7 raw bytes, because the replacement is wider than the \
             byte it replaced"
        );
        assert_eq!(forced.units_of(0).len(), 2, "content unit + raw mirror");
        assert_eq!(forced.units_of(0)[1].kind(), UnitKind::RawMirror);

        let detected = model_of(&[FileInput::plain(raw)]);
        assert_clean(&detected);
        let file = detected.file(0).expect("file 0");
        assert_eq!(file.descriptor().kind(), FileKind::Binary);
        assert_eq!(file.size(), 7, "raw byte count");
        assert_eq!(detected.units_of(0).len(), 1, "no mirror for binary");
    }

    /// A BOM-only file canonicalizes to zero bytes (D21 strips the whole
    /// leading run), so the empty-file rule and the mirror rule fire together:
    /// no tree, one empty unit, and a mirror carrying the original bytes.
    #[test]
    fn bom_only_file_is_empty_but_keeps_its_bytes_in_a_mirror() {
        let raw = "\u{FEFF}\u{FEFF}".as_bytes();
        let model = model_of(&[FileInput::plain(raw)]);
        assert_clean(&model);
        let file = model.file(0).expect("file 0");
        assert_eq!(file.size(), 0);
        assert_eq!(file.fine_root(), None);
        let units = model.units_of(0);
        assert_eq!(units.len(), 2);
        assert!(units[0].byte_range().is_empty());
        assert_eq!(units[1].kind(), UnitKind::RawMirror);
        assert_eq!(model.unit_bytes(&units[1]), Some(raw));
        assert!(requires_unit_commit(&units[1], file.descriptor()));
    }

    /// The seed supplier is consulted **once per fine-tree-bearing file** and
    /// never for a tree-less one — the contract [`FineSeedSource`] documents,
    /// so a vault-backed supplier can account for what it released.
    #[test]
    fn seed_supplier_is_called_once_per_covered_file_only() {
        let asked: Cell<Vec<u64>> = Cell::new(Vec::new());
        let supplier = |file_id: FileId| {
            let mut seen = asked.take();
            seen.push(file_id.0);
            asked.set(seen);
            Seed32::from_bytes([0x11; 32])
        };
        let model = assemble_content_model(&golden_inputs(), &supplier);
        assert_clean(&model);
        assert_eq!(
            asked.take(),
            vec![GOLDEN_FILE_TEXT_SPLIT, GOLDEN_FILE_BINARY],
            "only the two fine-tree-bearing files, once each, in order"
        );
    }

    /// The work-global counter runs across files without restarting, and the
    /// mirror of an earlier file does not disturb the next file's ids
    /// (MVP-SPEC.md line 76, D23).
    #[test]
    fn unit_ids_are_work_global_across_files() {
        let files = [
            FileInput::new(
                GOLDEN_TEXT_SPLIT_RAW,
                FileFlags::new().with_split(SplitMode::BlankLines),
            ),
            FileInput::plain(GOLDEN_BINARY_RAW),
            FileInput::plain(GOLDEN_TEXT_SPLIT_RAW),
        ];
        let model = model_of(&files);
        assert_clean(&model);
        let ids: Vec<(u64, u64)> = model
            .units()
            .iter()
            .map(|unit| (unit.file_id(), unit.unit_id()))
            .collect();
        assert_eq!(
            ids,
            vec![(0, 0), (0, 1), (0, 2), (0, 3), (1, 4), (2, 5), (2, 6)]
        );
    }

    /// Two files with identical bytes get identical `fine_root`s **only**
    /// because this fixture's supplier hands out one seed for every file. The
    /// production supplier keys `s_root` on `file_id`, which is what stops
    /// cross-file salt reuse — pinned here so the fixture's simplification is
    /// visible rather than mistaken for a property of the model.
    #[test]
    fn per_file_seeds_separate_identical_files() {
        let files = [
            FileInput::plain(GOLDEN_BINARY_RAW),
            FileInput::plain(GOLDEN_BINARY_RAW),
        ];
        let flat = model_of(&files);
        assert_eq!(
            flat.file(0).expect("file 0").fine_root(),
            flat.file(1).expect("file 1").fine_root(),
            "one seed for all files ⇒ identical roots"
        );

        let per_file = assemble_content_model(&files, &|id: FileId| {
            Seed32::from_bytes([u8::try_from(id.0).unwrap_or(0xFF); 32])
        });
        assert_ne!(
            per_file.file(0).expect("file 0").fine_root(),
            per_file.file(1).expect("file 1").fine_root(),
            "per-file seeds ⇒ distinct roots for identical bytes"
        );
    }

    /// An empty work is a valid, empty model — no panic, no units.
    #[test]
    fn empty_work_assembles_to_an_empty_model() {
        let model = model_of(&[]);
        assert_clean(&model);
        assert!(model.files().is_empty());
        assert!(model.units().is_empty());
        assert_eq!(model.unit(0), None);
        assert_eq!(model.file(0), None);
        assert!(model.units_of(0).is_empty());
    }

    /// Accessors reject out-of-model inputs instead of panicking — these are
    /// the paths R reaches with bundle-supplied units.
    #[test]
    fn accessors_are_total_on_foreign_units() {
        let model = golden_model();
        let foreign = Unit::new(99, 99, UnitKind::Normal, ByteRange::new(0, 4));
        assert_eq!(model.unit_bytes(&foreign), None);
        assert!(!model.is_covered(&foreign));
        assert_eq!(model.file(u64::MAX), None);
        assert_eq!(model.unit(u64::MAX), None);
        // A unit whose range escapes its file's domain resolves to None.
        let overlong = Unit::new(
            0,
            GOLDEN_FILE_BINARY,
            UnitKind::Normal,
            ByteRange::new(0, 99),
        );
        assert_eq!(model.unit_bytes(&overlong), None);
    }

    /// Decode 32 hex bytes for the pinned roots above.
    fn hex32(hex: &str) -> [u8; 32] {
        let bytes = hex.as_bytes();
        assert_eq!(bytes.len(), 64, "expected 64 hex digits");
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            let pair = &hex[index * 2..index * 2 + 2];
            *byte = u8::from_str_radix(pair, 16).expect("hex digits");
        }
        out
    }

    // ── Property test (G14 accept): every model satisfies the invariants ──

    #[cfg(feature = "test-util")]
    fn file_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            // Arbitrary bytes: mostly invalid UTF-8, so binary files.
            proptest::collection::vec(any::<u8>(), 0..=64),
            // Text-shaped: blank-line runs, CRLF, BOMs, NFD material.
            proptest::collection::vec(
                prop_oneof![
                    Just("\r\n".to_owned()),
                    Just("\n".to_owned()),
                    Just("\u{FEFF}".to_owned()),
                    Just("  \t".to_owned()),
                    Just("e\u{0301}".to_owned()),
                    Just("word".to_owned()),
                ],
                0..=24,
            )
            .prop_map(|parts| parts.concat().into_bytes()),
        ]
    }

    #[cfg(feature = "test-util")]
    fn file_flags() -> impl Strategy<Value = FileFlags> {
        (any::<bool>(), any::<bool>(), any::<bool>()).prop_map(|(force, split, no_tree)| {
            let mut flags = FileFlags::new();
            if force {
                flags = flags.with_force_text();
            }
            if split {
                flags = flags.with_split(SplitMode::BlankLines);
            }
            if no_tree {
                flags = flags.with_no_fine_tree();
            }
            flags
        })
    }

    #[cfg(feature = "test-util")]
    proptest! {
        // Fixed seed 0x614 — "G14" in the project's task-numbered convention
        // (docs/testing/proptest-conventions.md).
        #![proptest_config(proptest_config(0x0000_0614))]

        /// Every assembled model satisfies every G5/G6/G7 invariant, and
        /// assembly is deterministic on the same input.
        #[test]
        fn every_model_satisfies_the_content_invariants(
            work in proptest::collection::vec((file_bytes(), file_flags()), 0..=6),
        ) {
            let inputs: Vec<FileInput<'_>> = work
                .iter()
                .map(|(bytes, flags)| FileInput::new(bytes, *flags))
                .collect();
            let seeds = |id: FileId| Seed32::from_bytes([u8::try_from(id.0 % 251).unwrap_or(0); 32]);
            let model = assemble_content_model(&inputs, &seeds);

            let violations = model_invariant_violations(&model);
            prop_assert!(violations.is_empty(), "{violations:#?}");

            let again = assemble_content_model(&inputs, &seeds);
            prop_assert_eq!(&model, &again);
        }
    }
}
