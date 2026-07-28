//! File-level evidence stages: reveal-shape classification, partial-reveal
//! isolation, the full-reveal cross-checks, and the raw-mirror ↔ canonical
//! binding (task R4).
//!
//! R3 ([`super::structural`]) decides everything a verifier can see from
//! *structure*; R2 ([`super::unit_stages`]) verifies each revealed unit's
//! bytes. R4 is the layer where those two meet: it asks, per file, **how
//! much of this file the bundle shows**, and then runs the checks that only
//! that answer makes possible.
//!
//! # Reveal shape is derived, never declared (D28 rider 1)
//!
//! A `.sealproof` bundle carries **no** "partial / full" discriminant. The
//! shape is computed from the *signed* manifest's unit table and the
//! bundle's revealed set:
//!
//! ```text
//! N(F)     = { u.unit_id : u ∈ manifest.units, u.file_id = F, u.kind = Normal }
//! R(F)     = N(F) ∩ bundle.revealed
//! full(F) ⟺ N(F) ≠ ∅  ∧  R(F) = N(F)
//! ```
//!
//! A declared shape would be a second, sealer-forgeable source of truth, and
//! declaring "partial" while revealing everything would smuggle back the
//! permissive reading D28 rejected. Three clauses of that predicate are
//! load-bearing and must not be simplified away:
//!
//! - **`kind = Normal` only.** Raw mirrors are exempt *by kind*, never by
//!   position (MVP-SPEC.md line 92; D23 froze the sealer's placement rule,
//!   but a hand-built manifest may violate it). A file is fully revealed
//!   when its canonical-domain units are all revealed **whether or not its
//!   mirror is**; conversely a mirror-only reveal is *partial*. The
//!   exemption is routed through G7's
//!   [`full_reveal_concat_exempt`](crate::content::mirror::full_reveal_concat_exempt())
//!   so there is exactly one definition of it.
//! - **`N(F) ≠ ∅` (anti-vacuity).** R3's tiling accepts a hand-built
//!   `size = 0` file with **zero** units (`cursor == size` at 0). Without
//!   this clause such a file would be *vacuously* fully revealed by every
//!   bundle — including one revealing nothing — and the rule would demand
//!   `file_salt` for a file nobody touched. Mirrors
//!   [`FullFileRevealContext::attest`](crate::crypto::disclosure::FullFileRevealContext::attest),
//!   which already refuses an empty unit list on the generation side.
//! - **`s_root` is conditional on [`FineTree::Present`].** A
//!   `--no-fine-tree` file and an empty file have no fine tree, so demanding
//!   `s_root` for them would reject every honest bundle of that shape.
//!
//! # The frozen check order
//!
//! D27 makes fail-fast the sole normative mode, so the order below is frozen
//! and every input has exactly one first error. Files run in **manifest
//! file-table order** (matching [`super::structural::check_tiling`]);
//! within a file, **file-major** — all of a file's checks, then the next
//! file — because R4's checks are inherently per-file and the report's
//! per-file evidence is assembled file by file.
//!
//! | # | condition | error |
//! |---|---|---|
//! | 1 | `¬full(F)` ∧ `file_salt` present | [`VerifyError::PartialRevealSaltLeak`] `{FileSalt}` |
//! | 2 | `¬full(F)` ∧ `s_root` present | [`VerifyError::PartialRevealSaltLeak`] `{SRoot}` |
//! | 3 | `full(F)` ∧ `file_salt` absent | [`VerifyError::FullRevealMaterialMissing`] `{FileSalt}` |
//! | 4 | `full(F)` ∧ [`FineTree::Present`] ∧ `s_root` absent | [`VerifyError::FullRevealMaterialMissing`] `{SRoot}` |
//! | 5 | `full(F)` ∧ [`FineTree::Absent`] ∧ `s_root` present | [`VerifyError::FullRevealSRootWithoutFineTree`] (D74) |
//! | 6 | present material with the wrong exact length (`file_salt`, then `s_root`) | [`VerifyError::WrongLength`] (defensive; see below) |
//! | 7 | `full(F)`: concat(non-mirror bytes) ≠ `canon_commit`/`raw_commit` | [`VerifyError::ConcatCommitMismatch`] |
//! | 8 | `full(F)` ∧ fine tree: rebuild from `s_root` ≠ `fine_root` | [`VerifyError::FineRootRebuildMismatch`] |
//! | 9 | `full(F)` ∧ mirror revealed: mirror bytes ≠ `raw_commit` | [`VerifyError::RawCommitMismatch`] |
//! | 10 | `full(F)` ∧ mirror revealed ∧ text: `canonicalize_v(raw) ≠ canonical` | [`VerifyError::RawMirrorCanonicalizationMismatch`] |
//!
//! Rows 1–6 are the *classification* pass ([`classify_file_reveal`]); rows
//! 7–10 are the *content* pass ([`check_full_reveal_content`]). Both run
//! inside one file's turn, in that order, so the two arms of the
//! classification cannot drift apart into separate stages (D28 rider 2).
//!
//! Rows 4 and 5 are mutually exclusive ([`FineTree::Present`] versus
//! [`FineTree::Absent`]), so their relative order is unobservable; the
//! classifier writes them as one exhaustive match over the 2×2 of
//! (fine-tree state, `s_root` presence) precisely so all four combinations
//! — two legal, two rejected — are named rather than defaulted. Row 3 does
//! precede row 5, and that ordering is asserted.
//!
//! Row 5 is **D74** (`docs/decisions/D74-extraneous-full-reveal-s-root.md`).
//! It is what makes D28's totality claim total: strip units and the leak arm
//! fires, strip material and the missing arm fires, **add** material and
//! this arm fires — so a third party cannot alter a bundle's reveal shape
//! undetected in any direction.
//!
//! ## Cross-stage precedence
//!
//! R5's stage order is **R3 (structural) → R2 (per-unit) → R4 (file-level)**,
//! so a *present but wrong-length* `file_salt` is caught earlier, by R3
//! group 1, as `wrong-length-file-salt` — never by row 1 or 3. Row 6 is a
//! defensive backstop that yields the *identical* code if R4 is driven
//! directly, mirroring R3's own re-check of `path_salt` in
//! [`check_path_commits`](super::structural::check_path_commits). It is
//! deliberately ordered *after* the presence rules: presence is what rows
//! 1–5 adjudicate, and a hostile length must not be able to displace the
//! shape verdict when R4 is exercised alone.
//!
//! `s_root`'s zero-disclosure claim ("all units revealed ⇒ all leaves
//! revealed", MVP-SPEC.md line 114) holds *because* R3 already proved the
//! non-mirror units tile `[0, size)` exactly. The stage order is therefore
//! load-bearing for the privacy claim, not merely for determinism.
//!
//! # Why strict (D28)
//!
//! `canon_commit` and `raw_commit` have **no other verification path**:
//! `fine_root` and `unit_commit` are checked per unit (R2), `path_commit`
//! per touched file and byte ranges by the tiling invariant (R3). The two
//! whole-file content commitments are checked *only* by row 7. Making that
//! check optional would not weaken it — it would delete it, leaving two
//! signed, anchored, permanently stored fields a sealer may fill with
//! anything. See `docs/decisions/D28-full-reveal-strictness.md`.
//!
//! # The raw-mirror recompute is always [`TextMode::Forced`] (D20)
//!
//! Row 10 recomputes `canonicalize_v(raw_mirror_bytes)` under the
//! descriptor-recorded Unicode version and requires byte-equality with the
//! validated canonical bytes (MVP-SPEC.md line 121). The mode is **not a
//! parameter anywhere in this module's API**: it is fixed inside
//! `recompute_canonical_from_mirror` (private), which no caller can influence.
//!
//! That is enforcement, not preference. A `--force-text` file's mirror bytes
//! are by definition *not* valid UTF-8 (that is why the file needed forcing,
//! and why it needs a mirror at all), so a [`TextMode::Detected`] recompute
//! would return a **decode error** on exactly the files this binding exists
//! to bind. The check must yield an integrity verdict instead. Forced mode
//! is total and byte-identical to detected mode on valid UTF-8, so pinning
//! it costs nothing on ordinary text.
//!
//! # What R4 deliberately does **not** check
//!
//! - **A raw mirror inside a partial reveal.** MVP-SPEC.md line 92's
//!   selection rule ("includable only via a whole-file reveal or `--all`; a
//!   bare `--units <mirror-id>` is rejected") is a *builder* guard against a
//!   mistyped id, enforced at construction by G7's
//!   [`mirror_selectable`](crate::content::mirror::mirror_selectable). A
//!   bundle that ships a mirror alongside a partial reveal discloses only
//!   the sealer's own raw file; the mirror is still bound by `unit_commit`
//!   at R2, and no `file_salt` exists for it to open (rows 1–2). Turning it
//!   into a bundle-validity invariant would mint a permanent code and is not
//!   in line 121's enumeration — it needs its own decision first.
//! - **`raw_commit` on a text full reveal with no mirror in the manifest.**
//!   G7's rule is `needs_mirror ⟺ raw ≠ canonical`, so "no mirror entry"
//!   asserts `raw == canonical` and `raw_commit` *should* open to the
//!   canonical bytes. Checking it would cost one SHA-256 and catch a
//!   manifest that omits a mirror while carrying an unrelated `raw_commit` —
//!   but it is a **new invariant with a new permanent code**, absent from
//!   line 121, from R4's Accept list, and from D28. Recorded here as a
//!   decision candidate rather than implemented.
//! - **Whether a revealed unit's owning file must appear in
//!   `touched_files`.** That is **D80**, open and owned by F8. This module
//!   derives shape from the revealed set *alone*, so its classification is
//!   identical under either resolution — see [`FileRevealShape::Untouched`].
//!
//! # F seam (what R5 supplies)
//!
//! [`FileView`] / [`FileUnitEntry`] / [`FullRevealMaterialEntry`] /
//! [`VerifiedUnitBytes`] are the minimal projection this stage needs,
//! mirroring F5's manifest shapes without depending on them, exactly as R3
//! does. Every wire quantity is `u64` — adversary-controlled wire values are
//! never `usize` (the R2 convention).
//!
//! R5 calls exactly one function:
//!
//! ```text
//! let summaries: Vec<FileRevealSummary> =
//!     check_file_stages(&manifest_view, &bundle_view, &verified)?;
//! ```
//!
//! where `verified[i].bytes` is the `Vec<u8>` R2's
//! [`verify_revealed_unit`](super::unit_stages::verify_revealed_unit)
//! returned for that unit, and the three views are populated from the
//! decoded manifest body and bundle:
//!
//! - [`FileView`] per file-table entry, in **manifest file order** (its
//!   index is the `file_id`, spec line 76): `size`, `canon` from
//!   [`CanonMode`](crate::manifest::body::CanonMode), `raw_commit`, and
//!   `fine_tree` from [`FineTree`](crate::manifest::body::FineTree).
//! - [`FileUnitEntry`] per unit-table entry: `unit_id`, `file_id`, `kind`.
//! - [`FullRevealMaterialEntry`] per bundle full-reveal entry, carrying the
//!   **wire bytes** of `file_salt`/`s_root` — R5 does not pre-convert them,
//!   because their optionality is what the classification adjudicates.
//!
//! The returned summaries are in manifest file order and are material-free;
//! R5 copies `is_full()` into each
//! [`FileReveal::fully_revealed`](super::report::FileReveal) and uses the
//! [`RevealCensus`] counts for the revealed/unrevealed span rendering.
//!
//! # What R7 owes (tamper rows and positive fixtures)
//!
//! Every row below is reachable from this module today; the unit tests here
//! construct each one and can be lifted into R7's registry against R6's
//! fixture builder. Codes are pairwise distinct, so Q7's registry sweep
//! accepts the set:
//!
//! | row id | expected code |
//! |---|---|
//! | `verify-partial-reveal-salt-leak-file-salt` | `partial-reveal-salt-leak-file-salt` |
//! | `verify-partial-reveal-salt-leak-s-root` | `partial-reveal-salt-leak-s-root` |
//! | `verify-full-reveal-missing-file-salt` | `full-reveal-material-missing-file-salt` |
//! | `verify-full-reveal-missing-s-root` | `full-reveal-material-missing-s-root` |
//! | `verify-full-reveal-s-root-without-fine-tree` | `full-reveal-s-root-without-fine-tree` |
//! | `verify-concat-commit-mismatch-canon` | `concat-commit-mismatch-canon` |
//! | `verify-concat-commit-mismatch-raw` | `concat-commit-mismatch-raw` |
//! | `verify-fine-root-rebuild-mismatch` | `fine-root-rebuild-mismatch` |
//! | `verify-raw-commit-mismatch` | `raw-commit-mismatch` |
//! | `verify-raw-mirror-canonicalization-mismatch` | `raw-mirror-canonicalization-mismatch` |
//! | `verify-unknown-unicode-version` | `content-unknown-unicode-version` |
//!
//! **Two things that are deliberately NOT rows:**
//!
//! 1. **The unit-strip downgrade.** Dropping one revealed unit from a
//!    full-reveal bundle (leaving `file_salt` attached) surfaces as
//!    `partial-reveal-salt-leak-file-salt` — the *same* outcome as the
//!    isolation row, because the two mutations are one observable failure.
//!    `check_registry` would correctly refuse the second row. It is asserted
//!    here as the property
//!    `no_single_unit_deletion_from_a_full_reveal_verifies`, and belongs in
//!    R10 (D28's record documents this trap).
//! 2. **A forced-text mirror mismatch.** It shares
//!    `raw-mirror-canonicalization-mismatch` with the ordinary row above.
//!    What R7 owes instead is a **positive fixture** —
//!    `full-reveal-forced-text-mirror`, a full reveal whose raw mirror is
//!    invalid UTF-8, which MUST verify. That fixture is the *only* artifact
//!    that distinguishes a [`TextMode::Forced`] recompute from a
//!    [`TextMode::Detected`] one: under `Detected` it fails with
//!    `content-canonicalize-invalid-utf8`. Without it, D20's mode rule is
//!    untested at the bundle level. Modelled here by
//!    `forced_mode_is_enforced_for_invalid_utf8_mirrors`.
//!
//! The rest of D28's positive-fixture matrix — `full-reveal-fine-tree-text`,
//! `full-reveal-no-fine-tree-binary`, `full-reveal-empty-file`,
//! `full-reveal-via-enumerated-units`, `full-reveal-without-mirror`,
//! `partial-reveal-two-of-three-units`, `degenerate-zero-unit-file` — has one
//! named test each in this module's `tests`, so R6 has a shape checklist and
//! R7 has a "the rule is not over-broad" set.
//!
//! [`FineTree::Present`]: crate::manifest::body::FineTree::Present
//! [`FineTree::Absent`]: crate::manifest::body::FineTree::Absent

use crate::canon::{CanonicalBytes, CanonicalizeError, TextMode, canonicalize_v};
use crate::content::fine_tree::rebuild_fine_root;
use crate::content::mirror::full_reveal_concat_exempt;
use crate::content::unit::UnitKind as ContentUnitKind;
use crate::crypto::commit::{CommitmentDigest, verify_canon_commit, verify_raw_commit};
use crate::crypto::error::SaltKind;
use crate::crypto::material::{FileSalt, Salt16, Seed32};

use super::error::{ContentCommitKind, FullRevealMaterial, LengthField, VerifyError};
use super::structural::UnitKind;

// ---------------------------------------------------------------------------
// manifest-side view
// ---------------------------------------------------------------------------

/// Whether a file has a canonical rendition, and — if it does — the
/// commitment to it plus the Unicode version that produced it
/// (MVP-SPEC.md lines 83, 95; the R-side projection of
/// [`crate::manifest::body::CanonMode`]).
///
/// The text-only fields live inside the `Text` variant, so "`canon_commit`
/// on a binary file" is not a state this type can hold — the same shape F5
/// enforces on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCanonMode<'a> {
    /// Binary: no canonical rendition. The full-reveal concatenation opens
    /// `raw_commit` directly, and there is nothing for the raw-mirror
    /// canonicalization binding to bind to.
    Binary,
    /// Text: the canonical rendition is the tiling/commitment domain.
    Text {
        /// `canon_commit = SHA-256(0x04 ‖ file_salt ‖ canonical_bytes)`.
        canon_commit: &'a CommitmentDigest,
        /// The descriptor's recorded Unicode/canonicalization version —
        /// the `v` of `canonicalize_v` (spec line 121). Never "latest".
        unicode_version: &'a str,
    },
}

/// Whether a file carries a fine tree, and its root if so — the R-side
/// projection of [`crate::manifest::body::FineTree`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFineTree<'a> {
    /// No fine tree (`--no-fine-tree`, or an empty file). A full reveal of
    /// such a file runs only the concatenation check — and must **not**
    /// carry an `s_root` (D74).
    Absent,
    /// A fine tree whose root is the sole content commitment for covered
    /// bytes (spec line 96).
    Present {
        /// `fine_root` — the target of the full-reveal rebuild.
        root: &'a CommitmentDigest,
    },
}

/// The file-level projection of one manifest file-table entry.
#[derive(Debug, Clone, Copy)]
pub struct FileView<'a> {
    /// File id referenced by unit entries and reveal entries (spec line 76).
    pub file_id: u64,
    /// The file's `size` field: tiling-domain width and fine-tree leaf count
    /// (canonical bytes for text, raw for binary; spec line 98).
    pub size: u64,
    /// Text-vs-binary mode, carrying the text-only fields.
    pub canon: FileCanonMode<'a>,
    /// `raw_commit = SHA-256(0x03 ‖ file_salt ‖ raw_bytes)` (spec line 95) —
    /// the concatenation target for a binary file, and the mirror's opening
    /// target for a text file.
    pub raw_commit: &'a CommitmentDigest,
    /// Fine-tree state and root.
    pub fine_tree: FileFineTree<'a>,
}

/// The classification-relevant projection of one manifest unit-table entry.
///
/// Only `file_id` and `kind` participate in the shape predicate: ranges are
/// R3's business, and `kind` is the *sole* input to the raw-mirror exemption
/// (never position — module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileUnitEntry {
    /// Work-global `unit_id`.
    pub unit_id: u64,
    /// Owning file.
    pub file_id: u64,
    /// Normal or raw-mirror.
    pub kind: UnitKind,
}

/// The manifest side of the file-level view.
#[derive(Debug, Clone, Copy)]
pub struct FileStageManifestView<'a> {
    /// File table, in manifest order — the order files are checked in.
    pub files: &'a [FileView<'a>],
    /// Unit table, in manifest order.
    pub units: &'a [FileUnitEntry],
}

// ---------------------------------------------------------------------------
// bundle-side view
// ---------------------------------------------------------------------------

/// The full-reveal material a bundle attaches for one file, **as it arrives
/// on the wire**: both fields optional and both unvalidated
/// (MVP-SPEC.md line 114: per fully revealed file `{file_salt, s_root}`).
///
/// This optionality is exactly what D28's predicate adjudicates. Once
/// classified the material moves into [`FullRevealEvidence`], where it is no
/// longer optional and no longer untyped — a `Full` shape without its
/// `file_salt` is unrepresentable from that point on.
///
/// `Debug` is **redacted by hand**, not derived: this is the one type in the
/// stage that holds raw `file_salt`/`s_root` bytes, and on the path that
/// matters most — a *partial* reveal that leaked them — a derived `Debug`
/// would print the leaked salt straight into whatever log or panic message
/// rendered the view (project rule 6). It shows presence and length, which
/// is all the classification consumes.
#[derive(Clone, Copy)]
pub struct FullRevealMaterialEntry<'a> {
    /// The file this entry claims to describe.
    pub file_id: u64,
    /// The disclosed 16-byte `file_salt`, if the bundle carries one.
    pub file_salt: Option<&'a [u8]>,
    /// The disclosed 32-byte GGM fine-seed root `s_root`, if any.
    pub s_root: Option<&'a [u8]>,
}

impl core::fmt::Debug for FullRevealMaterialEntry<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        /// Presence + length only — never the bytes.
        fn shape(field: Option<&[u8]>) -> String {
            field.map_or_else(
                || "absent".to_owned(),
                |bytes| format!("<redacted; {} B>", bytes.len()),
            )
        }
        f.debug_struct("FullRevealMaterialEntry")
            .field("file_id", &self.file_id)
            .field("file_salt", &shape(self.file_salt))
            .field("s_root", &shape(self.s_root))
            .finish()
    }
}

/// The bundle side of the file-level view.
///
/// Deliberately **no** reveal-shape discriminant: shape is derived (D28
/// rider 1, a binding constraint on F8's bundle schema).
#[derive(Debug, Clone, Copy)]
pub struct FileStageBundleView<'a> {
    /// `unit_id`s the bundle reveals. R3 has already proved every id exists
    /// in the manifest unit table and that there are no duplicates.
    pub revealed_unit_ids: &'a [u64],
    /// Per-file full-reveal material entries, keyed by `file_id`.
    pub full_material: &'a [FullRevealMaterialEntry<'a>],
}

impl<'a> FileStageBundleView<'a> {
    /// The material entry for `file_id`, if the bundle carries one.
    ///
    /// A file with no entry is treated as carrying neither material — the
    /// same state as an entry with both fields `None`, so a bundle cannot
    /// change the verdict by choosing between the two encodings.
    fn material_for(&self, file_id: u64) -> Option<&FullRevealMaterialEntry<'a>> {
        self.full_material
            .iter()
            .find(|entry| entry.file_id == file_id)
    }
}

// ---------------------------------------------------------------------------
// verified unit bytes (R2 → R4 hand-off)
// ---------------------------------------------------------------------------

/// One revealed unit's **verified** bytes, as
/// [`verify_revealed_unit`](super::unit_stages::verify_revealed_unit)
/// returned them, plus the manifest facts R4 needs to filter and order them.
///
/// "Verified" is load-bearing: these bytes have already been authenticated
/// (AEAD), padding-checked, stripped to `true_length`, bound to
/// `true_length == range_width`, and bound to their single content
/// commitment. R4 never re-derives them.
///
/// `Debug` renders the byte **length**, not the bytes. They are not secret —
/// the bundle discloses them by design — but a derived `Debug` would dump a
/// whole document into any log line or panic message that formatted the
/// stage's inputs, which is not a thing a verifier should be able to do by
/// accident.
#[derive(Clone, Copy)]
pub struct VerifiedUnitBytes<'a> {
    /// Work-global `unit_id`.
    pub unit_id: u64,
    /// Owning file.
    pub file_id: u64,
    /// Normal or raw-mirror — the sole input to the concatenation exemption.
    pub kind: UnitKind,
    /// Byte-range start in the unit's own domain, the concatenation sort key.
    pub range_start: u64,
    /// The unit's exact verified bytes.
    pub bytes: &'a [u8],
}

impl core::fmt::Debug for VerifiedUnitBytes<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifiedUnitBytes")
            .field("unit_id", &self.unit_id)
            .field("file_id", &self.file_id)
            .field("kind", &self.kind)
            .field("range_start", &self.range_start)
            .field("bytes", &format_args!("<{} B>", self.bytes.len()))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// reveal shape (the typed classification result)
// ---------------------------------------------------------------------------

/// Which of format v1's **exactly three** per-file reveal shapes a bundle
/// exhibits for one file (D28; derived, never declared).
///
/// This is the verifier-side mirror of C7's generation-side witness pattern:
/// the material is carried **in the type**, so the full-reveal cross-checks
/// cannot be invoked without it and "we forgot to run the cross-check" is a
/// compile error rather than a silent acceptance.
#[derive(Debug)]
pub enum FileRevealShape<'a> {
    /// The bundle reveals **no** unit of this file — neither a normal unit
    /// nor its mirror.
    ///
    /// Derived from the revealed set alone. Whether such a file may
    /// nonetheless appear in `touched_files` (path disclosure without any
    /// byte disclosure), and conversely whether a revealed unit's owner
    /// *must* appear there, is **D80** — open, owned by F8. R4's
    /// classification is identical under either resolution, and the material
    /// rules treat `Untouched` exactly like `Partial`: both are `¬full`, so
    /// both forbid `file_salt`/`s_root`.
    Untouched(RevealCensus),
    /// Some but not all of the file is shown.
    ///
    /// The evidence type has **no slot** for `file_salt` or `s_root`, so
    /// nothing downstream can open `canon_commit`/`raw_commit`/`fine_root`
    /// for a partially revealed file (MVP-SPEC.md line 121, partial-reveal
    /// isolation).
    Partial(PartialRevealEvidence),
    /// Every non-mirror unit of the file is revealed, and the bundle carries
    /// the material that makes the whole-file openings checkable.
    Full(FullRevealEvidence<'a>),
}

impl FileRevealShape<'_> {
    /// The file this shape describes.
    #[must_use]
    pub const fn file_id(&self) -> u64 {
        self.census().file_id
    }

    /// Whether this is a full reveal — the flag R5 copies into the report's
    /// per-file [`FileReveal`](super::report::FileReveal).
    #[must_use]
    pub const fn is_full(&self) -> bool {
        matches!(self, Self::Full(_))
    }

    /// The unit counts the shape predicate was computed from.
    #[must_use]
    pub const fn census(&self) -> RevealCensus {
        match self {
            Self::Untouched(census) => *census,
            Self::Partial(evidence) => evidence.census,
            Self::Full(evidence) => evidence.census,
        }
    }

    /// The material-free classification outcome — **the value R5 keeps**.
    ///
    /// `file_salt`/`s_root` deliberately do not appear: they are consumed
    /// inside this stage and wiped when the shape drops
    /// ([`FileSalt`]/[`Seed32`] are `ZeroizeOnDrop`), so no secret material
    /// escapes into a value the orchestrator holds, renders, or serializes
    /// (project rule 6).
    #[must_use]
    pub const fn summary(&self) -> FileRevealSummary {
        FileRevealSummary {
            census: self.census(),
            kind: match self {
                Self::Untouched(_) => FileRevealKind::Untouched,
                Self::Partial(_) => FileRevealKind::Partial,
                Self::Full(_) => FileRevealKind::Full,
            },
        }
    }
}

/// The per-file unit census the shape predicate is computed from —
/// `|R(F)|` and `|N(F)|` (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevealCensus {
    /// The file this census describes.
    pub file_id: u64,
    /// How many of the file's non-mirror units the bundle reveals (`|R(F)|`).
    pub revealed_non_mirror_units: u64,
    /// How many non-mirror units the file has (`|N(F)|`). Raw mirrors are
    /// excluded from both counts — they are exempt by `kind`.
    pub total_non_mirror_units: u64,
}

/// Format v1's three per-file reveal shapes, as a plain discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRevealKind {
    /// No unit of the file is revealed.
    Untouched,
    /// Some but not all non-mirror units are revealed (or only the mirror).
    Partial,
    /// Every non-mirror unit is revealed, and the material was present.
    Full,
}

/// The material-free classification outcome for one file (see
/// [`FileRevealShape::summary`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRevealSummary {
    /// Which of the three shapes.
    pub kind: FileRevealKind,
    /// The unit counts behind it.
    pub census: RevealCensus,
}

impl FileRevealSummary {
    /// The file this summary describes.
    #[must_use]
    pub const fn file_id(&self) -> u64 {
        self.census.file_id
    }

    /// Whether the file is fully revealed — the report's `fully_revealed`.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        matches!(self.kind, FileRevealKind::Full)
    }
}

/// Evidence of a partial reveal. Structurally incapable of carrying
/// full-reveal material — there is no field for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialRevealEvidence {
    /// The unit counts. `revealed < total`, or the shape would be
    /// [`FileRevealShape::Full`] — except in the anti-vacuity case
    /// `total == 0`, where the file has no canonical content at all and
    /// only its mirror can be revealed.
    pub census: RevealCensus,
}

/// The fine-tree half of a full reveal's material.
///
/// [`Self::Present`] carries `s_root` **and** `fine_root` together, so the
/// rebuild cannot be written without both; [`Self::Absent`] has nowhere to
/// put an `s_root`, which is precisely why a stray one is rejected at
/// classification time rather than silently dropped (D74).
#[derive(Debug)]
pub enum FullRevealFineTree<'a> {
    /// `--no-fine-tree`, or an empty file. No rebuild runs.
    Absent,
    /// A fine tree: rebuild the whole tree from `s_root` over the
    /// concatenated bytes and match `fine_root` (spec line 121).
    Present {
        /// The bundle's 32-byte GGM fine-seed root, length-validated.
        s_root: Seed32,
        /// The manifest's `fine_root` to match.
        fine_root: &'a CommitmentDigest,
    },
}

/// Evidence of a full reveal: the file, its `file_salt`, and its fine-tree
/// material — none of it optional (D28's "enforcement by construction").
///
/// `file_salt` is the opaque [`FileSalt`], constructed here from the
/// bundle-disclosed bytes. A full reveal is the one context in which those
/// bytes are legitimately public (MVP-SPEC.md lines 95, 114), and this type
/// is the only way the file-level checks obtain them.
#[derive(Debug)]
pub struct FullRevealEvidence<'a> {
    /// The unit counts (`|R(F)| == |N(F)| > 0`).
    pub census: RevealCensus,
    /// The manifest entry, carrying the commitments the checks open.
    file: FileView<'a>,
    /// The disclosed content-commitment salt. Not `Option` — a `Full`
    /// without it is unrepresentable.
    file_salt: FileSalt,
    /// The fine-tree material, present iff the manifest records a fine tree.
    fine: FullRevealFineTree<'a>,
}

impl<'a> FullRevealEvidence<'a> {
    /// The fully revealed file.
    #[must_use]
    pub const fn file_id(&self) -> u64 {
        self.census.file_id
    }

    /// The manifest file entry this evidence opens.
    #[must_use]
    pub const fn file(&self) -> &FileView<'a> {
        &self.file
    }

    /// The fine-tree material.
    #[must_use]
    pub const fn fine_tree(&self) -> &FullRevealFineTree<'a> {
        &self.fine
    }

    /// Which whole-file commitment the concatenation check opens
    /// (`canon_commit` for text, `raw_commit` for binary; spec line 121).
    #[must_use]
    pub const fn concat_commit_kind(&self) -> ContentCommitKind {
        match self.file.canon {
            FileCanonMode::Binary => ContentCommitKind::Raw,
            FileCanonMode::Text { .. } => ContentCommitKind::Canon,
        }
    }
}

// ---------------------------------------------------------------------------
// the exemption bridge
// ---------------------------------------------------------------------------

/// Map the verifier's decode-side [`UnitKind`] onto G's model kind, so both
/// the tiling exemption (R3) and the concatenation exemption (here) resolve
/// through **one** definition —
/// [`full_reveal_concat_exempt`](crate::content::mirror::full_reveal_concat_exempt).
///
/// The two enums are distinct types on purpose (a wire projection versus the
/// content model) and they agree today; this bridge is what keeps them
/// agreeing, and what makes the exemption depend on `kind` alone.
const fn as_content_kind(kind: UnitKind) -> ContentUnitKind {
    match kind {
        UnitKind::Normal => ContentUnitKind::Normal,
        UnitKind::RawMirror => ContentUnitKind::RawMirror,
    }
}

/// Does this unit participate in the file's tiling / full-reveal
/// concatenation domain? (`true` for everything except a raw mirror.)
#[must_use]
pub const fn participates_in_concat(kind: UnitKind) -> bool {
    !full_reveal_concat_exempt(as_content_kind(kind))
}

// ---------------------------------------------------------------------------
// stage 1: classification + the material rules (D28 rows 1–5, +6)
// ---------------------------------------------------------------------------

/// Classify one file's reveal shape and enforce the material rules
/// (module-doc rows 1–6).
///
/// This is the single fallible classification point D28 rider 2 requires:
/// the partial-reveal isolation arm and the full-reveal missing-material arm
/// are the two consequences of *one* predicate, so they live here together
/// and cannot drift.
///
/// # Errors
///
/// In the frozen order of the module-doc table:
/// [`VerifyError::PartialRevealSaltLeak`] (rows 1–2),
/// [`VerifyError::FullRevealMaterialMissing`] (rows 3–4),
/// [`VerifyError::FullRevealSRootWithoutFineTree`] (row 5, D74), then
/// [`VerifyError::WrongLength`] (row 6, defensive — R3 group 1 is the
/// normative site).
pub fn classify_file_reveal<'a>(
    file: &FileView<'a>,
    units: &[FileUnitEntry],
    bundle: &FileStageBundleView<'_>,
) -> Result<FileRevealShape<'a>, VerifyError> {
    let file_id = file.file_id;

    // N(F): the file's non-mirror units — the tiling/concatenation domain.
    // R(F): those of them the bundle reveals.
    let mut total_non_mirror: u64 = 0;
    let mut revealed_non_mirror: u64 = 0;
    let mut revealed_any = false;
    for unit in units.iter().filter(|unit| unit.file_id == file_id) {
        let revealed = bundle.revealed_unit_ids.contains(&unit.unit_id);
        revealed_any |= revealed;
        if participates_in_concat(unit.kind) {
            total_non_mirror += 1;
            revealed_non_mirror += u64::from(revealed);
        }
    }

    // full(F) ⟺ N(F) ≠ ∅ ∧ R(F) = N(F). The non-emptiness clause is the
    // anti-vacuity guard (module docs): without it a hand-built zero-unit
    // file would be "fully revealed" by a bundle revealing nothing.
    let full = total_non_mirror > 0 && revealed_non_mirror == total_non_mirror;
    let census = RevealCensus {
        file_id,
        revealed_non_mirror_units: revealed_non_mirror,
        total_non_mirror_units: total_non_mirror,
    };

    let material = bundle.material_for(file_id);
    let file_salt_bytes = material.and_then(|entry| entry.file_salt);
    let s_root_bytes = material.and_then(|entry| entry.s_root);

    if !full {
        // Rows 1–2 — partial-reveal isolation (MVP-SPEC.md line 121). Note
        // this covers the untouched case too: forbidden material is
        // forbidden on any file that is not fully revealed.
        if file_salt_bytes.is_some() {
            return Err(VerifyError::PartialRevealSaltLeak {
                file_id,
                material: FullRevealMaterial::FileSalt,
            });
        }
        if s_root_bytes.is_some() {
            return Err(VerifyError::PartialRevealSaltLeak {
                file_id,
                material: FullRevealMaterial::SRoot,
            });
        }
        return Ok(if revealed_any {
            FileRevealShape::Partial(PartialRevealEvidence { census })
        } else {
            FileRevealShape::Untouched(census)
        });
    }

    // Row 3 — a full reveal MUST carry its `file_salt` (D28: strict).
    let Some(file_salt_bytes) = file_salt_bytes else {
        return Err(VerifyError::FullRevealMaterialMissing {
            file_id,
            material: FullRevealMaterial::FileSalt,
        });
    };

    // Rows 4–5 — **presence** of `s_root`: required iff the manifest records
    // a fine tree (row 4), and forbidden iff it does not (row 5, D74: the
    // present set must equal the required set — C14's precedent). The match
    // is exhaustive over the 2×2 of (fine-tree state, `s_root` presence), so
    // the two legal combinations and the two rejected ones are all named.
    let fine_material: Option<(&[u8], &'a CommitmentDigest)> = match (file.fine_tree, s_root_bytes)
    {
        (FileFineTree::Present { root }, Some(bytes)) => Some((bytes, root)),
        (FileFineTree::Absent, None) => None,
        (FileFineTree::Present { .. }, None) => {
            return Err(VerifyError::FullRevealMaterialMissing {
                file_id,
                material: FullRevealMaterial::SRoot,
            });
        }
        (FileFineTree::Absent, Some(_)) => {
            return Err(VerifyError::FullRevealSRootWithoutFineTree { file_id });
        }
    };

    // Row 6 — the defensive exact-length conversions, strictly after every
    // presence rule and in the same material order rows 1/3 and 2/4 use
    // (`file_salt`, then `s_root`). R3 group 1 already ran these checks and
    // is the normative site; repeating them costs nothing and keeps
    // `classify_file_reveal` correct when driven directly (module docs).
    let file_salt = Salt16::try_from_slice(SaltKind::File, file_salt_bytes).map_err(|_| {
        VerifyError::WrongLength {
            field: LengthField::FileSalt,
            expected: LengthField::FileSalt.spec_len(),
            actual: len_u64(file_salt_bytes),
        }
    })?;

    let fine = match fine_material {
        None => FullRevealFineTree::Absent,
        Some((bytes, fine_root)) => FullRevealFineTree::Present {
            s_root: Seed32::try_from(bytes).map_err(|_| VerifyError::WrongLength {
                field: LengthField::SRoot,
                expected: LengthField::SRoot.spec_len(),
                actual: len_u64(bytes),
            })?,
            fine_root,
        },
    };

    Ok(FileRevealShape::Full(FullRevealEvidence {
        census,
        file: *file,
        file_salt: FileSalt::from_disclosed(file_salt),
        fine,
    }))
}

// ---------------------------------------------------------------------------
// stage 2: the full-reveal content checks (rows 7–10)
// ---------------------------------------------------------------------------

/// Concatenate a file's **non-mirror** verified unit bytes in byte-range
/// order (MVP-SPEC.md lines 92, 121: the concatenation applies "only to the
/// file's non-mirror, canonical-domain units").
///
/// Ordering is by `range_start` and does not rely on input order: R3 already
/// proved the manifest's non-mirror ranges are sorted and tile `[0, size)`
/// exactly, so sorting here is a no-op on any bundle that reached this
/// stage — but it means the concatenation's meaning does not depend on the
/// order R5 happened to collect the units in.
///
/// The exemption is by `kind` alone, through G7's predicate — never by
/// position (D23 is a *sealer* rule a hand-built manifest may violate).
#[must_use]
pub fn concat_non_mirror_bytes(file_id: u64, units: &[VerifiedUnitBytes<'_>]) -> Vec<u8> {
    let mut parts: Vec<&VerifiedUnitBytes<'_>> = units
        .iter()
        .filter(|unit| unit.file_id == file_id && participates_in_concat(unit.kind))
        .collect();
    // Stable sort on the range start; `unit_id` breaks ties so the result is
    // total even for the degenerate equal-start ranges a hostile manifest
    // could present (R3 would already have rejected them).
    parts.sort_by_key(|unit| (unit.range_start, unit.unit_id));

    let mut content = Vec::with_capacity(parts.iter().map(|unit| unit.bytes.len()).sum());
    for unit in parts {
        content.extend_from_slice(unit.bytes);
    }
    content
}

/// Row 7 — the concatenated non-mirror bytes must open the file's whole-file
/// content commitment under the disclosed `file_salt`: `canon_commit` for
/// text, `raw_commit` for binary (MVP-SPEC.md line 121).
///
/// This is the **only** verification path either commitment has (D28
/// rationale 1).
///
/// # Errors
///
/// [`VerifyError::ConcatCommitMismatch`], carrying which commitment failed.
pub fn check_concat_commit(
    evidence: &FullRevealEvidence<'_>,
    content: &[u8],
) -> Result<(), VerifyError> {
    let outcome = match evidence.file.canon {
        FileCanonMode::Text { canon_commit, .. } => {
            verify_canon_commit(&evidence.file_salt, content, canon_commit)
        }
        FileCanonMode::Binary => {
            verify_raw_commit(&evidence.file_salt, content, evidence.file.raw_commit)
        }
    };
    outcome.map_err(|_| VerifyError::ConcatCommitMismatch {
        file_id: evidence.file_id(),
        commit: evidence.concat_commit_kind(),
    })
}

/// Row 8 — rebuild the whole fine tree from the bundled `s_root` over the
/// concatenated bytes and match `fine_root` (MVP-SPEC.md line 121: "the
/// verifier MUST rebuild").
///
/// A `--no-fine-tree` file (and an empty file) has
/// [`FullRevealFineTree::Absent`] and this check is a no-op — R4's Accept
/// bullet: such a full reveal "runs only the concat→commit check".
///
/// The rebuild goes through G9's
/// [`rebuild_fine_root`](crate::content::fine_tree::rebuild_fine_root()), the
/// *same* [`FineTreeBuilder`](crate::content::fine_tree::FineTreeBuilder) the
/// sealer ran — deliberately not a second implementation that could drift.
/// It returns `None` only for empty content, which contradicts a manifest
/// claiming a fine tree; that contradiction is reported as the same
/// integrity verdict rather than a distinct code, because the verifier
/// cannot tell a lying `fine_tree_present` from a lying `size`.
///
/// # Errors
///
/// [`VerifyError::FineRootRebuildMismatch`].
pub fn check_fine_root_rebuild(
    evidence: &FullRevealEvidence<'_>,
    content: &[u8],
) -> Result<(), VerifyError> {
    let FullRevealFineTree::Present { s_root, fine_root } = &evidence.fine else {
        return Ok(());
    };
    let rebuilt =
        rebuild_fine_root(s_root, content).ok_or(VerifyError::FineRootRebuildMismatch {
            file_id: evidence.file_id(),
        })?;
    if rebuilt.as_bytes() == *fine_root {
        Ok(())
    } else {
        Err(VerifyError::FineRootRebuildMismatch {
            file_id: evidence.file_id(),
        })
    }
}

/// Recompute a raw mirror's canonical rendition — **always** in
/// [`TextMode::Forced`] (decision D20).
///
/// The mode is fixed here and appears in no signature this module exposes,
/// so no call site can select [`TextMode::Detected`]. See the module docs
/// for why that is a correctness requirement rather than a preference: a
/// `--force-text` file's mirror bytes are not valid UTF-8, and a detected
/// recompute would answer with a *decode error* on exactly the files this
/// binding exists to bind.
fn recompute_canonical_from_mirror(
    unicode_version: &str,
    raw_bytes: &[u8],
) -> Result<CanonicalBytes, CanonicalizeError> {
    canonicalize_v(unicode_version, TextMode::Forced, raw_bytes)
}

/// Rows 9–10 — the revealed raw mirror's two checks, in frozen order
/// (MVP-SPEC.md lines 92, 121):
///
/// 9. the mirror's bytes open `raw_commit = SHA-256(0x03 ‖ file_salt ‖
///    raw_bytes)` — the "these are the exact original bytes" path;
/// 10. **raw-mirror ↔ canonical binding**: `canonicalize_v(raw_bytes)` under
///     the descriptor-recorded version equals the validated canonical bytes,
///     so a sealer cannot co-timestamp an "original" that does not
///     canonicalize to the sealed content.
///
/// Row 10 runs for **text** files only: a binary file has no canonical
/// rendition (spec line 83), so there is nothing to bind — and a mirror on a
/// binary file is already forced to equal the file's own bytes, since row 7
/// and row 9 open the *same* `raw_commit` with the concatenation and with
/// the mirror respectively.
///
/// `canonical` is the concatenation row 7 validated. Passing anything else
/// would bind the mirror to unvalidated bytes, which is why this function
/// takes the same slice `check_concat_commit` accepted.
///
/// # Errors
///
/// [`VerifyError::RawCommitMismatch`] (row 9),
/// [`VerifyError::RawMirrorCanonicalizationMismatch`] (row 10), or
/// [`VerifyError::Canon`] when the descriptor names a
/// Unicode/canonicalization version this build does not register — "upgrade
/// the verifier", explicitly **not** an integrity verdict.
pub fn check_raw_mirror(
    evidence: &FullRevealEvidence<'_>,
    mirror_bytes: &[u8],
    canonical: &[u8],
) -> Result<(), VerifyError> {
    let file_id = evidence.file_id();

    // Row 9 — the file_salt-keyed raw_commit opening.
    verify_raw_commit(&evidence.file_salt, mirror_bytes, evidence.file.raw_commit)
        .map_err(|_| VerifyError::RawCommitMismatch { file_id })?;

    // Row 10 — the canonicalization binding, text only.
    let FileCanonMode::Text {
        unicode_version, ..
    } = evidence.file.canon
    else {
        return Ok(());
    };

    let recomputed = recompute_canonical_from_mirror(unicode_version, mirror_bytes)
        .map_err(VerifyError::Canon)?;
    if recomputed.as_bytes() == canonical {
        Ok(())
    } else {
        Err(VerifyError::RawMirrorCanonicalizationMismatch { file_id })
    }
}

/// Rows 7–10 for one fully revealed file, in the frozen order.
///
/// Takes `&FullRevealEvidence` by design (D28's "enforcement by
/// construction"): the concatenation opening, the tree rebuild, and the
/// mirror's `raw_commit` opening cannot be invoked without the material, so
/// forgetting a cross-check is a compile error, not a silent acceptance.
///
/// The file's revealed mirror, if any, is found **by `kind`** among the
/// verified units — never by position.
///
/// # Errors
///
/// [`VerifyError::ConcatCommitMismatch`],
/// [`VerifyError::FineRootRebuildMismatch`],
/// [`VerifyError::RawCommitMismatch`],
/// [`VerifyError::RawMirrorCanonicalizationMismatch`], or
/// [`VerifyError::Canon`] — first failure wins (D27).
pub fn check_full_reveal_content(
    evidence: &FullRevealEvidence<'_>,
    units: &[VerifiedUnitBytes<'_>],
) -> Result<(), VerifyError> {
    let content = concat_non_mirror_bytes(evidence.file_id(), units);

    check_concat_commit(evidence, &content)?;
    check_fine_root_rebuild(evidence, &content)?;

    if let Some(mirror) = units
        .iter()
        .find(|unit| unit.file_id == evidence.file_id() && !participates_in_concat(unit.kind))
    {
        check_raw_mirror(evidence, mirror.bytes, &content)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// the stage entry point R5 calls
// ---------------------------------------------------------------------------

/// Run every file-level check in the frozen order (module docs): files in
/// manifest file-table order, file-major within each file.
///
/// **This is the seam R5 calls**, after R3's structural stage and after R2
/// has produced the per-unit verified bytes:
///
/// ```text
/// let summaries = check_file_stages(&manifest_view, &bundle_view, &verified)?;
/// ```
///
/// It returns one [`FileRevealSummary`] per manifest file, in manifest file
/// order, so R5 can populate the report's reveal set (`fully_revealed`,
/// revealed spans, unrevealed spans) without re-deriving the classification —
/// there must be exactly one place that decides what "fully revealed" means.
///
/// The summaries are **material-free by construction**: `file_salt` and
/// `s_root` live only for the duration of one file's checks and are wiped
/// when the [`FileRevealShape`] drops at the end of that iteration.
///
/// # Errors
///
/// The first violation, per D27's fail-fast contract — any of the errors
/// listed in the module-doc table.
pub fn check_file_stages(
    manifest: &FileStageManifestView<'_>,
    bundle: &FileStageBundleView<'_>,
    verified: &[VerifiedUnitBytes<'_>],
) -> Result<Vec<FileRevealSummary>, VerifyError> {
    let mut summaries = Vec::with_capacity(manifest.files.len());
    for file in manifest.files {
        let shape = classify_file_reveal(file, manifest.units, bundle)?;
        if let FileRevealShape::Full(evidence) = &shape {
            check_full_reveal_content(evidence, verified)?;
        }
        summaries.push(shape.summary());
    }
    Ok(summaries)
}

/// `usize → u64`, total on every supported target (the R2 convention).
fn len_u64(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::{UNICODE_17_0_0, UnicodeVersion, canonicalize};
    use crate::content::fine_tree::FineRoot;
    use crate::crypto::commit::{canon_commit, raw_commit};
    // Property tests need the proptest-bearing `test-util` tier, which the
    // wasm32 `--lib` test build deliberately does not enable (P14,
    // docs/wasm-toolchain.md). Everything else in this module runs on both.
    #[cfg(feature = "test-util")]
    use crate::test_util::strategies::proptest_config;
    #[cfg(feature = "test-util")]
    use proptest::prelude::*;

    /// Fixed, public, NON-SECRET test material (project rule 6). These are
    /// not derived from any `W` and appear in no committed artifact.
    const TEST_FILE_SALT: [u8; 16] = [0x11u8; 16];
    const OTHER_FILE_SALT: [u8; 16] = [0x22u8; 16];
    const TEST_S_ROOT: [u8; 32] = [0x33u8; 32];
    const OTHER_S_ROOT: [u8; 32] = [0x44u8; 32];

    fn file_salt() -> FileSalt {
        FileSalt::from_disclosed(Salt16::from_bytes(TEST_FILE_SALT))
    }

    fn seed() -> Seed32 {
        Seed32::from_bytes(TEST_S_ROOT)
    }

    fn canon_bytes(raw: &[u8]) -> CanonicalBytes {
        canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, raw).expect("forced text is total")
    }

    /// An owned, self-consistent single-file fixture: the manifest
    /// commitments really do open to the content, so every negative test
    /// perturbs exactly one thing.
    struct Fixture {
        file_id: u64,
        size: u64,
        content: Vec<u8>,
        mirror: Option<Vec<u8>>,
        canon_commit: CommitmentDigest,
        raw_commit: CommitmentDigest,
        fine_root: Option<CommitmentDigest>,
        text: bool,
        unicode_version: String,
    }

    impl Fixture {
        /// A text file whose canonical rendition is derived from `raw`
        /// through the real pipeline; a mirror is attached iff raw differs.
        fn text(file_id: u64, raw: &[u8], fine_tree: bool) -> Self {
            let canonical = canon_bytes(raw);
            let content = canonical.as_bytes().to_vec();
            let mirror = (raw != content.as_slice()).then(|| raw.to_vec());
            let salt = file_salt();
            Self {
                file_id,
                size: content.len() as u64,
                canon_commit: canon_commit(&salt, &content),
                raw_commit: raw_commit(&salt, raw),
                fine_root: fine_tree
                    .then(|| rebuild_fine_root(&seed(), &content).map(|r| *r.as_bytes()))
                    .flatten(),
                content,
                mirror,
                text: true,
                unicode_version: UNICODE_17_0_0.to_owned(),
            }
        }

        /// A binary file: the concatenation opens `raw_commit` directly.
        fn binary(file_id: u64, bytes: &[u8], fine_tree: bool) -> Self {
            let salt = file_salt();
            Self {
                file_id,
                size: bytes.len() as u64,
                content: bytes.to_vec(),
                mirror: None,
                canon_commit: [0u8; 32],
                raw_commit: raw_commit(&salt, bytes),
                fine_root: fine_tree
                    .then(|| rebuild_fine_root(&seed(), bytes).map(|r| *r.as_bytes()))
                    .flatten(),
                text: false,
                unicode_version: String::new(),
            }
        }

        fn view(&self) -> FileView<'_> {
            FileView {
                file_id: self.file_id,
                size: self.size,
                canon: if self.text {
                    FileCanonMode::Text {
                        canon_commit: &self.canon_commit,
                        unicode_version: &self.unicode_version,
                    }
                } else {
                    FileCanonMode::Binary
                },
                raw_commit: &self.raw_commit,
                fine_tree: match &self.fine_root {
                    Some(root) => FileFineTree::Present { root },
                    None => FileFineTree::Absent,
                },
            }
        }

        /// Unit ids 0.. for the content units (one per `split` chunk), then
        /// the mirror's id last when present (D23's placement, which the
        /// verifier must not *rely* on — see `mirror_exempt_by_kind`).
        fn units(&self, splits: usize) -> Vec<FileUnitEntry> {
            let mut units: Vec<FileUnitEntry> = (0..splits)
                .map(|i| FileUnitEntry {
                    unit_id: i as u64,
                    file_id: self.file_id,
                    kind: UnitKind::Normal,
                })
                .collect();
            if self.mirror.is_some() {
                units.push(FileUnitEntry {
                    unit_id: splits as u64,
                    file_id: self.file_id,
                    kind: UnitKind::RawMirror,
                });
            }
            units
        }

        /// The verified per-unit bytes, split into `splits` contiguous
        /// chunks, plus the mirror when present.
        fn verified(&self, splits: usize) -> Vec<VerifiedUnitBytes<'_>> {
            let chunk = self.content.len().div_ceil(splits.max(1));
            let mut out: Vec<VerifiedUnitBytes<'_>> = Vec::new();
            for i in 0..splits {
                let start = (i * chunk).min(self.content.len());
                let end = ((i + 1) * chunk).min(self.content.len());
                out.push(VerifiedUnitBytes {
                    unit_id: i as u64,
                    file_id: self.file_id,
                    kind: UnitKind::Normal,
                    range_start: start as u64,
                    bytes: &self.content[start..end],
                });
            }
            if let Some(mirror) = &self.mirror {
                out.push(VerifiedUnitBytes {
                    unit_id: splits as u64,
                    file_id: self.file_id,
                    kind: UnitKind::RawMirror,
                    range_start: 0,
                    bytes: mirror,
                });
            }
            out
        }

        fn all_unit_ids(&self, splits: usize) -> Vec<u64> {
            self.units(splits)
                .into_iter()
                .map(|unit| unit.unit_id)
                .collect()
        }

        fn material(&self) -> FullRevealMaterialEntry<'_> {
            FullRevealMaterialEntry {
                file_id: self.file_id,
                file_salt: Some(&TEST_FILE_SALT),
                s_root: self.fine_root.as_ref().map(|_| &TEST_S_ROOT[..]),
            }
        }
    }

    fn bundle<'a>(
        revealed: &'a [u64],
        material: &'a [FullRevealMaterialEntry<'a>],
    ) -> FileStageBundleView<'a> {
        FileStageBundleView {
            revealed_unit_ids: revealed,
            full_material: material,
        }
    }

    /// Drive the whole stage over one fixture.
    fn run(
        fixture: &Fixture,
        splits: usize,
        revealed: &[u64],
        material: &[FullRevealMaterialEntry<'_>],
    ) -> Result<Vec<FileRevealSummary>, VerifyError> {
        let files = [fixture.view()];
        let units = fixture.units(splits);
        let verified: Vec<VerifiedUnitBytes<'_>> = fixture
            .verified(splits)
            .into_iter()
            .filter(|unit| revealed.contains(&unit.unit_id))
            .collect();
        check_file_stages(
            &FileStageManifestView {
                files: &files,
                units: &units,
            },
            &bundle(revealed, material),
            &verified,
        )
    }

    // ── positive fixtures (D28's shape matrix) ──────────────────────────

    /// `full-reveal-fine-tree-text`: the base case — all units +
    /// `file_salt` + `s_root`, with a CRLF raw mirror, exercising every one
    /// of rows 7–10.
    #[test]
    fn full_reveal_fine_tree_text_verifies() {
        let fixture = Fixture::text(0, b"alpha\r\n\r\nbeta\r\n", true);
        assert!(fixture.mirror.is_some(), "CRLF source needs a mirror");
        assert!(fixture.fine_root.is_some());

        let ids = fixture.all_unit_ids(2);
        let material = [fixture.material()];
        let shapes = run(&fixture, 2, &ids, &material).expect("the base full reveal verifies");
        assert_eq!(shapes.len(), 1);
        assert!(shapes[0].is_full());
        assert_eq!(shapes[0].file_id(), 0);
    }

    /// R4 accept, stated directly against the four sub-checks: a
    /// text-with-mirror full reveal runs **all of** concat→`canon_commit`,
    /// tree rebuild→`fine_root`, mirror→`raw_commit`, and
    /// `canonicalize_v(raw) == canonical` — and a `--no-fine-tree` full
    /// reveal runs *only* the concat check.
    ///
    /// Each check is proven load-bearing on this same fixture shape by its
    /// own negative test below (`concat_commit_mismatch_rows`,
    /// `fine_root_rebuild_mismatch_row`, `raw_commit_mismatch_row`,
    /// `raw_mirror_canonicalization_mismatch_row`).
    #[test]
    fn text_with_mirror_runs_all_four_checks_and_no_fine_tree_runs_one() {
        let fixture = Fixture::text(0, b"alpha\r\n\r\nbeta\r\n", true);
        let files = [fixture.view()];
        let units = fixture.units(2);
        let material = [fixture.material()];
        let verified = fixture.verified(2);
        let shape = classify_file_reveal(
            &files[0],
            &units,
            &bundle(&fixture.all_unit_ids(2), &material),
        )
        .expect("classifies as Full");
        let FileRevealShape::Full(evidence) = &shape else {
            panic!("expected a full reveal, got {shape:?}");
        };
        assert_eq!(evidence.concat_commit_kind(), ContentCommitKind::Canon);
        assert!(matches!(
            evidence.fine_tree(),
            FullRevealFineTree::Present { .. }
        ));

        let content = concat_non_mirror_bytes(0, &verified);
        assert_eq!(content, fixture.content, "the two units reassemble");
        check_concat_commit(evidence, &content).expect("concat opens canon_commit");
        check_fine_root_rebuild(evidence, &content).expect("rebuild matches fine_root");
        let mirror = fixture.mirror.as_ref().expect("CRLF source has a mirror");
        check_raw_mirror(evidence, mirror, &content)
            .expect("mirror opens raw_commit and canonicalizes to the content");

        // The `--no-fine-tree` shape: the rebuild is structurally a no-op,
        // and it is the *type* that says so.
        let binary = Fixture::binary(1, b"binary payload", false);
        let files = [binary.view()];
        let no_tree = [FullRevealMaterialEntry {
            file_id: 1,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: None,
        }];
        let shape = classify_file_reveal(&files[0], &binary.units(1), &bundle(&[0], &no_tree))
            .expect("classifies as Full");
        let FileRevealShape::Full(evidence) = &shape else {
            panic!("expected a full reveal, got {shape:?}");
        };
        assert_eq!(evidence.concat_commit_kind(), ContentCommitKind::Raw);
        assert!(matches!(evidence.fine_tree(), FullRevealFineTree::Absent));
        check_fine_root_rebuild(evidence, &binary.content)
            .expect("no fine tree => no rebuild to run");
        // Even a wholly wrong byte string cannot fail the absent rebuild.
        check_fine_root_rebuild(evidence, b"nonsense").expect("still a no-op");
    }

    /// `full-reveal-no-fine-tree-binary`: all units + `file_salt`, **no**
    /// `s_root` — the `s_root` clause is conditional on `FineTree::Present`
    /// (R4 accept: a `--no-fine-tree` full reveal runs only the concat
    /// check).
    #[test]
    fn full_reveal_no_fine_tree_binary_verifies_without_s_root() {
        let fixture = Fixture::binary(3, &[0x00, 0xFF, 0x7E, 0x00], false);
        let material = [FullRevealMaterialEntry {
            file_id: 3,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: None,
        }];
        let shapes = run(&fixture, 1, &[0], &material).expect("no-fine-tree full reveal verifies");
        assert!(shapes[0].is_full());
        assert_eq!(shapes[0].census.total_non_mirror_units, 1);
    }

    /// `full-reveal-empty-file`: size 0, one `[0,0)` unit, `file_salt` only
    /// — R4 accept, and the case where the `file_salt` opening carries most
    /// of the evidence (D28: "strictness matters most in the degenerate
    /// case").
    #[test]
    fn full_reveal_empty_file_verifies() {
        let fixture = Fixture::binary(1, b"", false);
        assert_eq!(fixture.size, 0);
        let material = [FullRevealMaterialEntry {
            file_id: 1,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: None,
        }];
        let shapes = run(&fixture, 1, &[0], &material).expect("the empty file is a full reveal");
        assert!(shapes[0].is_full());
    }

    /// `full-reveal-via-enumerated-units`: `--units <every non-mirror id>`
    /// classifies **identically** to `--all` for that file (R4 accept).
    /// Shape is derived from the revealed set, so the two cannot differ.
    #[test]
    fn enumerated_units_classify_identically_to_all() {
        let fixture = Fixture::text(0, b"one\n\ntwo\n\nthree\n", true);
        assert!(fixture.mirror.is_none(), "already-canonical: no mirror");
        let material = [fixture.material()];

        let enumerated = run(&fixture, 3, &[0, 1, 2], &material).expect("enumerated verifies");
        let all = run(&fixture, 3, &fixture.all_unit_ids(3), &material).expect("--all verifies");
        assert!(enumerated[0].is_full() && all[0].is_full());
    }

    /// `full-reveal-without-mirror`: every canonical unit + material, the
    /// mirror withheld. The mirror is not part of the predicate (D28), so
    /// this is still a full reveal — rows 9–10 simply do not run.
    #[test]
    fn full_reveal_without_the_mirror_is_still_full() {
        let fixture = Fixture::text(0, "\u{FEFF}alpha\n".as_bytes(), true);
        assert!(fixture.mirror.is_some(), "BOM source needs a mirror");
        let material = [fixture.material()];

        // Reveal unit 0 (the only canonical unit) but not unit 1 (mirror).
        let shapes = run(&fixture, 1, &[0], &material).expect("full without the mirror verifies");
        assert!(shapes[0].is_full());
    }

    /// `partial-reveal-two-of-three-units`: neither material present —
    /// absence is *correct* on a partial reveal.
    #[test]
    fn partial_reveal_without_material_verifies() {
        let fixture = Fixture::text(0, b"one\n\ntwo\n\nthree\n", true);
        let shapes = run(&fixture, 3, &[0, 1], &[]).expect("a partial reveal with no material");
        assert_eq!(shapes[0].kind, FileRevealKind::Partial);
        assert_eq!(shapes[0].census.revealed_non_mirror_units, 2);
        assert_eq!(shapes[0].census.total_non_mirror_units, 3);
    }

    /// `degenerate-zero-unit-file`: the anti-vacuity clause. A hand-built
    /// size-0 file with **zero** units (which R3's tiling accepts) is *not*
    /// fully revealed by a bundle revealing nothing, so nothing is demanded
    /// of it — and attaching material to it is still a leak.
    #[test]
    fn zero_unit_file_is_not_vacuously_full() {
        let raw_commit_value = [0u8; 32];
        let files = [FileView {
            file_id: 7,
            size: 0,
            canon: FileCanonMode::Binary,
            raw_commit: &raw_commit_value,
            fine_tree: FileFineTree::Absent,
        }];
        let manifest = FileStageManifestView {
            files: &files,
            units: &[],
        };

        let shapes = check_file_stages(&manifest, &bundle(&[], &[]), &[])
            .expect("a zero-unit file demands nothing");
        assert_eq!(shapes[0].kind, FileRevealKind::Untouched);

        // …and it is emphatically not a licence to attach `file_salt`.
        let material = [FullRevealMaterialEntry {
            file_id: 7,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: None,
        }];
        assert_eq!(
            check_file_stages(&manifest, &bundle(&[], &material), &[])
                .expect_err("material on a non-full file leaks")
                .code(),
            "partial-reveal-salt-leak-file-salt"
        );
    }

    /// A mirror-only reveal is **partial** (D28), so it carries no
    /// `file_salt` — which is exactly why line 92 says the mirror's
    /// `raw_commit` opening happens only "when proving exact original
    /// bytes".
    #[test]
    fn mirror_only_reveal_is_partial() {
        let fixture = Fixture::text(0, b"alpha\r\n", true);
        let mirror_id = fixture.mirror.as_ref().map(|_| 1).expect("mirror exists");
        let shapes = run(&fixture, 1, &[mirror_id], &[]).expect("mirror-only reveal classifies");
        assert_eq!(shapes[0].kind, FileRevealKind::Partial);
    }

    // ── rows 1–5: the material rules ────────────────────────────────────

    /// Rows 1–2: partial-reveal isolation, one distinct code per material
    /// (the spec's own line-168 row, split per material).
    #[test]
    fn partial_reveal_salt_leak_rows() {
        let fixture = Fixture::text(0, b"one\n\ntwo\n", true);

        let leak_salt = [FullRevealMaterialEntry {
            file_id: 0,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: None,
        }];
        assert_eq!(
            run(&fixture, 2, &[0], &leak_salt)
                .expect_err("file_salt on a partial reveal")
                .code(),
            "partial-reveal-salt-leak-file-salt"
        );

        let leak_s_root = [FullRevealMaterialEntry {
            file_id: 0,
            file_salt: None,
            s_root: Some(&TEST_S_ROOT),
        }];
        assert_eq!(
            run(&fixture, 2, &[0], &leak_s_root)
                .expect_err("s_root on a partial reveal")
                .code(),
            "partial-reveal-salt-leak-s-root"
        );

        // Row 1 precedes row 2: with both leaked, `file_salt` wins.
        let both = [FullRevealMaterialEntry {
            file_id: 0,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: Some(&TEST_S_ROOT),
        }];
        assert_eq!(
            run(&fixture, 2, &[0], &both)
                .expect_err("both leaked")
                .code(),
            "partial-reveal-salt-leak-file-salt"
        );
    }

    /// Rows 3–4 (D28's strictness): a full reveal missing its material
    /// hard-fails, one distinct code per material. This is the third-party
    /// proof-downgrade attack — a 48-byte deletion in transit.
    #[test]
    fn full_reveal_missing_material_rows() {
        let fixture = Fixture::text(0, b"alpha\r\nbeta\r\n", true);
        let ids = fixture.all_unit_ids(1);

        // No material entry at all.
        assert_eq!(
            run(&fixture, 1, &ids, &[])
                .expect_err("full reveal without file_salt")
                .code(),
            "full-reveal-material-missing-file-salt"
        );

        // `file_salt` present, `s_root` stripped.
        let no_s_root = [FullRevealMaterialEntry {
            file_id: 0,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: None,
        }];
        assert_eq!(
            run(&fixture, 1, &ids, &no_s_root)
                .expect_err("full reveal of a fine-tree file without s_root")
                .code(),
            "full-reveal-material-missing-s-root"
        );

        // An entry present but empty is the same verdict as no entry —
        // a bundle cannot change the outcome by choosing the encoding.
        let empty = [FullRevealMaterialEntry {
            file_id: 0,
            file_salt: None,
            s_root: None,
        }];
        assert_eq!(
            run(&fixture, 1, &ids, &empty)
                .expect_err("an empty entry is not material")
                .code(),
            "full-reveal-material-missing-file-salt"
        );
    }

    /// Row 5 (**D74**): an extraneous `s_root` on a `FineTree::Absent` full
    /// reveal is rejected, not silently dropped — the typed classifier has
    /// nowhere to put it, and this project does not carry unverifiable
    /// fields in an adversarial format (C14's present-set-==-required-set
    /// precedent).
    #[test]
    fn extraneous_s_root_without_a_fine_tree_is_rejected() {
        let fixture = Fixture::binary(2, b"binary payload", false);
        let stray = [FullRevealMaterialEntry {
            file_id: 2,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: Some(&TEST_S_ROOT),
        }];
        let err = run(&fixture, 1, &[0], &stray).expect_err("a stray s_root is rejected");
        assert_eq!(
            err,
            VerifyError::FullRevealSRootWithoutFineTree { file_id: 2 }
        );
        assert_eq!(err.code(), "full-reveal-s-root-without-fine-tree");

        // Row 3 still precedes row 5: missing `file_salt` wins over a stray
        // `s_root`, so the frozen order is observable.
        let stray_only = [FullRevealMaterialEntry {
            file_id: 2,
            file_salt: None,
            s_root: Some(&TEST_S_ROOT),
        }];
        assert_eq!(
            run(&fixture, 1, &[0], &stray_only)
                .expect_err("missing file_salt wins")
                .code(),
            "full-reveal-material-missing-file-salt"
        );
    }

    /// Row 6, the defensive backstop: a present-but-wrong-length material
    /// value yields the *same* code R3 group 1 would have produced, never a
    /// panic and never a shape error.
    #[test]
    fn wrong_length_material_is_a_length_error() {
        let fixture = Fixture::text(0, b"alpha\r\n", true);
        let ids = fixture.all_unit_ids(1);

        let short_salt = [FullRevealMaterialEntry {
            file_id: 0,
            file_salt: Some(&[7u8; 15]),
            s_root: Some(&TEST_S_ROOT),
        }];
        assert_eq!(
            run(&fixture, 1, &ids, &short_salt)
                .expect_err("15-byte file_salt")
                .code(),
            "wrong-length-file-salt"
        );

        let short_seed = [FullRevealMaterialEntry {
            file_id: 0,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: Some(&[7u8; 31]),
        }];
        assert_eq!(
            run(&fixture, 1, &ids, &short_seed)
                .expect_err("31-byte s_root")
                .code(),
            "wrong-length-s-root"
        );

        // Row 6's internal order: with both wrong, `file_salt` wins — the
        // same material order rows 1/3 and 2/4 use.
        let both_short = [FullRevealMaterialEntry {
            file_id: 0,
            file_salt: Some(&[7u8; 15]),
            s_root: Some(&[7u8; 31]),
        }];
        assert_eq!(
            run(&fixture, 1, &ids, &both_short)
                .expect_err("both wrong-length")
                .code(),
            "wrong-length-file-salt"
        );

        // …and every presence rule still precedes every length rule: a
        // *missing* `s_root` beats a wrong-length `file_salt`.
        let missing_beats_length = [FullRevealMaterialEntry {
            file_id: 0,
            file_salt: Some(&[7u8; 15]),
            s_root: None,
        }];
        assert_eq!(
            run(&fixture, 1, &ids, &missing_beats_length)
                .expect_err("presence rules run first")
                .code(),
            "full-reveal-material-missing-s-root"
        );
    }

    // ── rows 7–10: the content checks ───────────────────────────────────

    /// Row 7, both discriminants: the concatenation must open
    /// `canon_commit` (text) / `raw_commit` (binary) — the *only*
    /// verification path either commitment has.
    #[test]
    fn concat_commit_mismatch_rows() {
        // Text: substitute one canonical byte after the fact.
        let mut fixture = Fixture::text(0, b"alpha\r\nbeta\r\n", true);
        fixture.content[0] ^= 0x01;
        let material = [fixture.material()];
        let err = run(&fixture, 1, &fixture.all_unit_ids(1), &material)
            .expect_err("altered canonical bytes");
        assert_eq!(
            err,
            VerifyError::ConcatCommitMismatch {
                file_id: 0,
                commit: ContentCommitKind::Canon,
            }
        );
        assert_eq!(err.code(), "concat-commit-mismatch-canon");

        // Binary: same, against raw_commit.
        let mut fixture = Fixture::binary(1, b"binary payload", false);
        fixture.content[3] ^= 0x80;
        let material = [FullRevealMaterialEntry {
            file_id: 1,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: None,
        }];
        let err = run(&fixture, 1, &[0], &material).expect_err("altered raw bytes");
        assert_eq!(err.code(), "concat-commit-mismatch-raw");
    }

    /// A wrong `file_salt` fails the concatenation opening exactly like
    /// wrong bytes do — a salted commitment cannot distinguish them.
    #[test]
    fn wrong_file_salt_fails_the_concat_opening() {
        let fixture = Fixture::binary(0, b"payload", false);
        let material = [FullRevealMaterialEntry {
            file_id: 0,
            file_salt: Some(&OTHER_FILE_SALT),
            s_root: None,
        }];
        assert_eq!(
            run(&fixture, 1, &[0], &material)
                .expect_err("wrong file_salt")
                .code(),
            "concat-commit-mismatch-raw"
        );
    }

    /// Row 8: the tree rebuilt from the bundled `s_root` must match
    /// `fine_root`. A substituted `s_root` and an altered `fine_root` both
    /// land on the same distinct code — the rebuild has one outcome.
    #[test]
    fn fine_root_rebuild_mismatch_row() {
        let fixture = Fixture::text(0, b"alpha\nbeta\n", true);
        let ids = fixture.all_unit_ids(1);

        let wrong_seed = [FullRevealMaterialEntry {
            file_id: 0,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: Some(&OTHER_S_ROOT),
        }];
        let err = run(&fixture, 1, &ids, &wrong_seed).expect_err("wrong s_root");
        assert_eq!(err, VerifyError::FineRootRebuildMismatch { file_id: 0 });
        assert_eq!(err.code(), "fine-root-rebuild-mismatch");

        // An altered manifest fine_root, same code (the concat still opens).
        let mut altered = fixture;
        if let Some(root) = altered.fine_root.as_mut() {
            root[0] ^= 0x01;
        }
        let material = [altered.material()];
        assert_eq!(
            run(&altered, 1, &altered.all_unit_ids(1), &material)
                .expect_err("altered fine_root")
                .code(),
            "fine-root-rebuild-mismatch"
        );
    }

    /// Row 7 precedes row 8: with *both* the content and `s_root` wrong,
    /// the concatenation error wins (D27 determinism).
    #[test]
    fn concat_check_precedes_the_tree_rebuild() {
        let mut fixture = Fixture::text(0, b"alpha\nbeta\n", true);
        fixture.content[0] ^= 0x01;
        let material = [FullRevealMaterialEntry {
            file_id: 0,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: Some(&OTHER_S_ROOT),
        }];
        assert_eq!(
            run(&fixture, 1, &fixture.all_unit_ids(1), &material)
                .expect_err("both wrong")
                .code(),
            "concat-commit-mismatch-canon"
        );
    }

    /// A fine tree declared on an empty file cannot be rebuilt (there is no
    /// tree), and that contradiction surfaces as the integrity verdict, not
    /// a panic.
    #[test]
    fn fine_tree_declared_on_an_empty_file_fails_the_rebuild() {
        let mut fixture = Fixture::binary(0, b"", false);
        fixture.fine_root = Some([0xAAu8; 32]);
        let material = [fixture.material()];
        assert_eq!(
            run(&fixture, 1, &[0], &material)
                .expect_err("no tree to rebuild")
                .code(),
            "fine-root-rebuild-mismatch"
        );
    }

    /// Row 9: the mirror's `file_salt`-keyed `raw_commit` opening.
    #[test]
    fn raw_commit_mismatch_row() {
        let mut fixture = Fixture::text(0, b"alpha\r\nbeta\r\n", true);
        if let Some(mirror) = fixture.mirror.as_mut() {
            mirror[0] ^= 0x01;
        }
        let material = [fixture.material()];
        let err = run(&fixture, 1, &fixture.all_unit_ids(1), &material)
            .expect_err("substituted mirror bytes");
        assert_eq!(err, VerifyError::RawCommitMismatch { file_id: 0 });
        assert_eq!(err.code(), "raw-commit-mismatch");
    }

    /// Row 10: the raw-mirror ↔ canonical binding. A mirror whose
    /// canonicalization is *not* the file's canonical content is rejected —
    /// the co-timestamped-"original" equivocation (spec line 121). The
    /// manifest's `raw_commit` is recomputed over the substituted mirror so
    /// row 9 passes and row 10 is genuinely the failing check.
    #[test]
    fn raw_mirror_canonicalization_mismatch_row() {
        let mut fixture = Fixture::text(0, b"alpha\r\nbeta\r\n", true);
        let forged: Vec<u8> = b"COMPLETELY DIFFERENT\r\n".to_vec();
        fixture.raw_commit = raw_commit(&file_salt(), &forged);
        fixture.mirror = Some(forged);

        let material = [fixture.material()];
        let err = run(&fixture, 1, &fixture.all_unit_ids(1), &material)
            .expect_err("the mirror does not canonicalize to the content");
        assert_eq!(
            err,
            VerifyError::RawMirrorCanonicalizationMismatch { file_id: 0 }
        );
        assert_eq!(err.code(), "raw-mirror-canonicalization-mismatch");
    }

    /// Row 9 precedes row 10: with both wrong, `raw_commit` wins.
    #[test]
    fn raw_commit_check_precedes_the_canonicalization_binding() {
        let mut fixture = Fixture::text(0, b"alpha\r\nbeta\r\n", true);
        fixture.mirror = Some(b"COMPLETELY DIFFERENT\r\n".to_vec());
        let material = [fixture.material()];
        assert_eq!(
            run(&fixture, 1, &fixture.all_unit_ids(1), &material)
                .expect_err("both mirror checks fail")
                .code(),
            "raw-commit-mismatch"
        );
    }

    // ── D20: the recompute mode is Forced, and that is enforced ─────────

    /// **The D20 enforcement test.** A `--force-text` file's mirror bytes
    /// are invalid UTF-8 by definition. R4's recompute is pinned to
    /// [`TextMode::Forced`], so the honest bundle **verifies**; a
    /// [`TextMode::Detected`] recompute would instead return a *decode
    /// error* on exactly this file — asserted below against the real
    /// pipeline, so the mode choice is provably load-bearing rather than
    /// incidental.
    #[test]
    fn forced_mode_is_enforced_for_invalid_utf8_mirrors() {
        let raw: &[u8] = b"alpha\xFF\xFEbeta\r\n";
        assert!(
            !crate::canon::is_text(raw),
            "the fixture must fail G2's strict-UTF-8 detection — i.e. it is a \
             file that only reaches the manifest via --force-text"
        );

        let fixture = Fixture::text(0, raw, true);
        assert!(
            fixture.mirror.is_some(),
            "forced text always needs a mirror"
        );

        let material = [fixture.material()];
        let shapes = run(&fixture, 1, &fixture.all_unit_ids(1), &material)
            .expect("a forced-text full reveal must produce a verdict, not a decode error");
        assert!(shapes[0].is_full());

        // The counterfactual: the mode R4 does NOT use fails here.
        assert!(
            matches!(
                canonicalize_v(UNICODE_17_0_0, TextMode::Detected, raw),
                Err(CanonicalizeError::InvalidUtf8 { .. })
            ),
            "a Detected recompute must fail on these bytes — that is the bug \
             TextMode::Forced exists to prevent"
        );
    }

    /// The negative direction of the same file: a forced-text mirror that
    /// does *not* canonicalize to the content still yields the **integrity**
    /// verdict, never a canonicalization error. (Not a second tamper row —
    /// it shares `raw-mirror-canonicalization-mismatch` with the valid-UTF-8
    /// row; R7 owns that row, and this file's contribution is the *positive*
    /// fixture above.)
    #[test]
    fn invalid_utf8_mirror_mismatch_is_an_integrity_verdict() {
        let mut fixture = Fixture::text(0, b"alpha\xFF\xFEbeta\r\n", true);
        let forged: Vec<u8> = b"\xFF\xFE totally other bytes\r\n".to_vec();
        fixture.raw_commit = raw_commit(&file_salt(), &forged);
        fixture.mirror = Some(forged);

        let material = [fixture.material()];
        let err = run(&fixture, 1, &fixture.all_unit_ids(1), &material)
            .expect_err("the forged mirror does not canonicalize to the content");
        assert_eq!(err.code(), "raw-mirror-canonicalization-mismatch");
        assert_ne!(err.code(), "content-canonicalize-invalid-utf8");
    }

    /// An unregistered Unicode version is "upgrade the verifier", surfaced
    /// through the `Canon` wrapper arm with G's own code — never an
    /// integrity verdict, and never a panic.
    #[test]
    fn unknown_unicode_version_is_not_an_integrity_verdict() {
        let mut fixture = Fixture::text(0, b"alpha\r\nbeta\r\n", true);
        fixture.unicode_version = "unicode-99.0.0".to_owned();
        let material = [fixture.material()];
        let err = run(&fixture, 1, &fixture.all_unit_ids(1), &material)
            .expect_err("this build does not register that version");
        assert_eq!(err.code(), "content-unknown-unicode-version");
        assert!(matches!(err, VerifyError::Canon(_)));
    }

    // ── structural properties of the classification ─────────────────────

    /// The exemption is by `kind`, never by position: moving the mirror to
    /// the front of the unit table changes nothing about the shape or the
    /// concatenation (D23 is a *sealer* rule; a hand-built manifest may
    /// violate it).
    #[test]
    fn mirror_exempt_by_kind_not_by_position() {
        let fixture = Fixture::text(0, b"alpha\r\nbeta\r\n", true);
        let files = [fixture.view()];

        let mut units = fixture.units(1);
        units.reverse(); // mirror first
        let mut verified = fixture.verified(1);
        verified.reverse();

        let ids: Vec<u64> = units.iter().map(|unit| unit.unit_id).collect();
        let material = [fixture.material()];
        let shapes = check_file_stages(
            &FileStageManifestView {
                files: &files,
                units: &units,
            },
            &bundle(&ids, &material),
            &verified,
        )
        .expect("a mirror-first manifest verifies identically");
        assert!(shapes[0].is_full());

        assert!(participates_in_concat(UnitKind::Normal));
        assert!(!participates_in_concat(UnitKind::RawMirror));
    }

    /// The concatenation is ordered by byte range, not by the order R5
    /// happened to collect units in.
    #[test]
    fn concatenation_is_ordered_by_byte_range() {
        let fixture = Fixture::text(0, b"one\n\ntwo\n\nthree\n", true);
        let mut verified = fixture.verified(3);
        verified.reverse();
        assert_eq!(
            concat_non_mirror_bytes(0, &verified),
            fixture.content,
            "reversed input must still concatenate in range order"
        );
    }

    /// Files are checked in manifest file-table order, and every file's
    /// checks complete before the next file's begin (file-major, D28).
    #[test]
    fn files_run_in_manifest_order_file_major() {
        // File 0 leaks a salt; file 1 is missing one. File 0's error wins.
        let clean = Fixture::binary(0, b"aaaa", false);
        let other = Fixture::binary(1, b"bbbb", false);
        let files = [clean.view(), other.view()];
        let units = [
            FileUnitEntry {
                unit_id: 0,
                file_id: 0,
                kind: UnitKind::Normal,
            },
            FileUnitEntry {
                unit_id: 1,
                file_id: 1,
                kind: UnitKind::Normal,
            },
        ];
        let material = [FullRevealMaterialEntry {
            file_id: 0,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: None,
        }];
        let manifest = FileStageManifestView {
            files: &files,
            units: &units,
        };
        // File 0 is untouched but carries material -> leak; file 1 is fully
        // revealed with none -> missing. File-major order reports file 0.
        assert_eq!(
            check_file_stages(&manifest, &bundle(&[1], &material), &[])
                .expect_err("file 0 is reported first")
                .code(),
            "partial-reveal-salt-leak-file-salt"
        );

        // Reversing the file table reverses the verdict — proof the order
        // is the manifest's, not an accident of the error kinds.
        let files = [other.view(), clean.view()];
        let manifest = FileStageManifestView {
            files: &files,
            units: &units,
        };
        assert_eq!(
            check_file_stages(&manifest, &bundle(&[1], &material), &[])
                .expect_err("file 1 is now first")
                .code(),
            "full-reveal-material-missing-file-salt"
        );
    }

    /// Material attached to a file the manifest does not list is inert:
    /// classification is driven by the *manifest's* file table. R3's
    /// referential-integrity group is what rejects the dangling id, and it
    /// runs first (`unknown-file-ref`).
    #[test]
    fn material_for_an_unlisted_file_does_not_affect_classification() {
        let fixture = Fixture::binary(0, b"aaaa", false);
        let material = [
            FullRevealMaterialEntry {
                file_id: 0,
                file_salt: Some(&TEST_FILE_SALT),
                s_root: None,
            },
            FullRevealMaterialEntry {
                file_id: 99,
                file_salt: Some(&OTHER_FILE_SALT),
                s_root: Some(&OTHER_S_ROOT),
            },
        ];
        run(&fixture, 1, &[0], &material).expect("the dangling entry is R3's to reject");
    }

    /// No secret material in any `Debug` rendering this stage can produce
    /// (project rule 6). Three surfaces: the classified evidence (whose
    /// `FileSalt`/`Seed32` are redacted by construction — asserted here so a
    /// wrapper type cannot undo it), the **input** material view (the one
    /// place raw salt bytes exist, hand-redacted), and the verified-bytes
    /// view (content, rendered as a length).
    ///
    /// The patterns below are the byte fixtures rendered the two ways a
    /// `Debug` impl could emit them: hex (`11`, `33`) and decimal (`17`,
    /// `51`), the latter being what a derived `Debug` on `&[u8]` prints.
    #[test]
    fn no_debug_surface_of_this_stage_carries_secret_material() {
        let fixture = Fixture::text(0, b"alpha\r\nbeta\r\n", true);
        let files = [fixture.view()];
        let units = fixture.units(1);
        let material = [fixture.material()];
        let shape = classify_file_reveal(
            &files[0],
            &units,
            &bundle(&fixture.all_unit_ids(1), &material),
        )
        .expect("classifies");

        // The isolation path is where a leaked salt would be *most* likely
        // to reach a log: the bundle carries it, and the stage rejects.
        let leak = FullRevealMaterialEntry {
            file_id: 0,
            file_salt: Some(&TEST_FILE_SALT),
            s_root: Some(&TEST_S_ROOT),
        };
        let verified = fixture.verified(1);

        let surfaces = [
            format!("{shape:?}"),
            format!("{leak:?}"),
            format!("{:?}", bundle(&[0], core::slice::from_ref(&leak))),
            format!("{verified:?}"),
        ];

        for rendered in &surfaces {
            for secret in [
                "1111111111111111", // file_salt, hex
                "3333333333333333", // s_root, hex
                "17, 17",           // file_salt, decimal (derived &[u8] Debug)
                "51, 51",           // s_root, decimal
            ] {
                assert!(
                    !rendered.contains(secret),
                    "secret pattern {secret} leaked into {rendered}"
                );
            }
        }

        assert!(surfaces[0].contains("redacted"), "{}", surfaces[0]);
        assert!(surfaces[1].contains("redacted; 16 B"), "{}", surfaces[1]);
        assert!(surfaces[1].contains("redacted; 32 B"), "{}", surfaces[1]);
        // Content is rendered as a length, never as bytes.
        assert!(surfaces[3].contains(" B>"), "{}", surfaces[3]);
        assert!(
            !surfaces[3].contains("alpha"),
            "content leaked into {}",
            surfaces[3]
        );

        // …and absence renders as absence, not as an empty byte string.
        let absent = FullRevealMaterialEntry {
            file_id: 0,
            file_salt: None,
            s_root: None,
        };
        let rendered = format!("{absent:?}");
        assert!(rendered.contains("absent"), "{rendered}");
    }

    // ── properties ──────────────────────────────────────────────────────

    /// Split a canonical corpus into `splits` units and reveal `keep` of
    /// them; the shape must be `Full` iff every unit is kept.
    #[cfg(feature = "test-util")]
    fn split_and_subset() -> impl Strategy<Value = (Vec<u8>, usize, Vec<u64>)> {
        (
            proptest::collection::vec(proptest::char::range('a', 'z'), 1..40),
            1usize..5,
        )
            .prop_flat_map(|(chars, splits)| {
                let text: String = chars.into_iter().collect();
                (
                    Just(text.into_bytes()),
                    Just(splits),
                    proptest::collection::vec(any::<bool>(), splits),
                )
            })
            .prop_map(|(bytes, splits, keep)| {
                let revealed: Vec<u64> = keep
                    .iter()
                    .enumerate()
                    .filter_map(|(i, k)| k.then_some(i as u64))
                    .collect();
                (bytes, splits, revealed)
            })
    }

    #[cfg(feature = "test-util")]
    proptest! {
        #![proptest_config(proptest_config(0x0052_0004))]

        /// The classification property: `Full` **iff** every non-mirror unit
        /// is revealed, over randomized splits and randomized subsets — and
        /// an honest full reveal always verifies while an honest partial
        /// reveal (which carries no material) never errors.
        #[test]
        fn full_iff_every_non_mirror_unit_is_revealed(
            (bytes, splits, revealed) in split_and_subset()
        ) {
            let fixture = Fixture::binary(0, &bytes, false);
            let expect_full = revealed.len() == splits;

            let material: Vec<FullRevealMaterialEntry<'_>> = if expect_full {
                vec![FullRevealMaterialEntry {
                    file_id: 0,
                    file_salt: Some(&TEST_FILE_SALT),
                    s_root: None,
                }]
            } else {
                Vec::new()
            };

            let shapes = run(&fixture, splits, &revealed, &material)
                .map_err(|e| TestCaseError::fail(format!("honest bundle rejected: {e}")))?;
            prop_assert_eq!(shapes[0].is_full(), expect_full);
            prop_assert_eq!(
                shapes[0].kind == FileRevealKind::Untouched,
                revealed.is_empty()
            );
        }

        /// D28's downgrade property, the half that is *not* a tamper row
        /// (it shares an outcome with the isolation row, and Q7 correctly
        /// refuses two rows claiming one outcome): **no single-unit deletion
        /// from a full-reveal bundle verifies**. Stripping a unit while
        /// leaving `file_salt` attached turns the bundle into a partial
        /// reveal carrying forbidden material.
        #[test]
        fn no_single_unit_deletion_from_a_full_reveal_verifies(
            (bytes, splits, _ignored) in split_and_subset()
        ) {
            let fixture = Fixture::binary(0, &bytes, false);
            let material = [FullRevealMaterialEntry {
                file_id: 0,
                file_salt: Some(&TEST_FILE_SALT),
                s_root: None,
            }];

            for dropped in 0..splits {
                let revealed: Vec<u64> = (0..splits as u64)
                    .filter(|id| *id != dropped as u64)
                    .collect();
                let err = run(&fixture, splits, &revealed, &material)
                    .err()
                    .ok_or_else(|| TestCaseError::fail("a downgraded bundle verified"))?;
                prop_assert_eq!(err.code(), "partial-reveal-salt-leak-file-salt");
            }
        }

        /// The raw-mirror binding holds for every mirror-prone input: the
        /// honest mirror canonicalizes to the file's content, and any other
        /// byte string that does not is rejected — with the recompute in
        /// forced mode throughout, so arbitrary (including invalid-UTF-8)
        /// bytes produce a verdict rather than a decode error.
        #[test]
        fn raw_mirror_binding_holds_over_arbitrary_bytes(
            raw in proptest::collection::vec(any::<u8>(), 0..48)
        ) {
            let fixture = Fixture::text(0, &raw, false);
            let material = [FullRevealMaterialEntry {
                file_id: 0,
                file_salt: Some(&TEST_FILE_SALT),
                s_root: None,
            }];
            let ids = fixture.all_unit_ids(1);
            run(&fixture, 1, &ids, &material)
                .map_err(|e| TestCaseError::fail(format!("honest mirror rejected: {e}")))?;
        }
    }

    /// Round-trip against G9: `rebuild_fine_root` over the concatenation is
    /// the same construction the sealer ran, so an honest full reveal always
    /// reproduces `fine_root` (the verifier path **is** the sealer path).
    #[test]
    fn rebuild_reproduces_the_sealers_root() {
        let content = b"the quick brown fox\n";
        let root = rebuild_fine_root(&seed(), content).expect("non-empty");
        assert_eq!(
            root,
            FineRoot::from_bytes(*root.as_bytes()),
            "FineRoot round-trips through its bytes"
        );

        let fixture = Fixture::binary(0, content, true);
        assert_eq!(fixture.fine_root, Some(*root.as_bytes()));
        let material = [fixture.material()];
        run(&fixture, 1, &[0], &material).expect("the honest rebuild matches");
    }
}
