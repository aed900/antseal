//! The golden end-to-end content-model fixture (tasks/G.md G14 accept) — a
//! small multi-file work exercising every branch of
//! [`assemble_content_model`](super::assemble_content_model) at once, with a
//! **clearly test-only** synthetic seed supplier.
//!
//! # The work
//!
//! | `file_id` | file | flags | exercises |
//! | --- | --- | --- | --- |
//! | 0 | [`GOLDEN_TEXT_SPLIT_RAW`] | `--split blank-lines` | CRLF canonicalization, D22 split, D23 raw mirror, covered units |
//! | 1 | [`GOLDEN_BINARY_RAW`] | — | binary detection, raw fine-tree domain, single unit, no mirror |
//! | 2 | [`GOLDEN_NO_FINE_TREE_RAW`] | `--no-fine-tree` | D24 single-unit-regardless, `unit_commit` present, no tree |
//! | 3 | [`GOLDEN_EMPTY_RAW`] | — | the empty-file rule (line 78): one empty unit, no tree |
//!
//! Together they cover both `fine_root` presence states, both
//! [`FileKind`](super::FileKind)s, both [`UnitKind`](super::UnitKind)s, and
//! the work-global id counter running across four files without restarting
//! (MVP-SPEC.md line 76).
//!
//! # The seed supplier is synthetic and labelled (project rule 6)
//!
//! [`SyntheticFineSeeds`] derives each file's `s_root` from the documented
//! NON-SECRET fixture pattern [`TEST_MASTER_SECRET_W`] under its own domain
//! label, **not** from `HKDF(W, "fine-seed", file_id)`. Using a deliberately
//! different construction means these fixture seeds can never collide with a
//! real vault derivation, and no committed value here is reachable from any
//! production key schedule. It is the seal-side `s_root` *interface* this
//! fixture pins, not C's derivation, which C's own vectors cover.

use sha2::{Digest, Sha256};

use crate::crypto::hkdf::{FileId, le64};
use crate::crypto::material::Seed32;
use crate::test_util::TEST_MASTER_SECRET_W;

use super::assemble::{
    ContentModel, FileFlags, FileInput, FineSeedSource, SplitMode, assemble_content_model,
};

/// `file_id` of the CRLF text file sealed with `--split blank-lines`.
pub const GOLDEN_FILE_TEXT_SPLIT: u64 = 0;
/// `file_id` of the binary file.
pub const GOLDEN_FILE_BINARY: u64 = 1;
/// `file_id` of the `--no-fine-tree` text file.
pub const GOLDEN_FILE_NO_FINE_TREE: u64 = 2;
/// `file_id` of the empty file.
pub const GOLDEN_FILE_EMPTY: u64 = 3;

/// File 0: CRLF text, three blank-line-separated paragraphs, sealed with
/// `--split blank-lines`.
///
/// 41 raw bytes canonicalizing to 34 (every `CR LF` loses its CR), so it
/// needs a raw mirror (D23), and the second separator is a *two*-blank-line
/// run — both blank lines ride with the preceding unit under D22.
pub const GOLDEN_TEXT_SPLIT_RAW: &[u8] = b"alpha one\r\nalpha two\r\n\r\nbeta\r\n\r\n\r\ngamma\r\n";

/// File 1: binary — a lone 0x80 continuation byte makes it invalid UTF-8, so
/// detection says binary without any flag (MVP-SPEC.md line 83). Its `CR LF`
/// is deliberately left un-normalized by the model: binary files have no
/// canonical rendition.
pub const GOLDEN_BINARY_RAW: &[u8] = &[0x00, 0x01, 0x02, 0x80, 0xFF, 0xFE, 0x0D, 0x0A, 0x00];

/// File 2: already-canonical text (LF, NFC, no BOM) matched by a
/// `--no-fine-tree` glob. It *contains* a blank line, so the single-unit
/// outcome is a real assertion rather than a coincidence of the content.
pub const GOLDEN_NO_FINE_TREE_RAW: &[u8] = b"para one\n\npara two\n";

/// File 3: the empty file — one empty unit, no fine tree (MVP-SPEC.md line
/// 78), and no mirror (raw and canonical are both zero-length).
pub const GOLDEN_EMPTY_RAW: &[u8] = b"";

/// Domain label of the fixture seed derivation — deliberately unlike any
/// production HKDF label so a fixture `s_root` can never coincide with a
/// vault-derived one.
pub const SYNTHETIC_FINE_SEED_LABEL: &[u8] = b"antseal:test-only:content-fixture:fine-seed:v1";

/// The fixture's `s_root` supplier: **test-only, synthetic, non-secret**.
///
/// `s_root(file_id) = SHA-256(SYNTHETIC_FINE_SEED_LABEL ‖ TEST_MASTER_SECRET_W ‖ le64(file_id))`
///
/// Deterministic and independent of any vault, so the committed golden
/// `fine_root`s are reproducible anywhere. See the module docs for why this
/// is deliberately *not* C's `HKDF(W, "fine-seed", file_id)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyntheticFineSeeds;

/// The single value of [`SyntheticFineSeeds`], for call sites that want a
/// name rather than a constructor.
pub const SYNTHETIC_FINE_SEEDS: SyntheticFineSeeds = SyntheticFineSeeds;

impl FineSeedSource for SyntheticFineSeeds {
    fn fine_seed(&self, file_id: FileId) -> Seed32 {
        let mut hasher = Sha256::new();
        hasher.update(SYNTHETIC_FINE_SEED_LABEL);
        hasher.update(TEST_MASTER_SECRET_W);
        hasher.update(le64(file_id.0));
        Seed32::from_bytes(hasher.finalize().into())
    }
}

/// The golden work's four files with their flags, in file-table order.
#[must_use]
pub fn golden_inputs() -> [FileInput<'static>; 4] {
    [
        FileInput::new(
            GOLDEN_TEXT_SPLIT_RAW,
            FileFlags::new().with_split(SplitMode::BlankLines),
        ),
        FileInput::plain(GOLDEN_BINARY_RAW),
        FileInput::new(
            GOLDEN_NO_FINE_TREE_RAW,
            FileFlags::new().with_no_fine_tree(),
        ),
        FileInput::plain(GOLDEN_EMPTY_RAW),
    ]
}

/// The golden work assembled: [`golden_inputs`] through
/// [`assemble_content_model`] with [`SyntheticFineSeeds`].
///
/// `'static` because every input is a compile-time constant, so the model
/// borrows nothing a caller must keep alive.
#[must_use]
pub fn golden_model() -> ContentModel<'static> {
    assemble_content_model(&golden_inputs(), &SYNTHETIC_FINE_SEEDS)
}

/// Every content-model invariant G5/G6/G7 state, checked against a model —
/// the shared oracle behind G14's golden fixture, its property test, and
/// G17's end-to-end fixture.
///
/// Returns one human-readable message per violation and an empty vector for a
/// well-formed model, so callers can `assert!(….is_empty())` or
/// `prop_assert!(…)` without the oracle deciding how failure is reported.
///
/// The list, and where each rule comes from:
///
/// 1. file ids are positional; unit ids are work-global, dense, ascending
///    (MVP-SPEC.md line 76, D23)
/// 2. within a file: normal units ascending, then at most one raw mirror,
///    last (D23)
/// 3. normal units exactly tile `[0, size)` of the file's own domain, and
///    concatenate to it (lines 84, 98, 121)
/// 4. the mirror spans `[0, raw_len)` of the raw domain, is present iff the
///    file is text with `raw != canonical`, and is exempt from both tiling
///    and full-reveal concatenation (line 92, D23)
/// 5. `unit_commit` presence is exactly the negation of fine-tree coverage
///    (line 94) — the sole-commitment rule
/// 6. `fine_root` is present iff the descriptor says so, and then the file is
///    non-empty (lines 78, 85)
/// 7. the descriptor is self-consistent at this `size`, and a canonical
///    rendition exists iff the file is text (line 83)
/// 8. the canonical rendition is reproducible from the raw bytes by the
///    verifier's own recompute (line 121, D20)
/// 9. sub-file units exist only where the split gate admits them (D24)
#[must_use]
pub fn model_invariant_violations(model: &ContentModel<'_>) -> Vec<String> {
    use crate::canon::{UnicodeVersion, canonicalize_forced};

    use super::mirror::{full_reveal_concat_exempt, needs_mirror, tiling_exempt};
    use super::unit::{SplitEligibleText, UnitKind, is_fine_tree_covered, requires_unit_commit};

    let mut bad: Vec<String> = Vec::new();
    let mut note = |message: String| bad.push(message);

    // (1) Work-global ids: dense from 0, ascending, file ids positional.
    for (index, unit) in model.units().iter().enumerate() {
        let expected = u64::try_from(index).unwrap_or(u64::MAX);
        if unit.unit_id() != expected {
            note(format!(
                "unit at index {index} has unit_id {} (ids must be dense from 0)",
                unit.unit_id()
            ));
        }
        if !unit.true_length_matches_range() {
            note(format!(
                "unit {} true_length {} != range width {}",
                unit.unit_id(),
                unit.true_length(),
                unit.byte_range().length()
            ));
        }
    }
    for (index, file) in model.files().iter().enumerate() {
        let expected = u64::try_from(index).unwrap_or(u64::MAX);
        if file.file_id() != expected {
            note(format!(
                "file at index {index} has file_id {}",
                file.file_id()
            ));
        }
    }
    let spanned: usize = model
        .files()
        .iter()
        .map(|file| model.units_of(file.file_id()).len())
        .sum();
    if spanned != model.units().len() {
        note(format!(
            "per-file unit spans cover {spanned} of {} units",
            model.units().len()
        ));
    }

    for file in model.files() {
        let units = model.units_of(file.file_id());
        let descriptor = file.descriptor();
        let size = file.size();

        // (7) Descriptor self-consistency and the text/rendition biconditional.
        if let Err(error) = descriptor.validate_with_size(size) {
            note(format!(
                "file {}: descriptor invalid: {error}",
                file.file_id()
            ));
        }
        let is_text_file = matches!(descriptor.kind(), super::FileKind::Text);
        if file.canonical().is_some() != is_text_file {
            note(format!(
                "file {}: canonical rendition presence must equal text-ness",
                file.file_id()
            ));
        }
        if file.domain_bytes().len() as u64 != size {
            note(format!(
                "file {}: domain bytes {} != size {size}",
                file.file_id(),
                file.domain_bytes().len()
            ));
        }

        // (8) The verifier's recompute reproduces the canonical rendition.
        if let Some(canonical) = file.canonical()
            && canonicalize_forced(UnicodeVersion::CURRENT, file.raw()) != *canonical
        {
            note(format!(
                "file {}: canonicalize(raw) != canonical (line 121 would fail)",
                file.file_id()
            ));
        }

        // (6) fine_root presence.
        if file.fine_root().is_some() != descriptor.fine_tree_present() {
            note(format!(
                "file {}: fine_root presence != descriptor.fine_tree_present()",
                file.file_id()
            ));
        }
        if file.fine_root().is_some() && size == 0 {
            note(format!(
                "file {}: empty file carries a fine_root",
                file.file_id()
            ));
        }

        // (2) Order within the file, and at most one mirror, last.
        let mirrors = units
            .iter()
            .filter(|unit| unit.kind() == UnitKind::RawMirror)
            .count();
        if mirrors > 1 {
            note(format!("file {}: {mirrors} raw mirrors", file.file_id()));
        }
        if let Some(position) = units
            .iter()
            .position(|unit| unit.kind() == UnitKind::RawMirror)
            && position + 1 != units.len()
        {
            note(format!(
                "file {}: raw mirror at position {position} of {} (D23: last)",
                file.file_id(),
                units.len()
            ));
        }
        if units.is_empty() {
            note(format!(
                "file {}: no units (line 78: never empty)",
                file.file_id()
            ));
        }

        // (3) Normal units tile [0, size) exactly and concatenate to the domain.
        let mut next = 0u64;
        let mut concatenated: Vec<u8> = Vec::new();
        for unit in units.iter().filter(|unit| !tiling_exempt(unit.kind())) {
            if unit.byte_range().start() != next {
                note(format!(
                    "file {}: unit {} starts at {}, expected {next} (gap/overlap)",
                    file.file_id(),
                    unit.unit_id(),
                    unit.byte_range().start()
                ));
            }
            next = unit.byte_range().end().unwrap_or(u64::MAX);
            match model.unit_bytes(unit) {
                Some(bytes) => concatenated.extend_from_slice(bytes),
                None => note(format!(
                    "file {}: unit {} bytes unresolvable",
                    file.file_id(),
                    unit.unit_id()
                )),
            }
        }
        if next != size {
            note(format!(
                "file {}: normal units tile [0, {next}), expected [0, {size})",
                file.file_id()
            ));
        }
        if concatenated != file.domain_bytes() {
            note(format!(
                "file {}: full-reveal concatenation != domain bytes",
                file.file_id()
            ));
        }

        // (4) The mirror: presence rule, span, exemptions, bytes.
        let expected_mirror = file
            .canonical()
            .is_some_and(|canonical| needs_mirror(file.raw(), canonical));
        if (mirrors == 1) != expected_mirror {
            note(format!(
                "file {}: mirror presence {} != needs_mirror {expected_mirror}",
                file.file_id(),
                mirrors == 1
            ));
        }
        for unit in units
            .iter()
            .filter(|unit| unit.kind() == UnitKind::RawMirror)
        {
            let raw_len = file.raw().len() as u64;
            if unit.byte_range().start() != 0 || unit.byte_range().length() != raw_len {
                note(format!(
                    "file {}: mirror spans ({}, {}), expected (0, {raw_len})",
                    file.file_id(),
                    unit.byte_range().start(),
                    unit.byte_range().length()
                ));
            }
            if !tiling_exempt(unit.kind()) || !full_reveal_concat_exempt(unit.kind()) {
                note(format!("file {}: mirror is not exempt", file.file_id()));
            }
            if model.unit_bytes(unit) != Some(file.raw()) {
                note(format!(
                    "file {}: mirror bytes are not the raw bytes",
                    file.file_id()
                ));
            }
        }

        // (5) The sole-commitment rule (line 94).
        for unit in units {
            let covered = is_fine_tree_covered(unit, descriptor);
            if covered != model.is_covered(unit) {
                note(format!(
                    "file {}: unit {} coverage disagrees with the model",
                    file.file_id(),
                    unit.unit_id()
                ));
            }
            if requires_unit_commit(unit, descriptor) == covered {
                note(format!(
                    "file {}: unit {} breaks unit_commit-iff-not-covered",
                    file.file_id(),
                    unit.unit_id()
                ));
            }
            if covered && file.fine_root().is_none() {
                note(format!(
                    "file {}: unit {} covered by a fine_root that is absent",
                    file.file_id(),
                    unit.unit_id()
                ));
            }
        }

        // (9) Sub-file units only where the split gate admits them (D24).
        let normal = units.len() - mirrors;
        if normal > 1 && SplitEligibleText::of(descriptor).is_none() {
            note(format!(
                "file {}: {normal} normal units on a split-ineligible file",
                file.file_id()
            ));
        }
    }

    bad
}
