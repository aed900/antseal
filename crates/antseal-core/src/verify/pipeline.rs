//! The `verify_bundle` evidence-pipeline orchestration (task R5).
//!
//! Everything else in [`super`] is a stage. This module is the one place
//! that runs them, in one order, over one decoded `.sealproof` — and turns
//! the result into a [`VerificationReport`]. It is pure and WASM-safe: no
//! I/O, no clock, no randomness, no async, no network. `verify_bundle` is
//! the function the browser verifier calls.
//!
//! # The frozen stage order
//!
//! MVP-SPEC.md lines 116–118 give the evidence layer's order, and D27 makes
//! the fail-fast first error the sole normative mode — so the order below is
//! **frozen** and is part of the tamper-matrix contract, not an
//! implementation detail. Every tamper row binds to the first error a given
//! mutation produces, which is a function of this order.
//!
//! | # | [`VerifyStage`] | what runs | owner |
//! |---|---|---|---|
//! | 1 | [`Decode`] | [`SealProof::decode`] — the three strict CBOR layers (bundle schema, manifest envelope, manifest body) | F8/F9 |
//! | 2 | [`Structural`] | [`check_structural`] (lengths → manifest refs → bundle refs → tiling → `path_commit`), then [`check_coherence`] (D80 touched-file coverage → reveal-section agreement) | R3 + R5 |
//! | 3 | [`Units`] | [`verify_revealed_unit`] per revealed unit, in manifest unit order: decrypt → padding → `true_length` → content binding | R2 |
//! | 4 | [`Files`] | [`check_file_stages`]: reveal-shape classification, partial-reveal isolation, full-reveal cross-checks, raw-mirror binding | R4 |
//! | 5 | [`Signatures`] | [`sig_policy::verify_body`] over the **received** body bytes: present-set == policy-set, then each algorithm | C14 |
//! | 6 | [`Anchors`] | M0 stub: one `absent` slot per embedded artifact (R12 replaces it at M2) | A18/R12 |
//!
//! Three orderings inside that table are load-bearing and are pinned by
//! tests in this module (`stage_order_*`):
//!
//! - **Structural before Units.** R3 proves ranges are well formed and tile
//!   their file before any ciphertext is opened, which is what lets R2 treat
//!   `range_width` as trustworthy and what makes `s_root`'s
//!   "discloses nothing on a full reveal" claim true (R4 module docs).
//! - **Units before Files.** R4 consumes the *verified* bytes R2 returns; it
//!   never re-derives them.
//! - **Files before Signatures.** A bundle whose content does not match its
//!   manifest is a content failure, and reporting it as such is more useful
//!   than reporting that the (perfectly valid) signature over that manifest
//!   verified. Note the signature stage is not a gate on the evidence
//!   stages: it is the last *evidence* stage, and by the time it runs the
//!   manifest's own claims have already been checked against the bytes.
//!
//! Within a stage, subjects are visited in **manifest order** (files by file
//! table index = `file_id`, units by unit-table order = `unit_id`), never in
//! bundle order — so "the first error" does not depend on how a sealer chose
//! to lay out the bundle's sections.
//!
//! # Two entry points, one stage list (D27)
//!
//! [`verify_bundle`] is the normative, tamper-authoritative mode: the first
//! failure aborts with one typed [`VerifyError`].
//! [`verify_bundle_collecting`] is the rendering aid whose
//! [`VerifyFailures::primary`] is *by construction* the same error — both
//! call the same private `run`, which differs only in whether the per-unit
//! stage stops at its first failure.
//!
//! Collection is deliberately narrow. D27 §3 forbids speculative cascades,
//! and the only stage whose subjects are genuinely independent of one
//! another is stage 3: each revealed unit carries its own key, ciphertext
//! and commitment, so "three units over-padded" is a set of independent
//! findings. Every other stage yields exactly one finding, because
//! everything downstream of a structural, file-level or signature failure
//! depends on the thing that failed.
//!
//! # What this stage does *not* do
//!
//! - **Storage linkage** (MVP-SPEC.md line 119) is a separate later stage
//!   (R20) and must never gate the evidence verdict — "storage is the
//!   product's bonus, not its proof". The report slot stays
//!   [`StorageLinkageResult::NotEvaluated`].
//! - **Anchor verification.** At M0 the anchor stage tolerates and reports
//!   [`AnchorState::Absent`] per embedded artifact; A18's state machine
//!   plugs in at M2 through R12. No artifact byte is parsed here, and no
//!   bundle-recorded anchor metadata is copied into the report: a TSA
//!   `source` string is explicitly "never verdict-bearing"
//!   ([`TsaAnchor::source`]), and rendering a `fetch_date` would require
//!   choosing a date format — a format-permanent decision R12/A18 owns.
//!   An empty anchor list therefore yields an empty `anchors` list, which is
//!   the M0 empty-anchor requirement (line 153).
//! - **Re-encoding anything.** `work_id` and the signature stage both read
//!   the manifest body bytes *as received*
//!   ([`Manifest::body_bytes`](crate::manifest::Manifest::body_bytes),
//!   a sub-slice of the caller's input), never a re-encoding (line 74).
//!
//! # Layering notes worth keeping
//!
//! - **The length group is a backstop here, not the enforcement point.**
//!   F8's schema stores every disclosed salt/seed/key/node hash as a
//!   fixed-size type, so a wrong-length one is already rejected at stage 1
//!   with a `bundle-wrong-length-*` code. Stage 2 still runs R3's group 1
//!   over the decoded values (they are all correct by then) so the R-level
//!   codes stay reachable if a field is ever relaxed to a variable-length
//!   byte string, and so the stage list stays complete.
//! - **The reveal-section check is what makes stage 3's dispatch total.**
//!   See [`super::coherence`]; the dispatch below keeps a defensive copy of
//!   the same two arms, yielding the identical codes.
//!
//! [`Decode`]: VerifyStage::Decode
//! [`Structural`]: VerifyStage::Structural
//! [`Units`]: VerifyStage::Units
//! [`Files`]: VerifyStage::Files
//! [`Signatures`]: VerifyStage::Signatures
//! [`Anchors`]: VerifyStage::Anchors
//! [`SealProof::decode`]: crate::bundle::SealProof::decode
//! [`TsaAnchor::source`]: crate::bundle::TsaAnchor::source
//! [`sig_policy::verify_body`]: crate::crypto::sig_policy::verify_body

use crate::bundle::{BundleV1, CoveredReveal, NonCoveredReveal, SealProof};
use crate::content::fine_tree::{FineRoot, RangeProofView, WireNode, verify_range};
use crate::content::unit::ByteRange as ContentByteRange;
use crate::crypto::commit::CommitmentDigest;
use crate::crypto::disclosure::UnitBinding;
use crate::crypto::error::SigAlg;
use crate::crypto::hkdf::UnitId;
use crate::crypto::sig_policy::{PolicyLabel, SigPolicy, verify_body};
use crate::crypto::unit_aead::Nonce24 as AeadNonce;
use crate::manifest::body::{CanonMode, FineTree, ManifestBodyV1, UnitEntry as ManifestUnitEntry};
use crate::manifest::registry::UnitKind as ManifestUnitKind;
use crate::manifest::work_id;

use super::coherence::check_coherence;
use super::coherence::{CoherenceBundleView, CoherenceUnit, RevealSection, RevealedUnitRef};
use super::error::{BindingMode, LengthField, VerifyError, VerifyFailures};
use super::file_stages::{
    FileCanonMode, FileFineTree, FileRevealSummary, FileStageBundleView, FileStageManifestView,
    FileUnitEntry, FileView, FullRevealMaterialEntry, VerifiedUnitBytes, check_file_stages,
};
use super::report::{
    AnchorKind, AnchorResult, AnchorState, Digest32, EvidenceLayerResult, FileReveal,
    REPORT_VERSION, RawMirrorReveal, RevealSet, SignatureScheme, StorageLinkageResult,
    SupportingEvidenceResult, UnitSpan, UnrevealedFilePlaceholder, VerificationReport,
    WorkMetadata,
};
use super::structural::{
    BundleView, DisclosedField, FileEntry as StructuralFileEntry, ManifestView, TouchedFile,
    UnitEntry as StructuralUnitEntry, UnitKind, check_structural,
};
use super::unit_stages::{ContentBinding, RevealedUnitInput, verify_revealed_unit};

/// The six stages of the evidence pipeline, in their **frozen** order
/// (module docs; MVP-SPEC.md lines 116–118).
///
/// This type exists so the order is a value the test suite can iterate and
/// assert over, rather than a comment that can drift from the code. It is
/// not an input to verification and carries no data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerifyStage {
    /// Stage 1 — F9's three strict CBOR decode layers.
    Decode,
    /// Stage 2 — R3's structural invariants, then R5's bundle ↔ manifest
    /// coherence rules.
    Structural,
    /// Stage 3 — R2's per-unit evidence stages, per revealed unit.
    Units,
    /// Stage 4 — R4's file-level reveal-shape checks.
    Files,
    /// Stage 5 — C14's `sig_policy` + signature verification.
    Signatures,
    /// Stage 6 — the anchor stage (M0: `absent` per artifact).
    Anchors,
}

impl VerifyStage {
    /// Every stage, **in the frozen order** the pipeline runs them.
    ///
    /// The declaration order, this constant and the `Ord` derive all agree;
    /// `stage_order_constant_matches_declaration` pins that, so the order
    /// cannot be changed in one place only.
    pub const ALL: [Self; 6] = [
        Self::Decode,
        Self::Structural,
        Self::Units,
        Self::Files,
        Self::Signatures,
        Self::Anchors,
    ];

    /// Stable lowercase name, for diagnostics and rendering.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Decode => "decode",
            Self::Structural => "structural",
            Self::Units => "units",
            Self::Files => "files",
            Self::Signatures => "signatures",
            Self::Anchors => "anchors",
        }
    }
}

impl core::fmt::Display for VerifyStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Options for a verification run.
///
/// Empty at M0 by design: everything the evidence layer needs is inside the
/// bundle, which is the point of a self-contained `.sealproof`. The
/// parameter exists in the signature D27 fixed so that later stages —
/// R12's anchor policy, R20's storage linkage, R21's `--live` — can be
/// switched on without a breaking change. `#[non_exhaustive]`, so adding a
/// field later stays non-breaking for callers that build it with
/// [`Default`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyOptions {}

impl VerifyOptions {
    /// The M0 options: nothing selected.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }
}

/// Verify a `.sealproof` bundle end to end — **the normative entry point**
/// (D27: fail-fast, tamper-authoritative).
///
/// Runs the frozen stage order of the module docs over `input` and returns
/// the [`VerificationReport`] for a bundle that passed the evidence layer.
/// Pure and total: no input, however hostile, can make it panic, and every
/// failure is a typed [`VerifyError`] carrying a stable code.
///
/// Verification is deterministic — the same bytes yield the same report,
/// and therefore the same canonical report bytes on native and on wasm32.
///
/// # Errors
///
/// The **first** failure in stage order (module docs). Every code in
/// [`VerifyError::code`] is reachable from here except the ones F8's schema
/// rejects earlier with a `bundle-*` code (see the layering note in the
/// module docs).
pub fn verify_bundle(
    input: &[u8],
    options: &VerifyOptions,
) -> Result<VerificationReport, VerifyError> {
    run(input, options, Mode::FailFast).map_err(VerifyFailures::into_primary)
}

/// Verify a `.sealproof` bundle, collecting independent findings for
/// rendering (D27's non-normative mode).
///
/// Identical to [`verify_bundle`] except that a failure in the per-unit
/// stage does not stop the other units from being checked. The returned
/// [`VerifyFailures::primary`] is **exactly** what [`verify_bundle`] returns
/// for the same input — the two share one stage list, so the rendering view
/// can never contradict the authoritative verdict.
///
/// # Errors
///
/// A non-empty [`VerifyFailures`], primary first (module docs).
pub fn verify_bundle_collecting(
    input: &[u8],
    options: &VerifyOptions,
) -> Result<VerificationReport, VerifyFailures> {
    run(input, options, Mode::Collect)
}

/// Whether the per-unit stage stops at its first failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Stop at the first failure (D27's normative mode).
    FailFast,
    /// Keep checking the remaining, independent units.
    Collect,
}

/// One revealed unit's verified bytes plus the manifest facts R4 needs.
///
/// Owned because [`VerifiedUnitBytes`] borrows; `Debug` renders the length
/// rather than the bytes, for the reason R4 gives on its own view type.
struct VerifiedUnit {
    unit_id: u64,
    file_id: u64,
    kind: UnitKind,
    range_start: u64,
    bytes: Vec<u8>,
}

impl core::fmt::Debug for VerifiedUnit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifiedUnit")
            .field("unit_id", &self.unit_id)
            .field("file_id", &self.file_id)
            .field("kind", &self.kind)
            .field("range_start", &self.range_start)
            .field("bytes", &format_args!("<{} B>", self.bytes.len()))
            .finish()
    }
}

/// One manifest unit-table row, flattened out of the nested file table.
///
/// The flattened order **is** the manifest unit-table order, and F5 pins
/// each unit's stored `unit_id` to its ordinal in it, so iterating this is
/// simultaneously "manifest order" and "`unit_id` order".
#[derive(Debug, Clone, Copy)]
struct UnitRow<'m> {
    file_id: u64,
    entry: &'m ManifestUnitEntry,
}

impl UnitRow<'_> {
    const fn unit_id(&self) -> u64 {
        self.entry.unit_id()
    }

    const fn kind(&self) -> UnitKind {
        match self.entry.kind() {
            ManifestUnitKind::Normal => UnitKind::Normal,
            ManifestUnitKind::RawMirror => UnitKind::RawMirror,
        }
    }

    const fn binding_mode(&self) -> BindingMode {
        match self.entry.binding() {
            UnitBinding::FineTreeCovered => BindingMode::FineTreeCovered,
            UnitBinding::NonCovered { .. } => BindingMode::NonCovered,
        }
    }
}

/// The single implementation behind both D27 entry points.
fn run(
    input: &[u8],
    _options: &VerifyOptions,
    mode: Mode,
) -> Result<VerificationReport, VerifyFailures> {
    // ── Stage 1: decode ────────────────────────────────────────────────
    let proof = SealProof::decode(input).map_err(VerifyError::Decode)?;
    let bundle = proof.bundle();
    let body = proof.manifest().body();

    let rows = flatten_units(body);

    // ── Stage 2: structural (R3) then coherence (R5) ───────────────────
    let struct_files = structural_files(body);
    let struct_units = structural_units(&rows);
    let touched = touched_files(bundle);
    let revealed_ids = bundle.revealed_unit_ids();
    let proof_refs: Vec<u64> = bundle
        .covered_reveals()
        .iter()
        .map(CoveredReveal::unit_id)
        .collect();
    let disclosed = disclosed_lengths(bundle);

    check_structural(
        &ManifestView {
            files: &struct_files,
            units: &struct_units,
        },
        &BundleView {
            revealed_unit_ids: &revealed_ids,
            touched_files: &touched,
            proof_unit_refs: &proof_refs,
            disclosed_lengths: &disclosed,
        },
    )?;

    let coherence_units = coherence_units(&rows);
    let reveals = revealed_unit_refs(bundle);
    let touched_ids: Vec<u64> = touched.iter().map(|file| file.file_id).collect();
    check_coherence(
        &coherence_units,
        &CoherenceBundleView {
            reveals: &reveals,
            touched_file_ids: &touched_ids,
        },
    )?;

    // ── Stage 3: per-unit evidence (R2) ────────────────────────────────
    let (verified_owned, unit_failures) = run_unit_stage(bundle, body, &rows, mode);
    if let Some(failures) = into_failures(unit_failures) {
        return Err(failures);
    }
    let verified: Vec<VerifiedUnitBytes<'_>> = verified_owned
        .iter()
        .map(|unit| VerifiedUnitBytes {
            unit_id: unit.unit_id,
            file_id: unit.file_id,
            kind: unit.kind,
            range_start: unit.range_start,
            bytes: &unit.bytes,
        })
        .collect();

    // ── Stage 4: file-level checks (R4) ────────────────────────────────
    // `fine_roots` is an owned side table because `FileEntry::fine_tree`
    // yields a `FineTree` by value, and `FileView` borrows its root.
    let fine_roots: Vec<Option<CommitmentDigest>> = body
        .files()
        .iter()
        .map(|file| file.fine_tree().root().copied())
        .collect();
    let file_views = file_views(body, &fine_roots);
    let file_units = file_unit_entries(&rows);
    let full_material = full_reveal_material(bundle);
    let summaries = check_file_stages(
        &FileStageManifestView {
            files: &file_views,
            units: &file_units,
        },
        &FileStageBundleView {
            revealed_unit_ids: &revealed_ids,
            full_material: &full_material,
        },
        &verified,
    )?;

    // ── Stage 5: sig_policy + signatures (C14) ─────────────────────────
    let scheme = check_signatures(&proof)?;

    // ── Stage 6: anchors (M0 stub) ─────────────────────────────────────
    let anchors = anchor_stubs(bundle);

    Ok(VerificationReport {
        report_version: REPORT_VERSION,
        work: WorkMetadata {
            work_id: Digest32(*work_id(proof.manifest().body_bytes()).as_bytes()),
            title: body.title().to_owned(),
            format_version: u32::try_from(body.format_version()).unwrap_or(u32::MAX),
            app_version: body.app_version().to_owned(),
            // Verbatim: the manifest stores POSIX seconds as a `uint`, and
            // the decimal rendering of that integer is the only form that
            // adds nothing. Choosing a human date format here would be a
            // format-permanent decision, and it belongs to R18's renderer.
            claimed_time_informational_only: Some(body.claimed_time().to_string()),
            signature_scheme: scheme,
        },
        evidence: EvidenceLayerResult {
            passed: true,
            units_verified: u64::try_from(verified.len()).unwrap_or(u64::MAX),
        },
        storage_linkage: StorageLinkageResult::NotEvaluated,
        anchors,
        supporting_evidence: SupportingEvidenceResult::None,
        reveal: reveal_set(body, bundle, &rows, &revealed_ids, &summaries)?,
    })
}

// ---------------------------------------------------------------------------
// stage 2 inputs
// ---------------------------------------------------------------------------

/// The manifest unit table, flattened in manifest order.
fn flatten_units(body: &ManifestBodyV1) -> Vec<UnitRow<'_>> {
    let mut rows = Vec::new();
    for (index, file) in body.files().iter().enumerate() {
        let file_id = u64::try_from(index).unwrap_or(u64::MAX);
        rows.extend(file.units().iter().map(|entry| UnitRow { file_id, entry }));
    }
    rows
}

fn structural_files(body: &ManifestBodyV1) -> Vec<StructuralFileEntry> {
    body.files()
        .iter()
        .enumerate()
        .map(|(index, file)| StructuralFileEntry {
            file_id: u64::try_from(index).unwrap_or(u64::MAX),
            size: file.size(),
            path_commit: *file.path_commit(),
        })
        .collect()
}

fn structural_units(rows: &[UnitRow<'_>]) -> Vec<StructuralUnitEntry> {
    rows.iter()
        .map(|row| StructuralUnitEntry {
            unit_id: row.unit_id(),
            file_id: row.file_id,
            kind: row.kind(),
            range_start: row.entry.range().start(),
            range_end: row.entry.range().end_exclusive().unwrap_or(u64::MAX),
        })
        .collect()
}

fn touched_files<'b>(bundle: &'b BundleV1<'b>) -> Vec<TouchedFile<'b>> {
    bundle
        .touched_files()
        .iter()
        .map(|file| TouchedFile {
            file_id: file.file_id(),
            path: file.path(),
            path_salt: file.path_salt().as_bytes(),
        })
        .collect()
}

/// Every disclosed fixed-length byte string in the bundle, as
/// (class, observed length) pairs.
///
/// All of them are already exact by construction — F8's schema decodes them
/// into fixed-size types — so this group is a backstop (module docs). It is
/// built from the *decoded* values rather than the wire so it stays honest
/// about what the pipeline actually holds.
fn disclosed_lengths(bundle: &BundleV1<'_>) -> Vec<DisclosedField> {
    fn field(field: LengthField, len: usize) -> DisclosedField {
        DisclosedField {
            field,
            len: u64::try_from(len).unwrap_or(u64::MAX),
        }
    }

    let mut fields = Vec::new();
    for reveal in bundle.noncovered_reveals() {
        fields.push(field(
            LengthField::UnitSalt,
            reveal.unit_salt().as_bytes().len(),
        ));
    }
    for file in bundle.touched_files() {
        fields.push(field(
            LengthField::PathSalt,
            file.path_salt().as_bytes().len(),
        ));
    }
    for full in bundle.full_reveals() {
        fields.push(field(
            LengthField::FileSalt,
            full.file_salt().as_bytes().len(),
        ));
        if let Some(s_root) = full.disclosed_s_root() {
            fields.push(field(LengthField::SRoot, s_root.as_bytes().len()));
        }
    }
    for reveal in bundle.covered_reveals() {
        for entry in reveal.cover() {
            fields.push(field(
                LengthField::GgmCoveringSeed,
                entry.seed().as_bytes().len(),
            ));
        }
        for node in reveal.paths() {
            fields.push(field(
                LengthField::BoundaryNodeHash,
                node.hash().as_bytes().len(),
            ));
        }
    }
    fields
}

fn coherence_units(rows: &[UnitRow<'_>]) -> Vec<CoherenceUnit> {
    rows.iter()
        .map(|row| CoherenceUnit {
            unit_id: row.unit_id(),
            file_id: row.file_id,
            binding: row.binding_mode(),
        })
        .collect()
}

fn revealed_unit_refs(bundle: &BundleV1<'_>) -> Vec<RevealedUnitRef> {
    bundle
        .covered_reveals()
        .iter()
        .map(|reveal| RevealedUnitRef {
            unit_id: reveal.unit_id(),
            section: RevealSection::Covered,
        })
        .chain(
            bundle
                .noncovered_reveals()
                .iter()
                .map(|reveal| RevealedUnitRef {
                    unit_id: reveal.unit_id(),
                    section: RevealSection::NonCovered,
                }),
        )
        .collect()
}

// ---------------------------------------------------------------------------
// stage 3
// ---------------------------------------------------------------------------

/// Run R2's per-unit stages over every revealed unit, in manifest unit
/// order.
///
/// Returns the verified bytes and the findings. In [`Mode::FailFast`] the
/// findings list holds at most one element and iteration stops there; in
/// [`Mode::Collect`] every unit is attempted, since units are independent of
/// one another (D27 §3).
fn run_unit_stage(
    bundle: &BundleV1<'_>,
    body: &ManifestBodyV1,
    rows: &[UnitRow<'_>],
    mode: Mode,
) -> (Vec<VerifiedUnit>, Vec<VerifyError>) {
    let mut verified = Vec::new();
    let mut failures = Vec::new();

    for row in rows {
        let unit_id = row.unit_id();
        let Some(file) = body
            .files()
            .get(usize::try_from(row.file_id).unwrap_or(usize::MAX))
        else {
            // Unreachable: R3 group 2 proved every unit's file exists.
            continue;
        };
        let covered = bundle
            .covered_reveals()
            .iter()
            .find(|reveal| reveal.unit_id() == unit_id);
        let noncovered = bundle
            .noncovered_reveals()
            .iter()
            .find(|reveal| reveal.unit_id() == unit_id);

        let outcome = match (row.entry.binding(), covered, noncovered) {
            (UnitBinding::FineTreeCovered, Some(reveal), None) => {
                verify_covered(row, file.fine_tree(), file.size(), body, reveal)
            }
            (UnitBinding::NonCovered { unit_commit }, None, Some(reveal)) => {
                verify_non_covered(row, body, reveal, unit_commit)
            }
            // Not revealed at all — nothing to verify.
            (_, None, None) => continue,
            // Defensive backstops. `super::coherence` rejected both of
            // these in stage 2 with these exact codes; keeping the arms
            // here is what makes the dispatch total without an `unwrap`,
            // and mirrors R4's row-6 backstop.
            (UnitBinding::FineTreeCovered, ..) => Err(VerifyError::RevealModeMismatch {
                unit_id,
                manifest_binding: BindingMode::FineTreeCovered,
            }),
            (UnitBinding::NonCovered { .. }, ..) => Err(VerifyError::RevealModeMismatch {
                unit_id,
                manifest_binding: BindingMode::NonCovered,
            }),
        };

        match outcome {
            Ok(bytes) => verified.push(VerifiedUnit {
                unit_id,
                file_id: row.file_id,
                kind: row.kind(),
                range_start: row.entry.range().start(),
                bytes,
            }),
            Err(error) => {
                failures.push(error);
                if mode == Mode::FailFast {
                    break;
                }
            }
        }
    }

    (verified, failures)
}

/// R2 stages for a fine-tree-covered unit, with G13's `verify_range`
/// pre-bound over the bundle's cover and boundary path.
fn verify_covered(
    row: &UnitRow<'_>,
    fine_tree: FineTree,
    leaf_count: u64,
    body: &ManifestBodyV1,
    reveal: &CoveredReveal,
) -> Result<Vec<u8>, VerifyError> {
    let unit_id = row.unit_id();
    let range = row.entry.range();

    // Structurally unreachable: F5 ties a covered binding to a present
    // fine tree (`FileEntry::new`). Reusing G13's own semantic for
    // "a range against a file with no fine tree" keeps the arm total
    // without minting a code for a state the decoder cannot produce.
    let FineTree::Present { root } = fine_tree else {
        return Err(VerifyError::FineRootBindingFailed {
            unit_id,
            source: crate::content::fine_tree::FineTreeError::RangeOutOfBounds {
                start: range.start(),
                length: range.length(),
                leaf_count: 0,
            },
        });
    };

    let cover: Vec<WireNode<'_>> = reveal
        .cover()
        .iter()
        .map(|entry| WireNode {
            level: entry.address().level(),
            index: entry.address().index(),
            bytes: entry.seed().as_bytes(),
        })
        .collect();
    let boundary: Vec<WireNode<'_>> = reveal
        .paths()
        .iter()
        .map(|node| WireNode {
            level: node.address().level(),
            index: node.address().index(),
            bytes: node.hash().as_bytes(),
        })
        .collect();
    let view = RangeProofView {
        range: ContentByteRange::new(range.start(), range.length()),
        cover: &cover,
        boundary: &boundary,
    };
    let fine_root = FineRoot::from_bytes(root);
    let check = |bytes: &[u8]| verify_range(&view, bytes, leaf_count, &fine_root);

    let nonce = AeadNonce::from_bytes(*row.entry.nonce().as_bytes());
    verify_revealed_unit(
        RevealedUnitInput {
            seal_id: body.seal_id(),
            unit_id: UnitId(unit_id),
            nonce: &nonce,
            true_length: row.entry.true_length(),
            range_width: range.length(),
            k_u: reveal.k_u(),
            ciphertext: reveal.ciphertext().as_slice(),
        },
        ContentBinding::FineTreeCovered {
            verify_range: &check,
        },
    )
}

/// R2 stages for a non-covered unit (`--no-fine-tree` whole-file unit or a
/// raw mirror), bound by its own `unit_commit`.
fn verify_non_covered(
    row: &UnitRow<'_>,
    body: &ManifestBodyV1,
    reveal: &NonCoveredReveal,
    unit_commit: &CommitmentDigest,
) -> Result<Vec<u8>, VerifyError> {
    let range = row.entry.range();
    let nonce = AeadNonce::from_bytes(*row.entry.nonce().as_bytes());
    verify_revealed_unit(
        RevealedUnitInput {
            seal_id: body.seal_id(),
            unit_id: UnitId(row.unit_id()),
            nonce: &nonce,
            true_length: row.entry.true_length(),
            range_width: range.length(),
            k_u: reveal.k_u(),
            ciphertext: reveal.ciphertext().as_slice(),
        },
        ContentBinding::NonCovered {
            unit_salt: reveal.unit_salt(),
            unit_commit,
        },
    )
}

fn into_failures(mut findings: Vec<VerifyError>) -> Option<VerifyFailures> {
    if findings.is_empty() {
        return None;
    }
    let mut rest = findings.split_off(1);
    let primary = findings.pop()?;
    let mut failures = VerifyFailures::new(primary);
    for finding in rest.drain(..) {
        failures.push(finding);
    }
    Some(failures)
}

// ---------------------------------------------------------------------------
// stage 4 inputs
// ---------------------------------------------------------------------------

fn file_views<'m>(
    body: &'m ManifestBodyV1,
    fine_roots: &'m [Option<CommitmentDigest>],
) -> Vec<FileView<'m>> {
    body.files()
        .iter()
        .enumerate()
        .map(|(index, file)| FileView {
            file_id: u64::try_from(index).unwrap_or(u64::MAX),
            size: file.size(),
            canon: match file.canon() {
                CanonMode::Binary => FileCanonMode::Binary,
                CanonMode::Text {
                    canon_commit,
                    unicode_version,
                } => FileCanonMode::Text {
                    canon_commit,
                    unicode_version,
                },
            },
            raw_commit: file.raw_commit(),
            fine_tree: match fine_roots.get(index).and_then(Option::as_ref) {
                Some(root) => FileFineTree::Present { root },
                None => FileFineTree::Absent,
            },
        })
        .collect()
}

fn file_unit_entries(rows: &[UnitRow<'_>]) -> Vec<FileUnitEntry> {
    rows.iter()
        .map(|row| FileUnitEntry {
            unit_id: row.unit_id(),
            file_id: row.file_id,
            kind: row.kind(),
        })
        .collect()
}

/// The full-reveal material, **as wire bytes** — R4 adjudicates their
/// optionality, so R5 must not pre-convert them (R4 module docs).
fn full_reveal_material<'b>(bundle: &'b BundleV1<'b>) -> Vec<FullRevealMaterialEntry<'b>> {
    bundle
        .full_reveals()
        .iter()
        .map(|full| FullRevealMaterialEntry {
            file_id: full.file_id(),
            file_salt: Some(full.file_salt().as_bytes().as_slice()),
            s_root: full
                .disclosed_s_root()
                .map(|seed| seed.as_bytes().as_slice()),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// stage 5
// ---------------------------------------------------------------------------

/// C14's signature stage over the manifest body bytes **as received**.
///
/// The policy comes from the signed body, the public keys from the body's
/// `pubkeys` map, and the signatures from the envelope's enumerable
/// `signatures` container (F6 made it enumerable precisely so a
/// present-but-unlisted algorithm is detectable here). Every failure class
/// — unlisted extra, missing, non-canonical encoding, invalid — surfaces
/// through the [`VerifyError::Crypto`] wrapper arm with its own `crypto-*`
/// code unchanged.
fn check_signatures(proof: &SealProof<'_>) -> Result<SignatureScheme, VerifyError> {
    let body = proof.manifest().body();
    let policy = SigPolicy::new(body.sig_policy().iter().copied()).map_err(VerifyError::Crypto)?;
    let pubkeys = alg_material(body.pubkeys());
    let signatures = alg_material(proof.manifest().signatures());
    let label = verify_body(
        &policy,
        &pubkeys,
        &signatures,
        proof.manifest().body_bytes(),
    )
    .map_err(VerifyError::Crypto)?;
    Ok(match label {
        PolicyLabel::Hybrid => SignatureScheme::HybridPq,
        PolicyLabel::Ed25519Only => SignatureScheme::Ed25519Only,
        PolicyLabel::Other => SignatureScheme::Other,
    })
}

fn alg_material(map: &crate::manifest::SigAlgMap) -> Vec<(SigAlg, Vec<u8>)> {
    map.iter()
        .map(|(alg, bytes)| (alg, bytes.to_vec()))
        .collect()
}

// ---------------------------------------------------------------------------
// stage 6
// ---------------------------------------------------------------------------

/// The M0 anchor stage: one `absent` slot per embedded artifact, OTS
/// section first (bundle section-key order), no artifact byte parsed and no
/// bundle-recorded metadata copied (module docs).
fn anchor_stubs(bundle: &BundleV1<'_>) -> Vec<AnchorResult> {
    fn stub(kind: AnchorKind) -> AnchorResult {
        AnchorResult {
            kind,
            state: AnchorState::Absent,
            verified_time_unix: None,
            source: None,
            fetch_date: None,
        }
    }

    bundle
        .ots_anchors()
        .iter()
        .map(|_| stub(AnchorKind::Ots))
        .chain(bundle.tsa_anchors().iter().map(|_| stub(AnchorKind::Tsa)))
        .collect()
}

// ---------------------------------------------------------------------------
// the report's reveal set
// ---------------------------------------------------------------------------

/// Build the redaction/reveal-set data (MVP-SPEC.md line 121: position and
/// total size are always present).
///
/// A file with at least one revealed unit becomes a [`FileReveal`] carrying
/// its verified path; every other file becomes an
/// [`UnrevealedFilePlaceholder`] — size only, path withheld — including a
/// file whose path the bundle disclosed without revealing any of its bytes
/// (see [`super::coherence`]). Spans are sorted by start; R3's tiling check
/// already guarantees the manifest order is that order, but sorting here
/// keeps the report's own invariant local to the report.
fn reveal_set(
    body: &ManifestBodyV1,
    bundle: &BundleV1<'_>,
    rows: &[UnitRow<'_>],
    revealed_ids: &[u64],
    summaries: &[FileRevealSummary],
) -> Result<RevealSet, VerifyError> {
    let mut files = Vec::new();
    let mut unrevealed_files = Vec::new();

    for (index, file) in body.files().iter().enumerate() {
        let file_id = u64::try_from(index).unwrap_or(u64::MAX);
        let mut revealed_spans = Vec::new();
        let mut unrevealed_spans = Vec::new();
        let mut raw_mirror = None;
        let mut touched = false;

        for row in rows.iter().filter(|row| row.file_id == file_id) {
            let unit_id = row.unit_id();
            let is_revealed = revealed_ids.contains(&unit_id);
            touched |= is_revealed;
            match row.kind() {
                UnitKind::RawMirror => {
                    if is_revealed {
                        raw_mirror = Some(RawMirrorReveal {
                            unit_id,
                            raw_size: row.entry.true_length(),
                        });
                    }
                }
                UnitKind::Normal => {
                    let span = UnitSpan {
                        unit_id,
                        start: row.entry.range().start(),
                        end: row.entry.range().end_exclusive().unwrap_or(u64::MAX),
                    };
                    if is_revealed {
                        revealed_spans.push(span);
                    } else {
                        unrevealed_spans.push(span);
                    }
                }
            }
        }

        if !touched {
            unrevealed_files.push(UnrevealedFilePlaceholder {
                file_id,
                size: file.size(),
            });
            continue;
        }

        revealed_spans.sort_by_key(|span| span.start);
        unrevealed_spans.sort_by_key(|span| span.start);

        // D80 guarantees a `touched_files` entry exists for every file with
        // a revealed unit; the error arm is the unreachable backstop, and it
        // reports the same rule that would have caught it in stage 2.
        let Some(entry) = bundle
            .touched_files()
            .iter()
            .find(|entry| entry.file_id() == file_id)
        else {
            let unit_id = revealed_spans
                .first()
                .map_or_else(|| raw_mirror.map_or(0, |m| m.unit_id), |span| span.unit_id);
            return Err(VerifyError::RevealedUnitFileNotTouched { unit_id, file_id });
        };

        files.push(FileReveal {
            file_id,
            path: entry.path().to_owned(),
            total_size: file.size(),
            fully_revealed: summaries.get(index).is_some_and(FileRevealSummary::is_full),
            revealed_spans,
            unrevealed_spans,
            raw_mirror,
        });
    }

    Ok(RevealSet {
        files,
        unrevealed_files,
    })
}
