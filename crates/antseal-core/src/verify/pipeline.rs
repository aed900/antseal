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
//! | 2 | [`Structural`] | [`check_structural`] (lengths → manifest refs → bundle refs → tiling → `path_commit`), then [`check_coherence`] (D80 touched-file coverage → D82 touched-set exactness → reveal-section agreement) | R3 + R5 |
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
/// [`UnrevealedFilePlaceholder`] — size only, path withheld. Since D82 the
/// second arm handles only genuinely *untouched* files: a bundle disclosing
/// a path without revealing any of that file's bytes no longer reaches this
/// function, because stage 2's coherence group 1b rejects it (see
/// [`super::coherence`]). Spans are sorted by start; R3's tiling check
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

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::bundle::{
        BundleParts, CoverEntry as BundleCoverEntry, FullReveal, OpaqueBytes, PathNode,
        StorageRecord, TouchedFile as BundleTouchedFile, encode_bundle,
    };
    use crate::canon::{TextMode, UNICODE_17_0_0, canonicalize_v};
    use crate::content::fine_tree::{prove_range, rebuild_fine_root};
    use crate::crypto::commit::{canon_commit, path_commit, raw_commit, unit_commit};
    use crate::crypto::error::SaltKind;
    use crate::crypto::hkdf::derive_unit_key;
    use crate::crypto::material::{FileSalt, Key32, MasterSecretRef, NodeHash32, Salt16, Seed32};
    use crate::crypto::secrets::SealId;
    use crate::crypto::sig_policy::{public_keys, sign_body};
    use crate::crypto::unit_aead::encrypt_unit;
    use crate::manifest::body::{
        ByteRange, ContentAddress, FileEntry, Nonce24 as ManifestNonce, UnitEntry, encode_body,
    };
    use crate::manifest::{SigAlgMap, SigMaterial, encode_envelope};

    // -----------------------------------------------------------------
    // the R5 smoke fixture
    // -----------------------------------------------------------------
    //
    // **This is not R6.** R6 owns the seeded constructor for *every* M0
    // shape and is the substrate R7–R10 mutate; this is one hand-built
    // work, deliberately narrow, whose only job is to let R5's own
    // orchestration and stage order be tested at all. It lives in this
    // module (not `test_util`) so nothing outside R5 can depend on it and
    // R6 has nothing to unpick. It does exercise, in one work, every
    // branch the orchestration has:
    //
    // | file | shape | why it is here |
    // |---|---|---|
    // | 0 `notes/intro.md` | text, fine tree, 2 units + raw mirror, **fully revealed** | the covered dispatch, the full-reveal cross-checks, the mirror binding, D75's two routes to `fine_root` |
    // | 1 `data/blob.bin` | binary, fine tree, 3 units, **1 revealed** | partial-reveal isolation, blackout spans, a covered unit outside a full reveal |
    // | 2 `archive/old.txt` | text, `--no-fine-tree`, 1 unit, **untouched** | the non-covered `unit_commit` branch, and the committed-placeholder rendering |
    //
    // Every byte of key material is a recognisable constant pattern and
    // nothing here is derived from a real secret (`testdata/README.md`).
    //
    // # Why it survives R6 (task R29, decided here)
    //
    // R29 offered two ends: rewrite these tests against R6's shapes and
    // delete this fixture, or keep it as a deliberate **independent
    // construction** and assert the two agree. The second was taken, for
    // three reasons that are worth having written down rather than
    // inferred:
    //
    // 1. **Independence is the asset, not the duplication.** R9 froze
    //    R6's bundle bytes for 21 shapes, so one of the two definitions of
    //    "a valid bundle" is now a CI-enforced artifact. That makes the
    //    frozen half *authoritative-looking*, not *correct* — a builder
    //    bug that predates the freeze is pinned, not caught. A second
    //    construction that shares no code with the first, and agrees with
    //    it, is evidence the frozen artifact is right. Deleting it would
    //    have traded the only cross-check for a smaller file. This is the
    //    same argument that makes F14's independent CBOR implementation
    //    worth its cost.
    // 2. **Option (a) was not actually cheap.** These tests need two
    //    mutations R6's `Tweak` has no knob for — a corrupt Ed25519
    //    signature and a corrupted GGM **cover seed** — so deleting this
    //    fixture meant *adding* to R6's constructor, in the same region
    //    D83 is changing. The cheap-looking option cost a change to the
    //    frozen half.
    // 3. **The stage-order pins are ordering claims, and R9 pins
    //    outputs.** `stage_order_*` needs *combinations* of mutations
    //    (broken tiling **and** corrupt ciphertext, and so on) whose value
    //    is which error arrives first. No committed vector expresses that,
    //    so the fixture's most load-bearing tests had nothing to migrate
    //    to.
    //
    // What R29 fixes is the actual defect — the two definitions were
    // *unrelated*. `the_two_constructions_agree_on_a_valid_bundle` and
    // `the_two_constructions_agree_on_what_they_reject` below bind them,
    // so they can no longer drift silently.

    /// Fixed, public, NON-SECRET master secret.
    const TEST_W: [u8; 32] = [0x5A; 32];
    /// Fixed, public, NON-SECRET `seal_id`.
    const TEST_SEAL_ID: [u8; 16] = [0xB0; 16];
    /// Seeds the fixture's AEAD nonces, so the bundle bytes are reproducible.
    const TEST_RNG_SEED: [u8; 32] = [0x52; 32];

    const F0_PATH: &str = "notes/intro.md";
    const F1_PATH: &str = "data/blob.bin";
    const F2_PATH: &str = "archive/old.txt";

    fn w() -> MasterSecretRef<'static> {
        MasterSecretRef::from_bytes(&TEST_W)
    }

    fn seal_id() -> SealId {
        SealId::from_bytes(TEST_SEAL_ID)
    }

    fn salt16(pattern: u8) -> Salt16 {
        Salt16::try_from_slice(SaltKind::Unit, &[pattern; 16]).expect("16 bytes")
    }

    fn file_salt(pattern: u8) -> FileSalt {
        FileSalt::from_disclosed(salt16(pattern))
    }

    fn seed32(pattern: u8) -> Seed32 {
        Seed32::from_bytes([pattern; 32])
    }

    /// Which mutation a fixture carries: one knob per tamper case, plus
    /// the combinations the stage-order pins need.
    #[derive(Debug, Clone, Default)]
    struct Tweak {
        /// Flip a byte of the first GGM cover seed of unit 0 (D75).
        corrupt_cover_seed: bool,
        /// Flip a byte of file 0's disclosed `s_root`.
        corrupt_s_root: bool,
        /// Omit file 0's whole full-reveal entry (`file_salt` + `s_root`).
        drop_full_material: bool,
        /// Omit the `touched_files` entry for this file (D80).
        drop_touched_file: Option<u64>,
        /// Splice a `touched_files` entry for file 2 — which this fixture
        /// reveals nothing from — using this `path_salt` byte pattern
        /// (D82). `Some(0x32)` is the file's **genuine** salt, so
        /// `check_path_commits` (stage 2's structural groups, which run
        /// before coherence) cannot preempt D82's code with
        /// `path-commit-mismatch`; that is the whole point of the knob,
        /// and `path_salt = HKDF(W, "path-salt", file_id)` being a
        /// per-work constant is why the splice needs no forgery. Any other
        /// pattern is the junk-salt control.
        add_touched_file_2: Option<u8>,
        /// Emit this covered unit in `noncovered_reveals` instead.
        misplace_covered_unit: Option<u64>,
        /// Flip a ciphertext byte of each of these units.
        corrupt_ciphertext: Vec<u64>,
        /// Shorten file 1's first (unrevealed) unit range, opening a gap
        /// in the manifest's tiling of that file.
        break_tiling: bool,
        /// Flip a byte of the Ed25519 signature.
        corrupt_signature: bool,
    }

    /// One unit as the fixture builds it.
    struct PlannedUnit {
        unit_id: u64,
        file_id: u64,
        kind: ManifestUnitKind,
        range: ByteRange,
        bytes: Vec<u8>,
        covered: bool,
        ciphertext: Vec<u8>,
        nonce: ManifestNonce,
    }

    impl PlannedUnit {
        fn new(
            rng: &mut ChaCha20Rng,
            unit_id: u64,
            file_id: u64,
            kind: ManifestUnitKind,
            start: u64,
            bytes: &[u8],
            covered: bool,
        ) -> Self {
            let (ciphertext, nonce) = encrypt_unit(w(), &seal_id(), UnitId(unit_id), bytes, rng)
                .expect("fixture encryption succeeds");
            Self {
                unit_id,
                file_id,
                kind,
                range: ByteRange::new(start, u64::try_from(bytes.len()).expect("small")),
                bytes: bytes.to_vec(),
                covered,
                ciphertext,
                nonce: ManifestNonce::from_bytes(*nonce.as_bytes()),
            }
        }

        fn manifest_entry(&self) -> UnitEntry {
            let binding = if self.covered {
                UnitBinding::FineTreeCovered
            } else {
                UnitBinding::NonCovered {
                    unit_commit: unit_commit(&salt16(unit_salt_pattern(self.unit_id)), &self.bytes),
                }
            };
            UnitEntry::new(
                self.unit_id,
                self.kind,
                self.range,
                u64::try_from(self.bytes.len()).expect("small"),
                binding,
                self.nonce,
                ContentAddress::from_bytes([u8::try_from(self.unit_id).unwrap_or(0xFF); 32]),
            )
        }
    }

    /// The `unit_salt` pattern for a unit id (only non-covered units use it).
    fn unit_salt_pattern(unit_id: u64) -> u8 {
        0x40u8.wrapping_add(u8::try_from(unit_id).unwrap_or(0))
    }

    /// Build the fixture `.sealproof` bytes under `tweak`.
    #[allow(clippy::too_many_lines)]
    fn fixture(tweak: &Tweak) -> Vec<u8> {
        let mut rng = ChaCha20Rng::from_seed(TEST_RNG_SEED);

        // ── content ────────────────────────────────────────────────────
        let f0_raw = b"line one\r\nline two\r\n".to_vec();
        let f0_canon = canonicalize_v(UNICODE_17_0_0, TextMode::Detected, &f0_raw)
            .expect("fixture text canonicalizes")
            .into_bytes();
        let f1_raw: Vec<u8> = (0u8..30).collect();
        let f2_raw = b"kept back\n".to_vec();

        let f0_size = u64::try_from(f0_canon.len()).expect("small");
        let f1_size = u64::try_from(f1_raw.len()).expect("small");
        let f2_size = u64::try_from(f2_raw.len()).expect("small");
        let half = usize::try_from(f0_size / 2).expect("small");

        // ── units, in manifest order (so unit_id == ordinal) ───────────
        let mut units = vec![
            PlannedUnit::new(
                &mut rng,
                0,
                0,
                ManifestUnitKind::Normal,
                0,
                &f0_canon[..half],
                true,
            ),
            PlannedUnit::new(
                &mut rng,
                1,
                0,
                ManifestUnitKind::Normal,
                u64::try_from(half).expect("small"),
                &f0_canon[half..],
                true,
            ),
            PlannedUnit::new(
                &mut rng,
                2,
                0,
                ManifestUnitKind::RawMirror,
                0,
                &f0_raw,
                false,
            ),
            PlannedUnit::new(
                &mut rng,
                3,
                1,
                ManifestUnitKind::Normal,
                0,
                &f1_raw[..10],
                true,
            ),
            PlannedUnit::new(
                &mut rng,
                4,
                1,
                ManifestUnitKind::Normal,
                10,
                &f1_raw[10..20],
                true,
            ),
            PlannedUnit::new(
                &mut rng,
                5,
                1,
                ManifestUnitKind::Normal,
                20,
                &f1_raw[20..],
                true,
            ),
            PlannedUnit::new(&mut rng, 6, 2, ManifestUnitKind::Normal, 0, &f2_raw, false),
        ];

        if tweak.break_tiling {
            // Unit 3 is unrevealed, so narrowing its manifest range is a
            // pure tiling defect: `[0,9) [10,20) [20,30)` leaves byte 9
            // covered by nothing, and no per-unit check ever runs on it.
            units[3].range = ByteRange::new(0, 9);
        }

        // ── manifest ───────────────────────────────────────────────────
        let f0_root = rebuild_fine_root(&seed32(0x13), &f0_canon).expect("fine root");
        let f1_root = rebuild_fine_root(&seed32(0x23), &f1_raw).expect("fine root");

        let file0 = FileEntry::new(
            path_commit(&salt16(0x12), F0_PATH),
            raw_commit(&file_salt(0x11), &f0_raw),
            CanonMode::Text {
                canon_commit: canon_commit(&file_salt(0x11), &f0_canon),
                unicode_version: UNICODE_17_0_0.to_owned(),
            },
            f0_size,
            FineTree::Present {
                root: *f0_root.as_bytes(),
            },
            units[0..3]
                .iter()
                .map(PlannedUnit::manifest_entry)
                .collect(),
        )
        .expect("file 0 is well formed");

        let file1 = FileEntry::new(
            path_commit(&salt16(0x22), F1_PATH),
            raw_commit(&file_salt(0x21), &f1_raw),
            CanonMode::Binary,
            f1_size,
            FineTree::Present {
                root: *f1_root.as_bytes(),
            },
            units[3..6]
                .iter()
                .map(PlannedUnit::manifest_entry)
                .collect(),
        )
        .expect("file 1 is well formed");

        let file2 = FileEntry::new(
            path_commit(&salt16(0x32), F2_PATH),
            raw_commit(&file_salt(0x31), &f2_raw),
            CanonMode::Text {
                canon_commit: canon_commit(&file_salt(0x31), &f2_raw),
                unicode_version: UNICODE_17_0_0.to_owned(),
            },
            f2_size,
            FineTree::Absent,
            units[6..].iter().map(PlannedUnit::manifest_entry).collect(),
        )
        .expect("file 2 is well formed");

        let policy = SigPolicy::hybrid();
        let pubkeys = SigAlgMap::new(SigMaterial::Pubkey, public_keys(w(), &policy))
            .expect("fixture pubkeys");
        let body = ManifestBodyV1::new(
            "antseal-fixture/1".to_owned(),
            seal_id(),
            "R5 pipeline fixture".to_owned(),
            1_767_225_600,
            pubkeys,
            policy.algorithms().to_vec(),
            vec![file0, file1, file2],
        )
        .expect("fixture body is well formed");
        let body_bytes = encode_body(body).expect("fixture body encodes");

        let mut signature_material = sign_body(w(), &policy, &body_bytes);
        if tweak.corrupt_signature
            && let Some((_, bytes)) = signature_material.first_mut()
        {
            bytes[0] ^= 0x01;
        }
        let signatures =
            SigAlgMap::new(SigMaterial::Signature, signature_material).expect("fixture signatures");
        let manifest_bytes =
            encode_envelope(&body_bytes, &signatures).expect("fixture envelope encodes");

        // ── bundle ─────────────────────────────────────────────────────
        // Revealed: file 0 in full (units 0, 1 + mirror 2), file 1's unit 4
        // only, file 2 not at all.
        let revealed: [u64; 4] = [0, 1, 2, 4];
        let mut covered_reveals = Vec::new();
        let mut noncovered_reveals = Vec::new();

        for unit in &units {
            if !revealed.contains(&unit.unit_id) {
                continue;
            }
            let mut ciphertext = unit.ciphertext.clone();
            if tweak.corrupt_ciphertext.contains(&unit.unit_id) {
                ciphertext[0] ^= 0x01;
            }
            let k_u = derive_unit_key(w(), UnitId(unit.unit_id));
            let misplaced = tweak.misplace_covered_unit == Some(unit.unit_id);

            if unit.covered && !misplaced {
                let (s_root, content, leaf_count) = if unit.file_id == 0 {
                    (seed32(0x13), f0_canon.as_slice(), f0_size)
                } else {
                    (seed32(0x23), f1_raw.as_slice(), f1_size)
                };
                let proof = prove_range(
                    &s_root,
                    content,
                    ContentByteRange::new(unit.range.start(), unit.range.length()),
                    leaf_count,
                )
                .expect("fixture range proof");

                let mut cover: Vec<BundleCoverEntry> = proof
                    .cover()
                    .iter()
                    .map(|entry| {
                        // The disclosed form (D83): at `level == d` it is
                        // `salt_i ‖ 0x00·16`, not the raw derived seed.
                        BundleCoverEntry::new(
                            entry.node().address(),
                            Seed32::from_bytes(*entry.payload().as_bytes()),
                        )
                    })
                    .collect();
                if tweak.corrupt_cover_seed && unit.unit_id == 0 {
                    let mut bytes = *cover[0].seed().as_bytes();
                    bytes[0] ^= 0x01;
                    cover[0] = BundleCoverEntry::new(cover[0].address(), Seed32::from_bytes(bytes));
                }
                let paths: Vec<PathNode> = proof
                    .boundary()
                    .iter()
                    .map(|node| {
                        PathNode::new(
                            node.address(),
                            NodeHash32::from_bytes(*node.hash().as_bytes()),
                        )
                    })
                    .collect();

                covered_reveals.push(
                    CoveredReveal::new(
                        unit.unit_id,
                        k_u,
                        OpaqueBytes::from_vec(ciphertext),
                        cover,
                        paths,
                    )
                    .expect("fixture covered reveal"),
                );
            } else {
                noncovered_reveals.push(
                    NonCoveredReveal::new(
                        unit.unit_id,
                        k_u,
                        OpaqueBytes::from_vec(ciphertext),
                        salt16(unit_salt_pattern(unit.unit_id)),
                    )
                    .expect("fixture non-covered reveal"),
                );
            }
        }

        let mut planned_touched = vec![(0u64, F0_PATH, 0x12u8), (1, F1_PATH, 0x22)];
        if let Some(pattern) = tweak.add_touched_file_2 {
            planned_touched.push((2, F2_PATH, pattern));
        }
        let touched_files: Vec<BundleTouchedFile> = planned_touched
            .into_iter()
            .filter(|(file_id, ..)| tweak.drop_touched_file != Some(*file_id))
            .map(|(file_id, path, pattern)| {
                BundleTouchedFile::new(file_id, path.to_owned(), salt16(pattern))
            })
            .collect();

        // F8 rejects `full_reveals ⊄ touched_files` at decode, so dropping
        // file 0's path also drops its full-reveal entry — the D80 case
        // this fixture exercises is file 1's, which has no full reveal.
        let mut full_reveals = Vec::new();
        if !tweak.drop_full_material && tweak.drop_touched_file != Some(0) {
            let mut s_root = [0x13u8; 32];
            if tweak.corrupt_s_root {
                s_root[0] ^= 0x01;
            }
            full_reveals.push(FullReveal::new(
                0,
                salt16(0x11),
                Some(Seed32::from_bytes(s_root)),
            ));
        }

        let bundle = BundleV1::new(BundleParts {
            manifest: &manifest_bytes,
            storage_record: StorageRecord::new(
                ContentAddress::from_bytes([0x77; 32]),
                ManifestNonce::from_bytes([0x78; 24]),
                Key32::from_bytes([0x79; 32]),
            ),
            ots_anchors: Vec::new(),
            tsa_anchors: Vec::new(),
            receipt: None,
            covered_reveals,
            noncovered_reveals,
            touched_files,
            full_reveals,
        })
        .expect("fixture bundle is well formed");

        encode_bundle(&bundle).expect("fixture bundle encodes")
    }

    fn valid() -> Vec<u8> {
        fixture(&Tweak::default())
    }

    /// Verify `tweak`'s fixture and return the code of the first error.
    fn code_of(tweak: &Tweak) -> &'static str {
        verify_bundle(&fixture(tweak), &VerifyOptions::new())
            .expect_err("the tweaked fixture must not verify")
            .code()
    }

    // -----------------------------------------------------------------
    // the happy path
    // -----------------------------------------------------------------

    /// R5's headline Accept bullet: a valid bundle verifies end to end and
    /// the report says what the work is, what was shown, and what was not.
    #[test]
    fn a_valid_bundle_verifies_end_to_end() {
        let bytes = valid();
        let report = verify_bundle(&bytes, &VerifyOptions::new()).expect("fixture verifies");

        assert!(report.evidence.passed);
        assert_eq!(report.evidence.units_verified, 4);
        assert_eq!(report.work.title, "R5 pipeline fixture");
        assert_eq!(report.work.format_version, 1);
        assert_eq!(report.work.signature_scheme, SignatureScheme::HybridPq);
        assert_eq!(report.storage_linkage, StorageLinkageResult::NotEvaluated);
        assert_eq!(report.supporting_evidence, SupportingEvidenceResult::None);

        // `work_id` is SHA-256 over the received body bytes.
        let proof = SealProof::decode(&bytes).expect("fixture decodes");
        assert_eq!(
            report.work.work_id.0,
            *work_id(proof.manifest().body_bytes()).as_bytes()
        );

        // File 0: fully revealed, mirror rode along, no blackouts.
        let file0 = &report.reveal.files[0];
        assert_eq!(file0.path, F0_PATH);
        assert!(file0.fully_revealed);
        assert_eq!(file0.revealed_spans.len(), 2);
        assert!(file0.unrevealed_spans.is_empty());
        assert_eq!(file0.raw_mirror.map(|mirror| mirror.raw_size), Some(20));

        // File 1: one unit shown, two rendered as sized blackouts, with
        // position and total size present (MVP-SPEC.md line 121).
        let file1 = &report.reveal.files[1];
        assert_eq!(file1.path, F1_PATH);
        assert!(!file1.fully_revealed);
        assert_eq!(file1.total_size, 30);
        assert_eq!(file1.revealed_spans.len(), 1);
        assert_eq!(file1.revealed_spans[0].start, 10);
        assert_eq!(file1.unrevealed_spans.len(), 2);
        assert!(file1.raw_mirror.is_none());

        // File 2: a committed placeholder — size only, path withheld.
        assert_eq!(report.reveal.files.len(), 2);
        assert_eq!(report.reveal.unrevealed_files.len(), 1);
        assert_eq!(report.reveal.unrevealed_files[0].file_id, 2);
        assert_eq!(report.reveal.unrevealed_files[0].size, 10);
        let json = String::from_utf8(report.to_canonical_json().expect("serializes"))
            .expect("canonical JSON is UTF-8");
        assert!(!json.contains(F2_PATH), "placeholder leaked a path: {json}");
    }

    /// The M0 empty-anchor requirement (MVP-SPEC.md line 153): a bundle
    /// with no anchor artifacts verifies, and its anchor list is empty
    /// rather than absent.
    #[test]
    fn empty_anchor_bundle_verifies_with_an_empty_anchor_list() {
        let report = verify_bundle(&valid(), &VerifyOptions::new()).expect("fixture verifies");
        assert!(report.anchors.is_empty());
        let json = String::from_utf8(report.to_canonical_json().expect("report serializes"))
            .expect("canonical JSON is UTF-8");
        assert!(json.contains("\"anchors\":[]"), "{json}");
    }

    /// Determinism: two runs over the same bytes produce byte-identical
    /// canonical reports (the Q4/Q5 vector contract).
    #[test]
    fn verification_is_byte_deterministic() {
        let bytes = valid();
        let first = verify_bundle(&bytes, &VerifyOptions::new())
            .expect("verifies")
            .to_canonical_json()
            .expect("serializes");
        let second = verify_bundle(&bytes, &VerifyOptions::new())
            .expect("verifies")
            .to_canonical_json()
            .expect("serializes");
        assert_eq!(first, second);
        // The fixture itself is reproducible, which is what makes the
        // above a statement about verification rather than about luck.
        assert_eq!(bytes, valid());
    }

    /// No secret material reaches the report: the fixture's own salts,
    /// seeds and keys appear nowhere in the serialized bytes.
    #[test]
    fn no_fixture_secret_reaches_the_report() {
        let report = verify_bundle(&valid(), &VerifyOptions::new()).expect("verifies");
        let json = String::from_utf8(report.to_canonical_json().expect("serializes"))
            .expect("canonical JSON is UTF-8");
        for pattern in ["11111111", "13131313", "40404040", "5a5a5a5a"] {
            assert!(!json.contains(pattern), "{pattern} leaked into {json}");
        }
    }

    // -----------------------------------------------------------------
    // the frozen stage order
    // -----------------------------------------------------------------

    /// `VerifyStage::ALL` is the declaration order, complete and ascending
    /// — so the constant and the enum cannot drift apart.
    #[test]
    fn stage_order_constant_matches_declaration() {
        assert_eq!(
            VerifyStage::ALL,
            [
                VerifyStage::Decode,
                VerifyStage::Structural,
                VerifyStage::Units,
                VerifyStage::Files,
                VerifyStage::Signatures,
                VerifyStage::Anchors,
            ]
        );
        assert!(VerifyStage::ALL.windows(2).all(|pair| pair[0] < pair[1]));
        let names: Vec<&str> = VerifyStage::ALL.iter().map(|stage| stage.name()).collect();
        assert_eq!(
            names,
            [
                "decode",
                "structural",
                "units",
                "files",
                "signatures",
                "anchors"
            ]
        );
    }

    /// Stage 1 before everything: bytes that are not a bundle fail at
    /// decode, with the inner layer's own code (never an R code).
    #[test]
    fn stage_order_decode_runs_first() {
        for input in [&b""[..], &b"\x00\x01\x02"[..], &[0xFF; 64][..]] {
            let code = verify_bundle(input, &VerifyOptions::new())
                .expect_err("garbage is not a bundle")
                .code();
            assert!(
                code.starts_with("cbor-") || code.starts_with("bundle-"),
                "{code}"
            );
        }
    }

    /// Stage 2 before stage 3: a manifest whose units do not tile is
    /// rejected structurally even though a revealed unit's ciphertext is
    /// also corrupt.
    #[test]
    fn stage_order_structural_runs_before_units() {
        assert_eq!(
            code_of(&Tweak {
                break_tiling: true,
                corrupt_ciphertext: vec![0],
                ..Tweak::default()
            }),
            "tiling-gap"
        );
    }

    /// R3's four groups run before R5's coherence groups: with both a
    /// tiling violation and a missing `touched_files` entry, tiling wins.
    #[test]
    fn stage_order_structural_groups_run_before_coherence() {
        assert_eq!(
            code_of(&Tweak {
                break_tiling: true,
                drop_touched_file: Some(1),
                ..Tweak::default()
            }),
            "tiling-gap"
        );
    }

    /// Stage 3 before stage 4: a corrupt ciphertext is reported even
    /// though the file-level material is also missing.
    #[test]
    fn stage_order_units_run_before_files() {
        assert_eq!(
            code_of(&Tweak {
                corrupt_ciphertext: vec![0],
                drop_full_material: true,
                ..Tweak::default()
            }),
            "unit-decrypt-failed"
        );
    }

    /// Stage 4 before stage 5: a full reveal stripped of its material is
    /// reported even though the signature is also broken.
    #[test]
    fn stage_order_files_run_before_signatures() {
        assert_eq!(
            code_of(&Tweak {
                drop_full_material: true,
                corrupt_signature: true,
                ..Tweak::default()
            }),
            "full-reveal-material-missing-file-salt"
        );
    }

    /// Each mutation used above is observable on its own, so those tests
    /// are about ordering and not about one mutation being invisible.
    #[test]
    fn each_stage_order_mutation_is_observable_alone() {
        assert_eq!(
            code_of(&Tweak {
                break_tiling: true,
                ..Tweak::default()
            }),
            "tiling-gap"
        );
        assert_eq!(
            code_of(&Tweak {
                corrupt_ciphertext: vec![0],
                ..Tweak::default()
            }),
            "unit-decrypt-failed"
        );
        assert_eq!(
            code_of(&Tweak {
                drop_full_material: true,
                ..Tweak::default()
            }),
            "full-reveal-material-missing-file-salt"
        );
        assert_eq!(
            code_of(&Tweak {
                corrupt_signature: true,
                ..Tweak::default()
            }),
            "crypto-signature-invalid-ed25519"
        );
        assert_eq!(
            code_of(&Tweak {
                drop_touched_file: Some(1),
                ..Tweak::default()
            }),
            "revealed-unit-file-not-touched"
        );
    }

    // -----------------------------------------------------------------
    // D80 and the reveal-section rule
    // -----------------------------------------------------------------

    /// D80 through the whole pipeline: file 1 has a revealed unit, so its
    /// path must be disclosed.
    #[test]
    fn d80_revealed_unit_without_a_touched_file_is_rejected() {
        assert_eq!(
            code_of(&Tweak {
                drop_touched_file: Some(1),
                ..Tweak::default()
            }),
            "revealed-unit-file-not-touched"
        );
    }

    /// **D82** through the whole pipeline: file 2 is revealed from not at
    /// all, so a `touched_files` entry for it is rejected — even though the
    /// entry is *genuine* and opens the signed `path_commit`.
    #[test]
    fn d82_touched_file_without_a_revealed_unit_is_rejected() {
        assert_eq!(
            code_of(&Tweak {
                add_touched_file_2: Some(0x32),
                ..Tweak::default()
            }),
            "touched-file-without-revealed-unit"
        );
    }

    /// The trap D82's record spells out, pinned rather than assumed:
    /// `check_path_commits` runs **before** coherence and iterates the
    /// *bundle's* list, so a spliced entry whose salt does not open
    /// `path_commit` reports `path-commit-mismatch` and never reaches group
    /// 1b. A row built on such a fixture would silently test the wrong
    /// thing — so the two salts must produce two different codes, and the
    /// row above is on the good one.
    #[test]
    fn d82_a_junk_salt_is_claimed_by_the_earlier_path_commit_stage() {
        assert_eq!(
            code_of(&Tweak {
                add_touched_file_2: Some(0x99),
                ..Tweak::default()
            }),
            "path-commit-mismatch"
        );
    }

    /// The report's `UnrevealedFilePlaceholder` arm now handles only
    /// genuinely untouched files: with D82 in force there is no input that
    /// reaches [`reveal_set`] carrying a disclosed path for a file with no
    /// revealed unit. File 2 still renders as a placeholder in the valid
    /// fixture, path withheld.
    #[test]
    fn d82_leaves_the_placeholder_rendering_untouched() {
        let report = verify_bundle(&valid(), &VerifyOptions::new()).expect("the fixture verifies");
        let placeholders = &report.reveal.unrevealed_files;
        assert_eq!(placeholders.len(), 1);
        assert_eq!(placeholders[0].file_id, 2);
    }

    /// A covered unit shipped in `noncovered_reveals` is rejected before
    /// any ciphertext is opened.
    #[test]
    fn a_misplaced_covered_unit_is_rejected() {
        assert_eq!(
            code_of(&Tweak {
                misplace_covered_unit: Some(0),
                ..Tweak::default()
            }),
            "covered-unit-revealed-as-non-covered"
        );
    }

    // -----------------------------------------------------------------
    // D75: the two routes to `fine_root` are required to agree
    // -----------------------------------------------------------------

    /// **D75's owed agreement check, discharged transitively.** A full
    /// reveal of a fine-tree file carries two independent routes to
    /// `fine_root`: each unit's own GGM sub-cover (stage 3) and the file's
    /// `s_root` (stage 4). A cover seed that does not descend from the
    /// disclosed `s_root` yields different leaf salts, hence different
    /// leaves, hence a different folded root — so the *existing* per-unit
    /// binding rejects it, and reaching `fine_root` anyway would be a
    /// Merkle collision. The redundancy is enforced by both routes binding
    /// the same signed value, not by an extra comparison.
    #[test]
    fn d75_a_cover_seed_not_descending_from_s_root_is_rejected() {
        assert_eq!(
            code_of(&Tweak {
                corrupt_cover_seed: true,
                ..Tweak::default()
            }),
            "fine-root-binding-failed"
        );
    }

    /// The other route, mutated: an `s_root` that does not rebuild the
    /// manifest's `fine_root`. Distinct code, distinct stage — which is
    /// what makes the pair above a genuine agreement rather than one check
    /// wearing two hats.
    #[test]
    fn d75_an_s_root_that_does_not_rebuild_fine_root_is_rejected() {
        assert_eq!(
            code_of(&Tweak {
                corrupt_s_root: true,
                ..Tweak::default()
            }),
            "fine-root-rebuild-mismatch"
        );
    }

    // -----------------------------------------------------------------
    // D27: the two entry points
    // -----------------------------------------------------------------

    fn tamper_cases() -> Vec<Tweak> {
        vec![
            Tweak {
                break_tiling: true,
                ..Tweak::default()
            },
            Tweak {
                drop_touched_file: Some(1),
                ..Tweak::default()
            },
            Tweak {
                misplace_covered_unit: Some(0),
                ..Tweak::default()
            },
            Tweak {
                corrupt_ciphertext: vec![0],
                ..Tweak::default()
            },
            Tweak {
                corrupt_ciphertext: vec![0, 1],
                ..Tweak::default()
            },
            Tweak {
                corrupt_cover_seed: true,
                ..Tweak::default()
            },
            Tweak {
                corrupt_s_root: true,
                ..Tweak::default()
            },
            Tweak {
                drop_full_material: true,
                ..Tweak::default()
            },
            Tweak {
                corrupt_signature: true,
                ..Tweak::default()
            },
        ]
    }

    /// The D27 invariant, over every tamper case this module builds:
    /// `VerifyFailures::primary()` is exactly the fail-fast error.
    #[test]
    fn collecting_primary_equals_the_fail_fast_error() {
        for tweak in tamper_cases() {
            let bytes = fixture(&tweak);
            let fail_fast =
                verify_bundle(&bytes, &VerifyOptions::new()).expect_err("must not verify");
            let collected = verify_bundle_collecting(&bytes, &VerifyOptions::new())
                .expect_err("must not verify");
            assert_eq!(*collected.primary(), fail_fast, "{tweak:?}");
        }
    }

    /// Units are independent, so collecting mode reports all of them —
    /// and only them (no speculative file/signature findings, D27 §3).
    #[test]
    fn collecting_reports_every_independent_unit_failure() {
        let bytes = fixture(&Tweak {
            corrupt_ciphertext: vec![0, 1],
            ..Tweak::default()
        });
        let collected =
            verify_bundle_collecting(&bytes, &VerifyOptions::new()).expect_err("must not verify");
        assert_eq!(collected.count(), 2);
        let codes: Vec<&str> = collected.iter().map(VerifyError::code).collect();
        assert_eq!(codes, ["unit-decrypt-failed", "unit-decrypt-failed"]);
        assert_eq!(
            *collected.primary(),
            VerifyError::UnitDecryptFailed { unit_id: 0 }
        );
    }

    /// A failure outside the per-unit stage yields exactly one finding.
    #[test]
    fn collecting_does_not_cascade_past_a_non_unit_stage() {
        let bytes = fixture(&Tweak {
            break_tiling: true,
            ..Tweak::default()
        });
        let collected =
            verify_bundle_collecting(&bytes, &VerifyOptions::new()).expect_err("must not verify");
        assert_eq!(collected.count(), 1);
    }

    /// The valid fixture verifies identically through both entry points.
    #[test]
    fn both_entry_points_agree_on_a_valid_bundle() {
        let bytes = valid();
        let strict = verify_bundle(&bytes, &VerifyOptions::new()).expect("verifies");
        let collecting = verify_bundle_collecting(&bytes, &VerifyOptions::new())
            .map_err(|_| ())
            .expect("verifies");
        assert_eq!(strict, collecting);
    }

    // -----------------------------------------------------------------
    // hostile input
    // -----------------------------------------------------------------

    /// Every truncation, and a spread of single-bit flips, of a valid
    /// bundle is handled totally: a typed error or a report, never a panic
    /// (MVP-SPEC.md line 187, hostile bundles). R10 owns the fuzz target;
    /// this is the cheap deterministic sweep that keeps the guarantee
    /// alive between fuzz runs.
    #[test]
    fn hostile_inputs_never_panic() {
        let bytes = valid();
        for cut in 0..bytes.len() {
            drop(verify_bundle(&bytes[..cut], &VerifyOptions::new()));
        }
        for index in (0..bytes.len()).step_by(97) {
            let mut mutated = bytes.clone();
            mutated[index] ^= 0x01;
            drop(verify_bundle(&mutated, &VerifyOptions::new()));
        }
    }

    /// The options type is inert at M0 but present in the signature D27
    /// fixed, so later stages can be switched on without a break.
    #[test]
    fn default_options_are_the_m0_options() {
        assert_eq!(VerifyOptions::default(), VerifyOptions::new());
    }

    // -----------------------------------------------------------------
    // R29: the two definitions of "a valid bundle" agree
    // -----------------------------------------------------------------
    //
    // Gated on `test-vectors` because R6's constructor is (P14's tier
    // split); the fixture above and every test before this point stay
    // feature-free, so R5's suite is unchanged on a bare `cargo test -p
    // antseal-core`.

    #[cfg(feature = "test-vectors")]
    mod agreement_with_r6 {
        use super::*;
        use crate::test_util::bundle_fixtures::{
            FileSelection, FileSpec, Selection, Tweak as FixtureTweak, WorkSpec, build,
            build_tweaked,
        };
        use crate::test_util::vectors::first_difference;

        /// **The same work, described as data**: R5's three files, their
        /// contents, their splits and their fine-tree choices, expressed
        /// through R6's spec API instead of assembled by hand.
        ///
        /// Not [`shapes::multi_file`](crate::test_util::bundle_fixtures::shapes::multi_file),
        /// despite R29's text saying the two are the same work. They are
        /// nearly the same and differ in two places that matter to a report:
        /// `multi_file`'s file 0 is a **single** unit plus its mirror where
        /// this one is two, and its file 2 carries different bytes and so a
        /// different placeholder size. Building the twin here rather than
        /// widening `shapes` is deliberate — R9 froze `multi_file`'s bytes,
        /// so bending it to fit R5 would be a vector re-emit for a test's
        /// convenience.
        fn twin() -> (WorkSpec, Selection) {
            (
                WorkSpec::new(
                    // Same title, so `work.title` is not a difference the
                    // comparison has to be taught to ignore.
                    "R5 pipeline fixture",
                    vec![
                        FileSpec::text(F0_PATH, b"line one\r\nline two\r\n".to_vec())
                            .split(vec![9, 9]),
                        FileSpec::binary(F1_PATH, (0u8..30).collect::<Vec<u8>>())
                            .split(vec![10, 10, 10]),
                        FileSpec::text(F2_PATH, b"kept back\n".to_vec()).without_fine_tree(),
                    ],
                ),
                Selection(vec![
                    FileSelection::Full,
                    FileSelection::Units(vec![1]),
                    FileSelection::Untouched,
                ]),
            )
        }

        /// **R29's agreement assertion.** Two constructions that share no
        /// code produce the *same verification report* for the same work —
        /// everything but `work_id`, which must differ because the two use
        /// different master secrets, `seal_id`s and AEAD nonces by design.
        ///
        /// Written as one comparison over the whole report with that single
        /// field neutralised, rather than as a list of per-field
        /// assertions: a field **added** to the report is then covered from
        /// the moment it exists, which is the failure mode a hand-written
        /// checklist has and this does not.
        #[test]
        fn the_two_constructions_agree_on_a_valid_bundle() {
            let (spec, selection) = twin();
            let generated_bytes = build(&spec, &selection).bytes;
            let hand_bytes = valid();

            // The premise: these really are two different byte strings, so
            // the agreement below is a claim about two constructions and
            // not about one artifact compared with itself.
            assert_ne!(
                hand_bytes, generated_bytes,
                "the two fixtures produced identical bytes — the independence R29 kept is gone"
            );

            let hand = verify_bundle(&hand_bytes, &VerifyOptions::new())
                .expect("R5's hand-built fixture verifies");
            let generated =
                verify_bundle(&generated_bytes, &VerifyOptions::new()).expect("R6's twin verifies");

            assert_ne!(
                hand.work.work_id, generated.work.work_id,
                "`work_id` is SHA-256 over the manifest body; two works built from different \
                 secrets cannot share one"
            );

            let mut masked = hand.clone();
            masked.work.work_id = generated.work.work_id;
            if masked != generated {
                let json = |report: &VerificationReport| -> serde_json::Value {
                    serde_json::from_slice(&report.to_canonical_json().expect("report serializes"))
                        .expect("canonical JSON parses")
                };
                panic!(
                    "R5's hand-built fixture and R6's twin disagree about the same work: {}",
                    first_difference("report", &json(&masked), &json(&generated))
                );
            }
        }

        /// Agreement on **rejection**, not only on acceptance.
        ///
        /// The half that matters most: R5's fixture exists to pin the stage
        /// order, so its value is in which error arrives first, and a drift
        /// between the two constructions would show up here long before it
        /// showed up in a valid bundle. Each row is one mutation both
        /// vocabularies can express, named on each side.
        ///
        /// The assertion is that the two **agree**, never that a particular
        /// code appears: the tamper matrix owns the codes (error-code
        /// contract), and re-pinning them here would create a second place
        /// to edit when a row moves.
        #[test]
        fn the_two_constructions_agree_on_what_they_reject() {
            let (spec, selection) = twin();

            // Unit ids line up between the two by construction: both number
            // units work-globally in manifest order with each file's raw
            // mirror last (D23), so file 0 is units 0, 1 + mirror 2, file 1
            // is 3, 4, 5, and file 2 is unit 6.
            let rows: Vec<(&str, Tweak, FixtureTweak)> = vec![
                (
                    "drop the full-reveal material of file 0",
                    Tweak {
                        drop_full_material: true,
                        ..Tweak::default()
                    },
                    FixtureTweak {
                        drop_full_material: Some(0),
                        ..FixtureTweak::default()
                    },
                ),
                (
                    "drop file 1's touched-file entry (D80)",
                    Tweak {
                        drop_touched_file: Some(1),
                        ..Tweak::default()
                    },
                    FixtureTweak {
                        drop_touched_file: Some(1),
                        ..FixtureTweak::default()
                    },
                ),
                (
                    "corrupt unit 0's ciphertext",
                    Tweak {
                        corrupt_ciphertext: vec![0],
                        ..Tweak::default()
                    },
                    FixtureTweak {
                        corrupt_ciphertext: Some(0),
                        ..FixtureTweak::default()
                    },
                ),
                (
                    "ship covered unit 0 in `noncovered_reveals`",
                    Tweak {
                        misplace_covered_unit: Some(0),
                        ..Tweak::default()
                    },
                    FixtureTweak {
                        misplace_covered_unit: Some(0),
                        ..FixtureTweak::default()
                    },
                ),
                (
                    "touch file 2 without revealing any of it (D82)",
                    Tweak {
                        // 0x32 is the fixture's *genuine* `path_salt` for
                        // file 2, so `path_commit` still opens — the same
                        // property R6's knob has by derivation.
                        add_touched_file_2: Some(0x32),
                        ..Tweak::default()
                    },
                    FixtureTweak {
                        touch_without_reveal: Some(2),
                        ..FixtureTweak::default()
                    },
                ),
                (
                    "corrupt file 0's disclosed `s_root`",
                    Tweak {
                        corrupt_s_root: true,
                        ..Tweak::default()
                    },
                    FixtureTweak {
                        corrupt_disclosed_s_root: Some(0),
                        ..FixtureTweak::default()
                    },
                ),
            ];

            for (mutation, hand_tweak, fixture_tweak) in rows {
                let hand = code_of(&hand_tweak);
                let generated = verify_bundle(
                    &build_tweaked(&spec, &selection, &fixture_tweak).bytes,
                    &VerifyOptions::new(),
                )
                .expect_err("the tweaked twin must not verify")
                .code();
                assert_eq!(
                    hand, generated,
                    "`{mutation}`: R5's fixture reports `{hand}`, R6's twin reports \
                     `{generated}` — the two definitions of a valid bundle have drifted"
                );
            }
        }
    }
}
