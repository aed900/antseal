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
//! | 6 | [`Anchors`] | [`evaluate_anchors`] over every embedded artifact, against `anchor_digest`; receipt to the supporting-evidence slot | A18/R12 |
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
//! - **Gate the verdict on storage linkage** (MVP-SPEC.md line 119). R20's
//!   layer runs *after* the table above — by default, since D128 — and
//!   [`check_storage_linkage`] returns no `Result`, so no evidence stage
//!   can be sequenced behind it and nothing it finds can fail a bundle.
//!   "Storage is the product's bonus, not its proof": a `.sealproof` whose
//!   every recorded address is wrong still verifies, and its report says
//!   both things. A caller that suppresses the layer
//!   ([`VerifyOptions::without_storage_linkage`]) gets
//!   [`StorageLinkageResult::NotEvaluated`], which is what a run that did
//!   not do the work can honestly say — and that caller list is closed at
//!   the two committed-exhibit generators.
//! - **Online anchor evidence.** Stage 6 runs A18's machine *offline*: core
//!   fetches nothing and `verify_bundle` is handed nothing fetched, so an
//!   upgraded `.ots` renders `attested` and never the `--online`-only
//!   `proven` (D56 §3, and [`VerifyOptions`] on why the evidence is not a
//!   field here). That is a deliberate ceiling on this entry point, not a
//!   gap in the machine.
//! - **Trusting bundle-recorded anchor metadata.** No `source` string is
//!   ever copied out of the bundle: the wire carries none for either kind
//!   (D8 §1), and every identity the report renders is one the anchor stage
//!   derived from artifact bytes it parsed itself. `fetch_date` *is*
//!   sealer-recorded, and **D95** rules that it renders in every state that
//!   emits a slot — `invalid` included, with no state gate, as decimal
//!   POSIX seconds. Three authorities, not an assertion: registry §6.1
//!   grants display of a sealer claim (it says so about `anchor_status`,
//!   the sealer's own competing verdict); `claimed_time_informational_only`
//!   froze the identical construction in the v1 report bytes at Q14; and
//!   D59 §6(a) forbids *comparing* the value, which is where its hazard
//!   actually lives. Suppressing it on `invalid` would encode a
//!   verification distinction that does not exist.
//! - **Failing the bundle over an anchor.** D84 rule F2: an artifact that
//!   does not verify renders `invalid` in **its own slot** and changes
//!   nothing else — not the manifest verdict, not the evidence layer, not
//!   another anchor. The anchor stage returns no `Result`, which is that
//!   rule spelled as a type.
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
//! [`sig_policy::verify_body`]: crate::crypto::sig_policy::verify_body

use std::collections::{BTreeMap, BTreeSet};

use crate::anchor::model::{AnchorArtifacts, OnlineEvidence};
use crate::anchor::roots::TsaRootStore;
use crate::anchor::verdicts::evaluate_anchors;
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
use crate::manifest::{anchor_digest, work_id};

use super::coherence::check_coherence;
use super::coherence::{CoherenceBundleView, CoherenceUnit, RevealSection, RevealedUnitRef};
use super::error::{BindingMode, LengthField, VerifyError, VerifyFailures};
use super::file_stages::{
    FileCanonMode, FileFineTree, FileRevealSummary, FileStageBundleView, FileStageManifestView,
    FileUnitEntry, FileView, FullRevealMaterialEntry, MirrorCandidate, VerifiedUnitBytes,
    check_file_stages, participates_in_concat, resolve_raw_mirror,
};
use super::report::{
    AnchorResult, Digest32, EvidenceLayerResult, FileReveal, REPORT_VERSION, RawMirrorReveal,
    RevealSet, SignatureScheme, StorageLinkageResult, SupportingEvidenceResult, UnitSpan,
    UnrevealedFilePlaceholder, VerificationReport, WorkMetadata,
};
use super::storage_linkage::{ManifestLinkageSubject, UnitLinkageSubject, check_storage_linkage};
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
    /// Stage 6 — A18's per-anchor verdict machine, wired by R12.
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
/// Empty at M0 by design: everything the *evidence layer* needs is inside the
/// bundle, which is the point of a self-contained `.sealproof`. The parameter
/// exists in the signature D27 fixed so that later stages — R12's anchor
/// policy, R20's storage linkage, R21's `--live` — can be switched on without
/// a breaking change. `#[non_exhaustive]`, so adding a field stays
/// non-breaking for callers that build it with [`Default`].
///
/// # Why the anchor stage needed the first two fields (R12)
///
/// R12's task text says only *"invoke A's state machine"*, and A18's machine
/// takes two inputs a **pure, clock-free** pipeline cannot invent:
///
/// - **`verify_at_unix`.** `antseal-core` reads no clock at all
///   ([`anchor::chain`](crate::anchor::chain) module docs), so verification
///   time is the caller's. It is [`Option`] rather than required because
///   D53 §5b makes it **one-sided**: it separates `proven` from
///   `valid-at-stamping-cert-since-expired` and can never produce a failure,
///   so a caller with no clock loses one distinction and no safety. `None`
///   evaluates as `0` — the "no expiry claim" end of that one-sided test,
///   which is also the value
///   `chain::tests::verify_at_before_gentime_is_still_proven` already pins
///   as never producing a failure.
/// - **`tsa_roots`.** T3 validates against a *pinned* store. It defaults to
///   [`TsaRootStore::pinned`] and is overridable because A7's injection API
///   is what makes the untrusted-root row buildable at all. Overriding is
///   safe by construction rather than by policy:
///   [`TsaRootStore::from_static`] is `test`/`test-util`-gated, so outside a
///   test build [`TsaRootStore::pinned`] is the only value that exists to
///   pass.
///
/// # What is deliberately *not* here
///
/// [`OnlineEvidence`] — the `--online` overlay. `verify_bundle` performs no
/// online step and receives no online result, so every OTS anchor it renders
/// is the offline verdict (`pending`/`attested`/…). D56 §3 already requires
/// the offline verdict to be the cryptographic one and the overlay to be
/// distinct from it; carrying evidence here would need a borrowed field and
/// would put a network-shaped input in the type every WASM caller builds. The
/// host-supplied route is R16/R21/R22's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyOptions {
    /// The caller's verification time, POSIX seconds. See the type docs.
    verify_at_unix: Option<u64>,
    /// The TSA root store T3 validates against; `None` is
    /// [`TsaRootStore::pinned`].
    tsa_roots: Option<&'static TsaRootStore>,
    /// Whether the R20 storage-linkage layer runs. See the type docs and
    /// [`Self::without_storage_linkage`].
    storage_linkage: bool,
}

/// Hand-written rather than derived, because a derived `Default` would give
/// `storage_linkage: false` and therefore **disagree with [`Self::new`]**
/// (D128 §3.1). The two must be one value; the way to make that structural
/// rather than remembered is to define one in terms of the other.
impl Default for VerifyOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifyOptions {
    /// The default options: no verification time, the pinned root store, and
    /// the storage-linkage layer **on** — suppressible only through
    /// [`Self::without_storage_linkage`], which two committed-exhibit
    /// generators are the entire caller list for.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            verify_at_unix: None,
            tsa_roots: None,
            storage_linkage: true,
        }
    }

    /// Set the verification time (POSIX seconds) the anchor stage evaluates
    /// certificate expiry against.
    #[must_use]
    pub const fn with_verify_at_unix(mut self, verify_at_unix: u64) -> Self {
        self.verify_at_unix = Some(verify_at_unix);
        self
    }

    /// Evaluate TSA chains against `roots` instead of
    /// [`TsaRootStore::pinned`].
    #[must_use]
    pub const fn with_tsa_roots(mut self, roots: &'static TsaRootStore) -> Self {
        self.tsa_roots = Some(roots);
        self
    }

    /// **Suppress** the offline storage-linkage layer (R20), so
    /// [`VerificationReport::storage_linkage`] reports
    /// [`StorageLinkageResult::NotEvaluated`] — the literal truth about a run
    /// that did not do the work.
    ///
    /// Not a product surface. [`Self::new`] runs the layer (D128 §3 R1), and
    /// **this method's caller list is closed at two**, both committed-exhibit
    /// generators (D128 §3 R2/R3):
    ///
    /// - `test_util::vectors_report`'s `build_expect`, behind R9's 21 frozen
    ///   report cases and their regenerator;
    /// - `test_util::bundle_fixtures`'s `verify()` helper, behind R30's 26
    ///   `REPORT_DIGEST_BY_SHAPE` rows.
    ///
    /// A third call site is a red arm — the literal scan
    /// `without_storage_linkage_has_exactly_two_callers` asserts the
    /// closure — because a third suppressor is either a product surface that
    /// must not suppress (D128 §3 R5: R21's orchestration and R22's binding
    /// may not call this, so U30 has no `--no-storage-linkage` flag and R23's
    /// page no toggle) or an exhibit nobody ruled.
    ///
    /// # Why the switch exists at all
    ///
    /// All 21 R9 report vectors are `verify_bundle`'s own output over R6
    /// fixtures whose recorded addresses are recognisable placeholders
    /// (`bundle_fixtures::fixture_address`, and a `0x5E`/`0x5A`/`0x5C`
    /// storage record) — chosen at M0, when nothing recomputed them. Running
    /// the layer over *those* would re-value **every** case at once, and
    /// `scripts/vector-freeze.sh --update --verdict-event` refuses exactly
    /// that: *"all 21 cases moved. A format event moves every case at once;
    /// a verdict event does not"*. D105 §2.4 says the same in the other
    /// direction — a value addition that moves all the pins is a claim that
    /// is false.
    ///
    /// That is a fact about the **exhibits**, not about the stage, and D128
    /// separates the two knobs the earlier reading fused. There are three
    /// ways out, not the two this doc used to enumerate — a FIXTURE EVENT
    /// (give R6's fixtures real S4 addresses, moving the frozen bundle and
    /// manifest vectors too, D94 §5); a new freeze class (and D105 §10's
    /// declined one is a *different* hole, since it admits an **added** case
    /// and this adds none); and the one taken, **pinning the exhibits to a
    /// stated options tuple**. The exhibits never observed a default: both
    /// generators already built their own [`VerifyOptions`], so naming the
    /// value they pass changes a spelling and not a byte. Zero frozen digests
    /// moved, zero `REPORT_DIGEST_BY_SHAPE` rows moved, zero files under
    /// `testdata/`, `REPORT_VERSION` unchanged at 1.
    ///
    /// The layer's own coverage is unaffected by the suppression, because it
    /// never lived in these exhibits: `EXPECTED_CANONICAL_JSON_WITH_LINKAGE`
    /// (D105 ruling 4's whole-report rendering, dual-target through A90's
    /// `--lib` route), `tests/storage_linkage.rs`'s four address modes, and
    /// `verify::storage_linkage`'s unit tests.
    ///
    /// [`VerificationReport::storage_linkage`]:
    ///     super::report::VerificationReport::storage_linkage
    #[must_use]
    pub const fn without_storage_linkage(mut self) -> Self {
        self.storage_linkage = false;
        self
    }

    /// The verification time, or `None` if the caller supplied no clock.
    #[must_use]
    pub const fn verify_at_unix(&self) -> Option<u64> {
        self.verify_at_unix
    }

    /// The root store to validate against — the pinned one unless overridden.
    #[must_use]
    pub const fn tsa_roots(&self) -> &'static TsaRootStore {
        match self.tsa_roots {
            Some(roots) => roots,
            None => TsaRootStore::pinned(),
        }
    }

    /// Whether the storage-linkage layer runs — `true` unless the caller
    /// suppressed it ([`Self::without_storage_linkage`]).
    #[must_use]
    pub const fn storage_linkage(&self) -> bool {
        self.storage_linkage
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

/// R53: the report resolves "the file's raw mirror" through the same
/// accessor the full-reveal content check calls
/// ([`resolve_raw_mirror`]) — never through its own kind test.
impl MirrorCandidate for UnitRow<'_> {
    fn owning_file(&self) -> u64 {
        self.file_id
    }

    fn unit_kind(&self) -> UnitKind {
        self.kind()
    }
}

/// The single implementation behind both D27 entry points.
fn run(
    input: &[u8],
    options: &VerifyOptions,
    mode: Mode,
) -> Result<VerificationReport, VerifyFailures> {
    // ── Stage 1: decode ────────────────────────────────────────────────
    let proof = SealProof::decode(input).map_err(VerifyError::Decode)?;
    let bundle = proof.bundle();
    let body = proof.manifest().body();

    let rows = flatten_units(body);

    // ── Stage 2: structural (R3) then coherence (R5) ───────────────────
    let struct_files = structural_files(body);
    let struct_units = structural_units(rows.rows());
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

    let coherence_units = coherence_units(rows.rows());
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
    let (verified_owned, unit_failures) = run_unit_stage(bundle, body, rows.rows(), mode);
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
    let file_units = file_unit_entries(rows.rows());
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

    // ── Stage 6: anchors (A18 via R12) ─────────────────────────────────
    let (anchors, supporting_evidence) = anchor_stage(&proof, options);

    // ── The storage-linkage layer (R20) — beside, never inside ─────────
    // Last, and after every evidence stage has finished, so nothing in the
    // evidence layer can be sequenced behind it; `check_storage_linkage`
    // returns no `Result`, so nothing here can fail the bundle either.
    let storage_linkage = storage_linkage_layer(bundle, rows.rows(), options);

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
        storage_linkage,
        anchors,
        supporting_evidence,
        reveal: reveal_set(body, bundle, &rows, &revealed_ids, &summaries)?,
    })
}

// ---------------------------------------------------------------------------
// stage 2 inputs
// ---------------------------------------------------------------------------

/// The flattened manifest unit table plus the file→rows grouping its own
/// construction yields for free (R54).
///
/// [`flatten_units`] emits each file's rows contiguously, files in
/// file-table order, `file_id` = the enumerate index — so `spans[file_id]`
/// is exactly the half-open `rows` range that file owns. Built **once** per
/// verification: the grouping is what lets [`reveal_set`] visit each file's
/// own rows instead of re-filtering the whole table per file — the
/// Θ(|files| × |units|) shape the 2026-07-31 review's finding 6 measured at
/// ~2³⁰ steps for a legal at-cap no-reveal bundle. It holds ranges into
/// `rows`, never copies of them.
struct UnitRows<'m> {
    /// Every unit row, in manifest order (= `unit_id` order, F5's pin).
    rows: Vec<UnitRow<'m>>,
    /// `spans[file_id]` = that file's contiguous range of `rows` indices.
    spans: Vec<core::ops::Range<usize>>,
}

impl<'m> UnitRows<'m> {
    /// The whole table, for the consumers that are 1:1 with it.
    fn rows(&self) -> &[UnitRow<'m>] {
        &self.rows
    }

    /// The rows `file_id` owns, in manifest order; empty for an id outside
    /// the file table (defensive — the pipeline only asks about enumerated
    /// files).
    fn for_file(&self, file_id: u64) -> &[UnitRow<'m>] {
        usize::try_from(file_id)
            .ok()
            .and_then(|index| self.spans.get(index))
            .and_then(|span| self.rows.get(span.clone()))
            .unwrap_or(&[])
    }
}

/// The manifest unit table, flattened in manifest order, grouped by file as
/// a by-product (module type above).
fn flatten_units(body: &ManifestBodyV1) -> UnitRows<'_> {
    let mut rows = Vec::new();
    let mut spans = Vec::with_capacity(body.files().len());
    for (index, file) in body.files().iter().enumerate() {
        let file_id = u64::try_from(index).unwrap_or(u64::MAX);
        let start = rows.len();
        rows.extend(file.units().iter().map(|entry| UnitRow { file_id, entry }));
        spans.push(start..rows.len());
    }
    UnitRows { rows, spans }
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

    // Both reveal lookups built once (R54): the pre-R54 shape rescanned
    // each section per manifest row — Θ(|units| × |reveals|) on a fully
    // revealed work (2026-07-31 review, U1's class). First-wins per id
    // mirrors the `.find` it replaces; a repeated id within a section is
    // undecodable anyway (F8's strictly-ascending rule).
    let mut covered_by_id: BTreeMap<u64, &CoveredReveal> = BTreeMap::new();
    for reveal in bundle.covered_reveals() {
        covered_by_id.entry(reveal.unit_id()).or_insert(reveal);
    }
    let mut noncovered_by_id: BTreeMap<u64, &NonCoveredReveal> = BTreeMap::new();
    for reveal in bundle.noncovered_reveals() {
        noncovered_by_id.entry(reveal.unit_id()).or_insert(reveal);
    }

    for row in rows {
        let unit_id = row.unit_id();
        let Some(file) = body
            .files()
            .get(usize::try_from(row.file_id).unwrap_or(usize::MAX))
        else {
            // Unreachable: R3 group 2 proved every unit's file exists.
            continue;
        };
        let covered = covered_by_id.get(&unit_id).copied();
        let noncovered = noncovered_by_id.get(&unit_id).copied();

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

/// The anchor stage — **R12**: A18's state machine over every embedded
/// artifact, projected into the report's anchor slots.
///
/// # The digest is recomputed, never read
///
/// Every A18 rule is *about this seal*, and the thing that makes it so is
/// `anchor_digest` = SHA-256 over the **full embedded manifest envelope,
/// signatures included** ([`manifest::anchor_digest`], F7) — not `work_id`,
/// which covers the body only. It is recomputed here from
/// [`SealProof::anchor_digest_preimage`], which is a sub-slice of the
/// caller's own input (the zero-copy seam F13 asserts), so the bundle cannot
/// state its own anchor identity: a `.ots` or a token stamped over anything
/// else renders `invalid` with its own code rather than being believed.
///
/// # The receipt leaves by a different door
///
/// [`AnchorVerdicts::outcomes`] does not contain the receipt and
/// [`AnchorKind`] has no variant for it, so the `anchors` half of this
/// function **cannot** emit one; the receipt reaches the report only through
/// the second element of the returned pair, as a
/// [`SupportingEvidenceResult`] that carries no state and no time (A19).
///
/// # `absent` is not a slot
///
/// D53 §4a: [`AnchorState::Absent`] is the answer to a question about an
/// anchor **kind** the bundle does not carry, never about an artifact, and
/// R12 emits no slot for it. [`AnchorVerdicts::project_anchor_results`] is
/// where that filter lives, which is why a bundle with no anchors still
/// serializes the pinned `"anchors":[]`.
///
/// Slot order is `.ots` artifacts then TSA artifacts, each in wire order —
/// the M0 stub's order, matched deliberately by A18 so the projection lands
/// where the report already put things.
///
/// [`AnchorKind`]: super::report::AnchorKind
/// [`AnchorState::Absent`]: super::report::AnchorState::Absent
/// [`manifest::anchor_digest`]: crate::manifest::anchor_digest
/// [`SealProof::anchor_digest_preimage`]: crate::bundle::SealProof::anchor_digest_preimage
fn anchor_stage(
    proof: &SealProof<'_>,
    options: &VerifyOptions,
) -> (Vec<AnchorResult>, SupportingEvidenceResult) {
    let bundle = proof.bundle();
    let digest = *anchor_digest(proof.anchor_digest_preimage()).as_bytes();
    let artifacts = AnchorArtifacts::from_bundle(bundle);

    // Core never fetches, and `verify_bundle` is given nothing to have
    // fetched: the offline verdict is the whole of what this entry point can
    // say (see [`VerifyOptions`]).
    let verdicts = evaluate_anchors(
        &artifacts,
        &digest,
        &OnlineEvidence::new(),
        options.verify_at_unix().unwrap_or(0),
        options.tsa_roots(),
    );

    let supporting = verdicts
        .receipt()
        .map_or(SupportingEvidenceResult::None, |receipt| {
            SupportingEvidenceResult::ArbitrumReceipt {
                block_number: receipt.block_number(),
                transaction_count: u64::try_from(receipt.transaction_count()).unwrap_or(u64::MAX),
            }
        });

    (verdicts.project_anchor_results(), supporting)
}

// ---------------------------------------------------------------------------
// the storage-linkage layer (R20)
// ---------------------------------------------------------------------------

/// Assemble [`check_storage_linkage`]'s subjects out of the decoded bundle
/// and manifest, and run it — or report
/// [`StorageLinkageResult::NotEvaluated`] for the one caller shape that
/// suppressed it ([`VerifyOptions::without_storage_linkage`]).
///
/// Subjects are visited in **manifest unit order**, like every other stage:
/// the counts are order-independent, but a future per-unit rendering built on
/// this must not inherit an order the sealer chose by laying its sections out
/// one way rather than another.
///
/// Both halves of a unit subject come from opposite sides of the bundle — the
/// ciphertext from the reveal section, the address from the *signed* manifest
/// — which is what makes the comparison a statement rather than a tautology.
/// Units the bundle does not embed are skipped, not counted: they have no
/// bytes here to recompute anything from.
fn storage_linkage_layer(
    bundle: &BundleV1<'_>,
    rows: &[UnitRow<'_>],
    options: &VerifyOptions,
) -> StorageLinkageResult {
    if !options.storage_linkage() {
        return StorageLinkageResult::NotEvaluated;
    }

    let embedded: BTreeMap<u64, &[u8]> = bundle
        .covered_reveals()
        .iter()
        .map(|reveal| (reveal.unit_id(), reveal.ciphertext().as_slice()))
        .chain(
            bundle
                .noncovered_reveals()
                .iter()
                .map(|reveal| (reveal.unit_id(), reveal.ciphertext().as_slice())),
        )
        .collect();

    let subjects: Vec<UnitLinkageSubject<'_>> = rows
        .iter()
        .filter_map(|row| {
            embedded
                .get(&row.unit_id())
                .map(|ciphertext| UnitLinkageSubject {
                    unit_id: row.unit_id(),
                    ciphertext,
                    recorded_address: row.entry.address(),
                })
        })
        .collect();

    let record = bundle.storage_record();
    // The wire nonce and the AEAD nonce are deliberately distinct types; the
    // crossing is explicit here, as it is everywhere else in the tree.
    let nonce = AeadNonce::from_bytes(*record.nonce().as_bytes());
    check_storage_linkage(
        &subjects,
        &ManifestLinkageSubject {
            // The bytes **as received** — the pre-image the sealer encrypted,
            // never a re-encoding (module docs, line 74).
            manifest_bytes: bundle.manifest_bytes(),
            nonce: &nonce,
            k_m: record.k_m(),
            recorded_address: record.address(),
        },
    )
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
///
/// `raw_mirror` is emitted **only for a full reveal**, and the mirror is
/// resolved through [`resolve_raw_mirror`] — the same accessor
/// [`check_full_reveal_content`](super::file_stages::check_full_reveal_content)
/// uses — so the report can only ever name a mirror whose bytes rows 9–10
/// actually checked (R53).
fn reveal_set(
    body: &ManifestBodyV1,
    bundle: &BundleV1<'_>,
    rows: &UnitRows<'_>,
    revealed_ids: &[u64],
    summaries: &[FileRevealSummary],
) -> Result<RevealSet, VerifyError> {
    let mut files = Vec::new();
    let mut unrevealed_files = Vec::new();

    // Built once (R54): the per-file work below visits each file's own
    // rows via the shared [`UnitRows`] grouping instead of re-filtering the
    // whole table per file, and membership/`touched_files` lookups are a
    // set and a first-wins map instead of per-row and per-file rescans
    // (the R53-noted residue). Same rows in the same order per file, so
    // the report bytes are unchanged.
    let revealed: BTreeSet<u64> = revealed_ids.iter().copied().collect();
    let mut touched_by_id = BTreeMap::new();
    for entry in bundle.touched_files() {
        touched_by_id.entry(entry.file_id()).or_insert(entry);
    }

    for (index, file) in body.files().iter().enumerate() {
        let file_id = u64::try_from(index).unwrap_or(u64::MAX);
        let mut revealed_spans = Vec::new();
        let mut unrevealed_spans = Vec::new();
        let mut touched = false;

        for row in rows.for_file(file_id) {
            let unit_id = row.unit_id();
            let is_revealed = revealed.contains(&unit_id);
            touched |= is_revealed;
            // Spans cover the tiling domain only; the mirror sits outside
            // it and is resolved below, through the R53 accessor.
            if participates_in_concat(row.kind()) {
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

        if !touched {
            unrevealed_files.push(UnrevealedFilePlaceholder {
                file_id,
                size: file.size(),
            });
            continue;
        }

        // The file's revealed raw mirror — resolved by the SAME accessor
        // the full-reveal content check calls (R53), so the mirror this
        // report names is the mirror rows 9–10 opened. (An untouched file
        // reveals nothing, so resolving after the arm above loses no case.)
        // The candidates are the file's own rows — the accessor's
        // owning-file test still runs, and rows of other files were never
        // candidates it could return (R54).
        let revealed_mirror = resolve_raw_mirror(
            file_id,
            rows.for_file(file_id)
                .iter()
                .filter(|row| revealed.contains(&row.unit_id())),
        );

        revealed_spans.sort_by_key(|span| span.start);
        unrevealed_spans.sort_by_key(|span| span.start);

        // D80 guarantees a `touched_files` entry exists for every file with
        // a revealed unit; the error arm is the unreachable backstop, and it
        // reports the same rule that would have caught it in stage 2.
        let Some(entry) = touched_by_id.get(&file_id).copied() else {
            let unit_id = revealed_spans.first().map_or_else(
                || revealed_mirror.map_or(0, UnitRow::unit_id),
                |span| span.unit_id,
            );
            return Err(VerifyError::RevealedUnitFileNotTouched { unit_id, file_id });
        };

        let fully_revealed = summaries.get(index).is_some_and(FileRevealSummary::is_full);
        files.push(FileReveal {
            file_id,
            path: entry.path().to_owned(),
            total_size: file.size(),
            fully_revealed,
            revealed_spans,
            unrevealed_spans,
            // Full reveals only — the same `is_full` the sibling field
            // consults. On a partial reveal a revealed mirror is verified
            // as a *unit* (AEAD + `unit_commit`) but rows 9–10 never open
            // `raw_commit` with it and never bind it to the canonical
            // bytes, so reporting it would present unbound bytes as "the
            // original file" (2026-07-31 review, finding 8; R53).
            raw_mirror: revealed_mirror
                .filter(|_| fully_revealed)
                .map(|row| RawMirrorReveal {
                    unit_id: row.unit_id(),
                    raw_size: row.entry.true_length(),
                }),
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
        AnchorStatus, BundleParts, CoverEntry as BundleCoverEntry, FullReveal, OpaqueBytes,
        OtsAnchor, OtsUpgrade, PathNode, ReceiptRecord, StorageRecord,
        TouchedFile as BundleTouchedFile, TsaAnchor, encode_bundle,
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
    use crate::verify::report::{AnchorKind, AnchorState};

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
        /// Anchor artifacts to embed, each minted over **this fixture's own**
        /// `anchor_digest` (R12). Default is the M0 shape: no anchor
        /// sections at all, so every pre-R12 test is byte-unchanged.
        anchors: AnchorPlan,
        /// The sealer-recorded fetch date every embedded artifact carries;
        /// `None` is [`FIXTURE_FETCH_DATE`]. A knob rather than a constant
        /// only so D95's rider-(c) equality has a second value to move —
        /// nothing else may branch on this (D59 §6(a)).
        fetch_date: Option<u64>,
    }

    /// The fetch date every fixture artifact records unless a row moves it.
    const FIXTURE_FETCH_DATE: u64 = crate::anchor::testing::ots_writer::FETCH_DATE;

    /// Which anchor artifacts a fixture embeds (**R12**).
    ///
    /// Every shape is minted over the fixture's real `anchor_digest`, which
    /// is only knowable after the manifest envelope is encoded — so these are
    /// *plans*, resolved in [`fixture`] once the digest exists. That
    /// ordering is the point: an anchor artifact that could be built without
    /// the digest would not be about this seal.
    #[derive(Debug, Clone, Default)]
    struct AnchorPlan {
        ots: Vec<OtsShape>,
        tsa: Vec<TsaShape>,
        receipt: bool,
    }

    /// The `.ots` shapes D56's rules distinguish, named by the state each
    /// reaches offline.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum OtsShape {
        /// One pending calendar attestation — rule O5 → `pending`.
        Pending,
        /// Single-branch, ops-committing, header embedded — rule O4 →
        /// `attested`. Never `proven` here: that needs online evidence and
        /// `verify_bundle` is given none.
        CommittedUpgrade,
        /// Well-formed and committing, but its one branch ends in an
        /// attestation type this verifier does not implement — rule O9 →
        /// `internally-consistent-only`.
        Unevaluable,
        /// Stamped over `work_id` instead of `anchor_digest`. Rule O1 →
        /// `invalid`, and the shape that makes R12's digest choice
        /// observable rather than merely documented.
        StampedOverWorkId,
    }

    /// The TSA shapes, likewise.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TsaShape {
        /// A mock-CA token over this bundle's `anchor_digest`, with the
        /// signer certificate's validity window around `genTime`.
        Mock,
        /// The same, with the signer certificate already expired by the
        /// window's end — the `valid_at` lever for D53's C1/C2 split.
        MockShortLived,
        /// Bytes that are not a `TimeStampResp` at all — `invalid`.
        Garbage,
    }

    /// The mock TSA's `genTime`, and a verification time on either side of
    /// [`SHORT_LIVED`]'s `notAfter`.
    const MOCK_GEN_TIME: u64 = crate::anchor::testing::DEFAULT_GEN_TIME;
    /// A signer window that has already closed by [`AFTER_EXPIRY`].
    const SHORT_LIVED: (u64, u64) = (MOCK_GEN_TIME - 1_000, MOCK_GEN_TIME + 1_000);
    /// A verification time inside every mock window.
    const BEFORE_EXPIRY: u64 = MOCK_GEN_TIME + 10;
    /// A verification time after [`SHORT_LIVED`] closed.
    const AFTER_EXPIRY: u64 = MOCK_GEN_TIME + 100_000;

    /// The mock CA, built once: minting certificates and signing P-384 is the
    /// most expensive thing in this module and every row wants the same CA.
    fn mock_tsa(short_lived: bool) -> &'static crate::anchor::testing::MockTsa {
        use crate::anchor::testing::{MockTsa, MockTsaConfig};
        use std::sync::OnceLock;

        static LONG: OnceLock<MockTsa> = OnceLock::new();
        static SHORT: OnceLock<MockTsa> = OnceLock::new();
        let (cell, validity) = if short_lived {
            (&SHORT, SHORT_LIVED)
        } else {
            (&LONG, (MOCK_GEN_TIME - 1_000, MOCK_GEN_TIME + 1_000_000))
        };
        cell.get_or_init(|| {
            MockTsa::new(MockTsaConfig {
                signer_validity: validity,
                ..MockTsaConfig::default()
            })
            .expect("the mock CA mints")
        })
    }

    /// A `'static` store trusting both mock CAs and nothing else.
    ///
    /// `'static` because [`VerifyOptions::with_tsa_roots`] takes one, which is
    /// what keeps the option type `Copy` and lifetime-free for every real
    /// caller — and a real caller has only [`TsaRootStore::pinned`] to pass,
    /// because [`TsaRootStore::from_static`] is `test`/`test-util`-gated.
    fn mock_roots() -> &'static TsaRootStore {
        use std::sync::OnceLock;
        static STORE: OnceLock<TsaRootStore> = OnceLock::new();
        STORE.get_or_init(|| {
            let roots = vec![mock_tsa(false).pinned_root(), mock_tsa(true).pinned_root()];
            TsaRootStore::from_static(Box::leak(roots.into_boxed_slice()))
        })
    }

    /// Resolve an [`AnchorPlan`] against the digests only the built manifest
    /// can supply.
    fn build_anchors(
        plan: &AnchorPlan,
        anchor_digest: &[u8; 32],
        work_id_bytes: &[u8; 32],
        fetch_date: u64,
    ) -> (Vec<OtsAnchor>, Vec<TsaAnchor>, Option<ReceiptRecord>) {
        use crate::anchor::testing::ots_writer::{
            HEADER_NTIME, bitcoin, container, header_with, pending, unknown,
        };

        let height = 700_007u64;
        let ots = plan
            .ots
            .iter()
            .map(|shape| match shape {
                OtsShape::Pending => OtsAnchor::new(
                    AnchorStatus::Pending,
                    OpaqueBytes::from_vec(container(
                        anchor_digest,
                        &pending("https://calendar.example"),
                    )),
                    None,
                )
                .expect("pending ots anchor"),
                OtsShape::CommittedUpgrade => OtsAnchor::new(
                    AnchorStatus::Attested,
                    OpaqueBytes::from_vec(container(anchor_digest, &bitcoin(height))),
                    // With zero ops the branch commitment *is* the stamped
                    // digest, so a header carrying it at bytes 36..68 is
                    // committed by the ops (`ots_writer::committed_single_
                    // branch`, whose digest is synthetic and therefore not
                    // usable for a real bundle).
                    Some(OtsUpgrade::new(
                        height,
                        header_with(anchor_digest, HEADER_NTIME),
                        fetch_date,
                    )),
                )
                .expect("upgraded ots anchor"),
                OtsShape::Unevaluable => OtsAnchor::new(
                    AnchorStatus::Pending,
                    OpaqueBytes::from_vec(container(anchor_digest, &unknown())),
                    None,
                )
                .expect("unevaluable ots anchor"),
                OtsShape::StampedOverWorkId => OtsAnchor::new(
                    AnchorStatus::Pending,
                    OpaqueBytes::from_vec(container(
                        work_id_bytes,
                        &pending("https://calendar.example"),
                    )),
                    None,
                )
                .expect("wrong-digest ots anchor"),
            })
            .collect();

        let tsa = plan
            .tsa
            .iter()
            .map(|shape| {
                let token = match shape {
                    TsaShape::Mock => mock_tsa(false)
                        .issue(anchor_digest, None)
                        .expect("the mock signs"),
                    TsaShape::MockShortLived => mock_tsa(true)
                        .issue(anchor_digest, None)
                        .expect("the mock signs"),
                    TsaShape::Garbage => b"not a TimeStampResp".to_vec(),
                };
                // The bundle-recorded `status` is the sealer's claim and
                // is never verdict-bearing (D8 §1); the anchor stage derives
                // its own state from the token bytes. One value for every
                // shape is what keeps that visible.
                TsaAnchor::new(
                    AnchorStatus::Proven,
                    OpaqueBytes::from_vec(token),
                    Vec::new(),
                    fetch_date,
                )
                .expect("tsa anchor")
            })
            .collect();

        let receipt = plan.receipt.then(|| {
            ReceiptRecord::new(
                vec![[0xB1; 32], [0xB2; 32]],
                RECEIPT_BLOCK,
                OpaqueBytes::from_vec(b"fixture receipt payload".to_vec()),
            )
            .expect("receipt record")
        });

        (ots, tsa, receipt)
    }

    /// The Arbitrum block number the fixture receipt records.
    const RECEIPT_BLOCK: u64 = 271_828_182;

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

        // R12: the artifacts are minted over the digests the encoded manifest
        // *has*, not over a constant — which is why this happens here and not
        // in `Tweak`.
        let (ots_anchors, tsa_anchors, receipt) = build_anchors(
            &tweak.anchors,
            anchor_digest(&manifest_bytes).as_bytes(),
            work_id(&body_bytes).as_bytes(),
            tweak.fetch_date.unwrap_or(FIXTURE_FETCH_DATE),
        );

        let bundle = BundleV1::new(BundleParts {
            manifest: &manifest_bytes,
            storage_record: StorageRecord::new(
                ContentAddress::from_bytes([0x77; 32]),
                ManifestNonce::from_bytes([0x78; 24]),
                Key32::from_bytes([0x79; 32]),
            ),
            ots_anchors,
            tsa_anchors,
            receipt,
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
        // D128 §3 R1: the default **runs** the storage-linkage layer, so this
        // is no longer "the stage did not run" but what the stage found. This
        // fixture's recorded addresses are M0 placeholders (`[0x77; 32]` for
        // the storage record, `salt16`-patterned entries for the units), so
        // nothing links — and the four assertions above it, the evidence
        // layer, do not move by one field. "Storage is the product's bonus,
        // not its proof" (MVP-SPEC.md line 118), asserted rather than said.
        assert_eq!(
            report.storage_linkage,
            StorageLinkageResult::Evaluated {
                units_matched: 0,
                units_mismatched: 4,
                manifest_matched: false,
            }
        );
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

    /// [`Default`] and [`VerifyOptions::new`] agree, and the defaults are: no
    /// caller-supplied clock, the **pinned** root store rather than whatever
    /// was last injected, and the storage-linkage layer **on**.
    ///
    /// Two of the three are conservative in the "do less" sense and the third
    /// is deliberately not — which is why this test's title no longer calls
    /// the defaults *the conservative ones*, as it did until D128. §3 R1 rules
    /// the layer on by default, on spec line 38 (*"the page's storage story is the
    /// offline address-recomputation of the storage-linkage layer"*) read
    /// against R22's options-free `verify(bundle_bytes)`: the page cannot opt
    /// in, so the default must already be in.
    ///
    /// The first assertion is D128 §3.1's red arm. [`Default`] is hand-written
    /// precisely because the `derive` would give `storage_linkage: false` and
    /// disagree with [`VerifyOptions::new`] silently — a `verify_bundle` called
    /// through `VerifyOptions::default()` would then skip a layer the spec
    /// mandates, with nothing red anywhere.
    ///
    /// The root-store half became load-bearing at R12: `tsa_roots` defaults
    /// through a `match` rather than a stored value, so a bug that made the
    /// override sticky — or that defaulted to an empty store, under which
    /// every token would render `internally-consistent-only` and no test
    /// asserting a *failure* would notice — shows up here.
    #[test]
    fn the_defaults_are_no_clock_the_pinned_roots_and_the_layer_on() {
        assert_eq!(
            VerifyOptions::default(),
            VerifyOptions::new(),
            "`Default` and `new()` disagree. If `storage_linkage` is the field that \
             differs, the `#[derive(Default)]` is back: it yields `false` where \
             `new()` says `true`, so `verify_bundle` reached through \
             `VerifyOptions::default()` would skip a layer MVP-SPEC.md line 38 \
             mandates, silently (D128 §3.1)"
        );
        assert_eq!(VerifyOptions::new().verify_at_unix(), None);
        assert!(std::ptr::eq(
            VerifyOptions::new().tsa_roots(),
            TsaRootStore::pinned()
        ));
        assert!(
            VerifyOptions::new().storage_linkage(),
            "the default stopped running the storage-linkage layer (D128 §3 R1)"
        );
        assert!(
            VerifyOptions::default().storage_linkage(),
            "`Default` and `new()` disagree about the storage-linkage layer — \
             the `derive` is back (D128 §3.1)"
        );
        assert!(
            !VerifyOptions::new()
                .without_storage_linkage()
                .storage_linkage(),
            "the suppression switch stopped suppressing"
        );
        assert_eq!(
            VerifyOptions::new()
                .with_verify_at_unix(1_785_000_000)
                .verify_at_unix(),
            Some(1_785_000_000)
        );
    }

    /// Every file in the tree that names
    /// [`VerifyOptions::without_storage_linkage`], enumerated — **D128 §3 R2's
    /// red arm**, in D123's literal-scan shape.
    ///
    /// R2 closes the suppressing-caller list at **two**, both
    /// committed-exhibit generators, because a third suppressor is either a
    /// product surface that must not suppress (§3 R5: R21's orchestration,
    /// R22's binding, and through them U30 and R23) or an exhibit nobody
    /// ruled. Documenting that closure is not the same as holding it, so it
    /// is asserted here.
    ///
    /// The table has a **third** row, and the reason is worth stating rather
    /// than discovering. §3 R2's own sentence — *"exactly those two files plus
    /// its own definition and rustdoc"* — omits the site §3.2 row 3 mandates
    /// in the same ruling: `tests/storage_linkage.rs`'s
    /// `the_layer_is_silent_only_when_it_is_suppressed`, whose whole subject
    /// **is** the suppression. That file suppresses nothing committed and is no
    /// product surface; it is the switch's instrument, and §3.2 calls it *"the
    /// property R2's closed caller list depends on"*. So the closure R2 means
    /// is asserted separately and exactly: **two** suppressors under any
    /// `src/`, and the switch's own test outside it.
    ///
    /// The call **count** is pinned per file as well as the file set, so a
    /// *second* suppression inside an already-listed file reddens too — a
    /// file-level scan alone would let R9's executor grow a second suppressed
    /// call without a word.
    ///
    /// What is scanned for is the **call** form, `…()`, not the bare
    /// identifier: a rustdoc sentence saying R21 never suppresses is a
    /// sentence, not a suppression, and an instrument that reddened on prose
    /// would be one nobody could write prose around.
    ///
    /// Skipped on wasm32, which has no filesystem, exactly as
    /// `crypto::domain`'s crate-wide tag scan is. The property is about the
    /// source tree, not about a target.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn without_storage_linkage_has_exactly_two_callers() {
        use std::path::{Path, PathBuf};

        /// The switch's definition, its rustdoc, and this scan itself.
        const DEFINITION: &str = "crates/antseal-core/src/verify/pipeline.rs";
        /// `(path, calls, why it may suppress)` — the closed list.
        const CALLERS: [(&str, usize, &str); 3] = [
            (
                "crates/antseal-core/src/test_util/vectors_report.rs",
                1,
                "R9's report-vector executor: the 21 frozen cases (D128 §3 R3)",
            ),
            (
                "crates/antseal-core/src/test_util/bundle_fixtures.rs",
                1,
                "R30's digest-table helper: the 26 REPORT_DIGEST_BY_SHAPE rows (D128 §3 R3)",
            ),
            (
                "crates/antseal-core/tests/storage_linkage.rs",
                1,
                "the switch's own test — the layer is silent only when suppressed (D128 §3.2)",
            ),
        ];
        /// The call form. Built by `concat!` so this scan's own source does
        /// not have to contain the thing it hunts for — `pipeline.rs` is
        /// exempt from the count either way, but a scanner that matches
        /// itself is one nobody trusts on sight.
        const CALL: &str = concat!("without_storage_linkage", "()");

        fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
            let entries = std::fs::read_dir(dir)
                .unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));
            for entry in entries {
                let path = entry
                    .unwrap_or_else(|e| panic!("cannot read an entry under {}: {e}", dir.display()))
                    .path();
                // `target/` is build output and `.git/` is not source; both
                // exist at more than one depth (`fuzz/target/`).
                let skip = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n == "target" || n == ".git");
                if skip {
                    continue;
                }
                if path.is_dir() {
                    collect(&path, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    out.push(path);
                }
            }
        }

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("the crate sits two levels under the workspace root")
            .to_path_buf();
        let mut files = Vec::new();
        collect(&root, &mut files);
        assert!(
            files.len() > 300,
            "the walker found only {} files — it is not reaching the tree",
            files.len()
        );

        let mut found: BTreeMap<String, usize> = BTreeMap::new();
        let mut saw_definition = false;
        for file in &files {
            let text = std::fs::read_to_string(file)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
            let relative = file
                .strip_prefix(&root)
                .expect("every scanned file is under the root")
                .to_string_lossy()
                .replace('\\', "/");
            if relative == DEFINITION {
                saw_definition = true;
                continue;
            }
            let count = text.matches(CALL).count();
            if count > 0 {
                found.insert(relative, count);
            }
        }
        assert!(
            saw_definition,
            "the scan did not reach the switch's own definition file — walker broken?"
        );

        // 1. No file outside the closed list may call the switch.
        let listed: BTreeSet<&str> = CALLERS.iter().map(|(path, _, _)| *path).collect();
        let strays: Vec<&String> = found
            .keys()
            .filter(|path| !listed.contains(path.as_str()))
            .collect();
        assert!(
            strays.is_empty(),
            "a third caller of `{CALL}` appeared: {strays:?}. D128 §3 R2 closes the \
             suppressing-caller list at the two committed-exhibit generators — a further \
             suppressor is either a product surface that must not suppress (§3 R5: R21, \
             R22, U30, R23) or an exhibit nobody ruled. Kill criterion 3; this is a \
             decision, not an edit."
        );

        // 2. Every listed entry is real and suppresses exactly as often as
        //    stated — so the list cannot rot, and cannot hide a second call.
        for (path, calls, why) in CALLERS {
            let seen = found.get(path).copied().unwrap_or(0);
            assert_eq!(
                seen, calls,
                "`{path}` calls `{CALL}` {seen} time(s), not {calls}. It is on D128 §3 R2's \
                 closed list as: {why}. A count that moved is a suppression nobody ruled, or \
                 a listed site that stopped suppressing."
            );
        }

        // 3. R2's closure, stated as the number it is about: exactly two
        //    suppressors under a crate's `src/`. The switch's own test is
        //    outside every `src/` by construction.
        let in_src = CALLERS
            .iter()
            .filter(|(path, _, _)| path.contains("/src/"))
            .count();
        assert_eq!(
            in_src, 2,
            "D128 §3 R2's caller list is closed at two library-side suppressors"
        );
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

    // -----------------------------------------------------------------
    // R53: the raw-mirror seam — one resolution, and no unbound mirror
    // in a partial reveal's report
    // -----------------------------------------------------------------
    //
    // The 2026-07-31 adversarial review (findings 1–3 `high`, finding 8
    // `medium`): the content check and the report resolved "the file's
    // mirror" independently (first-wins versus last-wins), and the report
    // emitted `raw_mirror` for partial reveals even though rows 9–10 —
    // the `raw_commit` opening and the canonicalization binding — run
    // only for `FileRevealShape::Full`. Gated on `test-vectors` like
    // `agreement_with_r6`, because the shapes are R6's.

    #[cfg(feature = "test-vectors")]
    mod raw_mirror_seam {
        use super::*;
        use crate::test_util::bundle_fixtures::{build, shapes};

        /// **Finding 8, the live defect.** A partial reveal that also
        /// reveals the file's raw mirror verifies — the mirror unit is
        /// AEAD/`unit_commit`-verified like any revealed unit — but the
        /// report must NOT name it as the file's `raw_mirror`: nothing
        /// opened `raw_commit` with its bytes and nothing bound them to
        /// the canonical rendition (rows 9–10 are full-reveal-only), so a
        /// renderer following [`FileReveal::raw_mirror`]'s documented
        /// meaning would present unbound bytes as "the original file".
        ///
        /// Before R53's gate this failed with
        /// `raw_mirror = Some(RawMirrorReveal { unit_id: 3, .. })`.
        #[test]
        fn a_partial_reveals_report_omits_the_unbound_mirror() {
            let case =
                shapes::by_name("split-multi-unit/partial-with-mirror").expect("catalogue entry");
            let built = build(&case.spec, &case.selection);

            // The shape is what it claims: the mirror IS revealed and the
            // normal units are a strict subset.
            let facts = &built.files[0];
            let mirror_id = facts.mirror_unit_id.expect("the shape has a mirror");
            assert!(built.revealed_unit_ids.contains(&mirror_id));
            assert!(!facts.fully_revealed);

            let report =
                verify_bundle(&built.bytes, &VerifyOptions::new()).expect("the bundle verifies");

            // Every revealed unit — the mirror included — was verified as
            // a unit. What the gate withholds is the whole-file claim,
            // not the unit-level evidence.
            assert_eq!(
                report.evidence.units_verified,
                u64::try_from(built.revealed_unit_ids.len()).expect("small"),
            );

            let file = &report.reveal.files[0];
            assert!(!file.fully_revealed);
            assert_eq!(
                file.raw_mirror, None,
                "a partial reveal's report carries a raw_mirror whose bytes rows 9–10 \
                 never checked (2026-07-31 review, finding 8)"
            );
        }

        /// The pinned D29 bytes for the partial-with-mirror shape — the
        /// report-string snapshot standing in for a frozen R9 vector.
        ///
        /// Why not a vector: `FROZEN.sha256` is `#! status frozen`, under
        /// which additions are the one legal change — but the `report`
        /// kind's executor requires every document to carry all of
        /// [`REQUIRED_SHAPES`](crate::test_util::vectors_report::REQUIRED_SHAPES),
        /// so a minimal one-case second document cannot pass it, and the
        /// committed 21-case document may not change a byte. Until a
        /// format-version event re-opens the vector set, this snapshot is
        /// the byte pin; the shape's handle
        /// (`split-multi-unit/partial-with-mirror`) is already in R6's
        /// catalogue so a v2 freeze can promote it.
        #[test]
        fn the_partial_with_mirror_report_bytes_are_pinned() {
            let case =
                shapes::by_name("split-multi-unit/partial-with-mirror").expect("catalogue entry");
            let built = build(&case.spec, &case.selection);
            let report =
                verify_bundle(&built.bytes, &VerifyOptions::new()).expect("the bundle verifies");
            let json = String::from_utf8(report.to_canonical_json().expect("D29 encoding"))
                .expect("the D29 encoding is UTF-8");
            // `units_verified` is 2 — the mirror WAS verified as a unit —
            // while the reveal set carries `"raw_mirror":null`: unit-level
            // evidence stays, the unproven whole-file claim goes.
            let pinned = concat!(
                r#"{"report_version":1,"work":{"work_id":"#,
                r#""986a6e4297dade15e3ab93ea285fe37f455bdd886915075d9d579418cdb142c5","#,
                r#""title":"split multi unit","format_version":1,"#,
                r#""app_version":"antseal-fixture/1","#,
                r#""claimed_time_informational_only":"1767225600","#,
                r#""signature_scheme":"hybrid-pq"},"#,
                r#""evidence":{"passed":true,"units_verified":2},"#,
                // D128 §3 R1: the default runs the layer, so this whole-report
                // literal now carries the evaluated object rather than the
                // string. Re-expressed, not re-blessed — the fixture's
                // addresses are R6 `Placeholder`s, so the two embedded
                // ciphertexts and the manifest all mismatch, and every other
                // byte of the pin is unchanged.
                r#""storage_linkage":{"evaluated":{"units_matched":0,"#,
                r#""units_mismatched":2,"manifest_matched":false}},"anchors":[],"#,
                r#""supporting_evidence":"none","reveal":{"files":[{"file_id":0,"#,
                r#""path":"notes/split.md","total_size":34,"fully_revealed":false,"#,
                r#""revealed_spans":[{"unit_id":1,"start":12,"end":24}],"#,
                r#""unrevealed_spans":[{"unit_id":0,"start":0,"end":12},"#,
                r#"{"unit_id":2,"start":24,"end":34}],"raw_mirror":null}],"#,
                r#""unrevealed_files":[]}}"#,
            );
            assert_eq!(
                json, pinned,
                "the D29 report bytes for `split-multi-unit/partial-with-mirror` moved — \
                 if deliberate, this is a report-format event (D29), not a test tweak"
            );
        }

        /// The control: a full reveal's revealed mirror IS reported —
        /// the gate must not suppress the datum rows 9–10 actually
        /// checked. (The 21 frozen R9 vectors pin the same fact for
        /// every committed full-reveal shape; this is the local pair to
        /// the test above.)
        #[test]
        fn a_full_reveals_report_keeps_its_checked_mirror() {
            let case = shapes::by_name("split-multi-unit/all").expect("catalogue entry");
            let built = build(&case.spec, &case.selection);
            let mirror_id = built.files[0]
                .mirror_unit_id
                .expect("the shape has a mirror");

            let report =
                verify_bundle(&built.bytes, &VerifyOptions::new()).expect("the bundle verifies");
            let file = &report.reveal.files[0];
            assert!(file.fully_revealed);
            let mirror = file.raw_mirror.expect("a checked mirror is reported");
            assert_eq!(mirror.unit_id, mirror_id);
        }
    }

    /// R53's two-mirror pin at the **pipeline** surface. F40 landed D23
    /// clause 3 in `FileEntry::new` and committed the decode-layer fixture
    /// (`test_util::tamper_rows_mirror`); this drives the same envelope
    /// through [`verify_bundle`], pinning that a two-mirror manifest inside
    /// a well-formed `.sealproof` dies at stage 1 with the F40 code — it
    /// never reaches the mirror-resolution seam the R53 accessor unified.
    /// Gated on `test-util` because the envelope builder lives on the
    /// tamper tier.
    #[cfg(feature = "test-util")]
    mod two_mirror_manifest_at_the_pipeline {
        use super::*;
        use crate::test_util::tamper_rows_mirror;

        #[test]
        fn a_two_mirror_manifest_dies_at_decode_with_the_f40_code() {
            let envelope = tamper_rows_mirror::FIXTURES
                .iter()
                .find(|fixture| fixture.id == "body-second-raw-mirror")
                .and_then(|fixture| (fixture.build)())
                .expect("F40's two-mirror envelope builds");

            // Graft it into an otherwise-valid bundle: layer 1 treats the
            // embedded manifest as opaque bytes (D78), so the bundle
            // re-encodes cleanly and the rejection is attributable to the
            // manifest decode alone.
            let valid_bytes = valid();
            let mut parts = BundleV1::decode(&valid_bytes)
                .expect("the smoke fixture decodes")
                .into_parts();
            parts.manifest = &envelope;
            let grafted = encode_bundle(&BundleV1::new(parts).expect("layer-1 rules still hold"))
                .expect("the grafted bundle re-encodes");

            let failure = verify_bundle(&grafted, &VerifyOptions::new())
                .expect_err("a two-mirror manifest must not verify");
            assert_eq!(failure.code(), "manifest-multiple-raw-mirrors");
        }
    }

    // -----------------------------------------------------------------
    // R12: the anchor stage, wired
    // -----------------------------------------------------------------
    //
    // These are **in-module** tests rather than an integration target, and
    // the reason is A90's ruling: the `wasm32-core-tests` lane runs this
    // crate's `--lib` tests, and every file under `crates/antseal-core/
    // tests/` is a separate crate that never executes there. A verdict row
    // that lives only there satisfies a wasm32 Accept row *in appearance
    // only*. A18 and A43 already run their rows this way.
    //
    // Every row below is a **differential**: the same fixture with one input
    // changed, asserted to produce two different answers. A single-state
    // assertion over a fixture would stay green under an anchor stage that
    // returned that state unconditionally, which is exactly the shape the M0
    // stub had.

    /// The plan builder, so a row reads as its shape list.
    fn anchored(ots: &[OtsShape], tsa: &[TsaShape], receipt: bool) -> Tweak {
        Tweak {
            anchors: AnchorPlan {
                ots: ots.to_vec(),
                tsa: tsa.to_vec(),
                receipt,
            },
            ..Tweak::default()
        }
    }

    /// Verify with the mock root store and an explicit verification time.
    fn report_at(tweak: &Tweak, verify_at: u64) -> VerificationReport {
        verify_bundle(
            &fixture(tweak),
            &VerifyOptions::new()
                .with_verify_at_unix(verify_at)
                .with_tsa_roots(mock_roots()),
        )
        .expect("an anchored fixture still verifies")
    }

    fn states(report: &VerificationReport) -> Vec<(AnchorKind, AnchorState)> {
        report
            .anchors
            .iter()
            .map(|slot| (slot.kind, slot.state))
            .collect()
    }

    /// **R12 Accept row 1.** Every state the offline stage can reach lands in
    /// its own slot, in `.ots`-then-TSA wire order.
    ///
    /// Six of the seven, in one bundle plus one clock change. The seventh,
    /// `absent`, is a *kind-level* answer that emits no slot at all (D53 §4a)
    /// and is pinned by [`an_anchorless_bundle_emits_no_slots`] below —
    /// asserting it here would need a slot that must not exist.
    ///
    /// `proven` for the `.ots` is deliberately unreachable: it requires online
    /// evidence and `verify_bundle` is handed none (see [`VerifyOptions`]).
    /// The upgraded artifact therefore renders `attested`, which is D56 §3's
    /// rule — a cryptographic verdict does not move with network weather.
    #[test]
    fn every_offline_reachable_anchor_state_lands_in_its_own_slot() {
        let tweak = anchored(
            &[
                OtsShape::Pending,
                OtsShape::CommittedUpgrade,
                OtsShape::Unevaluable,
                OtsShape::StampedOverWorkId,
            ],
            &[TsaShape::Mock, TsaShape::MockShortLived, TsaShape::Garbage],
            false,
        );

        use AnchorKind::{Ots, Tsa};
        use AnchorState::{
            Attested, InternallyConsistentOnly, Invalid, Pending, Proven,
            ValidAtStampingCertSinceExpired,
        };

        assert_eq!(
            states(&report_at(&tweak, BEFORE_EXPIRY)),
            vec![
                (Ots, Pending),
                (Ots, Attested),
                (Ots, InternallyConsistentOnly),
                (Ots, Invalid),
                (Tsa, Proven),
                (Tsa, Proven),
                (Tsa, Invalid),
            ],
            "the anchor stage's slots are not A18's verdicts in wire order"
        );

        // The clock moves exactly one slot — D53's C1/C2 split — which is
        // both the sixth state and the proof that `verify_at` is threaded
        // through rather than defaulted somewhere inside.
        assert_eq!(
            states(&report_at(&tweak, AFTER_EXPIRY))[5],
            (Tsa, ValidAtStampingCertSinceExpired),
            "`verify_at_unix` is not reaching the chain validator"
        );

        // …and the store is threaded too: against the *pinned* roots the
        // mock CA is not trusted, and D53's C6 is what a token that reaches
        // no pinned root renders.
        let pinned = verify_bundle(
            &fixture(&tweak),
            &VerifyOptions::new().with_verify_at_unix(BEFORE_EXPIRY),
        )
        .expect("the bundle still verifies against the pinned store");
        assert_eq!(
            states(&pinned)[4],
            (Tsa, InternallyConsistentOnly),
            "`with_tsa_roots` is not reaching the chain validator"
        );
    }

    /// **R12's own load-bearing choice**: the digest is
    /// `SHA-256(manifest envelope)` — signatures included — and not `work_id`.
    ///
    /// A differential over two `.ots` artifacts in **one** bundle that differ
    /// in nothing but the digest they stamp. Implementing the stage against
    /// `work_id(body)` — the other 32-byte identity in scope, one line away in
    /// the same function — swaps the two answers, so this row is what makes
    /// F7's distinction observable at the pipeline surface instead of only in
    /// `manifest::ids`.
    #[test]
    fn the_stage_evaluates_against_the_envelope_digest_not_work_id() {
        let report = report_at(
            &anchored(
                &[OtsShape::Pending, OtsShape::StampedOverWorkId],
                &[],
                false,
            ),
            BEFORE_EXPIRY,
        );
        assert_eq!(
            states(&report),
            vec![
                (AnchorKind::Ots, AnchorState::Pending),
                (AnchorKind::Ots, AnchorState::Invalid),
            ],
            "the two artifacts differ only in which identity they stamp; if both \
             render the same state the stage is not checking the digest at all, and \
             if they are swapped it is checking `work_id`"
        );

        // Anti-vacuity: the two digests really are different values, so the
        // row above cannot be passing because they coincide.
        let bytes = fixture(&anchored(&[], &[], false));
        let proof = SealProof::decode(&bytes).expect("the fixture decodes");
        assert_ne!(
            anchor_digest(proof.anchor_digest_preimage()).as_bytes(),
            work_id(proof.manifest().body_bytes()).as_bytes(),
        );
    }

    /// **R12 Accept row 3.** A receipt populates the supporting-evidence slot
    /// and changes **no** anchor slot.
    ///
    /// The differential is the receipt flag alone: everything else in the two
    /// bundles is byte-identical, so "the anchor slots are unaffected" is a
    /// measurement rather than a claim.
    #[test]
    fn a_receipt_fills_the_supporting_slot_and_no_anchor_slot() {
        let without = report_at(
            &anchored(&[OtsShape::Pending], &[TsaShape::Mock], false),
            BEFORE_EXPIRY,
        );
        let with = report_at(
            &anchored(&[OtsShape::Pending], &[TsaShape::Mock], true),
            BEFORE_EXPIRY,
        );

        assert_eq!(without.supporting_evidence, SupportingEvidenceResult::None);
        assert_eq!(
            with.supporting_evidence,
            SupportingEvidenceResult::ArbitrumReceipt {
                block_number: RECEIPT_BLOCK,
                transaction_count: 2,
            }
        );
        assert_eq!(
            with.anchors, without.anchors,
            "opting a receipt in moved an anchor slot — the receipt is not an anchor \
             (MVP-SPEC.md line 110; A19)"
        );

        // A19 structurally: the receipt reaches the report through a type
        // with no `AnchorState`, so no `AnchorKind` can name it and the slot
        // count is unmoved.
        assert_eq!(with.anchors.len(), 2);
    }

    /// **D84 rule F2, at the pipeline surface.** An anchor that fails renders
    /// `invalid` in its own slot and changes nothing else — not the evidence
    /// layer, not the reveal set, not the work metadata, not another anchor.
    ///
    /// Measured against an anchorless control, field by field, because
    /// "the bundle still verifies" alone would hold for a stage that failed
    /// every anchor.
    #[test]
    fn a_failing_anchor_changes_nothing_but_its_own_slot() {
        let control = report_at(&anchored(&[], &[], false), BEFORE_EXPIRY);
        let anchored_report = report_at(
            &anchored(
                &[OtsShape::StampedOverWorkId, OtsShape::Pending],
                &[TsaShape::Garbage],
                false,
            ),
            BEFORE_EXPIRY,
        );

        assert!(control.anchors.is_empty());
        assert_eq!(
            states(&anchored_report),
            vec![
                (AnchorKind::Ots, AnchorState::Invalid),
                (AnchorKind::Ots, AnchorState::Pending),
                (AnchorKind::Tsa, AnchorState::Invalid),
            ],
            "a failing artifact took its siblings down with it"
        );

        assert_eq!(anchored_report.evidence, control.evidence);
        assert_eq!(anchored_report.reveal, control.reveal);
        assert_eq!(anchored_report.work.work_id, control.work.work_id);
        assert_eq!(anchored_report.work.title, control.work.title);
        assert_eq!(
            anchored_report.work.signature_scheme,
            control.work.signature_scheme
        );
        assert_eq!(anchored_report.storage_linkage, control.storage_linkage);
        assert_eq!(
            anchored_report.supporting_evidence,
            control.supporting_evidence
        );
    }

    /// **D53 §4a.** `absent` is the answer about an anchor *kind* the bundle
    /// does not carry, and R12 emits no slot for it — which is also what
    /// keeps the 20 pinned R9 vectors' `"anchors":[]` where it is.
    ///
    /// The wrong implementation is the M0 stub's converse: emitting an
    /// `absent` slot per *missing kind* would put two entries here.
    #[test]
    fn an_anchorless_bundle_emits_no_slots() {
        let report = report_at(&anchored(&[], &[], false), BEFORE_EXPIRY);
        assert!(
            report.anchors.is_empty(),
            "an anchorless bundle produced {} slot(s); `absent` is a kind-level \
             answer with no slot (D53 §4a)",
            report.anchors.len()
        );
        let json = String::from_utf8(report.to_canonical_json().expect("D29 encoding"))
            .expect("the D29 encoding is UTF-8");
        assert!(json.contains(r#""anchors":[],"supporting_evidence":"none""#));
    }

    /// The metadata half of R12's `Do`: verified time, source and fetch date
    /// reach the slots, and the *only* source strings that appear are ones the
    /// stage derived from artifact bytes it parsed itself.
    ///
    /// The bundle records `AnchorStatus::Proven` on every TSA anchor and a
    /// `fetch_date`, so a stage that copied the sealer's claim would look
    /// identical on state — and is caught here, because the garbage token
    /// renders `invalid` while claiming `proven`.
    #[test]
    fn slot_metadata_comes_from_the_artifact_never_from_the_bundles_claim() {
        let report = report_at(
            &anchored(
                &[OtsShape::CommittedUpgrade],
                &[TsaShape::Mock, TsaShape::Garbage],
                false,
            ),
            BEFORE_EXPIRY,
        );

        // The `.ots`: no verified time offline (a lone header's
        // proof-of-work is self-referential), a block source, a fetch date.
        let ots = &report.anchors[0];
        assert_eq!(ots.state, AnchorState::Attested);
        assert_eq!(ots.verified_time_unix, None);
        assert_eq!(ots.source.as_deref(), Some("bitcoin-block-700007"));
        assert!(ots.fetch_date.is_some());

        // The good token: `genTime` as the verified time, and a signer
        // identity read out of the certificate the path validated.
        let good = &report.anchors[1];
        assert_eq!(good.state, AnchorState::Proven);
        assert_eq!(good.verified_time_unix, Some(MOCK_GEN_TIME as i64));
        assert!(
            good.source
                .as_deref()
                .is_some_and(|s| s.contains("antseal mock TSA")),
            "the TSA source is not the validated signer's subject: {:?}",
            good.source
        );

        // The garbage token: nothing was parsed far enough to claim a
        // source, and the bundle's own `status: proven` claim is not it.
        let bad = &report.anchors[2];
        assert_eq!(bad.state, AnchorState::Invalid);
        assert_eq!(bad.verified_time_unix, None);
        assert_eq!(
            bad.source, None,
            "an unparseable token contributed a source string — the only place one \
             could have come from is the bundle, and D8 §1 removed that field"
        );
        // …and the one field that *is* copied from the bundle's claim, in the
        // test named for it. **D95**: it renders on `invalid` too, because the
        // field is bound by nothing in *every* state, so a state gate would
        // claim a corroboration that never happened. Asserting the value —
        // not merely `is_some()` — is what makes this a pin rather than a
        // shrug: the rendering is decimal POSIX seconds, format-permanent.
        assert_eq!(
            bad.fetch_date.as_deref(),
            Some(FIXTURE_FETCH_DATE.to_string()).as_deref(),
            "a refuted anchor's sealer-recorded fetch date is not rendered as the wire \
             `uint` in decimal POSIX seconds (D95)"
        );
    }

    /// **D95 rider (c), and the measure that makes the ruling safe.**
    ///
    /// `fetch_date` is rendered but must never be *read*: D59 §6(a) forbids
    /// comparing it to anything, in any direction. That was true only by
    /// inspection — and inspection is exactly what D94 §4 caught out five
    /// times over. This makes it an equality.
    ///
    /// Two bundles identical but for the recorded fetch date must produce
    /// anchor slots equal in every field **except** `fetch_date` itself. An
    /// implementer who adds the forbidden `gen_time <= fetch_date` check —
    /// the natural, tempting, and normatively prohibited one — turns this red
    /// immediately, because the two runs would disagree on `state`.
    ///
    /// Modelled on D59's `nonce_is_inert_when_none_is_supplied`.
    #[test]
    fn the_recorded_fetch_date_moves_no_other_field_of_any_anchor_slot() {
        let shapes = &[
            OtsShape::Pending,
            OtsShape::CommittedUpgrade,
            OtsShape::StampedOverWorkId,
        ];
        let tsa = &[TsaShape::Mock, TsaShape::MockShortLived, TsaShape::Garbage];

        let baseline = report_at(&anchored(shapes, tsa, false), BEFORE_EXPIRY);
        let moved = report_at(
            &Tweak {
                fetch_date: Some(FIXTURE_FETCH_DATE + 86_400 * 365),
                ..anchored(shapes, tsa, false)
            },
            BEFORE_EXPIRY,
        );

        assert_eq!(
            baseline.anchors.len(),
            moved.anchors.len(),
            "the fetch date changed the slot count"
        );
        let mut really_moved = 0_usize;
        for (before, after) in baseline.anchors.iter().zip(&moved.anchors) {
            // A slot that carries no fetch date cannot demonstrate anything —
            // an `.ots` without a D79 upgrade group has none to move, which is
            // availability, not policy (D95 §1). Count the ones that can, and
            // require below that some did.
            match (&before.fetch_date, &after.fetch_date) {
                (Some(b), Some(a)) => {
                    assert_ne!(b, a, "the knob did not reach this slot's fetch date");
                    really_moved += 1;
                }
                (None, None) => {}
                (b, a) => panic!(
                    "moving the recorded fetch date made a slot's fetch date appear or \
                     vanish: {b:?} -> {a:?}"
                ),
            }
            assert_eq!(
                (before.kind, before.state, before.verified_time_unix),
                (after.kind, after.state, after.verified_time_unix),
                "moving the sealer's recorded fetch date moved a verdict field — D59 \
                 §6(a) forbids reading this value in any direction"
            );
            assert_eq!(
                before.source, after.source,
                "moving the sealer's recorded fetch date moved the derived source"
            );
        }
        // Anti-vacuity: if the knob reached nothing, the loop above compared a
        // fixture with itself and would stay green under any implementation.
        assert!(
            really_moved >= 2,
            "only {really_moved} slot(s) saw the fetch date move; this row needs the \
             three TSA slots plus the upgraded `.ots` to carry one"
        );
    }
}
