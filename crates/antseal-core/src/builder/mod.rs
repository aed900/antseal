//! The M3 production bundle builder — **pure assembly** of a `.sealproof`
//! (task R13; MVP-SPEC.md lines 36, 112–114, 156; decision **D70** §7 is the
//! implementation contract this module follows verbatim).
//!
//! [`build_bundle`] turns already-computed material — the plaintext manifest
//! envelope bytes, the manifest storage record, a resolved per-file reveal
//! plan, per-unit ciphertexts, per-file plaintext for touched files, the
//! derivation secret, anchor artifacts and an optional receipt — into
//! encoded `.sealproof` bytes. It is a pure function: no I/O, no clock, no
//! randomness, no network, WASM-safe. Fetching, previews, consent and file
//! output are R15/R16/U28/U29's (`antseal-cli`); nothing of them lives here.
//!
//! # What is emitted, exactly (spec lines 112–114; registry §§7.6–7.14)
//!
//! | subject | entry | present iff |
//! | --- | --- | --- |
//! | covered revealed unit | {`unit_id`, `k_u`, ciphertext, leaf-exact GGM sub-cover, boundary Merkle paths} (§7.11) | unit revealed ∧ fine-tree covered |
//! | non-covered revealed unit (`--no-fine-tree`, raw mirror) | {`unit_id`, `unit_salt`, `k_u`, ciphertext} (§7.12) | unit revealed ∧ not covered |
//! | touched file | {`path`, `path_salt`} (§7.13) | ≥ 1 unit of the file revealed |
//! | fully revealed file | {`file_salt`} (§7.14) | `full(F)` (D28 — unconditional) |
//! | … its `s_root` | §7.14 key 2 | `full(F)` ∧ fine tree present (D28/D74) |
//! | … its raw-mirror unit | an **ordinary** §7.12 entry — no flag, no link | `full(F)` ∧ manifest records a mirror (D70) |
//! | manifest storage record | §7.7 | always |
//! | anchor artifacts | §§7.8–7.9 | always (empty sections are legal) |
//! | Arbitrum receipt | §7.10 | iff the caller opted it in |
//!
//! No nonce field exists anywhere in a bundle — nonces stay manifest-only,
//! the single authoritative copy (spec line 91; asserted against F's schema
//! by R2, and re-asserted here by the post-encode byte scan).
//!
//! # D70: raw-mirror inclusion is derived, not selected
//!
//! There is **no mirror knob in v1** (D70 §7.1). Inclusion is computed
//! inside the builder as `full(F) ∧ manifest-has-mirror(F)`, the mirror
//! located by `kind` (the `resolve_raw_mirror` semantics — never by
//! position; at most one exists per decoded manifest, D23 clause 3, so
//! [`FileEntry::raw_mirror`](crate::manifest::body::FileEntry::raw_mirror)
//! is total). A file with no mirror contributes nothing — no error, no log
//! (D70 §5): binary files, already-canonical text and the empty file all
//! take that no-op path. `--no-fine-tree` is orthogonal: a mirror-bearing
//! `--no-fine-tree` file's full reveal emits **two** §7.12 entries (its
//! whole-file unit and its mirror) and no `s_root`.
//!
//! Because [`FilePlan`] can express neither "full without the mirror" nor
//! "partial with the mirror" — [`FilePlan::Full`] has no mirror field, and
//! [`FilePlan::Units`] indices address the file's **normal**-unit list only
//! — R6's `FullNoMirror`/`UnitsWithMirror` remain fixture-only shapes this
//! API is structurally unable to produce. The parity test asserts that
//! inability rather than merely not exercising it.
//!
//! # `full(F)` is derived, never declared (D28 rider 1)
//!
//! `full(F) ⟺ N(F) ≠ ∅ ∧ R(F) = N(F)` over the manifest's normal units —
//! the same predicate the verifier derives, computed the same way, so the
//! two cannot disagree. A [`FilePlan::Units`] selection that names every
//! normal unit **is** a full reveal: it pulls in `file_salt`, `s_root` and
//! the mirror exactly as [`FilePlan::Full`] does (the promotion case D70
//! §7.6 names for R16's consent gate).
//!
//! # Generation-side isolation, by construction
//!
//! - **Untouched files:** the assembly loop `continue`s before deriving
//!   anything — no salt, no seed, no path, no entry.
//! - **`file_salt`:** the only byte path in the crate is
//!   [`FullFileRevealDisclosure::file_salt_bytes`], and reaching it requires
//!   [`FullFileRevealContext::attest`] against the real manifest unit table
//!   (C7). The partial branch holds a [`PartialRevealDisclosure`], which has
//!   no `file_salt` slot at all.
//! - **`s_root` / GGM seeds:** cover seeds come only out of
//!   [`prove_range`]'s leaf-exact cover (G11/G12 — the only seed-disclosure
//!   path in the crate), and `s_root` is emitted only inside the branch that
//!   has already established `full(F)`, routed through
//!   [`canonical_leaf_level_payload`] so the `n = 1` disclosed form has
//!   exactly one implementation (D83).
//! - **Paths:** [`FilePlan::Untouched`] has no path slot, so a path for an
//!   untouched file is unrepresentable (R14 property (d) by construction).
//!
//! # The mandatory self-check, and what it structurally cannot see
//!
//! Every built bundle is run through
//! [`verify_bundle`](crate::verify::verify_bundle) before it is returned;
//! any failure aborts the build ([`BuildError::SelfCheck`]). On top of it
//! run the **internal assertions** — the checks D70 §7.3 measured the
//! verifier as unable to make:
//!
//! | assertion | why the self-check cannot see it | negative control |
//! | --- | --- | --- |
//! | every emitted mirror entry belongs to a `full(F)` file | the verifier tolerates a partial's mirror (R53, deliberate non-check) | `forcing` seam, `emit_mirror_for` |
//! | every `full(F)` file with a manifest mirror has its mirror emitted | the mirror-less full reveal is a frozen accepted vector | `forcing` seam, `omit_mirror` |
//! | receipt present ⟺ opted | receipt presence is legal either way on the wire | `forcing` seam, `drop_receipt`/`inject_receipt` |
//! | no `file_salt`/fine-seed/nonce **bytes** outside their sanctioned places | the verifier does not hold `W` and cannot derive the needles | `forcing` seam, `smuggle` |
//!
//! Each assertion is re-derived from the emitted sections plus the decoded
//! manifest — never from the assembly's own plan variables — so a forced
//! mutation of the sections is caught by derivation, not bookkeeping. The
//! byte scans are C7's prescribed runtime serialization assertion
//! ([`encoded_output_contains_file_salt`]) extended to the fine seed and the
//! revealed units' nonces; they cost `O(bundle × subjects)` windows and run
//! once per build, on the sealer's own machine.
//!
//! # Relationship to R6 (`test_util::bundle_fixtures`)
//!
//! R6's five-point seam ("What R13 must preserve", its module docs) is
//! honored point for point: (1) assembly is a pure function of
//! already-computed material, same input shape, so the parity test feeds
//! both the same inputs; (2) every derivation is C's or G's —
//! [`derive_unit_key`], the C7 disclosure types, [`derive_fine_seed`],
//! [`prove_range`] — never re-implemented; (3) isolation is enforced by
//! construction in the one branch that established `full(F)`; (4) the
//! manifest-order contract survives — units are emitted in manifest
//! unit-table order (= ascending work-global `unit_id`, F5), files in
//! file-table order; (5) there is **no [`Tweak`]-equivalent** here — the
//! only mutation surface is the `test-vectors`-gated [`forcing`] seam,
//! which exists so R14's negative controls can prove the guards fail, and
//! which no production build compiles in.
//!
//! # Secret hygiene (project rule 6)
//!
//! `W` is borrowed ([`MasterSecretRef`], redacted `Debug`), never copied.
//! Derived material lives in the crypto layer's zeroize-on-drop newtypes
//! and reaches the output only where the spec disburses it. Nothing here
//! logs; [`BuildInputs`]' hand-written `Debug` renders lengths and counts,
//! never plaintext, ciphertext or key bytes; [`BuildError`] carries ids
//! only.
//!
//! [`FullFileRevealDisclosure::file_salt_bytes`]: crate::crypto::disclosure::FullFileRevealDisclosure::file_salt_bytes
//! [`FullFileRevealContext::attest`]: crate::crypto::disclosure::FullFileRevealContext::attest
//! [`PartialRevealDisclosure`]: crate::crypto::disclosure::PartialRevealDisclosure
//! [`Tweak`]: crate::test_util::bundle_fixtures::Tweak

use std::collections::{BTreeMap, BTreeSet};

use crate::bundle::{
    BundleParts, BundleV1, CoverEntry as BundleCoverEntry, CoveredReveal, FullReveal,
    NonCoveredReveal, OpaqueBytes, OtsAnchor, PathNode, ReceiptRecord, StorageRecord,
    TouchedFile as BundleTouchedFile, TsaAnchor, encode_bundle,
};
use crate::content::fine_tree::{canonical_leaf_level_payload, prove_range};
use crate::content::ggm::{NodeAddress, depth_for_leaf_count};
use crate::content::unit::ByteRange as ContentByteRange;
use crate::crypto::disclosure::{
    FullFileRevealContext, FullFileRevealDisclosure, NonCoveredUnitDisclosure,
    PartialRevealDisclosure, encoded_output_contains_file_salt,
};
use crate::crypto::hkdf::{FileId, UnitId, derive_fine_seed, derive_unit_key};
use crate::crypto::material::{MasterSecretRef, NodeHash32, Salt16, Seed32};
use crate::manifest::Manifest;
use crate::manifest::body::{FileEntry, FineTree, ManifestBodyV1, UnitEntry};
use crate::manifest::registry::UnitKind;
use crate::verify::{VerifyOptions, verify_bundle};

pub mod error;
#[cfg(feature = "test-vectors")]
pub mod forcing;

pub use error::{BuildError, ForbiddenMaterial};

// ---------------------------------------------------------------------------
// the resolved reveal plan
// ---------------------------------------------------------------------------

/// What one file's reveal shows — **what the sealer selected**, never a
/// declared shape (D28 rider 1; R6's `FileSelection` carries the same
/// principle). The builder derives `full(F)` from coverage, exactly as the
/// verifier does.
///
/// Structural properties this type is load-bearing for (D70 §7.1):
///
/// - [`Self::Units`] indices address the file's **normal**-unit list, so a
///   raw mirror cannot be named — "partial with mirror" is unrepresentable
///   (the API-boundary rejection of an explicitly listed mirror id is
///   R16's, via [`unit_selectable`](crate::content::mirror::unit_selectable)).
/// - [`Self::Full`] has no mirror field, so "full without mirror" is
///   equally unrepresentable — the mirror rides automatically whenever the
///   manifest records one.
/// - [`Self::Untouched`] has no path slot, so a path cannot be disclosed
///   for an untouched file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilePlan {
    /// Nothing shown, nothing derived: no `touched_files` entry, no salt,
    /// no seed — the committed-placeholder shape (spec line 95).
    Untouched,
    /// Reveal these normal units, by index within the file's normal-unit
    /// list (manifest order). Duplicates cannot exist (`BTreeSet`); a set
    /// naming **every** normal unit classifies as a full reveal, with
    /// everything that entails (D70 §7.6's promotion case).
    Units {
        /// The file's vault-held path, disclosed because the reveal
        /// touches the file (spec line 95).
        path: String,
        /// Indices into the file's normal-unit list. Must be non-empty
        /// and in range ([`BuildError::NoUnitsSelected`],
        /// [`BuildError::UnitIndexOutOfRange`]).
        units: BTreeSet<usize>,
    },
    /// Reveal every normal unit — plus the raw mirror iff the manifest
    /// records one (derived inside the builder; a mirror-less file is a
    /// no-op, never an error — D70 §5).
    Full {
        /// The file's vault-held path, disclosed because the reveal
        /// touches the file.
        path: String,
    },
}

impl FilePlan {
    /// A full-file reveal of the file at `path`.
    #[must_use]
    pub fn full(path: impl Into<String>) -> Self {
        Self::Full { path: path.into() }
    }

    /// A unit-set reveal of the file at `path`. Duplicate indices collapse
    /// (the same dedup rule R16 applies to `--units` lists).
    #[must_use]
    pub fn units(path: impl Into<String>, units: impl IntoIterator<Item = usize>) -> Self {
        Self::Units {
            path: path.into(),
            units: units.into_iter().collect(),
        }
    }
}

/// A whole resolved reveal plan: one [`FilePlan`] per manifest file, in
/// file-table order (index = `file_id`, spec line 76).
///
/// The length must equal the manifest's file count
/// ([`BuildError::PlanFileCountMismatch`]) — a plan is a total statement
/// about the work, with "say nothing about this file" spelled
/// [`FilePlan::Untouched`] rather than by omission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevealPlan {
    files: Vec<FilePlan>,
}

impl RevealPlan {
    /// A plan from per-file choices, in file-table order.
    #[must_use]
    pub fn new(files: Vec<FilePlan>) -> Self {
        Self { files }
    }

    /// The per-file choices, in file-table order.
    #[must_use]
    pub fn files(&self) -> &[FilePlan] {
        &self.files
    }
}

// ---------------------------------------------------------------------------
// the inputs
// ---------------------------------------------------------------------------

/// Everything [`build_bundle`] consumes — already-computed material only
/// (R13's Do list; R6 seam point 1). Gathering it is R16's job.
pub struct BuildInputs<'a> {
    /// The plaintext manifest **envelope** bytes, exactly as anchored
    /// (spec line 98: bytes anchored ≠ bytes stored). Embedded verbatim.
    pub manifest: &'a [u8],
    /// The manifest's own storage triple {address, nonce, `k_m`}
    /// (registry §7.7). Always embedded.
    pub storage_record: StorageRecord,
    /// The resolved reveal plan (per file: full / units / untouched).
    pub plan: &'a RevealPlan,
    /// Per-unit ciphertexts by work-global `unit_id`. Every **revealed**
    /// unit's ciphertext must be present (mirrors included — R16's
    /// gathering step fetches all units of every touched file, D70 §7.5);
    /// entries for unrevealed units are tolerated and ignored.
    pub unit_ciphertexts: &'a BTreeMap<u64, Vec<u8>>,
    /// Per-file plaintext by `file_id` — the file's tiling-domain content
    /// (canonical bytes for text, raw bytes for binary). Required for every
    /// touched fine-tree file (G rebuilds the whole tree to cut boundary
    /// paths); tolerated and ignored otherwise.
    pub file_contents: &'a BTreeMap<u64, Vec<u8>>,
    /// The derivation secret `W`, borrowed (C7's API shape).
    pub w: MasterSecretRef<'a>,
    /// OTS anchor artifacts, in journal order (with their upgrade groups
    /// and fetch dates inside). Always embedded; empty is legal.
    pub ots_anchors: Vec<OtsAnchor>,
    /// TSA anchor artifacts (tokens, intermediates, fetch dates). Always
    /// embedded; empty is legal.
    pub tsa_anchors: Vec<TsaAnchor>,
    /// The Arbitrum receipt — embedded **iff** `Some` (`--include-receipt`,
    /// spec line 36; registry §7.10).
    pub receipt: Option<ReceiptRecord>,
}

impl core::fmt::Debug for BuildInputs<'_> {
    /// Lengths and counts only: `file_contents` holds plaintext of files
    /// the reveal may only partially disclose, and printing it would be
    /// the disclosure (project rule 6).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BuildInputs")
            .field("manifest", &format_args!("<{} B>", self.manifest.len()))
            .field("plan_files", &self.plan.files.len())
            .field("unit_ciphertexts", &self.unit_ciphertexts.len())
            .field("file_contents", &self.file_contents.len())
            .field("w", &self.w)
            .field("ots_anchors", &self.ots_anchors.len())
            .field("tsa_anchors", &self.tsa_anchors.len())
            .field("receipt", &self.receipt.is_some())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------

/// Build, self-verify and encode a `.sealproof` for the given inputs.
///
/// Pure and WASM-safe: no I/O, no clock, no randomness. The returned bytes
/// have already passed [`verify_bundle`](crate::verify::verify_bundle) and
/// the D70 §7.3 internal assertions (module docs).
///
/// # Errors
///
/// See [`BuildError`] — input validation first, then F's assembly/encoding
/// rejections, then the mandatory self-check and the internal assertions
/// (the assertion variants are unreachable through this entry point by
/// construction and exist for the [`forcing`] seam's negative controls).
pub fn build_bundle(inputs: BuildInputs<'_>) -> Result<Vec<u8>, BuildError> {
    let decoded = Manifest::decode(inputs.manifest)?;
    let sections = assemble(&inputs, decoded.body())?;
    let receipt_opted = inputs.receipt.is_some();
    finish(inputs, decoded.body(), sections, receipt_opted)
}

/// The assembled reveal-side sections, pre-validation. Internal: the only
/// ways out are [`finish`] (production) and the [`forcing`] seam (tests).
struct Sections {
    covered: Vec<CoveredReveal>,
    noncovered: Vec<NonCoveredReveal>,
    touched: Vec<BundleTouchedFile>,
    full_reveals: Vec<FullReveal>,
}

/// One file's resolved reveal, mid-assembly.
struct ResolvedFile<'m> {
    path: &'m str,
    /// The revealed unit ids — normal units plus the derived mirror.
    revealed: BTreeSet<u64>,
    full: bool,
}

/// Assemble the reveal-side sections for `plan` over the decoded manifest.
///
/// Emission order: files in file-table order, units in manifest unit-table
/// order — which **is** ascending work-global `unit_id` (F5 pins the
/// ordinal), so F9's strictly-ascending section rule is satisfied with no
/// sorting and no special-casing of the mirror (D70 §7.1).
fn assemble(inputs: &BuildInputs<'_>, body: &ManifestBodyV1) -> Result<Sections, BuildError> {
    let files = body.files();
    let plan = inputs.plan.files();
    if plan.len() != files.len() {
        return Err(BuildError::PlanFileCountMismatch {
            expected: files.len() as u64,
            got: plan.len() as u64,
        });
    }

    let mut sections = Sections {
        covered: Vec::new(),
        noncovered: Vec::new(),
        touched: Vec::new(),
        full_reveals: Vec::new(),
    };

    for (index, (entry, choice)) in files.iter().zip(plan.iter()).enumerate() {
        let file_id = index as u64;
        let Some(resolved) = resolve_file(file_id, entry, choice)? else {
            // Untouched: derive and emit nothing (R13 Do; module docs).
            continue;
        };

        // ── per-file disclosure material (C7's typed gates) ────────────
        let path_salt = if resolved.full {
            let all: Vec<UnitId> = entry
                .units()
                .iter()
                .filter(|unit| unit.kind() == UnitKind::Normal)
                .map(|unit| UnitId(unit.unit_id()))
                .collect();
            // `full` was derived as exact coverage of that same list, so
            // the witness attests by construction; a refusal means the two
            // derivations drifted apart and must surface, not panic.
            let context = FullFileRevealContext::attest(FileId(file_id), &all, &all)
                .ok_or(BuildError::FullRevealWitnessRefused { file_id })?;
            let disclosure = FullFileRevealDisclosure::new(inputs.w, context);
            let file_salt = Salt16::from_bytes(*disclosure.file_salt_bytes());
            let s_root = disclosed_s_root(inputs.w, file_id, entry)?;
            sections
                .full_reveals
                .push(FullReveal::new(file_id, file_salt, s_root));
            Salt16::from_bytes(*disclosure.path_salt().as_bytes())
        } else {
            // The partial-reveal disclosure type has no `file_salt` slot —
            // the leak is unrepresentable, not merely avoided (C7 Rule 2).
            let disclosure = PartialRevealDisclosure::new(inputs.w, FileId(file_id));
            Salt16::from_bytes(*disclosure.path_salt().as_bytes())
        };
        sections.touched.push(BundleTouchedFile::new(
            file_id,
            resolved.path.to_owned(),
            path_salt,
        ));

        // ── per-unit reveal entries, in manifest unit order ────────────
        for unit in entry.units() {
            if !resolved.revealed.contains(&unit.unit_id()) {
                continue;
            }
            push_reveal_entry(inputs, entry, file_id, unit, &mut sections)?;
        }
    }

    Ok(sections)
}

/// Resolve one file's plan into its revealed unit-id set and derived
/// classification; `None` for an untouched file.
fn resolve_file<'m>(
    file_id: u64,
    entry: &'m FileEntry,
    choice: &'m FilePlan,
) -> Result<Option<ResolvedFile<'m>>, BuildError> {
    let normal_ids: Vec<u64> = entry
        .units()
        .iter()
        .filter(|unit| unit.kind() == UnitKind::Normal)
        .map(UnitEntry::unit_id)
        .collect();

    let (path, revealed_normal): (&str, Vec<u64>) = match choice {
        FilePlan::Untouched => return Ok(None),
        FilePlan::Units { path, units } => {
            if units.is_empty() {
                return Err(BuildError::NoUnitsSelected { file_id });
            }
            let mut ids = Vec::with_capacity(units.len());
            for &unit_index in units {
                let Some(&id) = normal_ids.get(unit_index) else {
                    return Err(BuildError::UnitIndexOutOfRange {
                        file_id,
                        index: unit_index as u64,
                        normal_units: normal_ids.len() as u64,
                    });
                };
                ids.push(id);
            }
            (path, ids)
        }
        FilePlan::Full { path } => (path, normal_ids.clone()),
    };

    // full(F) ⟺ N(F) ≠ ∅ ∧ R(F) = N(F), derived exactly as the verifier
    // derives it (D28 rider 1). The selection indices are a deduplicated
    // in-range subset, so set equality is a length equality.
    let full = !normal_ids.is_empty() && revealed_normal.len() == normal_ids.len();

    let mut revealed: BTreeSet<u64> = revealed_normal.into_iter().collect();
    // D70 §7.1: mirror inclusion is derived here — full(F) ∧
    // manifest-has-mirror(F), the mirror located by kind. A file with no
    // mirror contributes nothing: no error, no log.
    if full && let Some(mirror) = entry.raw_mirror() {
        revealed.insert(mirror.unit_id());
    }

    Ok(Some(ResolvedFile {
        path,
        revealed,
        full,
    }))
}

/// The disclosed `s_root` for a fully revealed file, when it has a fine
/// tree: the derived fine seed, routed through the same prover-side rule
/// the cover uses so the `n = 1` disclosed form (`salt_0 ‖ 0x00·16`, D83;
/// registry §7.14 key 2) has exactly one implementation.
fn disclosed_s_root(
    w: MasterSecretRef<'_>,
    file_id: u64,
    entry: &FileEntry,
) -> Result<Option<Seed32>, BuildError> {
    match entry.fine_tree() {
        FineTree::Absent => Ok(None),
        FineTree::Present { .. } => {
            let depth = depth_for_leaf_count(entry.size()).ok_or(BuildError::FineTreeDepth {
                file_id,
                size: entry.size(),
            })?;
            Ok(Some(canonical_leaf_level_payload(
                &derive_fine_seed(w, FileId(file_id)),
                NodeAddress::root(),
                depth,
            )))
        }
    }
}

/// Emit one revealed unit's entry into the section its manifest binding
/// dictates — the same dispatch rule the verifier's coherence stage
/// re-checks, decided by C7's disclosure gate: a `unit_salt` disclosure
/// exists iff the unit is non-covered.
fn push_reveal_entry(
    inputs: &BuildInputs<'_>,
    entry: &FileEntry,
    file_id: u64,
    unit: &UnitEntry,
    sections: &mut Sections,
) -> Result<(), BuildError> {
    let unit_id = unit.unit_id();
    let ciphertext = inputs
        .unit_ciphertexts
        .get(&unit_id)
        .ok_or(BuildError::MissingCiphertext { unit_id })?
        .clone();
    let k_u = derive_unit_key(inputs.w, UnitId(unit_id));

    if let Some(disclosure) =
        NonCoveredUnitDisclosure::for_unit(inputs.w, UnitId(unit_id), unit.binding())
    {
        // Non-covered: `--no-fine-tree` whole-file unit or raw mirror
        // (registry §7.12 — a mirror is an ordinary entry, no flag).
        let reveal = NonCoveredReveal::new(
            unit_id,
            k_u,
            OpaqueBytes::from_vec(ciphertext),
            Salt16::from_bytes(*disclosure.unit_salt().as_bytes()),
        )
        .map_err(|source| BuildError::Assembly { source })?;
        sections.noncovered.push(reveal);
    } else {
        // Fine-tree covered: leaf-exact GGM sub-cover + boundary Merkle
        // paths (G11/G12). `prove_range` is the only seed-disclosure path
        // in the crate, and its cover is leaf-exact by type.
        let content = inputs
            .file_contents
            .get(&file_id)
            .ok_or(BuildError::MissingFileContent { file_id })?;
        let s_root = derive_fine_seed(inputs.w, FileId(file_id));
        let proof = prove_range(
            &s_root,
            content,
            ContentByteRange::new(unit.range().start(), unit.range().length()),
            entry.size(),
        )
        .map_err(|source| BuildError::RangeProof {
            file_id,
            unit_id,
            source,
        })?;
        let cover: Vec<BundleCoverEntry> = proof
            .cover()
            .iter()
            .map(|cover_entry| {
                // The DISCLOSED payload, not the derived seed: the two
                // differ at `level == d` by D83's canonical zero tail.
                BundleCoverEntry::new(
                    cover_entry.node().address(),
                    Seed32::from_bytes(*cover_entry.payload().as_bytes()),
                )
            })
            .collect();
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
        let reveal = CoveredReveal::new(
            unit_id,
            k_u,
            OpaqueBytes::from_vec(ciphertext),
            cover,
            paths,
        )
        .map_err(|source| BuildError::Assembly { source })?;
        sections.covered.push(reveal);
    }
    Ok(())
}

/// Validate, encode, self-verify and internally assert — the one exit for
/// both the production path and the [`forcing`] seam, so a forced bundle
/// faces exactly the guards a production bundle faces.
fn finish(
    inputs: BuildInputs<'_>,
    body: &ManifestBodyV1,
    sections: Sections,
    receipt_opted: bool,
) -> Result<Vec<u8>, BuildError> {
    let BuildInputs {
        manifest,
        storage_record,
        w,
        ots_anchors,
        tsa_anchors,
        receipt,
        ..
    } = inputs;

    let bundle = BundleV1::new(BundleParts {
        manifest,
        storage_record,
        ots_anchors,
        tsa_anchors,
        receipt,
        covered_reveals: sections.covered,
        noncovered_reveals: sections.noncovered,
        touched_files: sections.touched,
        full_reveals: sections.full_reveals,
    })
    .map_err(|source| BuildError::Assembly { source })?;
    let bytes = encode_bundle(&bundle).map_err(|source| BuildError::Encode { source })?;

    // The mandatory self-check (R13 Do): nothing that fails its own
    // verification ever leaves the builder. Default options — the builder
    // reads no clock, and the anchor stage's verdicts are slot-local and
    // never fail a bundle (D84 rule F2), so no option could change the
    // accept/reject bit this gate reads.
    verify_bundle(&bytes, &VerifyOptions::new())
        .map_err(|source| BuildError::SelfCheck { source })?;

    // The internal assertions the self-check structurally cannot make
    // (D70 §7.3; module docs table).
    assert_beyond_self_check(w, body, &bundle, &bytes, receipt_opted)?;

    Ok(bytes)
}

// ---------------------------------------------------------------------------
// the internal assertions (D70 §7.3)
// ---------------------------------------------------------------------------

/// Re-derive every guarantee from the **emitted** sections plus the signed
/// manifest — never from the assembly's plan variables — and refuse the
/// build on any violation. See the module-docs table for what each guards
/// and why the self-check cannot.
fn assert_beyond_self_check(
    w: MasterSecretRef<'_>,
    body: &ManifestBodyV1,
    bundle: &BundleV1<'_>,
    bytes: &[u8],
    receipt_opted: bool,
) -> Result<(), BuildError> {
    let revealed: BTreeSet<u64> = bundle.revealed_unit_ids().into_iter().collect();

    // full(F), re-derived the verifier's way from the emitted reveal set.
    let mut full_files: BTreeSet<u64> = BTreeSet::new();
    for (index, entry) in body.files().iter().enumerate() {
        let file_id = index as u64;
        let normal_ids: Vec<u64> = entry
            .units()
            .iter()
            .filter(|unit| unit.kind() == UnitKind::Normal)
            .map(UnitEntry::unit_id)
            .collect();
        let full = !normal_ids.is_empty() && normal_ids.iter().all(|id| revealed.contains(id));
        if full {
            full_files.insert(file_id);
        }

        // Both mirror ⟷ full-reveal directions (D70 §§4, 7.3): the mirror
        // located by kind, independently of the assembly's resolution.
        if let Some(mirror) = entry.raw_mirror() {
            let unit_id = mirror.unit_id();
            let emitted = revealed.contains(&unit_id);
            if emitted && !full {
                return Err(BuildError::MirrorEmittedWithoutFullReveal { file_id, unit_id });
            }
            if full && !emitted {
                return Err(BuildError::MirrorMissingFromFullReveal { file_id, unit_id });
            }
        }
    }

    // Receipt presence ⟺ the caller's opt-in.
    if bundle.receipt().is_some() != receipt_opted {
        return Err(BuildError::ReceiptPresenceMismatch {
            opted: receipt_opted,
        });
    }

    // ── the byte scans: vault material must not appear outside its
    //    sanctioned places (C7's runtime serialization assertion) ────────
    //
    // The embedded manifest legitimately holds every nonce, so the scans
    // run over the bytes OUTSIDE its span. The span is taken from a
    // re-parse of our own output, whose manifest slice borrows `bytes` by
    // the type's zero-copy contract.
    let reparsed = BundleV1::decode(bytes).map_err(|source| BuildError::Reparse { source })?;
    let embedded = reparsed.manifest_bytes();
    let start = (embedded.as_ptr() as usize)
        .checked_sub(bytes.as_ptr() as usize)
        .ok_or(BuildError::ManifestSpanUntracked)?;
    let end = start
        .checked_add(embedded.len())
        .ok_or(BuildError::ManifestSpanUntracked)?;
    if end > bytes.len() {
        return Err(BuildError::ManifestSpanUntracked);
    }
    let outside: [&[u8]; 2] = [&bytes[..start], &bytes[end..]];

    for (index, entry) in body.files().iter().enumerate() {
        let file_id = index as u64;
        if full_files.contains(&file_id) {
            // A full reveal legitimately discloses file_salt and s_root.
            continue;
        }
        if outside
            .iter()
            .any(|region| encoded_output_contains_file_salt(w, FileId(file_id), region))
        {
            return Err(BuildError::ForbiddenBytesInEncoding {
                material: ForbiddenMaterial::FileSalt { file_id },
            });
        }
        if entry.fine_tree().is_present() {
            let seed = derive_fine_seed(w, FileId(file_id));
            if outside
                .iter()
                .any(|region| contains_window(region, seed.as_bytes()))
            {
                return Err(BuildError::ForbiddenBytesInEncoding {
                    material: ForbiddenMaterial::FineSeed { file_id },
                });
            }
        }
    }

    // Nonces stay manifest-only (spec line 91): no revealed unit's nonce
    // may appear outside the embedded manifest.
    for entry in body.files() {
        for unit in entry.units() {
            if !revealed.contains(&unit.unit_id()) {
                continue;
            }
            if outside
                .iter()
                .any(|region| contains_window(region, unit.nonce().as_bytes()))
            {
                return Err(BuildError::ForbiddenBytesInEncoding {
                    material: ForbiddenMaterial::UnitNonce {
                        unit_id: unit.unit_id(),
                    },
                });
            }
        }
    }

    Ok(())
}

/// Does `haystack` contain `needle` as a byte subsequence? The same
/// windows scan C7's helper uses; a false positive needs an accidental
/// 16/24/32-byte collision (≈ 2⁻¹²⁸ per offset — negligible).
fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(test)]
mod tests;
