//! Golden-vector kind **`content-model`** (task G21): the seal-side content
//! model's *derived* values, committed as a vector **file**.
//!
//! Spec basis: work-global `unit_id` assignment in manifest order
//! (MVP-SPEC.md line 76), the empty-file rule (line 78), text/binary detection
//! and the descriptor's frozen Unicode version (line 83), the fine tree's byte
//! domain (line 85), the raw mirror (line 92), the `unit_commit`-iff-not-covered
//! rule (line 94), the file-table `size` domain (line 98), the M0 milestone
//! (line 153) and Verification (line 169).
//!
//! # Why this kind exists — the gap G14 left
//!
//! G14's golden end-to-end fixture is committed as **Rust constants**
//! ([`crate::content::fixtures`], `test-vectors` tier). The wasm32 `--lib` lane
//! executes it, so an assembly divergence between native and wasm32 fails a
//! unit test there. But the Q5 **bit-match** lane
//! (`crates/wasm-bitmatch`, `scripts/wasm-bitmatch.sh`) compares committed
//! vector *files* byte-for-byte between the two targets, and a Rust constant is
//! not a file: the assembly's derived values — per-file `fine_root`, unit
//! ranges and work-global ids, `size`, descriptor fields — sat outside that
//! lane entirely. This kind puts them in it.
//!
//! G15's `fine-tree` vectors pin the tree primitives; this pins the
//! **composition above them**: which bytes become leaves, how many there are,
//! which unit owns which range, and which units a `fine_root` covers at all.
//!
//! # What the document pins
//!
//! Per case (one *work*), and recomputed as one value:
//!
//! - **per file** — the descriptor as recorded (`kind`, `fine_tree_present`,
//!   `fine_tree_domain`, `unicode_version`), the raw and domain lengths, the
//!   canonical rendition's bytes, the synthetic `s_root` the model was handed,
//!   and the `fine_root` it derived;
//! - **per unit** — the work-global `unit_id`, its file, its kind, its byte
//!   range and `true_length`, whether a `fine_root` covers it, whether it
//!   therefore carries a `unit_commit`, and its bytes.
//!
//! # Deliberately absent: range proofs
//!
//! No cover seed, boundary node or proof byte is pinned here. Openings are
//! *executed* (see [`check_case_behaviour`]) but never committed, so this
//! document is independent of the `cover_entry` wire encoding — which decision
//! **D83** may still change (a leaf-level cover payload becoming 16 bytes
//! rather than 32). G15's `fine-tree` vectors own proof bytes and move with
//! that decision; these do not.
//!
//! # How it is checked
//!
//! [`build_expect`] recomputes the entire `expect` object from `inputs` through
//! [`assemble_content_model`] and the model's public accessors, and the
//! document is compared as a whole — a missing, extra or reordered entry fails
//! as loudly as a wrong byte. On top of that, [`execute`] runs the assertions a
//! value comparison cannot express:
//!
//! 1. **The G14 tie** — the case named [`GOLDEN_CASE`] must carry exactly
//!    [`golden_inputs`]' bytes and flags, and must recompute to exactly
//!    [`golden_model`]'s rendering. The committed file and the Rust fixture
//!    therefore cannot drift apart in either direction.
//! 2. **The nine-invariant oracle** — [`model_invariant_violations`] must be
//!    empty for every case.
//! 3. **Every covered unit really opens** — each is proved through
//!    [`prove_unit`] and verified against the file's own `fine_root`, so
//!    "covered" is demonstrated rather than declared.
//! 4. **The verifier's recompute agrees** — every text file's canonical bytes
//!    are re-derived through the *descriptor-recorded version string* on the
//!    verifier's own total entry point, which is the check MVP-SPEC.md line 121
//!    performs against a revealed raw mirror.
//! 5. **Shape coverage**, asserted structurally rather than by case name: both
//!    [`FileKind`]s, both [`UnitKind`]s, both `fine_root` presence states, a
//!    multi-unit split, an empty file, and a file whose raw and canonical
//!    renditions differ.
//!
//! # No independent generator, and why
//!
//! Unlike G15's kind there is no `gen_vectors.py`. A second implementation of
//! *this* document would have to reimplement NFC under a pinned Unicode
//! version, the D21 canonicalization pipeline, D22's split, D23's mirror rule
//! and the whole GGM/Merkle tree — i.e. the product. What stands behind the
//! values instead is decomposition: the tree layer is cross-checked against
//! Python by `fine-tree/gen_vectors.py`, the canonicalization layer by G3's
//! UTF-8 corpus, and what this kind adds — the composition — is checked by
//! whole-document regeneration, by the tie to G14's independently written
//! constants, and by the native↔WASM byte comparison.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::canon::{UnicodeVersionError, canonicalize_v_forced};
use crate::content::fixtures::{
    SYNTHETIC_FINE_SEED_LABEL, SYNTHETIC_FINE_SEEDS, golden_inputs, golden_model,
    model_invariant_violations,
};
use crate::content::{
    ContentModel, CoveredUnit, FileFlags, FileInput, FileKind, FineSeedSource, SplitMode, UnitKind,
    assemble_content_model, prove_unit, requires_unit_commit,
};
use crate::crypto::hkdf::FileId;

use super::vectors::{RECOMPUTED_DIGEST_DOMAIN, VectorError, VectorSummary, decode_hex, hex};
use super::vectors_fine_tree::first_difference;

/// The registered kind name.
pub const KIND: &str = "content-model";

/// Name of the case that **is** G14's golden fixture. The executor requires it
/// to exist and to agree with [`golden_inputs`]/[`golden_model`] exactly; that
/// requirement is this kind's whole reason for existing, so it is a constant
/// rather than a convention.
pub const GOLDEN_CASE: &str = "golden-four-file-work";

/// Name of the second case: a `--force-text` file that is **not** valid UTF-8.
pub const FORCED_TEXT_CASE: &str = "force-text-invalid-utf8";

/// The `--force-text` case's single file (see [`FORCED_TEXT_CASE`]).
///
/// Chosen to land three D20/D21 corners at the model layer at once:
///
/// - `EF BB` is a **truncated** BOM — lossy decoding yields one U+FFFD
///   (Unicode §3.9 maximal subparts), and U+FFFD is *not* U+FEFF, so stage 2
///   must not strip it;
/// - `FF FE` mid-stream are two bytes that can never begin a UTF-8 sequence,
///   so they become two separate U+FFFDs rather than one;
/// - both line endings are `CR LF`, so raw and canonical differ for a second,
///   independent reason and the file needs a raw mirror (D23).
///
/// The file is therefore text **only** because `--force-text` says so
/// (MVP-SPEC.md line 83), which is the branch G14's four golden files leave
/// untouched.
pub const FORCED_TEXT_RAW: &[u8] = b"\xEF\xBBhead\r\n\xFF\xFEtail\r\n";

fn payload_err(problem: String) -> VectorError {
    VectorError::Payload {
        kind: KIND,
        problem,
    }
}

fn check_err(check: &'static str, problem: String) -> VectorError {
    VectorError::Check {
        kind: KIND,
        check,
        problem,
    }
}

// ---------------------------------------------------------------------------
// payload types
// ---------------------------------------------------------------------------

/// Everything needed to recompute the expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    /// The documented fixed test seed (hex) the synthetic `s_root` supplier
    /// derives from.
    w: String,
    /// The supplier's domain label (see [`SYNTHETIC_FINE_SEED_LABEL`]).
    fine_seed_label: String,
    /// The cases, each one whole *work*.
    cases: Vec<CaseInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseInput {
    name: String,
    /// One sentence saying what this case discharges.
    pins: String,
    /// The work's files, in file-table order — `file_id` is the position.
    files: Vec<FileInputSpec>,
}

/// One file as `--seal` would receive it: bytes plus the flags the CLI sets.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileInputSpec {
    /// The file's raw bytes, hex.
    raw: String,
    /// `--force-text`.
    force_text: bool,
    /// `--split`: `"none"` or `"blank-lines"`.
    split: String,
    /// Whether a `--no-fine-tree` glob matched.
    no_fine_tree: bool,
}

impl FileInputSpec {
    /// The flags this spec names.
    fn flags(&self) -> Result<FileFlags, VectorError> {
        let mut flags = FileFlags::new();
        if self.force_text {
            flags = flags.with_force_text();
        }
        match self.split.as_str() {
            "none" => {}
            "blank-lines" => flags = flags.with_split(SplitMode::BlankLines),
            other => {
                return Err(payload_err(format!(
                    "files[].split must be `none` or `blank-lines`, found `{other}`"
                )));
            }
        }
        if self.no_fine_tree {
            flags = flags.with_no_fine_tree();
        }
        Ok(flags)
    }

    /// Render a [`FileInput`] back to its spec — the direction the emitter and
    /// the G14 tie both need.
    fn of(input: &FileInput<'_>) -> serde_json::Value {
        let flags = input.flags();
        serde_json::json!({
            "raw": hex(input.raw()),
            "force_text": flags.force_text(),
            "split": match flags.split() {
                None => "none",
                Some(SplitMode::BlankLines) => "blank-lines",
            },
            "no_fine_tree": flags.no_fine_tree_matched(),
        })
    }
}

/// One case's decoded files, owned so the borrowed [`FileInput`]s can point
/// into them.
struct DecodedCase {
    raws: Vec<Vec<u8>>,
    flags: Vec<FileFlags>,
}

impl DecodedCase {
    fn of(case: &CaseInput) -> Result<Self, VectorError> {
        let mut raws = Vec::with_capacity(case.files.len());
        let mut flags = Vec::with_capacity(case.files.len());
        for spec in &case.files {
            raws.push(decode_hex(KIND, "cases[].files[].raw", &spec.raw)?);
            flags.push(spec.flags()?);
        }
        Ok(Self { raws, flags })
    }

    /// The borrowed inputs `assemble_content_model` takes.
    fn inputs(&self) -> Vec<FileInput<'_>> {
        self.raws
            .iter()
            .zip(&self.flags)
            .map(|(raw, flags)| FileInput::new(raw, *flags))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// executor
// ---------------------------------------------------------------------------

/// Execute a `content-model` vector (module docs).
///
/// `inputs`/`expect` arrive from the shared envelope, whose fields (schema,
/// version, NON-SECRET marker, format-version placement) the caller has
/// already checked.
///
/// # Errors
///
/// Every [`VectorError`] class: a malformed payload, a recomputation that
/// disagrees with the committed document, or a behavioural assertion the
/// committed values cannot express.
pub fn execute(
    inputs: serde_json::Value,
    expect: serde_json::Value,
    description: String,
) -> Result<VectorSummary, VectorError> {
    let parsed: Inputs =
        serde_json::from_value(inputs).map_err(|e| payload_err(format!("inputs: {e}")))?;

    // Fixture discipline: the document must derive from the documented seed
    // through the documented, clearly test-only supplier.
    let w_bytes = decode_hex(KIND, "inputs.w", &parsed.w)?;
    let w_array: [u8; 32] = w_bytes
        .try_into()
        .map_err(|_| check_err("w-length", "inputs.w must be exactly 32 bytes".to_owned()))?;
    if w_array != super::TEST_MASTER_SECRET_W {
        return Err(check_err(
            "w-is-documented-test-seed",
            "inputs.w is not the documented fixed test seed 0x00..0x1f (testdata/README.md)"
                .to_owned(),
        ));
    }
    let expected_label = String::from_utf8_lossy(SYNTHETIC_FINE_SEED_LABEL).into_owned();
    if parsed.fine_seed_label != expected_label {
        return Err(check_err(
            "fine-seed-label",
            format!(
                "inputs.fine_seed_label is `{}`, the documented supplier label is `{expected_label}`",
                parsed.fine_seed_label
            ),
        ));
    }
    for case in &parsed.cases {
        if case.pins.trim().is_empty() {
            return Err(check_err(
                "case-pins",
                format!("case `{}` states no `pins` sentence", case.name),
            ));
        }
    }

    // 1. The whole `expect` object, recomputed and compared as one value.
    let recomputed = build_expect(&parsed)?;
    if recomputed != expect {
        return Err(check_err(
            "document",
            first_difference("expect", &recomputed, &expect),
        ));
    }

    // 2. The G14 tie: the golden case IS the Rust fixture, both ways round.
    check_golden_case_tie(&parsed)?;

    // 3. The assertions a value comparison cannot express.
    for case in &parsed.cases {
        let decoded = DecodedCase::of(case)?;
        let model = assemble_content_model(&decoded.inputs(), &SYNTHETIC_FINE_SEEDS);
        check_case_behaviour(&case.name, &model)?;
    }
    check_shape_coverage(&parsed)?;

    // 4. Q5 bit-match: SHA-256 over the serialization of every recomputed
    //    artifact. Serializing the recomputed value (rather than hand-feeding
    //    fields) means a future field is covered the moment it is added.
    let serialized = serde_json::to_vec(&recomputed)
        .map_err(|e| check_err("digest-serialization", e.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(RECOMPUTED_DIGEST_DOMAIN);
    digest.update(KIND.as_bytes());
    digest.update([0x00]);
    digest.update(super::vectors::prefix_len(serialized.len()));
    digest.update(&serialized);

    Ok(VectorSummary {
        kind: KIND,
        description,
        items: parsed.cases.len(),
        recomputed_digest: digest.finalize().into(),
    })
}

/// Recompute the entire `expect` object from `inputs`, through the public
/// assembly entry point and the model's accessors.
///
/// Also the **regenerator**: `tests/content_model_vectors.rs` calls it via
/// [`regenerate_expect`] and diffs the result against the committed file.
///
/// # Errors
///
/// [`VectorError::Payload`] for a malformed case (bad hex, an unknown split
/// mode).
fn build_expect(inputs: &Inputs) -> Result<serde_json::Value, VectorError> {
    let mut cases = Vec::with_capacity(inputs.cases.len());
    for case in &inputs.cases {
        let decoded = DecodedCase::of(case)?;
        let model = assemble_content_model(&decoded.inputs(), &SYNTHETIC_FINE_SEEDS);
        let mut rendered = render_model(&model);
        if let Some(object) = rendered.as_object_mut() {
            object.insert("name".to_owned(), serde_json::json!(case.name));
        }
        cases.push(rendered);
    }
    Ok(serde_json::json!({ "cases": cases }))
}

/// Regenerate the whole `expect` object from a committed document's `inputs`,
/// so a regenerator can diff it against the file.
///
/// # Errors
///
/// As [`build_expect`], plus [`VectorError::Envelope`] when the supplied
/// document is not a `content-model` vector at all.
pub fn regenerate_expect(document: &serde_json::Value) -> Result<serde_json::Value, VectorError> {
    let kind = document.get("kind").and_then(serde_json::Value::as_str);
    if kind != Some(KIND) {
        return Err(VectorError::Envelope(format!(
            "not a `{KIND}` vector (kind is {kind:?})"
        )));
    }
    let inputs = document
        .get("inputs")
        .ok_or_else(|| VectorError::Envelope("document has no `inputs`".to_owned()))?;
    let parsed: Inputs =
        serde_json::from_value(inputs.clone()).map_err(|e| payload_err(format!("inputs: {e}")))?;
    build_expect(&parsed)
}

/// The `inputs` object the emitter writes: the documented seed and supplier
/// label, then one case per entry of [`case_specs`].
///
/// Generation-time only — every check reads the committed file's own copy.
#[must_use]
pub fn build_inputs() -> serde_json::Value {
    let cases: Vec<serde_json::Value> = case_specs()
        .into_iter()
        .map(|(name, pins, files)| {
            serde_json::json!({
                "name": name,
                "pins": pins,
                "files": files.iter().map(FileInputSpec::of).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::json!({
        "w": hex(&super::TEST_MASTER_SECRET_W),
        "fine_seed_label": String::from_utf8_lossy(SYNTHETIC_FINE_SEED_LABEL),
        "cases": cases,
    })
}

/// The committed cases, in file order: name, the sentence it discharges, and
/// the files it seals.
fn case_specs() -> Vec<(&'static str, &'static str, Vec<FileInput<'static>>)> {
    vec![
        (
            GOLDEN_CASE,
            "G14's golden end-to-end work, byte-identical to `content::fixtures::golden_inputs()`: \
             CRLF text under --split blank-lines with a raw mirror, a binary file, a --no-fine-tree \
             file and an empty file — both FileKinds, both UnitKinds, both fine_root presence \
             states, and the work-global unit_id counter running across four files without \
             restarting (MVP-SPEC.md lines 76, 78, 83, 85, 92, 94, 98)",
            golden_inputs().to_vec(),
        ),
        (
            FORCED_TEXT_CASE,
            "the --force-text branch G14's four files leave untouched: a file that is NOT valid \
             UTF-8 is sealed as text, so its canonical rendition is D20's lossy U+FFFD transform \
             (truncated BOM and lone continuation bytes alike) and its raw mirror is the only \
             carrier of the original bytes (MVP-SPEC.md lines 83, 92, 121)",
            vec![FileInput::new(
                FORCED_TEXT_RAW,
                FileFlags::new().with_force_text(),
            )],
        ),
    ]
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

/// The stable wire spelling of a [`UnitKind`] — deliberately not `Debug`, so
/// renaming a Rust variant cannot silently move committed bytes.
const fn unit_kind_name(kind: UnitKind) -> &'static str {
    match kind {
        UnitKind::Normal => "normal",
        UnitKind::RawMirror => "raw-mirror",
    }
}

/// One assembled model, rendered as the value the document commits.
fn render_model(model: &ContentModel<'_>) -> serde_json::Value {
    let files: Vec<serde_json::Value> = model
        .files()
        .iter()
        .map(|file| {
            let descriptor = file.descriptor();
            // The seed the model was handed — requested only where a tree
            // exists, so a tree-less file pins `null` rather than a value the
            // assembly never used.
            let s_root = descriptor.fine_tree_present().then(|| {
                hex(SYNTHETIC_FINE_SEEDS
                    .fine_seed(FileId(file.file_id()))
                    .as_bytes())
            });
            serde_json::json!({
                "file_id": file.file_id(),
                "kind": descriptor.kind().to_string(),
                "raw_len": u64::try_from(file.raw().len()).unwrap_or(u64::MAX),
                "size": file.size(),
                "fine_tree_present": descriptor.fine_tree_present(),
                "fine_tree_domain": descriptor.fine_tree_domain().map(|d| d.to_string()),
                "unicode_version": descriptor.unicode_version(),
                "canonical": file.canonical().map(|c| hex(c.as_bytes())),
                "s_root": s_root,
                "fine_root": file.fine_root().map(|root| hex(root.as_bytes())),
                "unit_ids": model
                    .units_of(file.file_id())
                    .iter()
                    .map(|unit| unit.unit_id())
                    .collect::<Vec<_>>(),
            })
        })
        .collect();

    let units: Vec<serde_json::Value> = model
        .units()
        .iter()
        .map(|unit| {
            let descriptor = model
                .file(unit.file_id())
                .map(|file| file.descriptor())
                .expect("every unit belongs to a file of the same model");
            serde_json::json!({
                "unit_id": unit.unit_id(),
                "file_id": unit.file_id(),
                "kind": unit_kind_name(unit.kind()),
                "start": unit.byte_range().start(),
                "length": unit.byte_range().length(),
                "true_length": unit.true_length(),
                "covered": model.is_covered(unit),
                "unit_commit_required": requires_unit_commit(unit, descriptor),
                "bytes": hex(model.unit_bytes(unit).unwrap_or_default()),
            })
        })
        .collect();

    serde_json::json!({
        "file_count": files.len(),
        "unit_count": units.len(),
        "files": files,
        "units": units,
    })
}

// ---------------------------------------------------------------------------
// the assertions a value comparison cannot express
// ---------------------------------------------------------------------------

/// **The G14 tie.** The case named [`GOLDEN_CASE`] must carry exactly
/// [`golden_inputs`]' bytes and flags, and must recompute to exactly
/// [`golden_model`]'s rendering.
///
/// Both directions matter, and this is the whole point of the kind: without
/// the input comparison the file could pin a *different* work and still be
/// self-consistent; without the output comparison the Rust fixture could
/// change meaning while the file kept the old values.
fn check_golden_case_tie(inputs: &Inputs) -> Result<(), VectorError> {
    let case = inputs
        .cases
        .iter()
        .find(|case| case.name == GOLDEN_CASE)
        .ok_or_else(|| {
            check_err(
                "golden-case-present",
                format!("no case named `{GOLDEN_CASE}` — this kind exists to pin G14's fixture"),
            )
        })?;

    let committed: Vec<serde_json::Value> = case
        .files
        .iter()
        .map(|spec| {
            serde_json::json!({
                "raw": spec.raw,
                "force_text": spec.force_text,
                "split": spec.split,
                "no_fine_tree": spec.no_fine_tree,
            })
        })
        .collect();
    let fixture: Vec<serde_json::Value> = golden_inputs().iter().map(FileInputSpec::of).collect();
    if committed != fixture {
        let (a, b) = (
            serde_json::Value::Array(fixture),
            serde_json::Value::Array(committed),
        );
        return Err(check_err(
            "golden-case-inputs",
            format!(
                "the `{GOLDEN_CASE}` case is no longer `content::fixtures::golden_inputs()`: {}",
                first_difference("inputs.cases[golden].files", &a, &b)
            ),
        ));
    }

    let decoded = DecodedCase::of(case)?;
    let from_file = render_model(&assemble_content_model(
        &decoded.inputs(),
        &SYNTHETIC_FINE_SEEDS,
    ));
    let from_fixture = render_model(&golden_model());
    if from_file != from_fixture {
        return Err(check_err(
            "golden-case-model",
            first_difference("golden_model()", &from_fixture, &from_file),
        ));
    }
    Ok(())
}

/// Per-case behaviour: the nine-invariant oracle, every covered unit actually
/// opening against its file's committed `fine_root`, and the verifier's own
/// canonicalization recompute agreeing with the model's rendition.
fn check_case_behaviour(name: &str, model: &ContentModel<'_>) -> Result<(), VectorError> {
    let violations = model_invariant_violations(model);
    if !violations.is_empty() {
        return Err(check_err(
            "model-invariants",
            format!("case `{name}`: {}", violations.join("; ")),
        ));
    }

    for file in model.files() {
        let descriptor = file.descriptor();

        // (a) The verifier's recompute (MVP-SPEC.md line 121, D20): the
        //     canonical rendition must be reproducible from the raw bytes
        //     through the DESCRIPTOR-RECORDED version string — never
        //     `UnicodeVersion::CURRENT`, which is the substitution an aging
        //     honest bundle would be false-positived by.
        if let Some(canonical) = file.canonical() {
            let version = descriptor.unicode_version().ok_or_else(|| {
                check_err(
                    "text-file-records-a-version",
                    format!(
                        "case `{name}`: file {} is text with no version",
                        file.file_id()
                    ),
                )
            })?;
            let recomputed = recompute_canonical(version, file.raw()).map_err(|e| {
                check_err(
                    "verifier-recompute",
                    format!("case `{name}`: file {}: {e}", file.file_id()),
                )
            })?;
            if recomputed != canonical.as_bytes() {
                return Err(check_err(
                    "verifier-recompute",
                    format!(
                        "case `{name}`: file {}: canonicalize_v(raw) != canonical — \
                         MVP-SPEC.md line 121 would fail on this file's raw mirror",
                        file.file_id()
                    ),
                ));
            }
        }

        // (b) Every covered unit really opens against the model's own
        //     `fine_root` — "covered" demonstrated, not declared. Proof BYTES
        //     are never pinned (module docs: D83 independence).
        let Some(fine_root) = file.fine_root() else {
            continue;
        };
        let domain = file.domain_bytes();
        for unit in model.units_of(file.file_id()) {
            let Some(covered) = CoveredUnit::of(unit, descriptor) else {
                continue;
            };
            let proof = prove_unit(
                &SYNTHETIC_FINE_SEEDS.fine_seed(FileId(file.file_id())),
                domain,
                covered,
                file.size(),
            )
            .map_err(|e| {
                check_err(
                    "covered-unit-opens",
                    format!(
                        "case `{name}`: unit {} could not be proved: {e}",
                        unit.unit_id()
                    ),
                )
            })?;
            let revealed = model.unit_bytes(unit).ok_or_else(|| {
                check_err(
                    "covered-unit-opens",
                    format!(
                        "case `{name}`: unit {}'s bytes are unresolvable",
                        unit.unit_id()
                    ),
                )
            })?;
            proof.verify(revealed, fine_root).map_err(|e| {
                check_err(
                    "covered-unit-opens",
                    format!(
                        "case `{name}`: unit {} does not open against its file's fine_root: {e}",
                        unit.unit_id()
                    ),
                )
            })?;
        }
    }
    Ok(())
}

/// The verifier-side canonicalization recompute, reached the way R4 reaches
/// it: by the descriptor-recorded **version string**, through the narrowed
/// total entry point (G22), whose error type cannot express an invalid-UTF-8
/// failure at all.
fn recompute_canonical(version: &str, raw: &[u8]) -> Result<Vec<u8>, UnicodeVersionError> {
    canonicalize_v_forced(version, raw).map(|canonical| canonical.as_bytes().to_vec())
}

/// Shape coverage, asserted **structurally** — over what the committed cases
/// actually contain, never over their names. A renamed case keeps passing; a
/// case set that quietly stops covering a branch does not.
fn check_shape_coverage(inputs: &Inputs) -> Result<(), VectorError> {
    let mut kinds: Vec<FileKind> = Vec::new();
    let mut unit_kinds: Vec<UnitKind> = Vec::new();
    let mut with_tree = false;
    let mut without_tree = false;
    let mut multi_unit = false;
    let mut empty_file = false;
    let mut raw_differs = false;
    let mut forced_text = false;

    for case in &inputs.cases {
        let decoded = DecodedCase::of(case)?;
        let model = assemble_content_model(&decoded.inputs(), &SYNTHETIC_FINE_SEEDS);
        for file in model.files() {
            let kind = file.descriptor().kind();
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }
            if file.fine_root().is_some() {
                with_tree = true;
            } else {
                without_tree = true;
            }
            if file.size() == 0 && file.raw().is_empty() {
                empty_file = true;
            }
            if file
                .canonical()
                .is_some_and(|canonical| canonical.as_bytes() != file.raw())
            {
                raw_differs = true;
            }
            if kind == FileKind::Text && !crate::canon::is_text(file.raw()) {
                forced_text = true;
            }
            let normal = model
                .units_of(file.file_id())
                .iter()
                .filter(|unit| unit.kind() == UnitKind::Normal)
                .count();
            if normal > 1 {
                multi_unit = true;
            }
        }
        for unit in model.units() {
            if !unit_kinds.contains(&unit.kind()) {
                unit_kinds.push(unit.kind());
            }
        }
    }

    let missing: Vec<&str> = [
        (kinds.len() == FileKind::ALL.len(), "both FileKinds"),
        (unit_kinds.len() == UnitKind::ALL.len(), "both UnitKinds"),
        (with_tree, "a file with a fine_root"),
        (without_tree, "a file without a fine_root"),
        (multi_unit, "a multi-unit (--split) file"),
        (empty_file, "an empty file"),
        (raw_differs, "a text file whose raw != canonical"),
        (forced_text, "a --force-text file that is not valid UTF-8"),
    ]
    .into_iter()
    .filter_map(|(present, what)| (!present).then_some(what))
    .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(check_err(
            "shape-coverage",
            format!("the case set no longer covers: {}", missing.join(", ")),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `--force-text` fixture really does exercise the branch it claims:
    /// its bytes fail strict detection, so it reaches the manifest as text
    /// only because the flag says so.
    #[test]
    fn forced_text_fixture_is_not_valid_utf8() {
        assert!(!crate::canon::is_text(FORCED_TEXT_RAW));
    }

    /// Lossy decoding of the fixture is the D20 corner it is chosen for: the
    /// truncated BOM becomes ONE U+FFFD which stage 2 must not strip, and the
    /// two mid-stream bytes become two more.
    #[test]
    fn forced_text_fixture_canonicalizes_to_the_documented_replacements() {
        let model = assemble_content_model(
            &[FileInput::new(
                FORCED_TEXT_RAW,
                FileFlags::new().with_force_text(),
            )],
            &SYNTHETIC_FINE_SEEDS,
        );
        let file = model.file(0).expect("one file");
        let canonical = file.canonical().expect("forced text has a rendition");
        assert_eq!(canonical.as_str(), "\u{FFFD}head\n\u{FFFD}\u{FFFD}tail\n");
        assert_eq!(
            model.units_of(0).len(),
            2,
            "raw != canonical, so the file needs a mirror (D23)"
        );
    }

    /// The wire spellings are a contract: a Rust variant rename must not move
    /// committed bytes.
    #[test]
    fn unit_kind_names_are_stable_and_distinct() {
        assert_eq!(unit_kind_name(UnitKind::Normal), "normal");
        assert_eq!(unit_kind_name(UnitKind::RawMirror), "raw-mirror");
    }

    /// `build_inputs` regenerates to something the executor accepts end to
    /// end — the emitter and the executor cannot drift apart.
    #[test]
    fn build_inputs_round_trips_through_the_executor() {
        let inputs = build_inputs();
        let document = serde_json::json!({ "kind": KIND, "inputs": inputs.clone() });
        let expect = regenerate_expect(&document).expect("regeneration");
        let summary = execute(inputs, expect, "round-trip".to_owned()).expect("execution");
        assert_eq!(summary.kind, KIND);
        assert_eq!(summary.items, 2);
    }

    /// The G14 tie is **able to fail**: a case that renames itself away from
    /// the golden name, and one whose bytes drift from the fixture, are both
    /// rejected.
    #[test]
    fn the_golden_tie_rejects_a_drifted_fixture() {
        let mut inputs = build_inputs();
        let cases = inputs
            .get_mut("cases")
            .and_then(serde_json::Value::as_array_mut)
            .expect("cases");
        // Drift one byte of the golden work's first file.
        let raw = cases[0]["files"][0]["raw"]
            .as_str()
            .expect("hex")
            .to_owned();
        let mutated = format!("ff{}", &raw[2..]);
        cases[0]["files"][0]["raw"] = serde_json::json!(mutated);

        let document = serde_json::json!({ "kind": KIND, "inputs": inputs.clone() });
        // The document still regenerates (the expectations follow the inputs)
        // — it is the TIE that must catch this, not the value comparison.
        let expect = regenerate_expect(&document).expect("regeneration");
        let error = execute(inputs, expect, "drift".to_owned())
            .expect_err("a drifted golden case must be refused");
        assert!(error.to_string().contains("golden-case-inputs"), "{error}");
    }

    /// Coverage is asserted over content, not names: dropping the case that
    /// carries the `--force-text` branch is refused even though the remaining
    /// document is entirely self-consistent.
    #[test]
    fn shape_coverage_is_able_to_fail() {
        let mut inputs = build_inputs();
        inputs
            .get_mut("cases")
            .and_then(serde_json::Value::as_array_mut)
            .expect("cases")
            .truncate(1);
        let document = serde_json::json!({ "kind": KIND, "inputs": inputs.clone() });
        let expect = regenerate_expect(&document).expect("regeneration");
        let error = execute(inputs, expect, "narrowed".to_owned())
            .expect_err("a case set that stops covering a branch must be refused");
        assert!(error.to_string().contains("shape-coverage"), "{error}");
    }

    /// The regenerator refuses a document of another kind rather than
    /// silently producing something.
    #[test]
    fn regenerator_rejects_a_foreign_document() {
        let foreign = serde_json::json!({"kind": "fine-tree", "inputs": {}});
        let error =
            regenerate_expect(&foreign).expect_err("a foreign document must not regenerate");
        assert!(error.to_string().contains(KIND), "{error}");
    }

    /// The kind pins **no** proof bytes, so decision D83's cover-encoding
    /// change cannot move this document. Asserted mechanically rather than by
    /// comment: no rendered field name mentions a cover or a boundary.
    #[test]
    fn the_document_pins_no_proof_bytes() {
        let document = serde_json::json!({ "kind": KIND, "inputs": build_inputs() });
        let expect = regenerate_expect(&document).expect("regeneration");
        let text = serde_json::to_string(&expect).expect("serialize");
        for banned in [
            "\"cover\"",
            "\"boundary\"",
            "\"seeds\"",
            "\"leaf_count\"",
            "\"depth\"",
        ] {
            assert!(
                !text.contains(banned),
                "{banned} appears in the document — proof material must stay out (D83)"
            );
        }
        // The positive control: `covered` (a model fact) is present, so the
        // scan above is looking at a document that has something to find.
        assert!(text.contains("\"covered\""));
    }
}
