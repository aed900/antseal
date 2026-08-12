//! Golden-vector kind **`report`** (task R9): canonical bundles mapped to
//! the **expected serialized [`VerificationReport`]**, for every M0 shape.
//!
//! Spec basis: the M0 milestone's shape list (MVP-SPEC.md line 153), and
//! Verification's two standing obligations — golden vectors (line 167) and
//! *"the WASM build must bit-match native verification"* (line 169). The byte
//! format the vectors pin is frozen by
//! `docs/decisions/D29-report-byte-format.md`; determinism and
//! first-failure-wins by `docs/decisions/D27-verify-error-mode.md`.
//!
//! # What one case is
//!
//! A case names an R6 shape — `shapes::catalogue()`'s stable handle, e.g.
//! `unbalanced-n6/unit-1` — and pins, for the bundle that shape builds:
//!
//! | field | pins |
//! | --- | --- |
//! | `bundle_len` / `bundle_sha256` | the **input**: R6's constructor bytes, so an upstream change to what a shape means is a loud vector event and never a silent input swap |
//! | `revealed_unit_ids` | which work-global units the reveal shows |
//! | `report_len` / `report_json` | the **output**, byte-exact: lowercase hex of `to_canonical_json()`, which is the D29 encoding and the native↔WASM bit-match medium |
//! | `report` | the same bytes decoded, as an object — the review surface |
//!
//! `report` and `report_json` cannot drift: the executor decodes the hex and
//! requires the two to agree. Only `report_json` pins **field order** (a JSON
//! object compares order-insensitively, and D29 rule 1 makes declaration order
//! the wire order), so the hex is the authority and the object is the reader's
//! copy.
//!
//! # Why the bundle is named, not embedded
//!
//! R6's constructor is `test-vectors`-gated precisely so the wasm32 lane can
//! build bundles **in-process**. Naming the shape therefore costs the vector
//! nothing in coverage — both lanes construct the identical bytes, and
//! `bundle_sha256` proves they did — while keeping the committed document
//! reviewable rather than a hundred kilobytes of ciphertext hex, and keeping
//! exactly one definition of "a valid bundle" in the tree.
//!
//! # How it is checked
//!
//! [`build_expect`] recomputes the *entire* `expect` object from `inputs` and
//! the document is compared as one value, so a missing, extra, or reordered
//! case fails as loudly as a wrong byte. On top of that, [`execute`] runs the
//! assertions a value comparison cannot state:
//!
//! 1. **M0 shape coverage** — every shape [`REQUIRED_SHAPES`] enumerates must
//!    appear, so the milestone's checklist cannot quietly lose a row.
//! 2. **Structural coverage** — some case's report must carry an *empty*
//!    anchor list (the UNANCHORED bundle, MVP-SPEC.md line 153) and some other
//!    case's a populated one; and some case must render an unrevealed file as
//!    a committed placeholder (line 121).
//! 3. **Every report is a pass, with its own unit count** — `evidence.passed`
//!    holds and `units_verified` equals the number of units the bundle
//!    actually revealed, so a vector cannot pin a report that describes some
//!    other reveal.
//! 4. **Serialization is deterministic** — the report is serialized twice and
//!    the bytes must be identical (D27/D29).
//! 5. **The report leaks nothing** — no `W`, `k_u`, `unit_salt`, `path_salt`,
//!    `file_salt` or `s_root` of any file or unit of the work appears anywhere
//!    in the report bytes (project rule 6; the secret-material policy in
//!    [`crate::verify::report`]). A report legitimately discloses what its
//!    bundle discloses and no more.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::crypto::hkdf::{
    FileId, UnitId, derive_file_salt, derive_fine_seed, derive_path_salt, derive_unit_key,
    derive_unit_salt,
};
use crate::crypto::material::MasterSecretRef;
use crate::verify::report::REPORT_VERSION;
use crate::verify::{VerificationReport, VerifyOptions, verify_bundle};

use super::TEST_MASTER_SECRET_W;
use super::bundle_fixtures::{
    BuiltFixture, DEFAULT_SEED, FIXTURE_APP_VERSION, FIXTURE_SEAL_ID, build, shapes,
};
use super::vectors::{
    RECOMPUTED_DIGEST_DOMAIN, VectorError, VectorSummary, decode_hex, first_difference, hex,
};

/// The registered kind name.
pub const KIND: &str = "report";

/// The M0 shapes this kind **must** cover (MVP-SPEC.md line 153; tasks/R.md
/// R9), each paired with the milestone row it discharges.
///
/// A committed document missing one of these fails execution — on wasm32 as
/// well as natively, so the coverage claim is not a native-only courtesy.
pub const REQUIRED_SHAPES: &[(&str, &str)] = &[
    ("single-text-with-mirror/full-no-mirror", "full text reveal"),
    (
        "split-multi-unit/partial",
        "partial reveal with leaf-exact covers",
    ),
    (
        "unbalanced-n6/unit-0",
        "per-unit reveal at unbalanced n = 6 (leaves 0,1)",
    ),
    (
        "unbalanced-n6/unit-1",
        "per-unit reveal at unbalanced n = 6 (leaves 2,3)",
    ),
    (
        "unbalanced-n6/unit-2",
        "per-unit reveal at unbalanced n = 6 (leaves 4,5)",
    ),
    ("single-binary/full", "binary file"),
    ("no-fine-tree/full", "--no-fine-tree file"),
    ("single-text-with-mirror/full", "raw-mirror full reveal"),
    ("empty-file/full", "empty file"),
    ("one-byte-file/full", "one-byte file"),
    (
        "multi-file/mixed",
        "multi-file with an unrevealed committed-placeholder file",
    ),
];

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
    /// The documented fixed test seed (hex).
    w: String,
    /// The fixture `seal_id` every R6 bundle records (hex).
    seal_id: String,
    /// R6's [`DEFAULT_SEED`], as a `0x`-prefixed 16-digit LE64 value — the
    /// seed the AEAD nonces, and hence the bundle bytes, come from.
    seed: String,
    /// The fixed `app_version` R6 records, pinned so a crate-version bump can
    /// never silently move a committed report byte.
    app_version: String,
    /// The cases, each naming an R6 shape.
    cases: Vec<CaseInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseInput {
    /// The `shapes::catalogue()` handle this case builds.
    shape: String,
    /// One sentence: which M0 row this case discharges.
    pins: String,
}

/// What executing one case produced, kept so the behavioural assertions reuse
/// the (comparatively expensive) build + verify rather than repeating it.
struct CaseArtifacts {
    shape: String,
    built: BuiltFixture,
    report: VerificationReport,
    /// `report.to_canonical_json()` — the bytes the vector pins.
    canonical: Vec<u8>,
}

// ---------------------------------------------------------------------------
// executor
// ---------------------------------------------------------------------------

/// Execute a `report` vector (module docs).
///
/// `inputs`/`expect` arrive from the shared envelope, whose fields (schema,
/// version, NON-SECRET marker, format-version placement) the caller has
/// already checked.
///
/// # Errors
///
/// Every [`VectorError`] class: a malformed payload, a case naming a shape no
/// catalogue entry has, a recomputation that disagrees with the committed
/// document, or a behavioural assertion the committed values cannot express.
pub fn execute(
    inputs: serde_json::Value,
    expect: serde_json::Value,
    description: String,
) -> Result<VectorSummary, VectorError> {
    let parsed: Inputs =
        serde_json::from_value(inputs).map_err(|e| payload_err(format!("inputs: {e}")))?;
    check_fixture_inputs(&parsed)?;
    check_shape_coverage(&parsed)?;

    // 1. The whole `expect` object, recomputed and compared as one value.
    let (recomputed, artifacts) = build_expect(&parsed)?;
    if recomputed != expect {
        return Err(check_err(
            "document",
            first_difference("expect", &recomputed, &expect),
        ));
    }

    // 2. The assertions a value comparison cannot express.
    check_structural_coverage(&artifacts)?;
    for case in &artifacts {
        check_case_behaviour(case)?;
    }

    // 3. Q5 bit-match: SHA-256 over the serialization of every recomputed
    //    artifact — not a verdict, the bytes themselves. Serializing the
    //    recomputed value (rather than hand-feeding fields) means a future
    //    field is covered the moment it is added.
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
        items: artifacts.len(),
        recomputed_digest: digest.finalize().into(),
    })
}

/// Fixture discipline: the document must derive from the documented seed and
/// from R6's fixed constants, so a case's bytes are reproducible by anyone
/// reading the file rather than by whoever happened to generate it.
fn check_fixture_inputs(inputs: &Inputs) -> Result<(), VectorError> {
    let w_bytes = decode_hex(KIND, "inputs.w", &inputs.w)?;
    let w_array: [u8; 32] = w_bytes
        .try_into()
        .map_err(|_| check_err("w-length", "inputs.w must be exactly 32 bytes".to_owned()))?;
    if w_array != TEST_MASTER_SECRET_W {
        return Err(check_err(
            "w-is-documented-test-seed",
            "inputs.w is not the documented fixed test seed 0x00..0x1f (testdata/README.md)"
                .to_owned(),
        ));
    }
    let seal_id = decode_hex(KIND, "inputs.seal_id", &inputs.seal_id)?;
    if seal_id != FIXTURE_SEAL_ID {
        return Err(check_err(
            "seal-id",
            format!(
                "inputs.seal_id is `{}`, R6's fixture seal_id is `{}`",
                inputs.seal_id,
                hex(&FIXTURE_SEAL_ID)
            ),
        ));
    }
    let expected_seed = format!("0x{DEFAULT_SEED:016x}");
    if inputs.seed != expected_seed {
        return Err(check_err(
            "seed",
            format!(
                "inputs.seed is `{}`, R6's DEFAULT_SEED is `{expected_seed}`",
                inputs.seed
            ),
        ));
    }
    if inputs.app_version != FIXTURE_APP_VERSION {
        return Err(check_err(
            "app-version",
            format!(
                "inputs.app_version is `{}`, R6 records `{FIXTURE_APP_VERSION}`",
                inputs.app_version
            ),
        ));
    }
    Ok(())
}

/// Every M0 shape [`REQUIRED_SHAPES`] enumerates is present, every case names
/// a real catalogue entry, no shape appears twice, and every case says what it
/// pins.
fn check_shape_coverage(inputs: &Inputs) -> Result<(), VectorError> {
    if inputs.cases.is_empty() {
        return Err(check_err(
            "case-coverage",
            "a report vector with no cases pins nothing".to_owned(),
        ));
    }
    for (index, case) in inputs.cases.iter().enumerate() {
        if shapes::by_name(&case.shape).is_none() {
            return Err(check_err(
                "shape-registered",
                format!(
                    "cases[{index}]: `{}` is not a shapes::catalogue() handle",
                    case.shape
                ),
            ));
        }
        // Matches the INDEX.json `pins` rule: a one-word justification is no
        // justification.
        if case.pins.chars().count() < 12 {
            return Err(check_err(
                "case-pins",
                format!(
                    "cases[{index}] (`{}`): `pins` must state the M0 row this case discharges",
                    case.shape
                ),
            ));
        }
        if inputs.cases[..index].iter().any(|c| c.shape == case.shape) {
            return Err(check_err(
                "shape-unique",
                format!("shape `{}` appears more than once", case.shape),
            ));
        }
    }
    for (shape, row) in REQUIRED_SHAPES {
        if !inputs.cases.iter().any(|case| case.shape == *shape) {
            return Err(check_err(
                "m0-shape-coverage",
                format!("no case covers `{shape}` — the M0 shape \"{row}\" (MVP-SPEC.md line 153)"),
            ));
        }
    }
    Ok(())
}

/// The shapes whose *reports* must exhibit a structure the shape names alone
/// do not guarantee: the empty-anchor bundle, its populated counterpart, and a
/// committed placeholder.
fn check_structural_coverage(artifacts: &[CaseArtifacts]) -> Result<(), VectorError> {
    if !artifacts.iter().any(|case| case.report.anchors.is_empty()) {
        return Err(check_err(
            "empty-anchor-coverage",
            "no case yields an empty anchor list — the UNANCHORED bundle is an M0 \
             must-have (MVP-SPEC.md line 153)"
                .to_owned(),
        ));
    }
    if !artifacts.iter().any(|case| !case.report.anchors.is_empty()) {
        return Err(check_err(
            "populated-anchor-coverage",
            "no case yields a populated anchor list, so the empty one asserts nothing".to_owned(),
        ));
    }
    if !artifacts
        .iter()
        .any(|case| !case.report.reveal.unrevealed_files.is_empty())
    {
        return Err(check_err(
            "placeholder-coverage",
            "no case renders an unrevealed file as a committed placeholder \
             (MVP-SPEC.md line 121)"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Per case: the report is a pass describing *this* reveal, its serialization
/// is deterministic, and it leaks nothing (module docs, points 3–5).
fn check_case_behaviour(case: &CaseArtifacts) -> Result<(), VectorError> {
    let shape = case.shape.as_str();
    if !case.report.evidence.passed {
        return Err(check_err(
            "evidence-passed",
            format!("`{shape}`: a report exists only for a bundle that passed (D27 §4)"),
        ));
    }
    let revealed = u64::try_from(case.built.revealed_unit_ids.len()).unwrap_or(u64::MAX);
    if case.report.evidence.units_verified != revealed {
        return Err(check_err(
            "units-verified",
            format!(
                "`{shape}`: report claims {} verified unit(s), the bundle reveals {revealed}",
                case.report.evidence.units_verified
            ),
        ));
    }
    // The report's `format_version` is the manifest/bundle format the bundle
    // declared; a `v1` document may only pin `v1` reports.
    let v1 = u32::try_from(crate::manifest::registry::FORMAT_VERSION_V1).unwrap_or(u32::MAX);
    if case.report.work.format_version != v1 {
        return Err(check_err(
            "format-version",
            format!(
                "`{shape}`: report declares format_version {}, this document is v1",
                case.report.work.format_version
            ),
        ));
    }

    // D27/D29: two serializations of one report are byte-identical.
    let again = case
        .report
        .to_canonical_json()
        .map_err(|e| check_err("report-encode", format!("`{shape}`: {e}")))?;
    if again != case.canonical {
        return Err(check_err(
            "serialization-determinism",
            format!("`{shape}`: serializing the same report twice produced different bytes"),
        ));
    }

    check_no_secret_material(case)
}

/// Project rule 6: none of the work's secret material may appear in the report
/// bytes.
///
/// The report is UTF-8 JSON whose binary fields are lowercase hex (D29 rule
/// 6), so a substring search over the *rendered* hex is the search that
/// matters — a leak would arrive rendered, not raw. Each secret is re-derived
/// from `W` here rather than read off the fixture, so the check is independent
/// of whatever the builder chose to keep.
fn check_no_secret_material(case: &CaseArtifacts) -> Result<(), VectorError> {
    let text = core::str::from_utf8(&case.canonical)
        .map_err(|e| check_err("report-utf8", format!("`{}`: {e}", case.shape)))?;
    let shape = case.shape.as_str();
    let w_bytes = TEST_MASTER_SECRET_W;
    let w = MasterSecretRef::from_bytes(&w_bytes);

    let mut forbidden: Vec<(&'static str, String)> = vec![("W", hex(&TEST_MASTER_SECRET_W))];
    for file in &case.built.files {
        let file_id = FileId(file.file_id);
        forbidden.push((
            "file_salt",
            hex(derive_file_salt(w, file_id).expose_bytes_for_test_vectors()),
        ));
        forbidden.push(("path_salt", hex(derive_path_salt(w, file_id).as_bytes())));
        forbidden.push(("s_root", hex(derive_fine_seed(w, file_id).as_bytes())));
        for unit_id in file
            .normal_unit_ids
            .iter()
            .copied()
            .chain(file.mirror_unit_id)
        {
            let unit_id = UnitId(unit_id);
            forbidden.push(("k_u", hex(derive_unit_key(w, unit_id).as_bytes())));
            forbidden.push(("unit_salt", hex(derive_unit_salt(w, unit_id).as_bytes())));
        }
    }

    for (name, rendered) in forbidden {
        if text.contains(&rendered) {
            // The offending value is deliberately NOT echoed.
            return Err(check_err(
                "report-leaks-secret-material",
                format!(
                    "`{shape}`: the serialized report contains a derived `{name}` — the report \
                     model may carry no key, salt or seed (project rule 6; \
                     crate::verify::report secret-material policy)"
                ),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// recomputation (also the regenerator)
// ---------------------------------------------------------------------------

/// Recompute the entire `expect` object from `inputs`, building each named
/// shape through R6's constructor and running it through
/// [`verify_bundle`](crate::verify::verify_bundle).
///
/// Returns the value **and** the per-case artifacts, so the behavioural
/// assertions reuse one build + one verify per case.
///
/// # The options tuple is stated here, and that is the point (D128 §3 R3)
///
/// These 21 cases pin `verify_bundle`'s output, so they are a function of the
/// **options** it ran under as much as of the bundle — exactly as A22's
/// sibling `anchor` kind already declares `verify_at_unix` in its own
/// `inputs`, *because a verify option determines its pinned bytes*. This
/// executor has always built its own [`VerifyOptions`] rather than observing
/// an ambient default; since D128 it says which one, and why:
///
/// - **The layer is suppressed.** Every bundle here is an R6 `Placeholder`
///   fixture whose recorded addresses were chosen at M0, when nothing
///   recomputed them (`bundle_fixtures::fixture_address`, and a
///   `0x5E`/`0x5A`/`0x5C` storage record). Running the layer over them would
///   pin 21 identical `Evaluated { 0, N, false }` values — permanent,
///   fixture-only failures asserting something false about the product, where
///   `not-evaluated` "says nothing in either direction". That is worse
///   content, not merely more expensive to land.
/// - **The layer's coverage does not live here.** It lives at
///   `EXPECTED_CANONICAL_JSON_WITH_LINKAGE` (D105 ruling 4's whole-report
///   rendering, dual-target through A90's `--lib` route),
///   `tests/storage_linkage.rs`'s four address modes, and
///   `verify::storage_linkage`'s unit tests. Suppressing it here costs the
///   layer no assertion.
/// - **The tuple is explicit precisely so a future change to
///   [`VerifyOptions::new`] cannot move a frozen digest by accident.** That is
///   the whole reason D128 pays no FIXTURE EVENT and designs no freeze class:
///   the default and what the exhibits pin are two knobs, and only the first
///   moved.
///
/// [`VerifyOptions::new`]: crate::verify::VerifyOptions::new
///
/// # Errors
///
/// [`VectorError::Check`] for a case naming an unknown shape, a bundle the
/// pipeline refuses, or a report that will not encode.
fn build_expect(inputs: &Inputs) -> Result<(serde_json::Value, Vec<CaseArtifacts>), VectorError> {
    let mut cases = Vec::with_capacity(inputs.cases.len());
    let mut artifacts = Vec::with_capacity(inputs.cases.len());
    for input in &inputs.cases {
        let case = shapes::by_name(&input.shape).ok_or_else(|| {
            check_err(
                "shape-registered",
                format!("`{}` is not a shapes::catalogue() handle", input.shape),
            )
        })?;
        let built = build(&case.spec, &case.selection);
        // The stated tuple, not a default — see this function's docs.
        let options = VerifyOptions::new().without_storage_linkage();
        let report = verify_bundle(&built.bytes, &options).map_err(|e| {
            check_err(
                "bundle-verifies",
                format!(
                    "`{}`: the bundle must verify, got `{}`: {e}",
                    input.shape,
                    e.code()
                ),
            )
        })?;
        let canonical = report
            .to_canonical_json()
            .map_err(|e| check_err("report-encode", format!("`{}`: {e}", input.shape)))?;
        let decoded: serde_json::Value = serde_json::from_slice(&canonical).map_err(|e| {
            check_err(
                "report-json",
                format!(
                    "`{}`: the canonical report is not valid JSON: {e}",
                    input.shape
                ),
            )
        })?;
        let bundle_digest: [u8; 32] = Sha256::digest(&built.bytes).into();

        cases.push(serde_json::json!({
            "shape": input.shape,
            "bundle_len": built.bytes.len(),
            "bundle_sha256": hex(&bundle_digest),
            "revealed_unit_ids": built.revealed_unit_ids,
            "report_len": canonical.len(),
            "report_json": hex(&canonical),
            "report": decoded,
        }));
        artifacts.push(CaseArtifacts {
            shape: input.shape.clone(),
            built,
            report,
            canonical,
        });
    }
    Ok((
        serde_json::json!({
            "report_version": REPORT_VERSION,
            "cases": cases,
        }),
        artifacts,
    ))
}

/// Regenerate the whole `expect` object from a committed document's `inputs`,
/// so a regenerator test can diff value-for-value against the file.
///
/// # Errors
///
/// As [`build_expect`], plus [`VectorError::Envelope`] when the supplied
/// document is not a `report` vector at all.
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
    build_expect(&parsed).map(|(value, _)| value)
}

/// Build the `inputs` object a committed document carries, from a list of
/// `(shape, pins)` rows.
///
/// Lives here rather than in the emitter so the fixed fields — the documented
/// `W`, R6's `seal_id`, seed and `app_version` — have exactly one definition,
/// and so [`check_fixture_inputs`] is checking the same constants the
/// generator wrote.
#[must_use]
pub fn build_inputs(cases: &[(&str, &str)]) -> serde_json::Value {
    serde_json::json!({
        "w": hex(&TEST_MASTER_SECRET_W),
        "seal_id": hex(&FIXTURE_SEAL_ID),
        "seed": format!("0x{DEFAULT_SEED:016x}"),
        "app_version": FIXTURE_APP_VERSION,
        "cases": cases
            .iter()
            .map(|(shape, pins)| serde_json::json!({"shape": shape, "pins": pins}))
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shape [`REQUIRED_SHAPES`] names must exist in R6's catalogue —
    /// otherwise the coverage check could never be satisfied and would simply
    /// be a permanent red.
    #[test]
    fn every_required_shape_is_a_catalogue_entry() {
        for (shape, row) in REQUIRED_SHAPES {
            assert!(
                shapes::by_name(shape).is_some(),
                "`{shape}` ({row}) is not a shapes::catalogue() handle"
            );
        }
    }

    /// `REQUIRED_SHAPES` is a checklist, so a duplicated row would silently
    /// weaken it.
    #[test]
    fn required_shapes_are_unique() {
        let mut names: Vec<&str> = REQUIRED_SHAPES.iter().map(|(shape, _)| *shape).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    /// The smallest case list that clears [`check_shape_coverage`]: the
    /// mandated M0 rows, each carrying its checklist text as `pins`.
    fn covering_inputs() -> serde_json::Value {
        let owned: Vec<(&str, String)> = REQUIRED_SHAPES
            .iter()
            .map(|(shape, row)| (*shape, format!("the M0 shape \"{row}\"")))
            .collect();
        let rows: Vec<(&str, &str)> = owned
            .iter()
            .map(|(shape, pins)| (*shape, pins.as_str()))
            .collect();
        build_inputs(&rows)
    }

    /// A document whose `inputs` are fine but whose `expect` is not what the
    /// pipeline produces must fail — the test-of-the-test for the one thing
    /// this kind exists to do.
    #[test]
    fn a_tampered_expectation_fails_execution() {
        let inputs = covering_inputs();
        let parsed: Inputs = serde_json::from_value(inputs.clone()).expect("inputs parse");
        let (mut expect, _) = build_expect(&parsed).expect("recomputation");
        // Flip one hex digit of the pinned report bytes.
        let pointer = expect
            .pointer_mut("/cases/0/report_json")
            .expect("the case pins report_json");
        let mut hex_bytes = pointer.as_str().expect("hex string").to_owned();
        hex_bytes.replace_range(0..1, if hex_bytes.starts_with('7') { "8" } else { "7" });
        *pointer = serde_json::Value::String(hex_bytes);

        let error = execute(inputs, expect, "tampered".to_owned())
            .expect_err("a tampered expectation must not execute");
        let message = error.to_string();
        assert!(message.contains("report_json"), "{message}");
    }

    /// A case naming a shape no catalogue entry has is a malformed vector,
    /// reported rather than panicked on.
    #[test]
    fn an_unknown_shape_is_reported() {
        let inputs = build_inputs(&[("no-such-shape/never", "this shape does not exist")]);
        let error = execute(inputs, serde_json::json!({}), "unknown".to_owned())
            .expect_err("an unknown shape must not execute");
        assert!(error.to_string().contains("catalogue"), "{error}");
    }

    /// Dropping a mandated M0 shape fails, so the milestone checklist cannot
    /// quietly lose a row.
    #[test]
    fn a_missing_m0_shape_is_reported() {
        let inputs = build_inputs(&[("single-binary/full", "binary file, whole-file reveal")]);
        let error = execute(inputs, serde_json::json!({}), "partial".to_owned())
            .expect_err("missing M0 shapes must not execute");
        let message = error.to_string();
        assert!(message.contains("MVP-SPEC.md line 153"), "{message}");
    }

    /// The generated `inputs` are exactly what [`check_fixture_inputs`]
    /// demands — the generator and the checker share their constants.
    #[test]
    fn generated_inputs_satisfy_the_fixture_discipline() {
        let inputs = build_inputs(&[("single-binary/full", "binary file, whole-file reveal")]);
        let parsed: Inputs = serde_json::from_value(inputs).expect("inputs parse");
        check_fixture_inputs(&parsed).expect("generated inputs are disciplined");
    }

    /// The leak scan is not vacuous: fed a report-shaped string that *does*
    /// contain a derived salt, it fires.
    #[test]
    fn the_leak_scan_fires_on_a_planted_salt() {
        let case = shapes::by_name("single-binary/full").expect("shape exists");
        let built = build(&case.spec, &case.selection);
        let report = verify_bundle(&built.bytes, &VerifyOptions::new()).expect("verifies");
        let honest = report.to_canonical_json().expect("encodes");
        let planted = {
            let w_bytes = TEST_MASTER_SECRET_W;
            let w = MasterSecretRef::from_bytes(&w_bytes);
            let salt = hex(derive_path_salt(w, FileId(0)).as_bytes());
            let mut text = String::from_utf8(honest.clone()).expect("utf8");
            text.push_str(&salt);
            text.into_bytes()
        };
        let leaking = CaseArtifacts {
            shape: "planted".to_owned(),
            built,
            report,
            canonical: planted,
        };
        let error = check_no_secret_material(&leaking).expect_err("a planted salt must be caught");
        assert!(error.to_string().contains("path_salt"), "{error}");
    }
}
