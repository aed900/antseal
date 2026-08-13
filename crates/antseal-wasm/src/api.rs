//! The boundary's behaviour, with no `wasm_bindgen` in sight.
//!
//! Every export in `src/boundary.rs` is a two-line shim over a function here.
//! The split is what lets the native `cargo test`/`clippy` gate — which
//! compiles no `wasm-bindgen` at all (D18 §5 R3) — type-check and *execute*
//! the whole of the boundary's logic, and it is what makes R22's Accept row 2
//! (`native ≡ wasm32` over the R9 vectors) a comparison of two runs of the
//! same code rather than of two implementations.
//!
//! # The carriage rule
//!
//! Every function here hands over **bytes some `to_canonical_json()` produced**
//! — `report_bytes()` for the report, `OnlineOverlay::to_canonical_json` for
//! the overlay, `VerdictClass::to_canonical_json` for the verdict datum,
//! `RenderedVerdict`'s and `RenderedRedaction`'s for the two rendered halves
//! of the offline document, and `ProbePlan::to_canonical_json` for its probe
//! plan. None of them parses, re-serializes, or routes a
//! document through `serde_json::Value`: D29's Consequences and D65 §5 require
//! one serialization path everywhere so the bit-match contract covers
//! user-facing output, and a `Value` round trip alphabetizes the keys and
//! destroys D29 rule 1's declaration order. `tests/carriage.rs` scans this
//! file for the refused shapes.
//!
//! [`verify_rendered_json`] is where that rule earns its keep: the document is
//! five canonical byte strings **spliced by `format!`** in alphabetical member
//! order, the third carriage route D65's Correction section recognised and the
//! CLI's own `--json` already uses. Its `report` member is the report's bytes
//! verbatim, so a `Value` anywhere on this path would alphabetize the very
//! keys 21 committed vectors pin.
//!
//! `String::from_utf8` is a **validation pass over the same bytes**, not a
//! parse: it moves no key, and it is here because JS receives a string.
//!
//! # Options are constructed here, never accepted
//!
//! D128 §3 R5: R22 constructs its own [`VerifyOptions`] and does not take one
//! from JS. The export takes no options because the page has nothing to opt in
//! with, and spec line 38 names the storage-linkage layer as the page's entire
//! storage story — so it must run. `without_storage_linkage` is called
//! nowhere in this crate and its caller list stays closed at two.

use antseal_core::bundle::{BundleV1, SealProofError};
use antseal_core::verify::VerifyError;
use antseal_core::verify::orchestration::{
    LiveInputs, OnlineInputs, VerifyHost, VerifyModes, VerifyOutcome, VerifyRunError,
    verify_offline, verify_with_host,
};
use antseal_core::verify::pipeline::VerifyOptions;
use antseal_core::verify::plan::ProbePlan;
use antseal_core::verify::redaction::RenderedRedaction;

use crate::build_info::build_info;
use crate::error::BindingError;
use crate::escape::escape_for_dom;
use crate::online;

/// The page as a [`VerifyHost`]: it holds what its `fetch()` calls already
/// returned, folded into the typed values core accepts.
///
/// `live_inputs` can never be consulted — the page has no `--live` affordance
/// anywhere (CLI-only by spec, MVP-SPEC.md line 119) and this crate never
/// asks for that layer — so it returns the empty value rather than panicking.
/// A panic here would be a trap in a module whose Accept row forbids one.
struct PageHost {
    online: OnlineInputs,
}

impl VerifyHost for PageHost {
    fn online_inputs(&self) -> OnlineInputs {
        self.online.clone()
    }

    fn live_inputs(&self) -> LiveInputs {
        LiveInputs::none()
    }
}

/// The options every entry point here uses. One expression, so no export can
/// verify under different rules than another.
fn options() -> VerifyOptions {
    VerifyOptions::new()
}

/// Run the offline verification the page performs on drop.
fn run_offline(bundle_bytes: &[u8]) -> Result<VerifyOutcome, BindingError> {
    Ok(verify_offline(bundle_bytes, &options(), &escape_for_dom)?)
}

/// Run the online-augmented verification the page performs after its explicit
/// "confirm online" action.
fn run_online(bundle_bytes: &[u8], evidence_json: &str) -> Result<VerifyOutcome, BindingError> {
    let host = PageHost {
        online: online::parse(evidence_json)?,
    };
    Ok(verify_with_host(
        bundle_bytes,
        &options(),
        VerifyModes::OFFLINE.with_online(),
        &host,
        &escape_for_dom,
    )?)
}

/// Canonical bytes as the string JS receives, validated rather than parsed.
fn utf8(bytes: &[u8], document: &'static str) -> Result<String, BindingError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| BindingError::NotUtf8 { document })
}

/// Verify a `.sealproof` offline and return the full report.
///
/// The returned string is exactly `VerificationReport::to_canonical_json`'s
/// bytes — tier A, and what 21 committed vectors pin. It carries the
/// **machine-readable** verdict and, measured, **no rendered prose at all**:
/// across all 21 cases the only multi-word strings are the sealer's own work
/// titles (D130 §1 a.2). The sentences the page displays come from
/// [`verify_rendered_json`]; this export's contract is unchanged and its bytes
/// have not moved.
///
/// # Errors
///
/// [`BindingError::Run`] carrying `antseal-core`'s own rejection — malformed,
/// truncated, hostile and tampered bundles all arrive here, never at a panic.
pub fn verify_json(bundle_bytes: &[u8]) -> Result<String, BindingError> {
    let outcome = run_offline(bundle_bytes)?;
    utf8(outcome.report_bytes(), "report")
}

/// The whole offline document the page displays — **one call per drop**
/// (D130 §3 R1/R3, D132 §3 R1/R2).
///
/// Five members, in the alphabetical order the CLI's `--json` `result`
/// already emits:
///
/// | member | what it is |
/// | --- | --- |
/// | `plan` | `ProbePlan` — what an online confirmation would fetch: `{"blocks":[…],"receipt":{"tx_hash":…}\|null}`, **both keys always present** |
/// | `redaction` | `RenderedRedaction` — R19's disclosure block, as final display strings |
/// | `rendered` | `RenderedVerdict` — the offline verdict block, as final display strings |
/// | `report` | the report's canonical bytes, **verbatim**, byte-identical to [`verify_json`]'s |
/// | `verdict` | `VerdictClass` — D69's rung datum, **without** `exit_code`: D69 §3 R1 keeps one code table in the product and it is the CLI's |
///
/// **No options and no evidence document.** The offline block is
/// mode-invariant (D64 §2), and the online lines already have a home in
/// [`verify_online_json`]'s overlay — so R24 needs no sixth export and the
/// surface closes at five. D132 corrected the *reasoning* behind that and
/// kept the conclusion: the online **wording** was covered, the online
/// **fetch inputs** were not, and they arrive here as the `plan` member
/// rather than as a sixth export.
///
/// **The `plan` member is a product of a PASSING verdict, and that is what
/// decided D132.** It is computed after [`run_offline`] has returned, so a
/// bundle this function refuses yields no plan and the page has nothing to
/// fetch with — a structural property, not a discipline. No entry point may
/// return a plan from a decode alone (D132 §3 R6).
///
/// **One call**, because every export re-verifies the bundle from bytes: at
/// the caps that is multi-second in wasm on the main thread, and D129 §5 R10
/// measured that no Web Worker shape is admissible under the page's CSP. The
/// `report` member is here precisely so the page needs nothing else offline.
///
/// **No `schema` key and no interior version** (D65 §4): the one version a
/// consumer reads is `build_info()`'s.
///
/// # Errors
///
/// As [`verify_json`], plus [`BindingError::Encode`] for a sibling document
/// that could not be serialized — structurally unreachable, typed anyway.
pub fn verify_rendered_json(bundle_bytes: &[u8]) -> Result<String, BindingError> {
    let outcome = run_offline(bundle_bytes)?;

    // The page's own policy, applied to every sealer- and artifact-authored
    // value either half embeds (D130 §3 R5/R9). The CLI passes its terminal
    // set at the same seam; neither set is in core. The verdict half is
    // already rendered under it — `run_offline` handed it in.
    let disclosure = RenderedRedaction::new(&outcome.redaction(), &escape_for_dom);

    // D132 §3 R4/R6. Reached only after `run_offline` returned, so the plan
    // cannot describe a bundle that failed verification. The decode is the
    // bundle layer alone — the plan reads anchors and the receipt section and
    // nothing deeper — and its failure arm is structurally unreachable here,
    // because `run_offline` decoded these same bytes through the same layer a
    // moment ago. It is typed rather than unwrapped all the same, and it
    // carries `antseal-core`'s own frozen code so a reader could not tell this
    // rejection from any other.
    let bundle = BundleV1::decode(bundle_bytes).map_err(|source| {
        BindingError::Run(VerifyRunError::Verify(VerifyError::Decode(
            SealProofError::Bundle { source },
        )))
    })?;
    let plan = utf8(
        &ProbePlan::from_bundle(&bundle)
            .to_canonical_json()
            .map_err(|_| encode("the probe plan"))?,
        "probe plan",
    )?;

    let redaction = utf8(
        &disclosure
            .to_canonical_json()
            .map_err(|_| encode("the disclosure block"))?,
        "disclosure block",
    )?;
    let rendered = utf8(
        &outcome
            .rendered()
            .to_canonical_json()
            .map_err(|_| encode("the rendered verdict"))?,
        "rendered verdict",
    )?;
    // Tier A, verbatim: the same bytes `verify_json` hands over, never
    // re-serialized and never parsed (D65 §5).
    let report = utf8(outcome.report_bytes(), "report")?;
    let verdict = utf8(
        &outcome
            .verdict_class()
            .to_canonical_json()
            .map_err(|_| encode("the verdict datum"))?,
        "verdict datum",
    )?;

    // A splice of five canonical byte strings — never a `serde_json::Value`,
    // which would alphabetize the report's keys and destroy D29 rule 1's
    // declaration order. `tests/carriage.rs` scans this file for that shape.
    // `plan` sorts before `redaction`, so D132's member is prepended and no
    // existing member moves.
    Ok(format!(
        "{{\"plan\":{plan},\"redaction\":{redaction},\"rendered\":{rendered},\"report\":{report},\"verdict\":{verdict}}}"
    ))
}

/// A sibling document that would not serialize — structurally unreachable
/// (no map, no non-string key, no float in any of them), named individually
/// so the message says which one.
const fn encode(document: &'static str) -> BindingError {
    BindingError::Encode { document }
}

/// Fold the page's pre-fetched endpoint responses into the advisory online
/// overlay.
///
/// The overlay is a **sibling document**: it never overwrites the offline
/// verdict, and the report bytes are byte-identical whether or not this
/// entry point was called (D64 §3).
///
/// # Errors
///
/// [`BindingError::OnlineEvidence`] if the document is malformed;
/// [`BindingError::Run`] if the bundle itself is rejected.
pub fn verify_online_json(
    bundle_bytes: &[u8],
    evidence_json: &str,
) -> Result<String, BindingError> {
    let outcome = run_online(bundle_bytes, evidence_json)?;
    let overlay = outcome.overlay().ok_or(BindingError::MissingOverlay)?;
    let bytes = overlay.to_canonical_json()?;
    utf8(&bytes, "overlay")
}

/// D69's rung and the counts behind it, as the page states them.
///
/// This export exists because the rung is **not** a field of the report bytes
/// (D18 §5 R4 item 4 makes the fourth entry conditional on exactly that), and
/// because the page must get the rung from the module rather than recompute it
/// in JS — R27's parity gate needs one computation to compare.
///
/// With `evidence_json`, the rung is computed over the **online-augmented**
/// aggregate (D69 §3 R5: the strongest computation the run performed); without
/// it, over the offline one.
///
/// # Errors
///
/// As [`verify_json`] and [`verify_online_json`].
pub fn verdict_class_json(
    bundle_bytes: &[u8],
    evidence_json: Option<&str>,
) -> Result<String, BindingError> {
    let outcome = match evidence_json {
        Some(json) => run_online(bundle_bytes, json)?,
        None => run_offline(bundle_bytes)?,
    };
    let bytes = outcome.verdict_class().to_canonical_json()?;
    utf8(&bytes, "verdict datum")
}

/// The module's identity, for the page footer (D63 §5 R3).
///
/// # Errors
///
/// [`BindingError::Encode`] — structurally unreachable: the document is five
/// scalar fields and a list of integers.
pub fn build_info_json() -> Result<String, BindingError> {
    serde_json::to_string(&build_info()).map_err(|_| BindingError::Encode {
        document: "the build info",
    })
}
