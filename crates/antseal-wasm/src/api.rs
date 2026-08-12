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
//! the overlay, `VerdictClass::to_canonical_json` for the verdict datum. None
//! of them parses, re-serializes, or routes a document through
//! `serde_json::Value`: D29's Consequences and D65 §5 require one
//! serialization path everywhere so the bit-match contract covers user-facing
//! output, and a `Value` round trip alphabetizes the keys and destroys D29
//! rule 1's declaration order. `tests/carriage.rs` scans this file for the
//! refused shapes.
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

use antseal_core::verify::orchestration::{
    LiveInputs, OnlineInputs, VerifyHost, VerifyModes, VerifyOutcome, verify_offline,
    verify_with_host,
};
use antseal_core::verify::pipeline::VerifyOptions;

use crate::build_info::build_info;
use crate::error::BindingError;
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
    Ok(verify_offline(bundle_bytes, &options())?)
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
    )?)
}

/// Canonical bytes as the string JS receives, validated rather than parsed.
fn utf8(bytes: &[u8], document: &'static str) -> Result<String, BindingError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| BindingError::NotUtf8 { document })
}

/// Verify a `.sealproof` offline and return the full report.
///
/// The returned string is exactly `VerificationReport::to_canonical_json`'s
/// bytes: every display string R18 renders is already inside it, so page JS
/// does layout only.
///
/// # Errors
///
/// [`BindingError::Run`] carrying `antseal-core`'s own rejection — malformed,
/// truncated, hostile and tampered bundles all arrive here, never at a panic.
pub fn verify_json(bundle_bytes: &[u8]) -> Result<String, BindingError> {
    let outcome = run_offline(bundle_bytes)?;
    utf8(outcome.report_bytes(), "report")
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
