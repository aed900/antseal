//! The `#[wasm_bindgen]` items — the only place in this workspace where that
//! attribute appears.
//!
//! Every function here is a shim: it calls one `crate::api` function and
//! converts its error. Nothing decides anything, so the host build (which
//! compiles no `wasm-bindgen` at all) still type-checks and executes the whole
//! of the boundary's behaviour through `crate::api`.
//!
//! # Why the return type is a string
//!
//! D18 §5 R5: the module returns `to_canonical_json()`'s **bytes**, never a
//! structured JS value. `serde_wasm_bindgen`, `JsValue::from_serde` and
//! wasm-bindgen's own `serde-serialize` feature are all prohibited, because
//! each is a second serialization path and D29's Consequences require one
//! path everywhere so the bit-match contract covers user-facing output. Page
//! JS may `JSON.parse` the string for layout; what it must never receive is a
//! report that was serialized twice.
//!
//! # Errors
//!
//! Every fallible export returns `Result<String, JsError>`, which wasm-bindgen
//! turns into a **thrown JS `Error`** the caller catches — never an unhandled
//! trap. The message carries `antseal-core`'s frozen rejection code in front
//! of the sentence whenever the failure is a bundle rejection, which is the
//! same code-in-the-message shape the CLI uses.

use wasm_bindgen::prelude::*;

use crate::error::BindingError;

/// Runs once, at module instantiation.
///
/// The hook turns a Rust panic — which on `wasm32-unknown-unknown` aborts into
/// a target with no unwinding and no stdio — into a thrown JS `Error` carrying
/// the panic message. Without it the page would see an opaque
/// `RuntimeError: unreachable executed` and have nothing to report.
///
/// No `console_error_panic_hook`: that is a package, and this module's
/// dependency graph is an argued-per-entry allow-list (D18 §5 R6). The hook is
/// four lines.
#[wasm_bindgen(start)]
pub fn start() {
    std::panic::set_hook(Box::new(|info| {
        wasm_bindgen::throw_str(&format!("antseal verifier panicked: {info}"));
    }));
}

/// The typed error JS receives.
fn thrown(error: &BindingError) -> JsError {
    JsError::new(&error.message())
}

/// Verify a `.sealproof` offline; returns the full report as canonical JSON.
///
/// # Errors
///
/// Throws for every rejected bundle, carrying the stable code.
#[wasm_bindgen]
pub fn verify(bundle_bytes: &[u8]) -> Result<String, JsError> {
    crate::api::verify_json(bundle_bytes).map_err(|error| thrown(&error))
}

/// Fold pre-fetched endpoint responses into the advisory online overlay;
/// returns the overlay as canonical JSON.
///
/// `evidence_json` is the page's own document — R24 performs the `fetch()`
/// calls, this module performs the must-agree comparison. The module never
/// fetches.
///
/// # Errors
///
/// Throws for a malformed evidence document or a rejected bundle.
#[wasm_bindgen]
pub fn verify_online(bundle_bytes: &[u8], evidence_json: &str) -> Result<String, JsError> {
    crate::api::verify_online_json(bundle_bytes, evidence_json).map_err(|error| thrown(&error))
}

/// The whole offline document the page displays, as canonical JSON — the
/// fifth entry of D18 §5 R4's list, opened to five by D130 and closed again
/// there.
///
/// Takes no options and no evidence document (D130 §3 R2), and the page calls
/// it **once per drop**: every export re-verifies from bytes, and the
/// document's `report` member is byte-identical to [`verify`]'s, so nothing
/// else is needed offline.
///
/// # Errors
///
/// Throws for every rejected bundle, carrying the stable code.
#[wasm_bindgen]
pub fn verify_rendered(bundle_bytes: &[u8]) -> Result<String, JsError> {
    crate::api::verify_rendered_json(bundle_bytes).map_err(|error| thrown(&error))
}

/// D69's rung datum as canonical JSON — offline, or online-augmented when
/// `evidence_json` is supplied.
///
/// # Errors
///
/// Throws for a malformed evidence document or a rejected bundle.
#[wasm_bindgen]
pub fn verdict_class(
    bundle_bytes: &[u8],
    evidence_json: Option<String>,
) -> Result<String, JsError> {
    crate::api::verdict_class_json(bundle_bytes, evidence_json.as_deref())
        .map_err(|error| thrown(&error))
}

/// The module's identity for the page footer (D63 §5 R3), as JSON.
///
/// # Errors
///
/// Structurally unreachable; typed rather than unwrapped.
#[wasm_bindgen]
pub fn build_info() -> Result<String, JsError> {
    crate::api::build_info_json().map_err(|error| thrown(&error))
}
