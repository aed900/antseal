//! What the module can honestly know about itself.
//!
//! D63 §5 R3 makes this export **load-bearing rather than convenience**: the
//! page footer renders these fields from the module's own export and never
//! from separately injected HTML, so a mixed deploy — a fresh page beside a
//! stale `.wasm`, or the reverse — cannot present a consistent-looking footer.
//! R27/Q19 assert the rendered version equals this export's value; that is the
//! detector.
//!
//! # What is deliberately absent
//!
//! **The module's own SHA-256.** D63 §4 refuses it as a fixed point — a
//! digest of a file cannot live inside that file — so the page's published sum
//! arrives by build-time injection instead, and D63 §11.3 writes "R22 must not
//! grow a self-hash entry point" into this row's `Notes`. The closed export
//! list (D18 §5 R4) is what makes that unbuildable rather than merely
//! forbidden.

use antseal_core::format::SUPPORTED_VERSIONS;
use antseal_core::verify::REPORT_VERSION;
use serde::Serialize;

/// The commit the artifact was built from, stamped by `build.rs` from an
/// environment variable the build script supplies. `unknown` when nobody
/// supplied one — an honest answer, not a failure.
pub const SOURCE_COMMIT: &str = env!("ANTSEAL_SOURCE_COMMIT");

/// The module's identity, in declaration order.
///
/// Field order is the serialized order (`serde_json` preserves struct
/// declaration order), so this document is stable byte-for-byte across builds
/// of the same inputs — the property D63's published sums rest on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BuildInfo {
    /// The verifying library's version — the field R27/Q19 compare the
    /// footer against.
    pub core_version: &'static str,
    /// This boundary crate's own version. Distinct from `core_version`
    /// because the two can diverge and a footer that showed one label for
    /// both would hide it.
    pub binding_version: &'static str,
    /// Which `.sealproof` format versions this build verifies.
    pub supported_format_versions: &'static [u64],
    /// The report-serialization version the page will receive.
    pub report_version: u32,
    /// The source commit, or `unknown`.
    pub source_commit: &'static str,
}

/// This build's identity.
#[must_use]
pub const fn build_info() -> BuildInfo {
    BuildInfo {
        core_version: antseal_core::VERSION,
        binding_version: env!("CARGO_PKG_VERSION"),
        supported_format_versions: SUPPORTED_VERSIONS,
        report_version: REPORT_VERSION,
        source_commit: SOURCE_COMMIT,
    }
}
