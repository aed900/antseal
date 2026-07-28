//! The native↔WASM bit-match harness (task Q5).
//!
//! # The contract
//!
//! Executing **every committed golden vector** through
//! [`antseal_core::test_util::vectors`] must produce **byte-identical**
//! output natively and under `wasm32-unknown-unknown`. That output is the
//! *transcript* built here; the lane compares the two byte strings, and
//! their SHA-256, and fails loudly on any difference (MVP-SPEC.md lines
//! 167/169 — "the WASM build must bit-match native verification").
//!
//! Both sides run **the same function over the same bytes**:
//!
//! - the vectors are embedded at build time by `build.rs`, which walks
//!   `testdata/vectors/` (no hardcoded lists), so a new vector file is
//!   covered with zero changes here, in the runner, or in CI;
//! - the execution path is `antseal_core`'s own vector executor — the exact
//!   code the Q4 native runner uses, reachable on wasm32 because it lives
//!   behind the I/O-free `test-vectors` feature tier;
//! - the serialization is [`Transcript`], built under the **D29**
//!   determinism rules.
//!
//! # Transcript byte format
//!
//! Compact JSON via `serde_json::to_vec`, deterministic by construction
//! ([`docs/decisions/D29-report-byte-format.md`]): fields serialize in
//! declaration order, there are no maps, no floats, and no conditional
//! presence (absent values are `null`, never omitted); binary data is
//! lowercase hex. D29 is **recommended, not frozen** — consuming it here
//! does not freeze it; the freeze belongs to Q14.
//!
//! Failures are *recorded*, not raised: a vector that does not execute
//! contributes `status: "failed"` plus its error text. That keeps the
//! function total (no panics, no early exit) so a divergence shows up as a
//! byte difference to be diffed rather than a trap to be guessed at — and it
//! means a wasm-only failure is caught even when the native side is fine.
//!
//! # What this crate does NOT commit
//!
//! No wasm-bindgen anywhere: the wasm entry points are a raw C ABI over two
//! integers, and the module has zero imports. Decision **D18**
//! (feature-gated wasm-bindgen surface inside `antseal-core` vs a thin
//! wrapper crate) is untouched and remains free until M3.

use antseal_core::test_util::vectors::execute_vector_bytes;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The build-time table of committed vectors (see `build.rs`).
pub mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_vectors.rs"));
}

pub use embedded::{EMBEDDED_VECTORS, EmbeddedVector};

/// Transcript format version. `0` while D29 is a recommendation; Q14 freezes
/// the report byte format and this becomes `1`.
pub const TRANSCRIPT_VERSION: u32 = 0;

/// One executed vector. Every field is always present (D29 rule 4): fields
/// that do not apply to the outcome serialize as `null`.
#[derive(Debug, Clone, Serialize)]
pub struct TranscriptEntry {
    /// Repository-relative path with forward slashes.
    pub path: String,
    /// The `v<n>` directory the vector was discovered under.
    pub format_version: String,
    /// Exact byte length of the vector file, as embedded.
    pub bytes: u64,
    /// `"executed"` or `"failed"`.
    pub status: &'static str,
    /// Registered kind, when the vector executed.
    pub kind: Option<String>,
    /// The vector's own `description`, when it executed.
    pub description: Option<String>,
    /// Entries verified, when it executed.
    pub items: Option<u64>,
    /// Lowercase hex of `VectorSummary::recomputed_digest` — the digest over
    /// every byte the executor recomputed.
    pub recomputed_digest: Option<String>,
    /// `Display` text of the error, when it failed.
    pub error: Option<String>,
}

/// The whole run, in `path` order.
#[derive(Debug, Clone, Serialize)]
pub struct Transcript {
    /// See [`TRANSCRIPT_VERSION`].
    pub transcript_version: u32,
    /// Number of vectors executed.
    pub vector_count: u64,
    /// One entry per vector, sorted by `path`.
    pub entries: Vec<TranscriptEntry>,
}

/// Execute one embedded vector into a transcript entry. Total: every failure
/// mode becomes a recorded `status: "failed"` entry.
fn entry_for(vector: &EmbeddedVector) -> TranscriptEntry {
    let base = TranscriptEntry {
        path: vector.path.to_owned(),
        format_version: vector.format_version.to_owned(),
        bytes: vector.bytes.len() as u64,
        status: "failed",
        kind: None,
        description: None,
        items: None,
        recomputed_digest: None,
        error: None,
    };
    match execute_vector_bytes(vector.bytes, vector.format_version) {
        Ok(summary) => TranscriptEntry {
            status: "executed",
            kind: Some(summary.kind.to_owned()),
            description: Some(summary.description),
            items: Some(summary.items as u64),
            recomputed_digest: Some(hex(&summary.recomputed_digest)),
            ..base
        },
        Err(error) => TranscriptEntry {
            error: Some(error.to_string()),
            ..base
        },
    }
}

/// Build the transcript over an arbitrary vector set (the tests use this to
/// feed synthetic and deliberately-corrupt inputs).
#[must_use]
pub fn transcript_for(vectors: &[EmbeddedVector]) -> Transcript {
    let mut entries: Vec<TranscriptEntry> = vectors.iter().map(entry_for).collect();
    // `build.rs` already emits the table sorted by path; sorting again makes
    // the ordering a property of THIS function rather than of the generator,
    // so the two sides cannot disagree because of how the table was built.
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    // ── Deliberate-divergence hook (Q5 test-of-the-test) ────────────────
    // Off unless `--cfg antseal_bitmatch_inject_divergence` is passed, which
    // ONLY `./scripts/wasm-bitmatch.sh --self-test` does, and then only for
    // the wasm32 build. It simulates two classic platform-divergence shapes
    // at once so the lane can be PROVEN to go red on demand instead of on
    // trust:
    //
    //   * container iteration order (Q5's own example, "HashMap-ordered
    //     serialization") — reverse the entry order;
    //   * platform-dependent formatting — uppercase the hex digests.
    //
    // Both are injected because the first is invisible while only one vector
    // is committed; the second is observable at any vector count, so the
    // self-test never degrades into a no-op as the corpus changes.
    #[cfg(all(target_arch = "wasm32", antseal_bitmatch_inject_divergence))]
    {
        entries.reverse();
        for entry in &mut entries {
            entry.recomputed_digest = entry
                .recomputed_digest
                .as_ref()
                .map(|digest| digest.to_uppercase());
        }
    }

    Transcript {
        transcript_version: TRANSCRIPT_VERSION,
        vector_count: entries.len() as u64,
        entries,
    }
}

/// Build the transcript over every committed vector.
#[must_use]
pub fn transcript() -> Transcript {
    transcript_for(EMBEDDED_VECTORS)
}

/// The canonical transcript bytes — the exact byte string the bit-match
/// compares.
///
/// Serialization cannot fail for this type (no maps with non-string keys, no
/// non-finite floats — there are no floats at all), but the impl never
/// unwraps: an impossible failure degrades to a self-describing byte string
/// that will differ from the other side and fail the lane loudly rather than
/// silently.
#[must_use]
pub fn transcript_bytes() -> Vec<u8> {
    match serde_json::to_vec(&transcript()) {
        Ok(bytes) => bytes,
        Err(error) => format!("{{\"transcript_serialization_failed\":\"{error}\"}}").into_bytes(),
    }
}

/// SHA-256 of [`transcript_bytes`].
#[must_use]
pub fn transcript_sha256() -> [u8; 32] {
    Sha256::digest(transcript_bytes()).into()
}

/// Lowercase hex (D29 rule 6).
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// wasm32 entry points — raw C ABI, zero imports, zero unsafe
// ---------------------------------------------------------------------------

/// The exports `scripts/wasm-bitmatch.mjs` calls.
///
/// The transcript is computed once, leaked to `'static`, and handed to JS as
/// `(pointer, length)` into the module's exported linear memory. No data
/// flows *into* the module and there is no allocator ABI, so nothing here
/// dereferences a raw pointer.
///
/// # `unsafe_code` opt-out (workspace lint policy, root `Cargo.toml`)
///
/// The **only** `unsafe` token in this crate is the `unsafe(no_mangle)`
/// attribute below — required to give the three exports stable symbol names
/// a `WebAssembly.Module` can call. There is no `unsafe` block and no unsafe
/// *operation* anywhere in the crate. The invariant `no_mangle` asks the
/// author to uphold is "no duplicate symbol names across linked libraries";
/// it is met trivially and permanently: this cdylib is the whole module —
/// `scripts/wasm-bitmatch.mjs` instantiates it alone, with zero imports and
/// nothing else linked in (the runner asserts the import list is empty), and
/// the three names are `bitmatch_`-prefixed. The allow is scoped to this
/// module, never the crate root.
#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod wasm_exports {
    use std::sync::OnceLock;

    /// `usize` is 32-bit on `wasm32-unknown-unknown`, so the pointer/length
    /// casts below are lossless. Asserted at compile time rather than
    /// assumed.
    const _: () = assert!(core::mem::size_of::<usize>() == 4);

    static TRANSCRIPT: OnceLock<&'static [u8]> = OnceLock::new();

    fn transcript() -> &'static [u8] {
        TRANSCRIPT.get_or_init(|| {
            let bytes: &'static mut [u8] = Box::leak(super::transcript_bytes().into_boxed_slice());
            bytes
        })
    }

    /// Byte length of the transcript. Call before [`bitmatch_ptr`].
    #[unsafe(no_mangle)]
    pub extern "C" fn bitmatch_len() -> u32 {
        transcript().len() as u32
    }

    /// Offset of the transcript within the exported `memory`.
    #[unsafe(no_mangle)]
    pub extern "C" fn bitmatch_ptr() -> u32 {
        transcript().as_ptr() as usize as u32
    }

    /// The transcript format version, so JS can refuse a module it does not
    /// understand instead of diffing garbage.
    #[unsafe(no_mangle)]
    pub extern "C" fn bitmatch_transcript_version() -> u32 {
        super::TRANSCRIPT_VERSION
    }
}
