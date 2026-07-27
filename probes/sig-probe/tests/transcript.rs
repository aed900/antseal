//! Golden pin of the deterministic output transcript.
//!
//! The SHA-256 below was produced by the native run on 2026-07-27
//! (toolchain 1.92.0, x86_64-unknown-linux-gnu) and is the value the
//! wasm32-unknown-unknown execution must reproduce (run-wasm.mjs recomputes
//! the transcript inside wasm and the runner compares hashes). Any change
//! to this value under the same pins is a determinism break — investigate,
//! never regenerate silently.
//!
//! Run with `--nocapture` to print the transcript hex (e.g. to diff a wasm
//! dump byte-by-byte).

use sha2::{Digest, Sha256};
use sig_probe::build_transcript;

/// SHA-256 of the 10714-byte transcript (see build_transcript docs for the
/// exact layout).
const GOLDEN_TRANSCRIPT_SHA256: &str =
    "92354c8d75efdc6dfd26cea301243e35ba0776753c61127846b77c8a3cffa298";

#[test]
fn transcript_matches_golden() {
    let t = build_transcript();
    let digest = Sha256::digest(&t);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    println!("transcript sha256 = {hex}");
    println!("transcript len    = {}", t.len());
    assert_eq!(
        hex, GOLDEN_TRANSCRIPT_SHA256,
        "native transcript diverged from the recorded golden"
    );
}
