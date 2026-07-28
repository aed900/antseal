//! Emits the **native** side of the Q5 bit-match.
//!
//!     cargo run -p wasm-bitmatch --bin bitmatch-emit --locked -- <out-file>
//!
//! Writes [`wasm_bitmatch::transcript_bytes`] verbatim to `<out-file>` and
//! prints the SHA-256 and vector count. `scripts/wasm-bitmatch.mjs` then
//! byte-compares the wasm32 module's transcript against that file.
//!
//! Kept as a binary rather than a test so the lane's two sides are produced
//! by two explicit, individually re-runnable commands — see
//! `scripts/wasm-bitmatch.sh`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(out_path) = std::env::args_os().nth(1) else {
        eprintln!("usage: bitmatch-emit <out-file>");
        return ExitCode::FAILURE;
    };

    let transcript = wasm_bitmatch::transcript();
    let bytes = wasm_bitmatch::transcript_bytes();

    if transcript.vector_count == 0 {
        eprintln!(
            "bitmatch-emit: zero vectors embedded — the bit-match would assert nothing. \
             Discovery (crates/wasm-bitmatch/build.rs) is broken or testdata/vectors/ is empty."
        );
        return ExitCode::FAILURE;
    }

    if let Err(error) = std::fs::write(&out_path, &bytes) {
        eprintln!(
            "bitmatch-emit: cannot write {}: {error}",
            out_path.to_string_lossy()
        );
        return ExitCode::FAILURE;
    }

    println!(
        "bitmatch-emit: native transcript -> {} ({} bytes, {} vector(s))",
        out_path.to_string_lossy(),
        bytes.len(),
        transcript.vector_count
    );
    println!(
        "bitmatch-emit: sha256 = {}",
        wasm_bitmatch::hex(&wasm_bitmatch::transcript_sha256())
    );
    for entry in &transcript.entries {
        println!(
            "  [{}] {} — recomputed {}",
            entry.status,
            entry.path,
            entry.recomputed_digest.as_deref().unwrap_or("(none)")
        );
    }
    ExitCode::SUCCESS
}
