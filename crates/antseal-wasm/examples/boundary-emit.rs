//! Emits the NATIVE side of R22's Accept row 2, for `scripts/wasm-boundary.mjs`
//! to compare the JS boundary against.
//!
//!     cargo run -p antseal-wasm --example boundary-emit -- <out.json>
//!
//! # What it emits, and why that is the comparison
//!
//! For every case in R9's committed `report` vector document it rebuilds the
//! bundle and runs **`verify_bundle` natively under the same options the
//! binding uses** — `VerifyOptions::new()`, the default, with the R20
//! storage-linkage layer ON. The node script feeds the same bundle bytes
//! through the wasm module's `verify()` export and requires the two report
//! byte strings to be identical.
//!
//! The comparison is deliberately **native ≡ wasm32 for one input**, not
//! binding ≡ vector file. R9's committed `report_json` values pin the
//! *suppressed* tuple — `VerifyOptions::new()` with the storage-linkage
//! switch turned off, stated at `vectors_report::build_expect` and ruled by
//! D128 §3 R3 — while R22's export takes no options and therefore always runs
//! the layer, so a comparison against the file would fail for a reason that
//! says nothing about the boundary. Measured at R22's landing: **21 of 21**
//! committed reports differ from the default tuple's, every one of them at
//! `storage_linkage`. R22's Accept row was corrected in place to say so.
//!
//! The switch is named without its call parentheses on purpose: the caller
//! scan in `antseal-core`'s `verify::pipeline` tests is a literal match over
//! every `.rs` file in the tree and does not skip comments, so quoting the
//! call site verbatim in prose registers as a third suppressing caller. (It
//! did, once, here — the scan caught it, which is the scan working.)
//!
//! # Why an example rather than a bin
//!
//! It needs `antseal-core`'s `test-vectors` tier, which is a **dev**
//! dependency here: a normal edge would put the fixture catalogue into the
//! shipped page module, and a `required-features` bin would make this crate
//! declare a feature — which D18 §5 R3 forbids, because that is what keeps
//! `gate-features.sh --check-partition` at seven declared features.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use antseal_core::test_util::bundle_fixtures::{build, shapes};
use antseal_core::verify::{VerifyOptions, verify_bundle};

/// The committed R9 corpus, relative to the workspace root.
const VECTOR_DOC: &str = "testdata/vectors/v1/report/verification-reports.json";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(out) = args.next() else {
        eprintln!("usage: boundary-emit <out.json>");
        return ExitCode::FAILURE;
    };

    match emit(&out) {
        Ok(count) => {
            println!("boundary-emit: {count} case(s) -> {out}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("::error::boundary-emit: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Build every R9 case, verify it natively, and write the corpus.
fn emit(out: &str) -> Result<usize, String> {
    // `CARGO_MANIFEST_DIR` is `crates/antseal-wasm`; the corpus is two levels
    // up. Resolved rather than assumed so a run from any directory works.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .ok_or("cannot locate the workspace root from CARGO_MANIFEST_DIR")?
        .to_path_buf();

    let document = fs::read_to_string(root.join(VECTOR_DOC))
        .map_err(|e| format!("cannot read {VECTOR_DOC}: {e}"))?;
    let document: serde_json::Value =
        serde_json::from_str(&document).map_err(|e| format!("{VECTOR_DOC} is not JSON: {e}"))?;

    let cases = document
        .get("inputs")
        .and_then(|inputs| inputs.get("cases"))
        .and_then(serde_json::Value::as_array)
        .ok_or("the vector document has no `inputs.cases` array")?;
    if cases.is_empty() {
        return Err(
            "the vector document lists no cases — a comparison over nothing \
                    asserts nothing"
                .to_owned(),
        );
    }

    let mut emitted = Vec::with_capacity(cases.len());
    for case in cases {
        let shape = case
            .get("shape")
            .and_then(serde_json::Value::as_str)
            .ok_or("a case has no `shape`")?;
        let known = shapes::by_name(shape)
            .ok_or_else(|| format!("`{shape}` is not a shapes::catalogue() handle"))?;
        let built = build(&known.spec, &known.selection);

        // THE options the binding uses — `crate::api::options()`'s value,
        // stated here so the two sides cannot silently differ. Never
        // `without_storage_linkage`: R22 has no flag to suppress the layer
        // with, and D128 §3 R5 closes that method's caller list at two.
        let report = verify_bundle(&built.bytes, &VerifyOptions::new())
            .map_err(|e| format!("`{shape}` must verify natively, got `{}`: {e}", e.code()))?;
        let canonical = report
            .to_canonical_json()
            .map_err(|e| format!("`{shape}`: the report will not encode: {e}"))?;

        emitted.push(serde_json::json!({
            "shape": shape,
            "bundle_hex": hex(&built.bytes),
            "report_len": canonical.len(),
            "report_hex": hex(&canonical),
        }));
    }

    let corpus = serde_json::json!({
        "source": VECTOR_DOC,
        "options": "VerifyOptions::new()",
        "cases": emitted,
    });
    let text = serde_json::to_string(&corpus).map_err(|e| format!("cannot encode corpus: {e}"))?;
    if let Some(parent) = PathBuf::from(out).parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    fs::write(out, text).map_err(|e| format!("cannot write {out}: {e}"))?;
    Ok(cases.len())
}

/// Lowercase hex.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('?'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('?'));
    }
    out
}
