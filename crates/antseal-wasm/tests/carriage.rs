//! The report-carriage rule, over THIS crate's sources.
//!
//! `antseal-core`'s own scan (`tests/verify_orchestration.rs`) is pointed at
//! exactly one file — `src/verify/orchestration.rs` — so it says nothing about
//! any other carriage path. This crate is a **second** carriage path for the
//! same bytes: the report leaves core as `Vec<u8>` and leaves this crate as a
//! JS string, and a `serde_json::Value` anywhere between the two would
//! alphabetize the keys and destroy D29 rule 1's declaration order (D65 §5).
//! So the rule is re-asserted here, over this crate, rather than assumed.
//!
//! # The one exception, and why it is not a hole
//!
//! `src/online.rs` **must** parse: its input is the page's pre-fetched
//! endpoint responses, which arrive as text. That is a parse of an INPUT
//! document, never of a report, and the exception is scoped to that one file
//! by name — `src/api.rs`, which is the file the report bytes actually pass
//! through, may name none of the refused shapes at all.

use std::fs;
use std::path::{Path, PathBuf};

/// This crate's source directory.
fn src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The shapes D65 §5 refuses on a report path, with the reason each is
/// refused — the message a future reader gets.
const REFUSED: &[(&str, &str)] = &[
    (
        "serde_json::Value",
        "D65 §5: a `Value` anywhere in the carriage path alphabetizes the report",
    ),
    (
        "serde_json::from_slice",
        "D65: the boundary must not re-parse the report it hands over",
    ),
    (
        "serde_json::from_str",
        "D65: the boundary must not re-parse the report it hands over",
    ),
    (
        "serde_wasm_bindgen",
        "D18 §5 R5: a second serialization path; the module returns bytes, never a structured value",
    ),
    (
        "from_serde",
        "D18 §5 R5: `JsValue::from_serde` is the same second path under another name",
    ),
];

/// The one file allowed to parse — and it parses INPUT, never a report.
const PARSE_SITE: &str = "online.rs";

/// Non-comment lines of `text` containing `needle`, as `label:line`.
///
/// Comment lines are skipped for the reason `antseal-core`'s sibling scan
/// skips them: a prose mention of a refused shape is documentation, and this
/// crate's module docs **must** be able to name the trap.
fn occurrences(label: &str, text: &str, needle: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !(trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("//!"))
        })
        .filter(|(_, line)| line.contains(needle))
        .map(|(number, _)| format!("{label}:{}", number + 1))
        .collect()
}

/// Every `.rs` file under `dir`, recursively.
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}

#[test]
fn the_boundary_never_reparses_the_report_it_hands_over() {
    let files = walk(&src());
    // Anti-vacuity: a walk that finds nothing would pass every assertion
    // below, and this crate's whole surface is four modules.
    assert!(
        files.len() >= 4,
        "the source walk found {} file(s) — the walk is broken, not the crate clean",
        files.len()
    );

    let mut offenders = Vec::new();
    for path in &files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for (needle, why) in REFUSED {
            // `online.rs` parses the page's INPUT document; that is what it is
            // for, and it touches no report byte.
            if name == PARSE_SITE && needle.starts_with("serde_json::from_") {
                continue;
            }
            for hit in occurrences(&name, &text, needle) {
                offenders.push(format!("{hit}: `{needle}` — {why}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the wasm boundary names a refused carriage shape:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_file_that_carries_the_report_parses_nothing_at_all() {
    // Stronger than the scan above, and scoped to the one file the report
    // bytes pass through: `api.rs` may name NONE of the refused shapes,
    // including the input-parse exception.
    let path = src().join("api.rs");
    let text = fs::read_to_string(&path).expect("api.rs must be readable");
    assert!(
        text.contains("pub fn verify_json"),
        "the scan is pointed at the wrong file: {} does not define `verify_json`",
        path.display()
    );
    for (needle, why) in REFUSED {
        assert!(
            occurrences("api.rs", &text, needle).is_empty(),
            "api.rs carries the report bytes and must name `{needle}` nowhere — {why}"
        );
    }
}

#[test]
fn the_carriage_scan_catches_a_planted_round_trip() {
    // The scan must be able to fail: a green result on the real tree proves
    // nothing about the predicate, so the predicate runs against a corpus with
    // a planted round trip — and against a prose mention it must ignore.
    let planted = "\
        pub fn verify_json(bundle: &[u8]) -> String {\n\
        \x20   let parsed: serde_json::Value = serde_json::from_slice(bytes).unwrap_or_default();\n\
        \x20   serde_json::to_string(&parsed).unwrap_or_default()\n\
        }\n\
        // a `serde_json::Value` round trip would alphabetize the report\n";
    assert_eq!(
        occurrences("planted.rs", planted, "serde_json::Value"),
        vec!["planted.rs:2"],
        "the scan must catch the code literal and ignore the prose mention"
    );
    assert_eq!(
        occurrences("planted.rs", planted, "serde_json::from_slice"),
        vec!["planted.rs:2"]
    );
    // …and it must find nothing in a boundary that carries the bytes properly.
    let correct = "pub fn verify_json(b: &[u8]) -> String { utf8(outcome.report_bytes()) }\n";
    for (needle, _) in REFUSED {
        assert!(
            occurrences("correct.rs", correct, needle).is_empty(),
            "the scan flagged a correct carriage on `{needle}`"
        );
    }
}

#[test]
fn the_js_surface_stays_closed_at_five_exports_plus_the_panic_hook() {
    // D18 §5 R4 closes the public JS surface and says additions are "a
    // decision, not a code change". `scripts/wasm-boundary.mjs` asserts the
    // same thing against the built module — but that runs only where node and
    // the wasm toolchain exist, so the rule would be unguarded in the ordinary
    // `cargo test --workspace` gate. This is a source-level guard for the same
    // property, and it is the one that runs everywhere.
    let text = fs::read_to_string(src().join("boundary.rs")).expect("boundary.rs must be readable");
    assert!(
        text.contains("#[wasm_bindgen(start)]"),
        "the scan is pointed at the wrong file: no panic-hook start function here"
    );
    // Comment lines are skipped for the same reason the carriage scan skips
    // them, and it is not hypothetical here: this file's own module doc names
    // the attribute in prose, so a raw substring count reports six.
    let exports = occurrences("boundary.rs", &text, "#[wasm_bindgen]").len();
    assert_eq!(
        exports, 5,
        "the JS surface is CLOSED at five entries plus the panic hook (D18 §5 R4, \
         opened by one and closed again by D130 §3 R1): `verify`, the \
         online-evidence entry, the rung datum, the build info and the rendered \
         document. A SIXTH export is a decision, not a code change — and a \
         self-hash entry point is forbidden outright (D63 §11.3)."
    );
    // The whole surface must be target-gated: an item that escaped the gate
    // would put wasm-bindgen into the native gate's compilation (D18 §5 R3).
    assert!(
        walk(&src()).iter().all(|path| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            name == "boundary.rs"
                || !fs::read_to_string(path)
                    .unwrap_or_default()
                    .contains("#[wasm_bindgen")
        }),
        "every `#[wasm_bindgen]` item must live in boundary.rs, which is the only \
         module compiled under cfg(target_arch = \"wasm32\")"
    );
}

#[test]
fn the_storage_linkage_layer_is_never_suppressed_here() {
    // D128 §3 R5 closes `without_storage_linkage`'s caller list at two
    // committed-exhibit generators, and R22's binding is named as a
    // non-caller. A literal scan is what makes that structural: the export
    // takes no options, so a suppressed layer could only arrive by this crate
    // building one.
    for path in walk(&src()) {
        let text = fs::read_to_string(&path).unwrap_or_default();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        assert!(
            occurrences(&name, &text, "without_storage_linkage").is_empty(),
            "{name} calls `without_storage_linkage` — the page has no flag to opt in with, \
             and spec line 38 names this layer as its entire storage story (D128 §3 R5)"
        );
    }
}
