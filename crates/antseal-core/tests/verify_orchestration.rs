//! **R21 — the carriage rule, enforced against the source (D65 §5).**
//!
//! D65 measured a trap that no behavioural test in this crate can see: the
//! obvious U30 implementation routes the report through a `serde_json::Value`,
//! `serde_json::Map` is a `BTreeMap` in this build, so the round trip
//! alphabetizes the report's keys and destroys D29 rule 1's declaration order
//! — *with R21's D64 byte-equality row green throughout*, because that row
//! compares the library's bytes across two runs.
//!
//! R21's half of the rule is *"hand U30 the bytes, and do not pre-parse the
//! report on its behalf"*. `verify::orchestration`'s unit tests assert the
//! bytes are `to_canonical_json()`'s and demonstrate the loss on this very
//! report; this file asserts the stronger, structural half — **the module
//! that produces them names `serde_json::Value` nowhere**, so the mistake
//! cannot be reintroduced by an accessor that looks convenient.
//!
//! Scope, deliberately: the module source only, never its `tests.rs`. The
//! test module *must* name `serde_json::Value` — demonstrating the loss is
//! its job — and a scan that forbade it there would forbid the measurement
//! (`verdict_wording.rs`'s own test-file exclusion, for the same reason).

use std::fs;
use std::path::{Path, PathBuf};

/// The module whose carriage rule this file enforces.
const ORCHESTRATION_SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/orchestration.rs");

/// The needles. Each is a *parse* of the report or a `Value`-typed surface —
/// the two shapes D65 §5 refuses.
const REFUSED: &[(&str, &str)] = &[
    (
        "serde_json::Value",
        "D65 §5: the report must be handed over as bytes; a `Value` anywhere \
         in the carriage path alphabetizes it",
    ),
    (
        "serde_json::from_slice",
        "D65: the library must not pre-parse the report on U30's behalf — \
         the parse is precisely where declaration order is lost",
    ),
    (
        "serde_json::from_str",
        "D65: the library must not pre-parse the report on U30's behalf",
    ),
];

/// Non-comment lines of `path` that contain `needle`, as `path:line`.
///
/// Comment lines are skipped for `verdict_wording.rs`'s reason: a prose
/// mention of a refused shape is documentation — and this module's docs
/// **must** name it, because naming the trap is how the rule survives.
fn occurrences(path: &Path, text: &str, needle: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !(trimmed.starts_with("//") || trimmed.starts_with('*'))
        })
        .filter(|(_, line)| line.contains(needle))
        .map(|(number, _)| format!("{}:{}", path.display(), number + 1))
        .collect()
}

#[test]
fn the_orchestration_module_never_parses_the_report_it_hands_over() {
    let path = PathBuf::from(ORCHESTRATION_SRC);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "the orchestration module must be readable at {}: {e}",
            path.display()
        )
    });
    assert!(
        text.contains("pub fn report_bytes"),
        "the scan is pointed at the wrong file: {} does not define \
         `report_bytes`",
        path.display()
    );

    let mut offenders = Vec::new();
    for (needle, why) in REFUSED {
        for hit in occurrences(&path, &text, needle) {
            offenders.push(format!("{hit}: `{needle}` — {why}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "the verify orchestration names a refused carriage shape:\n  {}",
        offenders.join("\n  ")
    );
}

/// The scan must be able to fail. A nonzero result on the real tree proves
/// nothing about the predicate, so the predicate runs against a corpus with a
/// planted round trip — and against a prose mention that must be ignored.
#[test]
fn the_carriage_scan_catches_a_planted_round_trip() {
    let planted = "\
        pub fn report_bytes(&self) -> Vec<u8> {\n\
        \x20   let parsed: serde_json::Value = serde_json::from_slice(&self.bytes).expect(\"\");\n\
        \x20   serde_json::to_vec(&parsed).expect(\"\")\n\
        }\n\
        // a `serde_json::Value` round trip would alphabetize the report\n";
    let path = Path::new("planted.rs");

    assert_eq!(
        occurrences(path, planted, "serde_json::Value"),
        vec!["planted.rs:2"],
        "the scan must catch the code literal and ignore the prose mention"
    );
    assert_eq!(
        occurrences(path, planted, "serde_json::from_slice"),
        vec!["planted.rs:2"]
    );

    // …and it must find nothing in a module that carries the bytes correctly.
    let correct = "\
        pub fn report_bytes(&self) -> &[u8] {\n\
        \x20   &self.report_bytes\n\
        }\n";
    for (needle, _) in REFUSED {
        assert!(
            occurrences(path, correct, needle).is_empty(),
            "the scan flagged a correct carriage on `{needle}`"
        );
    }
}
