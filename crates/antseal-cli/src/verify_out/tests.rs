//! Unit rows for the pieces that need no bundle: the rung → class mapping's
//! shape, and the `--json` assembly's own invariants.
//!
//! Everything that needs a real `.sealproof` lives in
//! `tests/verify_command.rs`, which builds them through R6's constructor.

use super::*;

/// The renderer's indents are the house's, and they are *only* indents: this
/// module coins no sentence, so a change to a frozen string cannot be
/// absorbed here (`antseal-core`'s `verdict_wording.rs` source scan covers
/// this file, and this row states the intent the scan enforces).
#[test]
fn the_layer_label_comes_from_the_frozen_table() {
    assert_eq!(evidence_layer_label(), wording::EVIDENCE_LAYER_LABEL);
}

/// The stability sentence is D65 §3's, and it names the three stable things a
/// scripter may gate on.
#[test]
fn the_stability_note_names_what_is_stable() {
    for promised in ["exit code", "`ok`", "`v`", "`result.report`"] {
        assert!(
            JSON_STABILITY_NOTE.contains(promised),
            "the note must name {promised}: {JSON_STABILITY_NOTE}"
        );
    }
    assert!(
        JSON_STABILITY_NOTE.contains("default arm"),
        "tier A's one hole is priced, not hidden"
    );
}

/// The `text` helper refuses non-UTF-8 rather than producing a malformed
/// document — the one place a bad member could reach stdout.
#[test]
fn a_non_utf8_member_is_refused_rather_than_emitted() {
    let error = text(&[0xFF, 0xFE]).expect_err("invalid UTF-8 must not pass");
    assert_eq!(error.class(), ErrorClass::Internal);
}
