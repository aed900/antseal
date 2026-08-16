//! **R87 — the docs that described C14 as pending, and the claim that says
//! "not on chain" without naming one.**
//!
//! Three shipped rustdocs stated as future what the tree had already done,
//! and one of them was a *renderer's* stated source of wording
//! (`verify::wording::signature_scheme_label`). Correcting prose is cheap;
//! keeping it corrected is what needs a test, because nothing in a compiler
//! reddens when a sentence stops being true.
//!
//! # Two halves, and only one of them is about text
//!
//! **The behavioural half** ([`r87_no_catalogue_bundle_verifies_to_the_not_evaluated_scheme`])
//! is the one with teeth. `report.rs`'s corrected doc claims that no
//! production path writes [`SignatureScheme::NotEvaluated`] into a report;
//! that is a claim about the pipeline, so it is checked by running the
//! pipeline over every committed shape rather than by reading the source. If
//! stage 5 ever becomes conditional again, this reddens and the prose does
//! not have to be re-audited to find out.
//!
//! **The textual half** sweeps `crates/**/*.rs` for the falsified sentences
//! and asserts the corrected ones are present. Presence is asserted, not just
//! absence, so deleting a correction reddens instead of passing quietly —
//! `verdict_wording.rs`'s `RESIDUE` idiom, for the same reason it gives: an
//! assertion that can only fail one way tests nothing about the other.
//!
//! # The scan flattens comment syntax before it searches
//!
//! A doc sentence wraps across `///` lines, so a line-by-line `contains` finds
//! only the sentences that happen to fit. Every file is flattened — comment
//! markers stripped, whitespace runs collapsed — with a byte→line map kept
//! beside it, so a needle split across three lines is still found and the
//! failure message still names the line it starts on.
//!
//! # What is deliberately still open
//!
//! [`OPEN_SITES`] carries the one over-claiming doc R87 did **not** repair:
//! `antseal-anchor`'s `ArbitrumConfirmation::Absent`, which sits outside the
//! crate this wave's wording lane was scoped to write. It is asserted
//! **present**, so the list cannot rot: whoever fixes that doc turns this test
//! red and must delete the entry in the same act, which is the point.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use antseal_core::test_util::bundle_fixtures::{build, shapes};
use antseal_core::verify::report::SignatureScheme;
use antseal_core::verify::{VerifyOptions, verify_bundle};

/// The workspace root (this crate sits at `crates/antseal-core`).
const WORKSPACE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// This file, which necessarily spells every sentence it bans.
///
/// Exempted by name and the exemption is *counted*, so renaming the file
/// cannot silently un-guard it — it makes the count wrong instead.
const SCAN_SITE: &str = "r87_doc_currency.rs";

/// Sentences the tree said and no longer may. Each is the doc R87 replaced,
/// with the reason it was false.
const FALSIFIED: &[(&str, &str)] = &[
    (
        "C14 supplies the datum at integration",
        "C14 landed: the pipeline's stage 5 runs `check_signatures` \
         unconditionally and its result is `WorkMetadata::signature_scheme`",
    ),
    (
        "Once C14 lands it becomes",
        "C14 has landed; a doc written in the future tense about a shipped \
         stage instructs the reader wrongly",
    ),
    (
        "Signature stage not yet wired",
        "the stage is wired; the variant survives as frozen report-v1 \
         surface, not as an integration slot",
    ),
    (
        "is a stage that has not run",
        "the stage runs on every verify — this was the claim the renderer's \
         own doc took its instruction from",
    ),
    (
        "Both endpoints agreed the transaction is not on chain",
        "D137 §3 R1: absence from *every* chain is not what two endpoints on \
         one chain establish — the sentence must not make the universal claim",
    ),
];

/// Doc sites that still carry a [`FALSIFIED`] sentence, each with the reason
/// it was left. **Asserted present**: a stale entry is a red, never a silent
/// pass.
const OPEN_SITES: &[(&str, &str, &str)] = &[(
    "crates/antseal-anchor/src/arbitrum/confirm.rs",
    "Both endpoints agreed the transaction is not on chain",
    "`ArbitrumConfirmation::Absent` — the fourth R87 site. Outside the write \
     scope of the lane that repaired the other three; the corrected wording \
     is `ReceiptConfirmation::NotOnChain`'s, which this crate does carry",
)];

/// The corrections, asserted **present** at the file that must carry them.
const CORRECTED: &[(&str, &str, &str)] = &[
    (
        "crates/antseal-core/src/verify/report.rs",
        "# Six fields; two of them are verifier statements",
        "the count R73 measured as one; C14 made it two and the heading sat \
         one paragraph above the field that falsified it",
    ),
    (
        "crates/antseal-core/src/verify/report.rs",
        "C14 has landed and supplies the datum on every verify",
        "`WorkMetadata::signature_scheme`'s field doc — the sentence the \
         renderer's comment used to copy",
    ),
    (
        "crates/antseal-core/src/verify/report.rs",
        "Representable, serialized, and produced by no production path",
        "`SignatureScheme::NotEvaluated`'s own doc: what it is, so a reader \
         does not conclude it is dead and delete frozen wire surface",
    ),
    (
        "crates/antseal-core/src/verify/wording.rs",
        "cited here by symbol and deliberately not restated",
        "`signature_scheme_label`'s derivation now points at the variant's \
         doc instead of copying it — copying is how the stale claim reached \
         a rendered string",
    ),
    (
        "crates/antseal-core/src/anchor/model.rs",
        "no receipt for this transaction hash",
        "`ReceiptConfirmation::NotOnChain`, re-spelled on D137 §3 R8's \
         corrected wording",
    ),
];

/// **The claim with teeth**: `report.rs` says no production path writes
/// `NotEvaluated` into a report, so the pipeline is run and asked.
///
/// What reddens it: making stage 5 conditional; returning `NotEvaluated` from
/// `check_signatures` for any policy; a catalogue that stops exercising both
/// production labels (which would let a stage that returns a constant pass).
#[test]
fn r87_no_catalogue_bundle_verifies_to_the_not_evaluated_scheme() {
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    let mut checked = 0usize;

    for case in shapes::catalogue() {
        let fixture = build(&case.spec, &case.selection);
        let report = verify_bundle(&fixture.bytes, &VerifyOptions::new())
            .unwrap_or_else(|err| panic!("{}: catalogue fixture must verify: {err:?}", case.name));

        assert_ne!(
            report.work.signature_scheme,
            SignatureScheme::NotEvaluated,
            "{}: stage 5 produced `not-evaluated`, which `WorkMetadata::signature_scheme`'s \
             corrected doc says no production path can — either the stage became conditional \
             again or the doc is wrong again",
            case.name
        );

        seen.insert(report.work.signature_scheme.wire_name());
        checked += 1;
    }

    assert!(
        checked > 0,
        "the catalogue drive verified nothing — the walk is broken, not the pipeline clean"
    );
    assert!(
        seen.contains("hybrid-pq") && seen.contains("ed25519-only"),
        "the catalogue must exercise both production labels or a stage returning one constant \
         would pass this test; saw {seen:?} over {checked} case(s)"
    );
    assert!(
        !seen.contains("not-evaluated"),
        "census disagrees with the per-case assertion above: {seen:?}"
    );
}

/// No doc under `crates/` still states a [`FALSIFIED`] sentence, except the
/// enumerated [`OPEN_SITES`].
#[test]
fn r87_no_doc_in_crates_still_states_a_falsified_sentence() {
    let mut offenders = Vec::new();
    let mut scanned = 0usize;
    let mut exempted = 0usize;

    for path in rust_sources(&Path::new(WORKSPACE_ROOT).join("crates")) {
        if path.ends_with(SCAN_SITE) {
            exempted += 1;
            continue;
        }
        let text = read(&path);
        scanned += 1;
        let (flat, line_of) = flatten(&text);
        let relative = relative_to_workspace(&path);

        for (needle, reason) in FALSIFIED {
            let Some(at) = flat.find(needle) else {
                continue;
            };
            if OPEN_SITES
                .iter()
                .any(|(site, open_needle, _)| relative == *site && open_needle == needle)
            {
                continue;
            }
            offenders.push(format!(
                "{relative}:{}: \"{needle}\" — {reason}",
                line_of[at]
            ));
        }
    }

    assert!(
        scanned > 0,
        "the doc sweep found no files — the walk is broken, not the docs clean"
    );
    assert_eq!(
        exempted, 1,
        "exactly one file defines these needles and must be exempt; {exempted} were skipped, so \
         `SCAN_SITE` no longer names this file and the sweep is checking itself"
    );
    assert!(
        offenders.is_empty(),
        "falsified doc sentences found in {scanned} scanned files:\n  {}",
        offenders.join("\n  ")
    );
}

/// Every [`OPEN_SITES`] entry still carries its sentence, and every
/// [`CORRECTED`] entry still carries its correction.
///
/// Both directions matter. Without the first, a fixed site leaves a stale
/// exemption that un-guards the file forever. Without the second, deleting a
/// correction passes the absence sweep silently — absence of the old sentence
/// is not presence of the new one.
#[test]
fn r87_the_open_sites_and_the_corrections_are_both_asserted_present() {
    let mut missing = Vec::new();

    for (site, needle, reason) in OPEN_SITES {
        let (flat, _) = flatten(&read(&Path::new(WORKSPACE_ROOT).join(site)));
        if !flat.contains(needle) {
            missing.push(format!(
                "{site}: no longer says \"{needle}\" — the R87 residue was repaired ({reason}); \
                 delete this `OPEN_SITES` entry in the same act, or the sweep stays blind to \
                 that file"
            ));
        }
    }

    for (site, needle, reason) in CORRECTED {
        let (flat, _) = flatten(&read(&Path::new(WORKSPACE_ROOT).join(site)));
        if !flat.contains(needle) {
            missing.push(format!(
                "{site}: the R87 correction is gone — expected \"{needle}\" ({reason})"
            ));
        }
    }

    assert!(
        missing.is_empty(),
        "{} asserted-present sentence(s) not found:\n  {}",
        missing.len(),
        missing.join("\n  ")
    );
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("{}: cannot read source: {err}", path.display()))
}

fn relative_to_workspace(path: &Path) -> String {
    let root = fs::canonicalize(WORKSPACE_ROOT).expect("the workspace root resolves");
    let full = fs::canonicalize(path).expect("a scanned file resolves");
    full.strip_prefix(&root)
        .unwrap_or(&full)
        .to_string_lossy()
        .into_owned()
}

/// Flatten a source file so a wrapped doc sentence is one string: comment
/// markers stripped, whitespace runs collapsed to a single space.
///
/// Returns the flattened text and a **per-byte** map back to source line
/// numbers, so a hit reports where it starts rather than only which file it
/// was in.
fn flatten(text: &str) -> (String, Vec<usize>) {
    let mut flat = String::new();
    let mut line_of: Vec<usize> = Vec::new();

    let mut push = |ch: char, line: usize, flat: &mut String| {
        flat.push(ch);
        for _ in 0..ch.len_utf8() {
            line_of.push(line);
        }
    };

    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim_start();
        let body = trimmed
            .strip_prefix("//!")
            .or_else(|| trimmed.strip_prefix("///"))
            .or_else(|| trimmed.strip_prefix("//"))
            .unwrap_or(trimmed);

        for ch in body.chars() {
            if ch.is_whitespace() {
                if !flat.ends_with(' ') {
                    push(' ', line, &mut flat);
                }
            } else {
                push(ch, line, &mut flat);
            }
        }
        if !flat.ends_with(' ') {
            push(' ', line, &mut flat);
        }
    }

    (flat, line_of)
}

/// Every `.rs` file under `dir`, recursively (skipping `target/`).
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(err) => panic!("{}: cannot read directory: {err}", current.display()),
        };
        for entry in entries {
            let path = entry
                .unwrap_or_else(|err| panic!("{}: cannot read entry: {err}", current.display()))
                .path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}
