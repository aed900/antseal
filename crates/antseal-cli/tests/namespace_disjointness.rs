//! **Q77's second leg** — the two stable kebab-case namespaces this project
//! publishes are disjoint, and the one reserved spelling stays reserved.
//!
//! # The two namespaces, and why nothing compared them
//!
//! - **Error codes** (`docs/testing/error-code-contract.md`), frozen in
//!   `testdata/error-codes/v1/CODES.txt`. A code is a *rejection class*: what
//!   was wrong with the bytes. Tamper rows bind to it, `--json` verdicts carry
//!   it, third-party verifiers compare against it.
//! - **U2's `ErrorClass` names**, frozen by the module table in
//!   `antseal_cli::error` and by `tests/exit_codes.rs`. A class is a *process
//!   outcome*: what the CLI did, paired with a fixed exit code.
//!
//! Each is checked within itself. The **pair** was checked by nobody: the
//! contract's own §2 records that the global distinctness rule deliberately
//! does not run across them, and Q80 measured the intersection **by hand**
//! (28 class names, zero intersection) and wrote *"not yet machine-checked —
//! Q77"*. This is that check.
//!
//! # Why it lives here and must not move
//!
//! `antseal-core` cannot see `CliError`, so a version of this inside
//! `error_universe.rs` would have to hardcode the 28 class names — and a
//! hardcoded copy of the thing under test is not a comparison, it is a second
//! place to forget. This test target can see both: the class table through the
//! `antseal_cli` dev-dependency, and the committed universe on disk.
//!
//! # The reservation this makes load-bearing
//!
//! `ErrorClass::AnchorGateAbort` renders as `anchor-gate-abort` (exit 22).
//! With the A domain registered under `anchor-` and 52 codes appended at A52,
//! that stem is now shared between the two namespaces at one spelling. §2
//! reserves it: **the A domain must never mint `anchor-gate-abort` as a
//! code.** D91 §5 made the reservation load-bearing by answering Q80's
//! argument for the `ots-`/`tsa-` split with the measurement that the split
//! would have shared a stem with the vault's live anchor slot names at *every*
//! code. A reservation nothing enforces is a comment; this enforces it.

use std::collections::BTreeSet;

use antseal_cli::error::ErrorClass;

/// The committed error-code universe (this crate sits at `crates/antseal-cli`).
const SNAPSHOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/error-codes/v1/CODES.txt"
);

/// Q80's measurement, pinned. `ErrorClass::ALL` is `[ErrorClass; 28]`, so this
/// is a second, independent statement of the same number: the array's own
/// length is a compile-time fact the module can change silently, and a
/// disjointness test over a shrunken set is a test that passes more easily.
const PINNED_CLASS_COUNT: usize = 28;

/// The spelling §2 reserves against the A domain.
const RESERVED_STEM: &str = "anchor-gate-abort";

/// Members of `a` that are also in `b`. Pure, so the planted-fault test below
/// needs neither a scratch file nor a fabricated `ErrorClass`.
fn intersection<'a>(a: &BTreeSet<&'a str>, b: &BTreeSet<&'a str>) -> Vec<&'a str> {
    a.intersection(b).copied().collect()
}

fn committed_codes(text: &str) -> BTreeSet<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

fn class_names() -> BTreeSet<&'static str> {
    ErrorClass::ALL.iter().map(|c| c.name()).collect()
}

/// **The gate.** No `ErrorClass` name is an error code, and no error code is
/// an `ErrorClass` name.
///
/// Cannot pass vacuously: both sets are asserted non-empty, the class set is
/// asserted at its pinned size, and the code set is asserted to be the real
/// one (it must contain a code from a family that is not A's, so a snapshot
/// truncated to nothing — or to only the A domain — fails here rather than
/// passing the disjointness trivially).
#[test]
fn error_codes_and_exit_class_names_are_disjoint() {
    let text = std::fs::read_to_string(SNAPSHOT)
        .unwrap_or_else(|e| panic!("cannot read testdata/error-codes/v1/CODES.txt: {e}"));
    let codes = committed_codes(&text);
    let classes = class_names();

    assert!(
        codes.len() > 100,
        "the committed universe parsed to {} code(s) — a disjointness check against a set \
         that small is not the check it claims to be",
        codes.len()
    );
    assert!(
        codes.contains("cbor-duplicate-map-key") && codes.contains("anchor-ots-bad-magic"),
        "the snapshot is missing codes this test uses as anchors; it is not the real universe"
    );
    assert_eq!(
        classes.len(),
        PINNED_CLASS_COUNT,
        "U2's class table changed size. That is allowed — but it is a deliberate event, and \
         this number is the one Q80 measured the intersection against"
    );

    let shared = intersection(&codes, &classes);
    assert!(
        shared.is_empty(),
        "these strings are BOTH a stable error code and a U2 exit-class name: {shared:?}\n\n\
         The two namespaces answer different questions — a code is a rejection class (what \
         was wrong with the bytes), a class is a process outcome (what the CLI did) — and a \
         `--json` consumer reads `error.class` while a verdict consumer reads the code. One \
         string meaning both is the one case where that distinction silently fails \
         (docs/testing/error-code-contract.md §2)."
    );
}

/// **The reservation, enforced.** `anchor-gate-abort` is a class name and must
/// never become a code.
///
/// Separate from the disjointness gate on purpose: that gate would catch this
/// too, but it would catch it as one anonymous member of a list, and this
/// reservation has a decision behind it (§2, D91 §5) that a reader of the
/// failure needs to be sent to.
#[test]
fn the_reserved_anchor_stem_is_a_class_name_and_never_a_code() {
    let text = std::fs::read_to_string(SNAPSHOT)
        .unwrap_or_else(|e| panic!("cannot read testdata/error-codes/v1/CODES.txt: {e}"));

    assert!(
        class_names().contains(RESERVED_STEM),
        "`{RESERVED_STEM}` is no longer a U2 class name, so the reservation in \
         docs/testing/error-code-contract.md §2 now protects nothing — either restore it or \
         retire the reservation deliberately"
    );
    assert!(
        !committed_codes(&text).contains(RESERVED_STEM),
        "`{RESERVED_STEM}` has been minted as an error code. §2 reserves this spelling \
         against the A domain: U2 already renders `ErrorClass::AnchorGateAbort` as exactly \
         this string (exit 22), and a reader cannot tell one namespace's use of it from the \
         other's. If A needs to name that outcome, it mints a distinct code."
    );
}

// ─────────────────────────────────────────────────────────────────────
// tests of the tests
// ─────────────────────────────────────────────────────────────────────

/// The comparator reports a shared string and stays quiet on disjoint sets.
#[test]
fn the_disjointness_comparator_reports_a_collision() {
    let codes: BTreeSet<&str> = ["anchor-ots-bad-magic", "network-failure"]
        .into_iter()
        .collect();
    let classes: BTreeSet<&str> = ["network-failure", "usage"].into_iter().collect();
    assert_eq!(
        intersection(&codes, &classes),
        vec!["network-failure"],
        "a string in both namespaces must be named — this is the S-domain shape §2 rules \
         out: `network-failure` is an S outcome wearing U's identity, and it must never \
         also be a code"
    );
    assert!(
        intersection(
            &["anchor-ots-bad-magic"].into_iter().collect(),
            &["usage"].into_iter().collect()
        )
        .is_empty()
    );
}

/// The snapshot parser drops comments and blanks and nothing else, so a code
/// cannot be hidden from this check by indenting it.
#[test]
fn the_snapshot_parser_ignores_only_comments_and_blank_lines() {
    assert_eq!(
        committed_codes("# header\n\n  spaced-code  \nplain-code\n#anchor-gate-abort\n"),
        ["spaced-code", "plain-code"].into_iter().collect()
    );
}
