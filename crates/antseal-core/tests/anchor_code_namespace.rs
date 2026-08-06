//! **A41** — D91's namespace ruling, checked where no enumerator sweep can
//! look: the committed **artifacts**.
//!
//! # What this adds that Q77 cannot
//!
//! Q77's prefix sweep (`error_universe`) quantifies over the exemplar
//! enumerators, so it sees every code an error *enum* can emit and nothing
//! else. Three of the four places D91's ruling can be undone are outside that
//! set:
//!
//! 1. **`testdata/tamper/MATRIX.json`.** A row's `expected` is a free string.
//!    A pending row expecting `ots-ops-do-not-commit-anchor-digest` would be
//!    accepted by the completeness checker (which compares outcome keys for
//!    distinctness, not for prefix) and would bind the losing spelling to a
//!    permanent row id — §3's *"a code is permanent from the moment a tamper
//!    row … binds to one"*, run in reverse.
//! 2. **`testdata/error-codes/v1/CODES.txt`.** The Q52 gate catches a code
//!    that is committed and not live; it has nothing to say about the
//!    *namespace* a committed code sits in.
//! 3. **Rust sources outside an exemplar list** — a `const` code, a doc
//!    example, a hand-written `match` arm added beside `code()` rather than
//!    inside it. `EmbeddedHeader::UNCOMMITTED_CODE` is proof that A codes
//!    really do live outside error enums.
//!
//! # The ruling, restated as three claims
//!
//! - **D91 §6.1** — the A domain has one prefix, `anchor-`; `ots-` and `tsa-`
//!   are closed as not-taken, in this wave and any later one.
//! - **D91 §6.2** — the digest-commitment check is `anchor-ots-digest-mismatch`
//!   and D58 §10.4's `ots-ops-do-not-commit-anchor-digest` is **never minted**.
//! - **D91 §6.3** — measured at the ruling, the losing spelling appeared six
//!   times and *"not one of them is code"*. That count is now stale in a
//!   harmless direction and the correction is recorded here rather than left
//!   to be rediscovered: it appears in Rust **twice**, and both are guards
//!   that exist to forbid it ([`GUARD_SITES`]). A guard has to spell what it
//!   bans.
//!
//! # A text-level ban on the fixtures would go red on the ruling's own words
//!
//! The first cut of this file scanned `testdata/**` for the losing spelling as
//! raw text. It failed immediately, on `testdata/tamper/MATRIX.json` line 466
//! — inside the `why` of the very cell D91 §9.1 fills, whose **verbatim**
//! authorised text reads *"D91 section 6.2 rules that
//! `anchor-ots-digest-mismatch` is its code and D58's
//! `ots-ops-do-not-commit-anchor-digest` is never minted"*. A record of a
//! ruling has to spell what the ruling forbids, exactly as a guard does.
//!
//! So the split is structural, not textual: the **code-bearing** fields of the
//! committed artifacts are checked (`expected`, and every line of `CODES.txt`)
//! and their prose fields are not. A checker that could not tell a mint from a
//! record would have had to be weakened or deleted the first time either was
//! written correctly.
//!
//! # What is deliberately *not* banned
//!
//! `ots-` and `tsa-` are closed as **error-code** prefixes only. Three live
//! namespaces legitimately spell them and are not touched:
//!
//! - the vault's anchor **slot names**, `ots-pending` and `tsa-0.der` (U9's
//!   store) — D91 §5 measured nine occurrences and used them as the argument
//!   that inverted Q80's;
//! - `MATRIX.json`'s **case and family ids** (`ots-digest-mismatch`,
//!   `tsa-imprint-mismatch`, `tsa-chain-expiry`), named by D53 §8. Row ids and
//!   case ids are permanent handles in their own namespace, and D91 §9.1 is
//!   explicit that *"no row id changes, since a prefix ruling renames no
//!   row"*. This file therefore reads `expected`, never `id` — narrowing it to
//!   the code namespace is what keeps it from demanding a rename the ruling
//!   does not authorise;
//! - a thread name (`ots-depth`) in A11's stack-depth test.
//!
//! That distinction is the whole reason this is a targeted scan rather than a
//! grep for `"ots-`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The workspace root (this crate sits at `crates/antseal-core`).
const WORKSPACE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// D91 §6.2's losing spelling. Never minted, in this wave or any later one.
const NEVER_MINTED: &str = "ots-ops-do-not-commit-anchor-digest";

/// D91 §6.1's closed prefixes. A code may not begin with either.
const CLOSED_PREFIXES: [&str; 2] = ["ots-", "tsa-"];

/// Files that necessarily contain [`NEVER_MINTED`] because they are the
/// guards that forbid it, each with the reason it is exempt.
///
/// Kept to *guards*, exactly as `tests/identifier_bans.rs` keeps its
/// enforcement-site list: a file that merely wants to discuss the losing
/// spelling belongs in Markdown, which this scan does not read.
const GUARD_SITES: &[(&str, &str)] = &[
    (
        "crates/antseal-core/tests/anchor_code_namespace.rs",
        "this file defines the ban",
    ),
    (
        "crates/antseal-core/src/anchor/ots/error.rs",
        "`the_losing_digest_code_spelling_is_never_minted` asserts no OtsError \
         code equals it",
    ),
    (
        "crates/antseal-core/src/anchor/ots/tests.rs",
        "A11's codec suite asserts the same thing from the parse surface",
    ),
];

// ─────────────────────────────────────────────────────────────────────
// pure comparators — so the planted faults below need no scratch tree
// ─────────────────────────────────────────────────────────────────────

/// Codes carrying a prefix D91 §6.1 closed.
///
/// Split out as a pure function over an iterator because the artifacts it
/// runs on cannot be mutated at test time: a checker never observed failing
/// proves nothing, and planting the fault in the artifact would mean writing
/// to the committed tree.
fn foreign_prefixed<'a>(codes: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    codes
        .into_iter()
        .filter(|code| CLOSED_PREFIXES.iter().any(|p| code.starts_with(p)))
        .collect()
}

/// 1-based line numbers on which `needle` occurs in `text`.
fn lines_containing(text: &str, needle: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| line.contains(needle))
        .map(|(i, _)| i + 1)
        .collect()
}

// ─────────────────────────────────────────────────────────────────────
// the scans
// ─────────────────────────────────────────────────────────────────────

/// Every file under `dir` with one of `extensions`, recursively.
fn files_with(dir: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|n| n == "target" || n == ".git")
            {
                continue;
            }
            out.extend(files_with(&path, extensions));
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| extensions.contains(&e))
        {
            out.push(path);
        }
    }
    out.sort();
    out
}

fn repo_relative(path: &Path) -> String {
    let root = fs::canonicalize(WORKSPACE_ROOT).unwrap_or_else(|_| PathBuf::from(WORKSPACE_ROOT));
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    canonical
        .strip_prefix(&root)
        .unwrap_or(&canonical)
        .to_string_lossy()
        .replace('\\', "/")
}

/// **D91 §6.2.** The losing spelling is minted in no Rust source, outside the
/// guards that ban it.
///
/// The failure mode this exists for is a hand edit: D58 §10.3's check-order
/// table and §10.4's code list still carry the spelling — correctly, since a
/// resolved decision is amended and never rewritten — so it remains one
/// copy-paste away from an implementer who reads D58 without reading its
/// amendment.
///
/// Rust only. The committed artifacts are checked structurally instead, for
/// the reason in the module docs: their prose fields quote the ruling.
#[test]
fn the_losing_digest_spelling_is_minted_in_no_rust_source() {
    let root = PathBuf::from(WORKSPACE_ROOT);
    let mut scanned = 0_usize;
    let mut offenders: Vec<String> = Vec::new();

    let targets = files_with(&root.join("crates"), &["rs"]);

    for path in &targets {
        let Ok(bytes) = fs::read(path) else { continue };
        scanned += 1;
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let hits = lines_containing(text, NEVER_MINTED);
        if hits.is_empty() {
            continue;
        }
        let rel = repo_relative(path);
        if GUARD_SITES.iter().any(|(site, _)| *site == rel) {
            continue;
        }
        offenders.push(format!("  {rel} (line(s) {hits:?})"));
    }

    assert!(
        scanned > 200,
        "the scan reached only {scanned} file(s); it is not looking at the tree"
    );
    assert!(
        offenders.is_empty(),
        "`{NEVER_MINTED}` is D58 §10.4's spelling and D91 §6.2 rules that it is NEVER minted \
         — the digest-commitment check is `anchor-ots-digest-mismatch`, to which D53 §8 \
         already binds M2 tamper row 1. Found in:\n{}\n\n\
         If you reached it from D58, read the D91 amendment at the head of its §10.4.",
        offenders.join("\n")
    );
}

/// Every guard site really does spell the banned string. Without this the
/// exemption list is a way to *hide* an occurrence: add a path, and the scan
/// above stops looking at it.
#[test]
fn every_guard_site_still_spells_the_banned_string() {
    for (site, reason) in GUARD_SITES {
        let path = PathBuf::from(WORKSPACE_ROOT).join(site);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("exempt guard site {site} is unreadable: {e}"));
        assert!(
            text.contains(NEVER_MINTED),
            "{site} is exempted from the ban ({reason}) but no longer contains \
             `{NEVER_MINTED}` — an exemption for a file that does not need one is a hole, \
             not a record. Drop the entry."
        );
    }
}

/// **D91 §6.1, in the tamper matrix.** No row's expected **code** carries a
/// closed prefix.
///
/// Reads `expected` only. Case ids and family ids are a different namespace
/// with permanent handles of their own (`ots-digest-mismatch`,
/// `tsa-imprint-mismatch`), and D91 §9.1 renames no row.
///
/// # Where the codes live now
///
/// **Corrected 2026-08-06 by A21, which broke this test by finishing its
/// job.** Every `expected` cell in `MATRIX.json` lived inside a `pending`
/// block, and A21 landed the last eight rows — so the walk now finds *zero*
/// cells and the anti-vacuity control below fired exactly as designed,
/// refusing to report green on a sweep that could no longer see anything.
///
/// That is the same shape as D96 rider (b), in a **third** instrument neither
/// of D96's planners opened: a check computed from a set A21 was about to
/// empty. The fix is the same one — follow the codes to where they now live.
/// A row's expected code is authoritative in the row itself, so the sweep
/// unions the registry's remaining cells (there may be pending cases again
/// one day) with every live row's `ErrorCode`.
///
/// Verdict states are deliberately excluded: they are a namespace separate
/// from error codes (contract §5, owned by A18/R17), and `ots-`/`tsa-` are
/// closed as **error-code** prefixes only.
#[test]
fn no_matrix_row_expects_a_code_under_a_closed_prefix() {
    use antseal_core::test_util::tamper::ExpectedOutcome;

    let path = PathBuf::from(WORKSPACE_ROOT).join("testdata/tamper/MATRIX.json");
    let text = fs::read_to_string(&path).expect("testdata/tamper/MATRIX.json must be readable");
    let doc: serde_json::Value = serde_json::from_str(&text).expect("MATRIX.json must parse");

    let mut expectations: BTreeSet<String> = BTreeSet::new();
    collect_expected(&doc, &mut expectations);
    for row in live_rows() {
        if let ExpectedOutcome::ErrorCode(code) = row.expected {
            expectations.insert(code.to_owned());
        }
    }

    // Anti-vacuity, and deliberately not a count: the sweep must reach the one
    // code D91 §9.1 fills — whether it is still a registry cell or, since A21,
    // the live row that discharges that case. A registry reorganisation that
    // hid `expected` behind a new level would satisfy any threshold and fail
    // this, and so would a row slice that stopped being linked in.
    assert!(
        expectations.contains("anchor-ots-digest-mismatch"),
        "the sweep did not reach D91 §9.1's own code — it found {expectations:?}, so it \
         could not have seen a violation either"
    );

    let owned: Vec<&str> = expectations.iter().map(String::as_str).collect();

    // Ordered before the prefix sweep on purpose. `NEVER_MINTED` begins with
    // `ots-`, so the sweep below would catch it too and this assertion would
    // be one nobody ever saw fail — the state this lane exists to remove.
    // First, and it names the ruling the sweep only implies.
    assert!(
        !owned.contains(&NEVER_MINTED),
        "a MATRIX.json row expects `{NEVER_MINTED}`. D91 §6.2 rules it is never minted, and a \
         row id is a permanent handle — binding it here would mint the losing spelling by \
         fixture, which is precisely how §3 says a code becomes permanent"
    );

    let foreign = foreign_prefixed(owned.iter().copied());
    assert!(
        foreign.is_empty(),
        "these MATRIX.json rows expect codes under a prefix D91 §6.1 closed: {foreign:?}\n\
         The A domain has one prefix, `anchor-`. A row id may keep its own spelling \
         (D91 §9.1 renames no row); its expected CODE may not."
    );
}

/// Every tamper row this target can reach — the ten slices homed in the
/// library.
///
/// F20's `anchor-schema-*` slice lives in the `tamper_matrix` target and is
/// out of reach from here; it binds `bundle-` codes, which no closed prefix
/// can match. The A-domain rows this ruling is actually about (A21's) are all
/// in the list below.
///
/// **This list is hand-maintained, which is the narrowing risk this file's
/// own docs warn about — so read what actually holds it shut.** A new slice
/// added elsewhere and not added here would silently shrink the sweep. What
/// stops that from mattering is scope: D91 §6.1 closes `ots-`/`tsa-` as **A
/// domain** prefixes, the A domain's rows are `tamper_rows_anchor_verdicts`,
/// and the caller's anti-vacuity assertion fails unless *that* slice is
/// present and reachable. A future **A** slice is the case to add here
/// deliberately; a future C/F/G/R slice is a bonus this sweep never promised.
fn live_rows() -> Vec<antseal_core::test_util::tamper::TamperRow> {
    use antseal_core::test_util::*;
    let mut rows = Vec::new();
    rows.extend_from_slice(tamper_rows_anchor_verdicts::ROWS);
    rows.extend_from_slice(tamper_rows_caps::ROWS);
    rows.extend_from_slice(tamper_rows_cbor::ROWS);
    rows.extend_from_slice(tamper_rows_crypto::ROWS);
    rows.extend_from_slice(tamper_rows_fine_tree::ROWS);
    rows.extend_from_slice(tamper_rows_format::ROWS);
    rows.extend_from_slice(tamper_rows_mirror::ROWS);
    rows.extend_from_slice(tamper_rows_pipeline::ROWS);
    rows.extend_from_slice(tamper_rows_structural::ROWS);
    rows.extend_from_slice(tamper_rows_version::ROWS);
    rows
}

/// Walk any JSON shape, collecting every `"expected"` string. Shape-agnostic
/// on purpose: a registry reorganisation must not silently narrow the scan.
fn collect_expected(value: &serde_json::Value, out: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if let (Some(text), true) = (child.as_str(), key == "expected") {
                    out.insert(text.to_owned());
                }
                collect_expected(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_expected(item, out);
            }
        }
        _ => {}
    }
}

/// **D91 §6.1, in the frozen universe.** No committed code carries a closed
/// prefix.
///
/// The Q52 gate cannot see this: it compares the committed set against the
/// live set and is silent about which namespace either sits in — which is
/// exactly the hole D91 §8 opens with.
#[test]
fn the_committed_universe_carries_no_closed_prefix() {
    let path = PathBuf::from(WORKSPACE_ROOT).join("testdata/error-codes/v1/CODES.txt");
    let text = fs::read_to_string(&path).expect("CODES.txt must be readable");
    let codes: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    assert!(
        codes.len() > 100,
        "CODES.txt parsed to {} code(s) — the check would be vacuous",
        codes.len()
    );
    let foreign = foreign_prefixed(codes);
    assert!(
        foreign.is_empty(),
        "these committed codes carry a prefix D91 §6.1 closed: {foreign:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// tests of the tests (planted faults on the pure comparators)
// ─────────────────────────────────────────────────────────────────────

/// The comparator reports a closed-prefix code and passes the ruled one.
/// D91's own example, and the shape a `starts_with(anything)` weakening
/// would break.
#[test]
fn the_prefix_comparator_catches_the_closed_namespaces() {
    assert_eq!(
        foreign_prefixed([
            "anchor-ots-digest-mismatch",
            NEVER_MINTED,
            "anchor-tsa-imprint-mismatch",
            "tsa-nonce-mismatch",
        ]),
        vec![NEVER_MINTED, "tsa-nonce-mismatch"],
        "both closed prefixes must be caught, and a code that merely CONTAINS `ots-` or \
         `tsa-` after the `anchor-` prefix must not be"
    );
    assert!(
        foreign_prefixed(["anchor-ots-bad-magic", "anchor-tsa-token-absent"]).is_empty(),
        "a kind segment inside the `anchor-` family is D91 §7.3's convention, not a violation"
    );
}

/// The line scanner finds the needle where it is and nowhere else.
#[test]
fn the_line_scanner_reports_the_lines_it_finds() {
    let text = "clean\nan ots-ops-do-not-commit-anchor-digest mention\nclean\n";
    assert_eq!(lines_containing(text, NEVER_MINTED), vec![2]);
    assert!(lines_containing("nothing here\n", NEVER_MINTED).is_empty());
}
