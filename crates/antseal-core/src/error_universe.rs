//! Q52 — the frozen error-code universe. The mechanism that makes decision
//! **D30**'s append-only rule enforceable instead of declared.
//!
//! # Why this exists
//!
//! `docs/testing/error-code-contract.md` §3 says a code may **never** be
//! renamed: third-party verifiers compare against the literal string, so a
//! rename silently breaks every one of them. Until Q52 that rule was enforced
//! by review discipline alone. The three enforcement layers the contract §4
//! names — per-domain distinctness meta-tests, the Q7 registry sweep, Q8
//! completeness — all check **distinctness and shape**, and *none of them can
//! see a rename*, because a renamed code is still distinct from every other
//! code and still correctly prefixed kebab-case.
//!
//! Measured at wave 7, before this file existed: **53 of the 191 codes (28 %)
//! could be renamed with a fully green suite** — 38 `manifest-`, 9 `content-`,
//! 4 `crypto-`, 2 `cbor-`. The codes that *were* safe were safe only
//! incidentally, because some committed vector, tamper row or hardcoded
//! assertion happened to spell them out; `bundle-`, `fine-root-` and R's
//! unprefixed set were covered that way and `manifest-` almost not at all.
//! Confirmed on a live sample rather than inferred: renaming
//! `manifest-empty-files` to `manifest-empty-file-list` left every one of the
//! other 705 tests green.
//!
//! (`docs/format/Q14-freeze-gate-plan.md` §2.3 states 54 of 190. Both figures
//! are one out: the universe is 191 — a prefix is not a partition of the
//! enumerators, see [`live_universe`] — and the renameable `manifest-` count
//! is 38.)
//!
//! # The mechanism
//!
//! One sorted, committed file — `testdata/error-codes/v1/CODES.txt` — holding
//! every stable code the crate can emit, collected from the
//! [`ENUMERATOR_COUNT`] per-domain enumerators. On every run the live universe
//! is recollected and compared with **additions-only** semantics:
//!
//! | change | verdict | why |
//! |---|---|---|
//! | a code is added | **pass** | D30 §3: *"Adding codes is routine and unrestricted"* |
//! | a code is removed | **fail**, naming it | a code the contract made permanent stopped existing |
//! | a code is renamed | **fail**, naming the old code | a rename *is* a removal plus an addition |
//!
//! That asymmetry is the whole design. It is the same rule
//! `scripts/vector-freeze.sh` applies to committed vector bytes (*"After Q14
//! the only legal change is an addition"*), applied to the code set.
//!
//! # Refreshing the snapshot
//!
//! ```text
//! ANTSEAL_BLESS_ERROR_CODES=1 cargo test -p antseal-core --lib -- error_universe
//! ```
//!
//! The bless path writes the **union** of the committed set and the live set,
//! never the live set alone. So blessing cannot drop a code either: the only
//! way to remove one from the snapshot is to edit the file by hand, which is a
//! reviewable act with a diff that says exactly what was given up.
//!
//! # What this does *not* pin
//!
//! Existence, not coverage. A code can be in the snapshot and be reachable by
//! no tamper row and owned by no task; the gate plan's finding **C3** records
//! that gap for the `crypto-` and `content-` families and it is `Q55`'s, not
//! this module's.
//!
//! There is also one bounded residue: a code added *and then renamed* before
//! anyone re-blesses the snapshot is invisible here, because it was never
//! committed in the first place. Blessing is therefore part of landing a new
//! code, not an afterthought — the same discipline as regenerating a vector.
//!
//! # Native-only
//!
//! The snapshot is read from disk and `wasm32-unknown-unknown` has no
//! filesystem (P14, `docs/wasm-toolchain.md`). The codes themselves are
//! target-independent — they are `&'static str` literals in `match` arms — so
//! nothing is lost by checking them on one target.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The committed snapshot, workspace-relative via the crate manifest dir so
/// it resolves on every OS and checkout location.
const SNAPSHOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/error-codes/v1/CODES.txt"
);

/// Repo-relative form, for failure messages that a reader can act on.
const SNAPSHOT_DISPLAY: &str = "testdata/error-codes/v1/CODES.txt";

/// Set this in the environment to rewrite the snapshot as the union of what
/// is committed and what is live. Named like `ANTSEAL_BLESS_VECTORS`, which
/// plays the same role for the golden-vector documents.
const BLESS_VAR: &str = "ANTSEAL_BLESS_ERROR_CODES";

/// How many per-domain enumerators the roster holds.
///
/// **Eight until A38/A52, eleven after**, and the three that arrived are all
/// one domain's: the A domain has two error families (`AnchorError` for
/// A5/A8's RFC 3161 / CMS / X.509 stage, `OtsError` for A11's `.ots` codec)
/// **and** one code that is not in an error type at all
/// (`EmbeddedHeader::UNCOMMITTED_CODE`, D56 rule O8).
///
/// D91 §8.2 requires this number to move deliberately and calls the move
/// "8 → 9", counting the A domain as one enumerator. It is **three**: D91's
/// §8.1 table was written from A5/A8's family alone, before A11's codec
/// sibling and A12's const were measured. The stake is unchanged and is the
/// reason the constant exists — a family with no roster entry freezes under
/// nothing.
/// **A18 took it to twelve** (2026-08-05). D56 §7 mints four `anchor-ots-*`
/// codes and three of them already had a home — `anchor-ots-digest-mismatch`
/// on `OtsError`, `anchor-ots-header-uncommitted` on A12's const. The two
/// **online** refutations, O6's and O7's, are raised by the state machine
/// itself and so had no enumerator until it existed; without this row they
/// would freeze under nothing, which is the exact condition D91 §8 found the
/// whole A domain in.
const ENUMERATOR_COUNT: usize = 12;

/// The per-domain enumerators, each as `(path, its own codes)`.
///
/// Splitting the collection per source — rather than folding straight into one
/// set — is what lets [`tests::the_universe_is_exactly_the_registered_enumerators`]
/// recompute the expected universe from the same calls and compare. A call
/// dropped from a fold would be invisible; a call dropped from this roster
/// changes its length.
fn by_enumerator() -> Vec<(&'static str, BTreeSet<&'static str>)> {
    vec![
        (
            "codec::decode::all_code_exemplars",
            crate::codec::decode::all_code_exemplars()
                .iter()
                .map(crate::codec::DecodeError::code)
                .collect(),
        ),
        (
            "manifest::error::all_code_exemplars",
            crate::manifest::error::all_code_exemplars()
                .iter()
                .map(crate::manifest::ManifestError::code)
                .collect(),
        ),
        (
            "bundle::error::all_code_exemplars",
            crate::bundle::error::all_code_exemplars()
                .iter()
                .map(crate::bundle::error::BundleError::code)
                .collect(),
        ),
        (
            "crypto::error::all_code_exemplars",
            crate::crypto::error::all_code_exemplars()
                .iter()
                .map(crate::crypto::CryptoError::code)
                .collect(),
        ),
        (
            "content::error::all_code_exemplars",
            crate::content::error::all_code_exemplars()
                .iter()
                .map(crate::content::ContentError::code)
                .collect(),
        ),
        (
            "canon::canon_code_exemplars",
            crate::canon::canon_code_exemplars()
                .iter()
                .map(crate::canon::CanonicalizeError::code)
                .collect(),
        ),
        (
            "content::fine_tree::error::all_code_exemplars",
            crate::content::fine_tree::error::all_code_exemplars()
                .iter()
                .map(crate::content::fine_tree::error::FineTreeError::code)
                .collect(),
        ),
        // ── A (D91 §6.1: one prefix, three sources) ──────────────────────
        (
            "anchor::error::all_code_exemplars",
            crate::anchor::error::all_code_exemplars()
                .iter()
                .map(crate::anchor::AnchorError::code)
                .collect(),
        ),
        (
            "anchor::ots::error::all_code_exemplars",
            crate::anchor::ots::all_code_exemplars()
                .iter()
                .map(crate::anchor::ots::OtsError::code)
                .collect(),
        ),
        // Not an error family: D56 rule O8's code is a `const` on A12's
        // `EmbeddedHeader`, because A12 answers one offline question and owns
        // no `AnchorState`. Registered anyway — a code no enumerator reaches
        // is a code that can be renamed with a fully green suite, which is
        // precisely what this module exists to prevent, and nothing in §1's
        // definition of a code requires it to come from a `code()` arm.
        (
            "anchor::ots::header::EmbeddedHeader::UNCOMMITTED_CODE",
            [crate::anchor::ots::EmbeddedHeader::UNCOMMITTED_CODE]
                .into_iter()
                .collect(),
        ),
        // Also not an error family, for the same reason and one step further
        // on: D56 rules O6 and O7 do not *fail*, they classify — the online
        // evidence agreed and it refuted the artifact — so their codes are
        // consts on A18's state machine. Registered here because a code no
        // enumerator reaches is a code that can be renamed with a fully green
        // suite.
        (
            "anchor::verdicts::all_code_exemplars",
            crate::anchor::verdicts::all_code_exemplars()
                .into_iter()
                .collect(),
        ),
        (
            "verify::error::all_error_exemplars",
            crate::verify::error::all_error_exemplars()
                .iter()
                .map(crate::verify::VerifyError::code)
                .collect(),
        ),
    ]
}

/// Every stable code the crate can emit, collected from the per-domain
/// enumerators and de-duplicated.
///
/// Codes legitimately appear in more than one enumerator: R's `VerifyError`
/// wrapper arms surface the **inner** code unchanged (contract §2), so every
/// `cbor-`, `crypto-`, `content-` and `fine-root-` code reachable through
/// `verify_bundle` is yielded twice — once by its owning domain and once
/// through the wrapper. The union is the universe; the duplication is the
/// contract working as specified.
///
/// The union is also strictly larger than the sum of the per-family counts a
/// reader would guess from the prefixes, because a prefix is not a partition
/// of the enumerators: `verify::error` mints `fine-root-rebuild-mismatch`
/// under G's prefix (`verify/error.rs:767`). Counting per prefix and per
/// enumerator gives different totals, which is why this function returns the
/// set rather than a number.
pub(crate) fn live_universe() -> BTreeSet<&'static str> {
    let mut codes = BTreeSet::new();
    for (_, family) in by_enumerator() {
        codes.extend(family);
    }
    codes
}

/// Codes grouped by their family prefix, for the census the gate prints.
/// D30's freeze entry (`docs/testing/error-code-contract.md` §7) records the
/// count per family at the freeze commit, and a printed census is a number
/// nobody has to maintain by hand.
///
/// It reads [`REGISTERED_PREFIXES`] rather than a literal of its own, which is
/// **Q77 / D91 §11.6**. Until then this function held a private six-element
/// list and was, in D91's words, *"presented as a census, but … the closest
/// thing the tree has to a prefix registry, and wrong by omission the moment
/// `anchor-` lands"*. It was: the run of the gate that first wired the A
/// domain printed `(unprefixed) 85` — R's 33 codes plus all 52 of A's, sorted
/// into R's bucket and printed as if they were R's, with a green suite. One
/// list now feeds both the census and the conformance gate, so the two cannot
/// drift.
fn census(codes: &BTreeSet<&'static str>) -> Vec<(&'static str, usize)> {
    let mut out: Vec<(&'static str, usize)> = REGISTERED_PREFIXES
        .iter()
        .map(|prefix| {
            (
                *prefix,
                codes.iter().filter(|code| code.starts_with(prefix)).count(),
            )
        })
        .collect();
    out.push((
        "(unprefixed)",
        codes
            .iter()
            .filter(|code| !REGISTERED_PREFIXES.iter().any(|p| code.starts_with(p)))
            .count(),
    ));
    out
}

// ─────────────────────────────────────────────────────────────────────
// Q77 — §2's namespace rules, machine-enforced (D91 §8)
// ─────────────────────────────────────────────────────────────────────
//
// §2's headline rule — *"A domain never mints a code under another domain's
// prefix"* — was enforced by **nothing**. A foreign-prefix code is pairwise
// distinct, correctly kebab-shaped and new, so all three distinctness layers
// pass it; `census` sorted it into the `"(unprefixed)"` bucket and *printed*
// it; and this module's comparison is additions-only, so it was absorbed.
// That is not hypothetical: it is how D58 came to specify sixteen codes under
// a namespace nobody had registered, with a fully green suite.

/// What prefixes one enumerator's codes may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Allowed {
    /// Exactly one prefix. Every code from this enumerator must start with it.
    Only(&'static str),
    /// Anything. Reserved for `verify::error`, whose exemplar list is a
    /// **superset of every other family's** by §2's wrapper rule — R surfaces
    /// the inner code unchanged — so it legitimately yields `cbor-`,
    /// `crypto-`, `content-`, `fine-root-` and `bundle-` codes beside its own
    /// unprefixed ones. Deliberately permissive rather than clever: an
    /// unprefixed R code and a code under an *unregistered* prefix are the
    /// same string shape, so no rule over this list can separate them. A
    /// foreign prefix is caught at the enumerator that actually mints it.
    AnyRegisteredOrUnprefixed,
}

/// §2's prefix table, transcribed — **one row per entry in
/// [`by_enumerator`], and the lookup against it is total**.
///
/// D91 §8.2 is emphatic about the totality and it is the load-bearing half: a
/// `filter_map` here would silently exempt an enumerator with no row, and the
/// enumerator without a row would be *the newly added one* — so the check
/// would go green over exactly the domain the ruling exists to constrain. An
/// unknown enumerator is therefore a failure, reported by name.
const ENUMERATOR_PREFIXES: &[(&str, Allowed)] = &[
    ("codec::decode::all_code_exemplars", Allowed::Only("cbor-")),
    (
        "manifest::error::all_code_exemplars",
        Allowed::Only("manifest-"),
    ),
    (
        "bundle::error::all_code_exemplars",
        Allowed::Only("bundle-"),
    ),
    (
        "crypto::error::all_code_exemplars",
        Allowed::Only("crypto-"),
    ),
    (
        "content::error::all_code_exemplars",
        Allowed::Only("content-"),
    ),
    ("canon::canon_code_exemplars", Allowed::Only("content-")),
    (
        "content::fine_tree::error::all_code_exemplars",
        Allowed::Only("fine-root-"),
    ),
    (
        "anchor::error::all_code_exemplars",
        Allowed::Only("anchor-"),
    ),
    (
        "anchor::ots::error::all_code_exemplars",
        Allowed::Only("anchor-"),
    ),
    (
        "anchor::ots::header::EmbeddedHeader::UNCOMMITTED_CODE",
        Allowed::Only("anchor-"),
    ),
    (
        "anchor::verdicts::all_code_exemplars",
        Allowed::Only("anchor-"),
    ),
    (
        "verify::error::all_error_exemplars",
        Allowed::AnyRegisteredOrUnprefixed,
    ),
];

/// §2's table, first column, backticked cells only — the registered
/// namespaces, in table order.
///
/// This is also what [`census`] buckets by, so the census and the
/// conformance gate cannot drift (D91 §11.6), and
/// [`tests::section_2_prefix_table_matches_registered_prefixes`] compares it
/// with the document itself, so neither can drift from §2.
const REGISTERED_PREFIXES: &[&str] = &[
    "cbor-",
    "manifest-",
    "bundle-",
    "crypto-",
    "content-",
    "fine-root-",
    "anchor-",
];

/// A namespace rule broken by one `(enumerator, code)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Violation<'a> {
    /// A code carrying a prefix its domain does not own — §2's headline rule.
    ForeignPrefix {
        /// Which enumerator yielded it.
        enumerator: &'a str,
        /// The offending code.
        code: &'a str,
        /// The prefix §2 registers to that enumerator's domain.
        expected: &'static str,
    },
    /// An enumerator with no [`ENUMERATOR_PREFIXES`] row. **Never a skip.**
    UnregisteredEnumerator {
        /// Which enumerator has no row.
        enumerator: &'a str,
    },
}

/// Every violation of §2's namespace rules in `roster`, against `table`.
///
/// A pure function over both inputs so the planted-fault test can exercise it
/// on a synthetic roster: the real roster cannot be made to violate the rule
/// at runtime without minting a code, and a code minted to prove a test works
/// is a code §3 makes permanent.
fn prefix_violations<'a>(
    roster: &'a [(&'a str, BTreeSet<&'a str>)],
    table: &[(&'static str, Allowed)],
) -> Vec<Violation<'a>> {
    let mut out = Vec::new();
    for (enumerator, codes) in roster {
        // Total by construction: no `filter_map`, no `continue` on a miss.
        let Some((_, allowed)) = table.iter().find(|(name, _)| name == enumerator) else {
            out.push(Violation::UnregisteredEnumerator { enumerator });
            continue;
        };
        if let Allowed::Only(expected) = allowed {
            for code in codes {
                if !code.starts_with(expected) {
                    out.push(Violation::ForeignPrefix {
                        enumerator,
                        code,
                        expected,
                    });
                }
            }
        }
    }
    out
}

/// The backticked first-column cells of a Markdown table, in order.
///
/// Rows whose first cell carries no backticks are skipped **by construction**,
/// which is what excludes §2's `*(unprefixed)*` and
/// `*(none — S mints no codes)*` rows without naming them.
fn backticked_first_column(table: &str) -> Vec<String> {
    table
        .lines()
        .filter(|line| line.trim_start().starts_with('|'))
        .filter_map(|line| {
            let cell = line.trim().trim_start_matches('|').split('|').next()?;
            let (_, rest) = cell.split_once('`')?;
            let (token, _) = rest.split_once('`')?;
            Some(token.to_owned())
        })
        .collect()
}

/// The lines of §2's prefix table: the first contiguous run of `|` lines after
/// the `## 2. Domain prefixes` heading.
///
/// Scoped to that one table on purpose — the document holds several others
/// (the decode-layer table, Q80's backing table, this section's own census)
/// and a document-wide scrape would silently absorb them.
fn section_2_table(doc: &str) -> String {
    doc.lines()
        .skip_while(|line| !line.starts_with("## 2. Domain prefixes"))
        .skip_while(|line| !line.trim_start().starts_with('|'))
        .take_while(|line| line.trim_start().starts_with('|'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The snapshot's own parse: one code per line, `#` comments and blank lines
/// ignored, order and duplicates checked by the caller rather than smoothed
/// over here.
fn parse_snapshot(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

/// The comparison, as a pure function over two sets so the planted-fault
/// tests below can exercise it without renaming anything in the tree.
///
/// `Ok(added)` — every committed code is still live; `added` is what is live
/// and not yet committed (legal, and reported so it can be blessed).
/// `Err(missing)` — committed codes that no enumerator emits any more. That
/// is a removal or a rename, and it is the failure this module exists for.
fn compare<'a>(
    committed: &'a [String],
    live: &BTreeSet<&'a str>,
) -> Result<Vec<&'a str>, Vec<&'a str>> {
    let missing: Vec<&str> = committed
        .iter()
        .map(String::as_str)
        .filter(|code| !live.contains(code))
        .collect();
    if !missing.is_empty() {
        return Err(missing);
    }
    let committed_set: BTreeSet<&str> = committed.iter().map(String::as_str).collect();
    Ok(live
        .iter()
        .copied()
        .filter(|code| !committed_set.contains(code))
        .collect())
}

/// The snapshot file's header. Rewritten verbatim by the bless path, so the
/// explanation travels with the artifact rather than only with this module.
fn header() -> String {
    format!(
        "\
# antseal — the stable machine-readable error-code universe, format v1.
#
# Decision D30; contract: docs/testing/error-code-contract.md.
# Mechanism and rationale: crates/antseal-core/src/error_universe.rs (Q52).
#
# One code per line, sorted, no duplicates. Lines starting with '#' and blank
# lines are ignored. This file is COMPARED ON EVERY TEST RUN against the codes
# collected from the per-domain exemplar enumerators, with
# ADDITIONS-ONLY semantics:
#
#   adding a code    passes  (D30 section 3: routine and unrestricted)
#   removing a code  FAILS   (the contract made it permanent)
#   renaming a code  FAILS   (a rename is a removal plus an addition)
#
# Third-party verifiers compare against these literals. Do not edit this file
# to make a failing test pass -- that is the exact move D30 section 3 forbids.
# To record newly added codes:
#
#   {BLESS_VAR}=1 cargo test -p antseal-core --lib -- error_universe
#
# The bless path writes the UNION of this file and the live set, so it can
# never drop a code; removing one is a hand edit with a reviewable diff.
"
    )
}

/// The snapshot file's full text for a given committed/live pair: the header
/// plus the **union**, sorted.
///
/// Separate from the write so the "blessing never drops a code" test can
/// exercise it with no filesystem at all — a test that needs a scratch
/// directory to prove a set operation is a test with two ways to fail.
fn render(committed: &[String], live: &BTreeSet<&str>) -> String {
    let mut union: BTreeSet<&str> = live.iter().copied().collect();
    union.extend(committed.iter().map(String::as_str));
    let body: String = union.iter().map(|code| format!("{code}\n")).collect();
    format!("{}{body}", header())
}

/// Rewrite the snapshot as the union of the committed and live sets.
fn bless(path: &Path, committed: &[String], live: &BTreeSet<&str>) -> std::io::Result<usize> {
    let text = render(committed, live);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, &text)?;
    Ok(parse_snapshot(&text).len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_path() -> PathBuf {
        PathBuf::from(SNAPSHOT)
    }

    /// **The gate.** Every code frozen into the snapshot is still emitted by
    /// some enumerator, under exactly that name.
    #[test]
    fn error_code_universe_has_not_lost_or_renamed_a_code() {
        let path = snapshot_path();
        let live = live_universe();

        if std::env::var_os(BLESS_VAR).is_some() {
            let committed = std::fs::read_to_string(&path)
                .map(|text| parse_snapshot(&text))
                .unwrap_or_default();
            let total = bless(&path, &committed, &live)
                .unwrap_or_else(|e| panic!("cannot write {SNAPSHOT_DISPLAY}: {e}"));
            println!("blessed {SNAPSHOT_DISPLAY}: {total} code(s)");
            return;
        }

        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "cannot read the frozen error-code universe {SNAPSHOT_DISPLAY}: {e}\n\
                 It is not optional: without it D30's append-only rule is enforced by \
                 nothing (Q52). Regenerate with `{BLESS_VAR}=1 cargo test -p antseal-core \
                 --lib -- error_universe` ONLY if you are creating it for the first time \
                 — otherwise restore it from git, because a deleted snapshot and a green \
                 suite is precisely the state this file exists to make impossible."
            )
        });
        let committed = parse_snapshot(&text);

        assert!(
            !committed.is_empty(),
            "{SNAPSHOT_DISPLAY} carries no codes — the check would be vacuous"
        );

        match compare(&committed, &live) {
            Err(missing) => panic!(
                "{} stable error code(s) in {SNAPSHOT_DISPLAY} are no longer emitted by any \
                 enumerator:\n{}\n\n\
                 A code is permanent from the moment a tamper row, a golden vector or a \
                 released verifier binds to it (docs/testing/error-code-contract.md §3). \
                 If you renamed one, rename it back and add the new name as a NEW code; \
                 adding is routine and unrestricted, renaming is not. If you deliberately \
                 deleted an error variant, the code still may not disappear from the \
                 contract — leave the line and record the retirement.",
                missing.len(),
                missing
                    .iter()
                    .map(|code| format!("  - {code}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            Ok(added) if !added.is_empty() => {
                // Legal by D30 §3 — pass, but say so, because a snapshot that
                // drifts behind the tree pins less every wave.
                println!(
                    "[error-universe] {} code(s) live and not yet in {SNAPSHOT_DISPLAY}: {}\n\
                     Adding is legal; record them with `{BLESS_VAR}=1 cargo test \
                     -p antseal-core --lib -- error_universe`.",
                    added.len(),
                    added.join(", ")
                );
            }
            Ok(_) => println!(
                "[error-universe] ok — {} frozen code(s), all still emitted",
                committed.len()
            ),
        }

        // The per-family census, printed rather than stored: D30 §7's freeze
        // entry wants the count per family at the freeze commit, and a number
        // kept in a second file is a number that goes stale (the exact shape
        // of every stale-count error the Q14 audit turned up).
        println!(
            "[error-universe] census — {} total: {}",
            live.len(),
            census(&live)
                .iter()
                .map(|(family, n)| format!("{family} {n}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    /// The universe is **exactly** the union of the registered enumerators —
    /// recomputed here from the same calls rather than read back out of
    /// [`live_universe`], so dropping a source shrinks one side only.
    ///
    /// Note what this can and cannot see. Five families are also reachable
    /// *transitively*, because `verify::error::all_error_exemplars` sources
    /// C's, G's and the canon list rather than restating them (contract §2's
    /// wrapper rule, `verify/error.rs:905/1064/1072`). Dropping one of those
    /// direct calls leaves the union unchanged — and correctly stays green,
    /// because what D30 freezes is the *set*, not the call graph. What cannot
    /// hide is a family that no longer reaches the union at all.
    ///
    /// Renamed at A52 from the_universe_is_exactly_the_eight_enumerators
    /// (unbackticked: Q69's guard reads a backticked test name as a live
    /// pointer, and this is a record of one that is gone),
    /// when the roster went to [`ENUMERATOR_COUNT`]: a guard whose name
    /// asserts a number it no longer checks is worse than one with no number
    /// at all, and the count now lives in a constant that the message quotes.
    #[test]
    fn the_universe_is_exactly_the_registered_enumerators() {
        let sources = by_enumerator();
        assert_eq!(
            sources.len(),
            ENUMERATOR_COUNT,
            "the enumerator roster changed size; a new domain must be added to \
             `by_enumerator` or its codes freeze under nothing"
        );

        let mut expected: BTreeSet<&'static str> = BTreeSet::new();
        for (enumerator, family) in &sources {
            assert!(
                !family.is_empty(),
                "`{enumerator}` yields no codes — an emptied exemplar list removes a whole \
                 family from D30's freeze while every distinctness meta-test stays green \
                 (nothing is trivially distinct from nothing)"
            );
            expected.extend(family.iter().copied());
        }

        let live = live_universe();
        assert_eq!(
            live, expected,
            "`live_universe` is not the union of the registered enumerators — a source \
             dropped, added, or filtered"
        );
    }

    // ── Q77: §2's namespace rules (D91 §8) ─────────────────────────────

    /// **§2's headline rule, enforced for the first time.** Every code
    /// carries the prefix §2 registers to the domain that mints it, and every
    /// enumerator has a row saying which prefix that is.
    #[test]
    fn every_code_carries_the_prefix_registered_to_its_domain() {
        let roster = by_enumerator();
        assert!(!roster.is_empty(), "an empty roster checks nothing");

        let violations = prefix_violations(&roster, ENUMERATOR_PREFIXES);
        assert!(
            violations.is_empty(),
            "docs/testing/error-code-contract.md §2: *a domain never mints a code under \
             another domain's prefix*. Violations:\n{}\n\n\
             If an enumerator is reported as unregistered, add its row to \
             `ENUMERATOR_PREFIXES` — the lookup is deliberately total, because a skipped \
             enumerator is exactly the newly added one and the check would go green over \
             the domain it exists to constrain (D91 §8.2).",
            violations
                .iter()
                .map(|v| format!("  - {v:?}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// **Test of the test**, on D91 §8.1's own example. The comparator must
    /// return the planted pair; it fails if anyone weakens it to a warning, to
    /// `starts_with(anything)`, or — the one D91 names — to skipping an
    /// enumerator it has no row for.
    #[test]
    fn the_prefix_check_goes_red_on_a_foreign_prefix() {
        let anchor = "anchor::error::all_code_exemplars";
        let roster: Vec<(&str, BTreeSet<&str>)> =
            vec![(anchor, ["ots-bad-magic"].into_iter().collect())];
        assert_eq!(
            prefix_violations(&roster, ENUMERATOR_PREFIXES),
            vec![Violation::ForeignPrefix {
                enumerator: anchor,
                code: "ots-bad-magic",
                expected: "anchor-",
            }],
            "the exact mutation D91 forbids — D58's sixteen codes were this shape"
        );

        // A code under the right prefix is not a violation, so the check is
        // not simply "everything fails".
        let ok: Vec<(&str, BTreeSet<&str>)> =
            vec![(anchor, ["anchor-ots-bad-magic"].into_iter().collect())];
        assert!(prefix_violations(&ok, ENUMERATOR_PREFIXES).is_empty());
    }

    /// **The totality D91 §8.2 calls the load-bearing half.** An enumerator
    /// with no table row is a failure naming it, never a silent skip.
    #[test]
    fn an_enumerator_with_no_prefix_row_fails_rather_than_skipping() {
        let roster: Vec<(&str, BTreeSet<&str>)> = vec![(
            "somebody::new_family::all_code_exemplars",
            ["anything-at-all"].into_iter().collect(),
        )];
        assert_eq!(
            prefix_violations(&roster, ENUMERATOR_PREFIXES),
            vec![Violation::UnregisteredEnumerator {
                enumerator: "somebody::new_family::all_code_exemplars",
            }],
            "a `filter_map` here would exempt precisely the family that has just been added \
             — which is the A family this whole mechanism exists to catch"
        );
    }

    /// **The const *is* the doc.** [`REGISTERED_PREFIXES`] is exactly the
    /// backticked first column of §2's table.
    ///
    /// Red when a prefix is added to the table and not the const, or the
    /// reverse. The length assertion is what stops it passing vacuously on a
    /// parse that finds nothing.
    #[test]
    fn section_2_prefix_table_matches_registered_prefixes() {
        const CONTRACT: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/testing/error-code-contract.md"
        );
        let doc = std::fs::read_to_string(CONTRACT)
            .unwrap_or_else(|e| panic!("cannot read docs/testing/error-code-contract.md: {e}"));
        let parsed = backticked_first_column(&section_2_table(&doc));

        assert!(
            parsed.len() >= 7,
            "§2's table parsed to {} prefix(es) — the table moved, or the scrape found the \
             wrong one; a check that parses nothing agrees with any const",
            parsed.len()
        );
        assert_eq!(
            parsed.len(),
            REGISTERED_PREFIXES.len(),
            "§2's table lists {} prefix(es) and `REGISTERED_PREFIXES` holds {}",
            parsed.len(),
            REGISTERED_PREFIXES.len()
        );
        let from_doc: BTreeSet<&str> = parsed.iter().map(String::as_str).collect();
        let from_const: BTreeSet<&str> = REGISTERED_PREFIXES.iter().copied().collect();
        assert_eq!(
            from_doc, from_const,
            "§2's table and `REGISTERED_PREFIXES` disagree. The table is the registry; the \
             const is what `census` buckets by and what the conformance gate reads, so a \
             prefix in one and not the other is a family registered in prose only — which \
             is what `fine-root-` was until Q77"
        );
    }

    /// The two parsers of §2's table, on planted input, so neither is trusted
    /// on the real document alone.
    #[test]
    fn the_section_2_scrape_reads_the_right_table_and_skips_unbackticked_rows() {
        let doc = "\
# preamble

| ignored | table |
|---|---|
| `not-` | wrong table |

## 2. Domain prefixes

| Prefix | Owner | Surface |
|---|---|---|
| `alpha-` | F | first |
| *(unprefixed)* | R | skipped by construction |
| `beta-` | A | second |

Trailing prose.

| `gamma-` | X | a later table |
";
        assert_eq!(
            backticked_first_column(&section_2_table(doc)),
            vec!["alpha-".to_owned(), "beta-".to_owned()],
            "the scrape must take §2's table only, and drop rows whose first cell carries no \
             backticks — which is how the `*(unprefixed)*` and S rows are excluded without \
             being named"
        );
    }

    /// The snapshot file itself is sorted, duplicate-free and kebab-case — the
    /// properties the comparison and every reader assume.
    #[test]
    fn snapshot_file_is_sorted_unique_and_kebab_case() {
        let text = std::fs::read_to_string(snapshot_path())
            .unwrap_or_else(|e| panic!("cannot read {SNAPSHOT_DISPLAY}: {e}"));
        let codes = parse_snapshot(&text);

        let mut sorted = codes.clone();
        sorted.sort();
        assert_eq!(codes, sorted, "{SNAPSHOT_DISPLAY} is not in sorted order");

        let unique: BTreeSet<&String> = codes.iter().collect();
        assert_eq!(
            unique.len(),
            codes.len(),
            "{SNAPSHOT_DISPLAY} carries a duplicate code"
        );

        for code in &codes {
            assert!(
                !code.is_empty()
                    && code
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    && !code.starts_with('-')
                    && !code.ends_with('-'),
                "{code:?} in {SNAPSHOT_DISPLAY} is not lowercase kebab-case \
                 (contract §1)"
            );
        }
    }

    // ── Tests of the test (planted faults on the pure comparator) ──────────
    //
    // A checker never observed failing proves nothing. The gate above cannot
    // rename a code in the tree at runtime, so the comparison is factored out
    // and the three faults it must catch are planted directly.

    #[test]
    fn the_comparison_catches_a_rename() {
        let committed = vec!["manifest-unknown-key".to_owned()];
        let live: BTreeSet<&str> = ["manifest-unknown-keys"].into_iter().collect();
        assert_eq!(
            compare(&committed, &live),
            Err(vec!["manifest-unknown-key"]),
            "a renamed code must be reported under its FROZEN name — that is the name \
             third-party verifiers hold"
        );
    }

    #[test]
    fn the_comparison_catches_a_removal() {
        let committed = vec!["crypto-rng-failure".to_owned(), "tiling-gap".to_owned()];
        let live: BTreeSet<&str> = ["tiling-gap"].into_iter().collect();
        assert_eq!(compare(&committed, &live), Err(vec!["crypto-rng-failure"]));
    }

    #[test]
    fn the_comparison_tolerates_an_addition() {
        let committed = vec!["tiling-gap".to_owned()];
        let live: BTreeSet<&str> = ["tiling-gap", "tiling-overlap"].into_iter().collect();
        assert_eq!(
            compare(&committed, &live),
            Ok(vec!["tiling-overlap"]),
            "adding a code is routine and unrestricted (D30 §3)"
        );
    }

    #[test]
    fn the_comparison_is_green_on_an_unchanged_universe() {
        let committed = vec!["a-code".to_owned(), "b-code".to_owned()];
        let live: BTreeSet<&str> = ["a-code", "b-code"].into_iter().collect();
        assert_eq!(compare(&committed, &live), Ok(Vec::new()));
    }

    /// Blessing may add, never drop. Proven, not asserted in prose, because
    /// "the update path cannot remove" is exactly what makes hand-editing the
    /// only way to lose a code.
    #[test]
    fn blessing_never_drops_a_committed_code() {
        // `retired-code` is committed and NOT live — the removal case.
        let committed = vec!["retired-code".to_owned(), "kept-code".to_owned()];
        let live: BTreeSet<&str> = ["kept-code", "new-code"].into_iter().collect();

        let written = parse_snapshot(&render(&committed, &live));
        assert_eq!(
            written,
            vec![
                "kept-code".to_owned(),
                "new-code".to_owned(),
                "retired-code".to_owned()
            ],
            "the bless path dropped a committed code; it must write the UNION so that \
             removing a code is only ever a reviewable hand edit"
        );
    }

    /// The rendered file is what the parser and the sorted/unique guard
    /// expect — the bless path cannot emit a snapshot its own gate rejects.
    #[test]
    fn rendered_snapshot_round_trips_through_the_parser() {
        let live = live_universe();
        let text = render(&[], &live);
        let parsed = parse_snapshot(&text);
        assert_eq!(parsed.len(), live.len());
        assert!(parsed.iter().map(String::as_str).eq(live.iter().copied()));
        assert!(
            text.starts_with('#'),
            "the rendered snapshot lost its header, which is where the append-only rule \
             is written down for whoever opens the file instead of this module"
        );
    }

    /// The snapshot parser ignores comments and blanks and nothing else — so
    /// a code cannot be hidden from the gate by indenting or commenting it.
    #[test]
    fn the_parser_ignores_only_comments_and_blank_lines() {
        let text = "# header\n\n  spaced-code  \nplain-code\n#commented-code\n";
        assert_eq!(
            parse_snapshot(text),
            vec!["spaced-code".to_owned(), "plain-code".to_owned()]
        );
    }
}
