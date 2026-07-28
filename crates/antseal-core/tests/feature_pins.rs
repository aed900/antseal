//! C24/D88 — the guard that `sha2`'s `zeroize` feature cannot be dropped
//! silently.
//!
//! `docs/zeroization-audit.md` R1 is resolved by a **feature**, not by code:
//! `sha2 = { ..., features = ["zeroize"] }`. A future dependency edit that
//! drops that one word silently restores recoverable `W` and GGM-seed residue
//! in dropped hashers (measured before/after in
//! `tests/zeroization_residue.rs`). Nothing about the source tree changes when
//! it happens, so nothing about the source tree can be trusted to notice.
//!
//! # Three layers, because no single one is sufficient
//!
//! D88 §7 states the property has "**no** compile-time detector". That is too
//! strong — one exists (layer 1, in `tests/digest_zeroize_link.rs`), but it
//! is only *half* a detector, and the half it misses is the half
//! `crypto.rs::zeroization_sweep` also misses:
//!
//! 1. **Compile-time** — `tests/digest_zeroize_link.rs`. `digest` re-exports
//!    the `zeroize` crate under `#[cfg(feature = "zeroize")]` and `sha2`
//!    re-exports `digest`, so naming `sha2::digest::zeroize` does not compile
//!    unless `digest/zeroize` is on. That covers `BlockBuffer`'s `Drop` — the
//!    buffer holding `W` verbatim and the GGM parent seed.
//!
//!    **What it cannot see:** `digest/zeroize` is also forwarded by
//!    `hmac/zeroize`. If a future edit dropped `sha2`'s feature while
//!    something else kept `digest/zeroize` alive, that check would still pass
//!    while `Sha256VarCore`'s own `Drop` — the SHA-256 **chaining state** —
//!    silently stopped being compiled. Necessary, not sufficient.
//!
//! 2. **Declaration** — this file. Assert the workspace pin itself still says
//!    what it must. This is the layer that catches exactly the case layer 1
//!    misses, and its failure message names the consequence and the fix.
//!
//!    It lives in a **separate test binary from layer 1 on purpose**: layer 1
//!    fails as `error[E0432]: unresolved import`, which would abort
//!    compilation of anything sharing its target and bury this file's
//!    explanation under a compiler error that says nothing about `W`.
//!
//! 3. **Behaviour** — `tests/zeroization_residue.rs`. The only layer that
//!    proves bytes are actually wiped rather than that a feature is nominally
//!    enabled, and the only one that would survive an upstream change of
//!    mechanism. It deliberately does **not** import `sha2::digest::zeroize`,
//!    so that dropping the feature makes it go *red with residue counts*
//!    rather than fail to build.
//!
//! # Widened at Q53: the whole exact-pin class, not just `sha2`
//!
//! Layer 2's shape — *a declaration in the tree still says what it must* —
//! was being applied to exactly two lines, `sha2` and `hmac`, while
//! `docs/dependency-policy.md` §1 declares a class of **seventeen**
//! format-, crypto- and consensus-affecting dependencies that must all carry
//! an exact `=x.y.z` requirement. Item 1 of Q14's own `Do` list is *"the
//! pinned CBOR encoder"* — and `minicbor = "=2.3.0"` was asserted by no test
//! at all (`tests/cbor_pin_eval.rs` names the version only in a doc comment;
//! all 13 of its assertions are behavioural and would pass on any conforming
//! minicbor). The same hole covered `serde`/`serde_json`, whose serializer
//! output *is* the frozen report byte format (D29), and every other member.
//!
//! The class is **derived from the policy, not restated here**. Restating it
//! would create a second hand-maintained copy of the list, which is the
//! failure mode this whole file exists to guard against one level down.
//!
//! # Also here, for the same reason (Q53)
//!
//! Q14 checklist row **D13** — the ML-DSA wasm32 probe verdict — is the same
//! *kind* of claim: a sentence in a document about the state of the tree,
//! checked by nobody. It is converted at the bottom of this file.
//!
//! Its two siblings live next to their own subjects rather than here, because
//! an assertion about a constant belongs beside the constant: row N3's third
//! site (`TRANSCRIPT_VERSION == 0`) is in
//! `crates/wasm-bitmatch/tests/bitmatch.rs`, and row N4's zero-`layer` count
//! (D86) is in `crates/antseal-core/tests/report_vectors.rs`.
//!
//! Native only: this file reads the workspace manifest from disk, and
//! `wasm32-unknown-unknown` has no filesystem (P14, `docs/wasm-toolchain.md`).

#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// The workspace root.
fn workspace_root() -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "..", ".."].iter().collect()
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The workspace root manifest — the single version-declaration point
/// (`docs/dependency-policy.md` §2).
fn workspace_manifest() -> String {
    read("Cargo.toml")
}

/// The single `sha2 = ...` declaration line from `[workspace.dependencies]`.
fn sha2_pin_line(manifest: &str) -> &str {
    let mut lines = manifest
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("sha2 ="));
    let line = lines
        .next()
        .expect("no `sha2 = ...` line in the workspace manifest — has the pin been renamed?");
    assert!(
        lines.next().is_none(),
        "more than one `sha2 = ...` line in the workspace manifest; \
         the exact-pin class requires a single declaration point \
         (docs/dependency-policy.md §2)"
    );
    line
}

/// Layer 2 — declaration. The workspace pin still enables `zeroize`, still
/// pins the exact version, and still disables default features.
///
/// This is the layer that catches `sha2`'s own feature being dropped while
/// some other crate keeps `digest/zeroize` alive — the case layer 1 is blind
/// to, and the case in which `Sha256VarCore`'s chaining-state `Drop` silently
/// stops being compiled.
#[test]
fn sha2_pin_declares_the_zeroize_feature() {
    let manifest = workspace_manifest();
    let line = sha2_pin_line(&manifest);

    assert!(
        line.contains("\"zeroize\""),
        "the sha2 workspace pin no longer enables the `zeroize` feature.\n\
         found: {line}\n\
         expected: sha2 = {{ version = \"=0.11.0\", default-features = false, \
         features = [\"zeroize\"] }}\n\n\
         This is not a style nit. Without that feature a dropped Hkdf<Sha256> \
         leaves 114 of 144 bytes of PRK-keyed HMAC state readable, the HKDF \
         extract context leaves the master secret W recoverable VERBATIM, and \
         every content::ggm::child_seed call strands its parent GGM seed in a \
         dropped hasher — a live contradiction of MVP-SPEC.md line 143.\n\
         See docs/decisions/D88-hkdf-hmac-zeroization.md and \
         docs/zeroization-audit.md R1. Removing it is a version bump under \
         docs/dependency-policy.md §4, never a drive-by."
    );
    assert!(
        line.contains("\"=0.11.0\""),
        "the sha2 pin is no longer exactly =0.11.0 — every residue and cost \
         number in D88 was measured against that version.\nfound: {line}"
    );
    assert!(
        line.contains("default-features = false"),
        "the sha2 pin no longer disables default features; `alloc`/`oid` \
         would re-enter the wasm32 surface.\nfound: {line}"
    );
}

/// `hmac`'s own `zeroize` feature stays **off**, per D88 §4.
///
/// It adds nothing once `sha2/zeroize` is on (measured: identical residue
/// with and without it), and an inert feature is a maintenance claim that has
/// to be re-defended at every bump. If a future edit turns it on, that should
/// be a decision with a reason, not drift — this test is where the reason
/// gets written down.
#[test]
fn hmac_pin_does_not_enable_zeroize() {
    let manifest = workspace_manifest();
    let line = manifest
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("hmac ="))
        .expect("no `hmac = ...` line in the workspace manifest");

    assert!(
        !line.contains("zeroize"),
        "the hmac pin now enables `zeroize`. D88 §2 measured that it adds \
         nothing once sha2/zeroize is on. If this is deliberate, amend D88 \
         and this test together.\nfound: {line}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Q53 — the whole exact-pin class, derived from the policy
// ─────────────────────────────────────────────────────────────────────────────

const POLICY: &str = "docs/dependency-policy.md";

/// Is this token shaped like a crate name (as opposed to a feature name, a
/// Rust type, or prose)?
fn looks_like_a_crate_name(token: &str) -> bool {
    token.len() >= 3
        && token.starts_with(|c: char| c.is_ascii_lowercase())
        && token
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Every inline-code span in `text`, in order.
fn code_spans(text: &str) -> Vec<&str> {
    let mut spans = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else { break };
        spans.push(&after[..close]);
        rest = &after[close + 1..];
    }
    spans
}

/// The **leading run** of names in a table cell: the code spans that come
/// before any prose, optionally joined by `+`.
///
/// This is what distinguishes `` `serde` + `serde_json` (pinned …) `` — two
/// class members — from `` `zeroize` — … `MasterSecret`/`SecretBuf` … `` —
/// one member whose row happens to name some types.
fn leading_names(cell: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut rest = cell.trim_start();
    loop {
        let Some(after) = rest.strip_prefix('`') else {
            break;
        };
        let Some(close) = after.find('`') else { break };
        let span = &after[..close];
        if !looks_like_a_crate_name(span) {
            break;
        }
        names.push(span);
        rest = after[close + 1..].trim_start();
        if let Some(tail) = rest.strip_prefix('+') {
            rest = tail.trim_start();
        }
    }
    names
}

fn is_exact_version(token: &str) -> bool {
    token.strip_prefix('=').is_some_and(|v| {
        let parts: Vec<&str> = v.split('.').collect();
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// `docs/dependency-policy.md` §1's table, as `name -> stated version`.
///
/// **Derived, never restated.** §1 is the normative definition of the class
/// ("Every format-, crypto-, or network-consensus-affecting dependency MUST be
/// pinned with an exact `=x.y.z` requirement"), and a copy of its membership
/// list living in this file would be a second thing to keep in step — the
/// exact failure this file exists to catch, one level up. If the section is
/// renamed or its table reshaped so this cannot parse it, the floor assertion
/// below turns red rather than the check quietly succeeding over nothing.
fn policy_exact_pin_class() -> BTreeMap<String, Option<String>> {
    let text = read(POLICY);
    let start = text
        .find("## 1. The exact-pin class")
        .expect("docs/dependency-policy.md has no `## 1. The exact-pin class` heading");
    let body = &text[start..];
    let end = body[1..]
        .find("\n## ")
        .map_or(body.len(), |offset| offset + 1);
    let section = &body[..end];

    let mut class: BTreeMap<String, Option<String>> = BTreeMap::new();
    for line in section.lines() {
        if !line.starts_with('|') {
            continue;
        }
        let cell = line.trim_start_matches('|').split('|').next().unwrap_or("");
        let spans = code_spans(cell);

        // Shape A — `name = "=x.y.z"` written out in one span (the rows that
        // nominate a whole stack at once).
        let mut had_assignment = false;
        for span in &spans {
            if let Some((name, rest)) = span.split_once(" = ") {
                let version = rest.trim_matches('"');
                if looks_like_a_crate_name(name) && is_exact_version(version) {
                    class.insert(name.to_owned(), Some(version[1..].to_owned()));
                    had_assignment = true;
                }
            }
        }
        if had_assignment {
            continue;
        }

        // Shape B — the row leads with its name(s); the versions follow in
        // the same order.
        let names = leading_names(cell);
        let versions: Vec<&str> = spans
            .iter()
            .copied()
            .filter(|span| is_exact_version(span))
            .collect();
        for (index, name) in names.iter().enumerate() {
            let version = versions.get(index).map(|v| v[1..].to_owned());
            class.insert((*name).to_owned(), version);
        }
    }
    class
}

/// `name -> version requirement` for every `[workspace.dependencies]` entry.
fn declared_dependencies(manifest: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut inside = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            inside = trimmed == "[workspace.dependencies]";
            continue;
        }
        if !inside || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((name, rhs)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !looks_like_a_crate_name(name) {
            continue;
        }
        let rhs = rhs.trim();
        let source = if rhs.starts_with('{') {
            match rhs.find("version") {
                Some(index) => &rhs[index..],
                None => continue,
            }
        } else {
            rhs
        };
        let Some(open) = source.find('"') else {
            continue;
        };
        let Some(close) = source[open + 1..].find('"') else {
            continue;
        };
        out.insert(
            name.to_owned(),
            source[open + 1..open + 1 + close].to_owned(),
        );
    }
    out
}

/// **Every member of the exact-pin class that has landed carries an exact
/// `=x.y.z` requirement, at the version the policy states.**
///
/// Q14 `Do` item 1 is *the pinned CBOR encoder*, and before this test nothing
/// asserted `minicbor = "=2.3.0"`: `tests/cbor_pin_eval.rs` names the version
/// in a doc comment and asserts only behaviour, which any conforming minicbor
/// would satisfy. The same was true of `serde`/`serde_json`, whose serializer
/// output *is* D29's frozen report byte format — a silent bump there is a
/// vector break with no test between it and the tree.
///
/// Members the policy names but the workspace has not adopted yet are skipped,
/// by §1's own rule that *"the pin rule binds from the moment it lands"*.
#[test]
fn every_exact_pin_class_member_that_has_landed_is_exactly_pinned() {
    let class = policy_exact_pin_class();
    assert!(
        class.len() >= 15,
        "only {} member(s) parsed out of {POLICY} §1 — the section was renamed or its \
         table reshaped, so this check is no longer reading the policy it claims to \
         enforce. Fix the parser together with the document; do NOT paste the list in \
         here.\nparsed: {:?}",
        class.len(),
        class.keys().collect::<Vec<_>>()
    );

    let manifest = workspace_manifest();
    let declared = declared_dependencies(&manifest);
    assert!(
        declared.len() >= 15,
        "only {} entry/entries parsed out of [workspace.dependencies] — the manifest \
         parser has stopped seeing the section",
        declared.len()
    );

    let mut checked = 0usize;
    for (name, policy_version) in &class {
        let Some(requirement) = declared.get(name) else {
            continue; // not landed yet — policy §1's own carve-out
        };
        checked += 1;
        if let Some(problem) = pin_problem(name, requirement, policy_version.as_deref()) {
            panic!("{problem}");
        }
    }

    assert!(
        checked >= 14,
        "only {checked} class member(s) are declared in the workspace, so this test is \
         checking almost nothing. Either the manifest lost its pins or the two parsers \
         have stopped agreeing on names."
    );
}

/// The rule, as a pure function, so the planted-fault tests below can exercise
/// it without editing the workspace manifest under a running test.
///
/// `None` if the declaration is in order; the failure sentence otherwise.
fn pin_problem(name: &str, requirement: &str, policy_version: Option<&str>) -> Option<String> {
    if !is_exact_version(requirement) {
        return Some(format!(
            "`{name}` is in the exact-pin class ({POLICY} §1) but is declared as \
             {requirement:?}, not an exact `=x.y.z`. Every member is format-, crypto- or \
             consensus-affecting by §1's own definition: a floating requirement means the \
             bytes this project promises to verify forever can change without a commit."
        ));
    }
    match policy_version {
        Some(stated) if requirement != format!("={stated}") => Some(format!(
            "`{name}` is pinned at {requirement:?} in Cargo.toml but {POLICY} §1 records \
             `={stated}`. A bump is a deliberate, reviewed event ({POLICY} §4) and it \
             moves BOTH — the manifest and the record of why that version was chosen. One \
             without the other leaves the rationale describing a version nobody builds."
        )),
        _ => None,
    }
}

/// The other direction: **nothing is exact-pinned without a policy row.**
///
/// An exact pin is a promise that somebody re-defends at every bump (§4's
/// checklist). A pin with no row in §1 is a promise nobody owns, and at the
/// next upstream sweep it reads as an arbitrary obstacle rather than as a
/// format commitment.
#[test]
fn nothing_is_exactly_pinned_without_a_policy_row() {
    // The internal path dep: `=0.0.0` exists only so the requirement is never
    // cargo's implicit `*`, which deny.toml's `wildcards = "deny"` rejects.
    // It is not a third-party version commitment and has no policy row.
    const NOT_A_THIRD_PARTY_PIN: &[&str] = &["antseal-core"];

    let class = policy_exact_pin_class();
    let manifest = workspace_manifest();

    for (name, requirement) in declared_dependencies(&manifest) {
        if !is_exact_version(&requirement) || NOT_A_THIRD_PARTY_PIN.contains(&name.as_str()) {
            continue;
        }
        assert!(
            class.contains_key(&name),
            "`{name} = {requirement:?}` is exact-pinned in the workspace manifest but has \
             no row in {POLICY} §1. Add the row — with why it is format-, crypto- or \
             consensus-affecting and which task decided it — or drop the exact pin. §1 \
             is explicitly *\"a floor, not a ceiling\"*: a dependency whose bytes end up \
             hashed, signed, stored or paid for joins the class in the same PR that \
             introduces it."
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Q53 — row D13: the ML-DSA wasm32 probe verdict still has its evidence
// ─────────────────────────────────────────────────────────────────────────────

/// Q14 checklist row **D13** is *"WASM probe decision recorded"*, and its
/// stated evidence is a human reading `docs/research/C11-signature-probe.md`.
///
/// Asserting a marker string in that document would pin **prose**, not the
/// fact. The fact — ML-DSA-65 runs on `wasm32-unknown-unknown` — is machine-
/// asserted already, by the `wasm32-core-tests` lane executing this crate's
/// `--lib` unit tests on that target, `crypto::sig_mldsa`'s among them. What
/// nothing checked is that the *chain* stays intact: drop `--lib` from the
/// lane, or empty out the module's tests, and the row's verdict silently
/// stops being evidenced while the research document still reads VIABLE.
///
/// So this asserts the three links, and names whichever one broke.
#[test]
fn the_mldsa_wasm32_probe_verdict_still_has_its_evidence() {
    let record = workspace_root().join("docs/research/C11-signature-probe.md");
    assert!(
        record.is_file(),
        "docs/research/C11-signature-probe.md is gone — Q14 row D13 cites it as the \
         record of the ml-dsa =0.1.1 wasm32 probe verdict (D13/D14), and the pins in \
         docs/dependency-policy.md §1 cite it as their rationale"
    );

    let mldsa = read("crates/antseal-core/src/crypto/sig_mldsa.rs");
    let tests = mldsa.matches("#[test]").count();
    assert!(
        tests >= 5,
        "crypto::sig_mldsa carries only {tests} unit test(s). The wasm32 evidence for \
         D13/D14's probe verdict is that THESE tests execute on \
         wasm32-unknown-unknown; an emptied module makes that lane green over nothing."
    );

    // Q43 moved this command out of inline YAML and into a committed script,
    // so the chain gained a link: ci.yml calls the script, the script runs the
    // tests. Assert BOTH — checking only the script would leave a lane that no
    // longer calls it green, and checking only the lane cannot see what it runs.
    let runner = read("scripts/wasm-tests.sh");
    assert!(
        runner.contains("cargo test -p antseal-core --lib --target wasm32-unknown-unknown"),
        "scripts/wasm-tests.sh no longer runs antseal-core's unit tests on \
         wasm32-unknown-unknown. That command IS the standing evidence for Q14 row \
         D13: without it the probe verdict rests on a research document from \
         2026-07-27 and nothing else."
    );

    let ci = read(".github/workflows/ci.yml");
    assert!(
        ci.contains("scripts/wasm-tests.sh --check"),
        "no CI lane invokes scripts/wasm-tests.sh --check any more, so nothing runs \
         antseal-core's unit tests on wasm32-unknown-unknown. That chain IS the standing \
         evidence for Q14 row D13: without it the probe verdict rests on a research \
         document from 2026-07-27 and nothing else. If the \
         lane was deliberately restructured, re-point this assertion at whatever \
         executes the ML-DSA tests on wasm32 — do not delete it."
    );
}

/// Diagnostic: print what the two parsers actually see. Ignored by default —
/// it asserts nothing, it is the thing you run when a pin test is red and you
/// want to know whether the parser or the tree is wrong.
#[test]
#[ignore = "diagnostic; prints the parsed class and the parsed manifest"]
fn show_the_parsed_pin_class() {
    let class = policy_exact_pin_class();
    let declared = declared_dependencies(&workspace_manifest());
    println!(
        "exact-pin class from {POLICY} §1 — {} member(s):",
        class.len()
    );
    for (name, version) in &class {
        let state = match declared.get(name) {
            Some(requirement) => format!("declared {requirement}"),
            None => "not landed".to_owned(),
        };
        println!(
            "  {name:<24} policy {:<10} {state}",
            version.as_deref().unwrap_or("—")
        );
    }
}

// ── Tests of the test: planted faults on the parsers and on the rule ────────
//
// A checker never observed failing proves nothing. These tests cannot edit the
// live workspace manifest under a running suite, so the parsers and the rule
// are exercised on synthetic input carrying exactly the faults they exist to
// catch.

/// A miniature §1 in the shapes the real one uses: a leading-name row, a
/// two-name row, an assignment row, a landed-later row with no version, and a
/// row that names no crate at all.
const SYNTHETIC_POLICY_SECTION: &str = r#"
## 1. The exact-pin class

| Dependency | Why exact-pinned | Deciding task |
| --- | --- | --- |
| `minicbor` (pinned `=2.3.0`, decision D7) | bytes | P10 |
| `zeroize` — **pinned `=1.9.0` 2026-07-27 (C5)**. Wiping semantics for `W`, `MasterSecret`/`SecretBuf`; the `derive` feature is NOT enabled | secrets | C |
| `serde` + `serde_json` (pinned `=1.0.229` / `=1.0.151` at R1) | report bytes | R1 |
| AEAD stack — nominated: `sha2 = "=0.11.0"`, `hkdf = "=0.13.0"` | keys | C |
| `self_encryption` | address recomputation | P15 |
| Argon2/scrypt (vault KDF) | vault format | U/C |

## 2. Single declaration point
"#;

#[test]
fn the_policy_parser_reads_every_row_shape_section_one_uses() {
    // `policy_exact_pin_class` reads the real file, so exercise the row logic
    // through the same helpers on synthetic text.
    let mut class: BTreeMap<String, Option<String>> = BTreeMap::new();
    for line in SYNTHETIC_POLICY_SECTION
        .lines()
        .filter(|l| l.starts_with('|'))
    {
        let cell = line.trim_start_matches('|').split('|').next().unwrap_or("");
        let spans = code_spans(cell);
        let mut had_assignment = false;
        for span in &spans {
            if let Some((name, rest)) = span.split_once(" = ") {
                let version = rest.trim_matches('"');
                if looks_like_a_crate_name(name) && is_exact_version(version) {
                    class.insert(name.to_owned(), Some(version[1..].to_owned()));
                    had_assignment = true;
                }
            }
        }
        if had_assignment {
            continue;
        }
        let names = leading_names(cell);
        let versions: Vec<&str> = spans
            .iter()
            .copied()
            .filter(|s| is_exact_version(s))
            .collect();
        for (index, name) in names.iter().enumerate() {
            class.insert(
                (*name).to_owned(),
                versions.get(index).map(|v| v[1..].to_owned()),
            );
        }
    }

    let expected: BTreeMap<String, Option<String>> = [
        ("minicbor", Some("2.3.0")),
        ("zeroize", Some("1.9.0")),
        ("serde", Some("1.0.229")),
        ("serde_json", Some("1.0.151")),
        ("sha2", Some("0.11.0")),
        ("hkdf", Some("0.13.0")),
        ("self_encryption", None),
    ]
    .into_iter()
    .map(|(name, version)| (name.to_owned(), version.map(str::to_owned)))
    .collect();

    assert_eq!(
        class, expected,
        "the §1 row parser mis-read one of the shapes the real table uses. The two that \
         actually bite: a row leading with TWO names (`serde` + `serde_json`) must yield \
         both, paired with the versions in order; and a row whose prose mentions types \
         or features in backticks (`W`, `MasterSecret`, `derive`) must yield only the \
         name it leads with."
    );
}

#[test]
fn the_manifest_parser_reads_both_declaration_shapes_and_stops_at_the_section() {
    let manifest = "\
[workspace.dependencies]
# a comment
plain = \"=1.2.3\"
tabled = { version = \"=4.5.6\", default-features = false, features = [\"x\"] }
caret = \"2\"
pathdep = { path = \"crates/x\", version = \"=0.0.0\" }

[workspace.lints.rust]
outside = \"=9.9.9\"
";
    let declared = declared_dependencies(manifest);
    assert_eq!(declared.get("plain").map(String::as_str), Some("=1.2.3"));
    assert_eq!(declared.get("tabled").map(String::as_str), Some("=4.5.6"));
    assert_eq!(declared.get("caret").map(String::as_str), Some("2"));
    assert_eq!(declared.get("pathdep").map(String::as_str), Some("=0.0.0"));
    assert!(
        !declared.contains_key("outside"),
        "the manifest parser ran past [workspace.dependencies]; §2 makes that section \
         the single declaration point, and a parser that reads the whole file would \
         accept a pin declared somewhere §2 forbids"
    );
}

#[test]
fn the_rule_catches_a_floating_requirement() {
    let problem = pin_problem("minicbor", "2.3.0", Some("2.3.0"))
        .expect("a caret requirement on a class member must be a failure");
    assert!(problem.contains("minicbor") && problem.contains("exact"));
    assert!(
        pin_problem("minicbor", "^2.3.0", Some("2.3.0")).is_some()
            && pin_problem("minicbor", "*", None).is_some(),
        "every non-exact requirement shape must fail, including a bare wildcard"
    );
}

#[test]
fn the_rule_catches_a_manifest_that_moved_without_its_policy_row() {
    let problem = pin_problem("minicbor", "=2.4.0", Some("2.3.0"))
        .expect("a manifest/policy version disagreement must be a failure");
    assert!(
        problem.contains("=2.4.0") && problem.contains("=2.3.0"),
        "the message must name BOTH versions — the whole point is that a bump moved one \
         copy of the fact and not the other.\nfound: {problem}"
    );
}

#[test]
fn the_rule_is_green_on_a_correct_pin() {
    assert_eq!(pin_problem("minicbor", "=2.3.0", Some("2.3.0")), None);
    // A member the policy names without stating a version (not landed at the
    // time the row was written) is still required to be exact when it lands.
    assert_eq!(pin_problem("self_encryption", "=0.36.0", None), None);
    assert!(pin_problem("self_encryption", "0.36", None).is_some());
}
