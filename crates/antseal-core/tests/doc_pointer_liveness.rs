//! Doc-named-test liveness (task Q69): every rustdoc pointer at a test must
//! resolve to something that exists.
//!
//! # Why
//!
//! F41 found `manifest/ids.rs`'s naming-ban note citing a test **and** a file
//! that never existed. Nothing could notice: a pointer at nothing compiles,
//! renders, and reads exactly like a pointer at a live guard — and it reads
//! like *evidence*, which is worse than saying nothing at all. A reviewer who
//! sees "`foo` asserts it" stops checking whether anything does.
//!
//! That is the rustdoc instance of F42's registry-prose problem, and of the
//! 2026-07-31 review's headline pattern (*recorded claims the code does not
//! implement*) applied to claims about **tests**. This file is the greppable
//! enforcement, in the spirit of `tests/identifier_bans.rs`.
//!
//! # What this does and does not prove
//!
//! It proves a pointer names something that **exists**. It does not prove the
//! named test asserts what the prose says — that is review work and stays
//! review work (Q69's own note). Catching pointers to *nothing* is the whole
//! ambition, and it is the failure mode that cannot be caught by reading.
//!
//! # The recognition rules (normative, and deliberately narrow)
//!
//! A greedy "every backticked snake_case token must be a function" would drown
//! in field names, locals, upstream API calls and module paths. Both rules
//! below were **measured over this crate** before being frozen, and the
//! numbers are the justification:
//!
//! **Rule 1 — a test-function pointer** is a backtick-quoted token inside a
//! doc comment that, after normalisation (drop a trailing `()`, drop a
//! trailing `*` and remember it as a prefix glob, keep only the last `::`
//! segment), matches `[a-z][a-z0-9_]*` **and contains at least
//! [`MIN_UNDERSCORES`] underscores**. It must resolve to a function defined
//! somewhere in this crate's `src/` or `tests/`.
//!
//! Four underscores is not a magic number, it is this repo's test-naming
//! convention: tests here are sentences
//! (`no_bundle_map_grows_a_deliberately_absent_field`), ordinary items are
//! nouns (`encode_envelope`, `check_section_cap`, `clamped_capacity`).
//! Measured at Q69 over the whole crate:
//!
//! | threshold | pointers recognised | not resolving |
//! | --- | --- | --- |
//! | ≥ 2 underscores | 351 | 135 — unusable, almost all ordinary API names |
//! | ≥ 3 underscores | 135 | 6 — 4 of them false (a module, an upstream method, two prose phrases) |
//! | **≥ 4 underscores** | **105** | **3 — every one a genuine dangling pointer** |
//!
//! The cost is recall: of this crate's 1 207 `#[test]` functions, 86.7 % have
//! four or more underscores, so a pointer at one of the 161 short-named tests
//! is not checked. That trade is deliberate — a rule with false positives gets
//! an allowlist, and an allowlist that grows is a rule nobody believes.
//!
//! **Rule 2 — a test-file pointer** is any `tests/<...>.rs` token in a doc
//! comment, at a non-path character boundary. It must exist relative to this
//! crate root. This rule needs no threshold: the `tests/` prefix and `.rs`
//! suffix together are unambiguous.
//!
//! Fenced code blocks inside doc comments are skipped by both rules: their
//! content is code, not prose about code.
//!
//! # Scope
//!
//! This crate only (`src/` and `tests/`) — where F41 found the defect and
//! where the format, crypto and verification claims live. Widening the sweep
//! to `antseal-cli`, `antseal-net`, `antseal-anchor` and `devnet-launcher` is
//! **Q70**; nothing here is crate-specific except the two roots.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// This crate's root.
const CRATE_ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// The underscore floor that separates a test-name-shaped token from an
/// ordinary identifier. See the module docs for the measurement.
const MIN_UNDERSCORES: usize = 4;

/// Pointers that deliberately do not resolve in this tree.
///
/// Exactly three kinds of entry are legitimate, and each must say which it is:
///
/// - a **forward reference** to a test a named task will land — the entry
///   names that task, so the allowlist cannot outlive it silently;
/// - an **external reference** to another project's test — the entry names
///   that project;
/// - a **cross-crate reference** to a test in a sibling crate of this
///   workspace — the entry names the crate and the file:line, so the claim
///   stays checkable by hand while the sweep is crate-scoped. This kind
///   exists because the Scope note above is real: the sweep covers this
///   crate only, and widening it is **Q70**. Such an entry is *born stale* by
///   design — when Q70 lands the pointer resolves and
///   [`no_allowlist_entry_is_stale`] fails, which is the intended way it gets
///   deleted. Added 2026-08-09 for A22, the first pointer this repo has had
///   from one crate's test docs at another crate's test.
///
/// Anything else is a dangling pointer wearing a disguise. Note the one
/// disguise this file cannot catch: dropping the backticks stops a claim
/// being a pointer at all while leaving it reading exactly like evidence.
/// Removing backticks to silence this test is therefore the one repair that
/// is never correct.
/// [`no_allowlist_entry_is_stale`] deletes the incentive to leave entries
/// behind: an entry that starts resolving fails the suite.
const ALLOWED: &[(&str, &str)] = &[
    (
        "tests/x25519.rs",
        "external reference: the pinned `ed25519-dalek`'s own test file, cited as \
         provenance for the RFC 8032 §7.1 seeds — not a file of ours and never \
         will be",
    ),
    (
        "the_three_way_splice_reaches_the_committed_vector_digest",
        "cross-crate reference: lives in the antseal-anchor crate at \
         src/ots/upgrade/tests.rs:636, cited by tests/anchor_vectors.rs as the \
         cross-check that runs the shipped `merge_upgrade` over the same archive \
         bytes to the same SHA-256 the A22 vector carries (D103 RULING 2a). It \
         cannot resolve here because this sweep is scoped to this crate; \
         widening it is Q70, and when Q70 lands this entry starts resolving and \
         no_allowlist_entry_is_stale will fail until it is deleted. The pointer \
         is real and was verified by hand on 2026-08-09",
    ),
];

/// The one file the sweep skips: this one, which must quote example pointers
/// — including deliberately dangling ones, in the rule fixture — to define
/// and check the rules at all. Exactly the exemption `identifier_bans.rs`
/// grants itself, for exactly the same reason. It is a single named file
/// rather than a mechanism, so it cannot grow.
const THIS_FILE: &str = "doc_pointer_liveness.rs";

/// A recognised test-function pointer.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FnPointer {
    /// The normalised identifier.
    name: String,
    /// The token ended in `*`, so it names a family and resolves by prefix.
    glob: bool,
}

impl FnPointer {
    /// As written in the doc, for failure messages.
    fn as_written(&self) -> String {
        if self.glob {
            format!("{}*", self.name)
        } else {
            self.name.clone()
        }
    }

    fn resolves(&self, defined: &BTreeSet<String>) -> bool {
        if self.glob {
            defined.iter().any(|f| f.starts_with(&self.name))
        } else {
            defined.contains(&self.name)
        }
    }
}

/// **Q69's accept.** Every rustdoc pointer at a test resolves.
///
/// Red direction, performed at Q69 before this test existed: the rules found
/// three genuine dangling pointers in the tree —
/// `forced_total_form_matches_the_fallible_one` (`canon/pipeline.rs`, a
/// mangling of the real `kat_forced_total_form_matches_the_fallible_one`,
/// and pointed at the wrong claim besides — the *arbitrary bytes* half is the
/// proptest's), `the_encode_gate_reports_the_decode_paths_own_codes`
/// (`codec/encode.rs`, F53's, one commit old — the class regrows that fast),
/// and `tests/x25519.rs` (upstream, now the one allowlist entry). All three
/// are fixed or explained at source.
///
/// Planted-fault direction, also performed: adding
/// `` `a_test_that_does_not_exist_anywhere` `` to any doc comment in this
/// crate turns this red, naming the file and the token.
#[test]
fn every_doc_named_test_pointer_resolves() {
    let sources = rust_sources();
    assert!(
        sources.len() > 50,
        "the source walk found only {} files — the walk is broken, not the \
         tree clean",
        sources.len()
    );

    let mut defined = BTreeSet::new();
    for path in &sources {
        defined.extend(defined_fns(&read(path)));
    }
    assert!(
        defined.len() > 500,
        "only {} function definitions found — the definition scan is broken",
        defined.len()
    );

    let allowed: BTreeSet<&str> = ALLOWED.iter().map(|(pointer, _)| *pointer).collect();
    let mut dangling = Vec::new();
    let mut fn_pointers = 0usize;
    let mut path_pointers = 0usize;
    let mut exempted = 0usize;

    for path in &sources {
        if path.ends_with(THIS_FILE) {
            exempted += 1;
            continue;
        }
        let text = read(path);
        let shown = path.strip_prefix(CRATE_ROOT).unwrap_or(path).display();

        for pointer in fn_pointers_in(&text) {
            fn_pointers += 1;
            let written = pointer.as_written();
            if !pointer.resolves(&defined) && !allowed.contains(written.as_str()) {
                dangling.push(format!(
                    "{shown}: `{written}` names no function in this crate"
                ));
            }
        }

        for pointer in path_pointers_in(&text) {
            path_pointers += 1;
            if !Path::new(CRATE_ROOT).join(&pointer).exists() && !allowed.contains(pointer.as_str())
            {
                dangling.push(format!("{shown}: `{pointer}` names no file in this crate"));
            }
        }
    }

    // Anti-vacuity: a rule that recognises nothing passes forever. The floors
    // are far below the Q69 census (105 function pointers, 26 file pointers)
    // and far above zero, so they catch an extractor that silently stops
    // matching without failing on ordinary growth.
    assert!(
        fn_pointers > 50 && path_pointers > 10,
        "recognised only {fn_pointers} function and {path_pointers} file \
         pointers — the extraction rules stopped matching"
    );
    assert_eq!(
        exempted, 1,
        "the self-exemption must match exactly this file — a stale name \
         silently un-guards the whole sweep"
    );

    assert!(
        dangling.is_empty(),
        "{} dangling doc pointer(s) — each reads as evidence and is not:\n  {}",
        dangling.len(),
        dangling.join("\n  ")
    );
}

/// An allowlist entry that has started resolving is stale, and a stale
/// allowlist is how a real dangling pointer hides later (F52's lesson, one
/// layer up). Forward references in particular must be removed by the task
/// that lands them.
#[test]
fn no_allowlist_entry_is_stale() {
    let mut defined = BTreeSet::new();
    for path in rust_sources() {
        defined.extend(defined_fns(&read(&path)));
    }

    for (pointer, reason) in ALLOWED {
        assert!(
            !reason.trim().is_empty(),
            "allowlist entry `{pointer}` carries no reason"
        );
        let resolved = if pointer.starts_with("tests/") && pointer.ends_with(".rs") {
            Path::new(CRATE_ROOT).join(pointer).exists()
        } else {
            defined.contains(*pointer)
        };
        assert!(
            !resolved,
            "allowlist entry `{pointer}` now resolves — delete it, the \
             exemption is spent"
        );
    }
}

/// The rules are exactly as the module documents them, checked against a
/// fixture that includes every shape the tree actually uses and every
/// near-miss that must **not** be recognised.
///
/// This is the permanent half of "prove it can fail": it fixes what the rules
/// recognise, so a later edit that quietly narrows them into recognising
/// nothing fails here rather than passing vacuously.
#[test]
fn the_recognition_rules_are_exactly_as_documented() {
    let fixture = r#"
//! Prose naming `some_test_with_four_underscores` and a glob
//! `family_of_related_guards_*` and a qualified
//! `tests::a_module_qualified_pointer_name` and a call form
//! `another_pointer_written_as_a_call()`. File pointer:
//! `tests/parser_caps.rs`, and a bare one at tests/vector_index.rs.
//!
//! Not pointers: `title`, `encode_envelope`, `check_section_cap`,
//! `MAX_BUNDLE_BYTES`, `SomeType`, `k_u`, `0x00`, `self_encryption`,
//! `a-kebab-cased-code`, `not/a/tests/path.rs`.
//!
//! ```rust
//! // inside a fence: code, not prose about code
//! let x = `ignored_token_inside_a_fenced_block`;
//! // tests/never_scanned.rs
//! ```
fn a_definition_outside_a_doc_comment() {}
// `a_pointer_in_an_ordinary_comment_is_not_scanned`
"#;

    let found: Vec<String> = fn_pointers_in(fixture)
        .iter()
        .map(FnPointer::as_written)
        .collect();
    assert_eq!(
        found,
        vec![
            "some_test_with_four_underscores".to_owned(),
            "family_of_related_guards_*".to_owned(),
            "a_module_qualified_pointer_name".to_owned(),
            "another_pointer_written_as_a_call".to_owned(),
        ],
        "rule 1 recognises the wrong set"
    );

    assert_eq!(
        path_pointers_in(fixture),
        vec![
            "tests/parser_caps.rs".to_owned(),
            "tests/vector_index.rs".to_owned(),
        ],
        "rule 2 recognises the wrong set"
    );

    assert_eq!(
        defined_fns(fixture),
        vec!["a_definition_outside_a_doc_comment".to_owned()]
    );

    // The glob really resolves by prefix, and the exact form really does not.
    let defined: BTreeSet<String> = ["family_of_related_guards_one".to_owned()]
        .into_iter()
        .collect();
    let pointers = fn_pointers_in("//! `family_of_related_guards_*` `family_of_related_guards_x`");
    assert!(pointers[0].resolves(&defined));
    assert!(!pointers[1].resolves(&defined));
}

// ---------------------------------------------------------------------------
// extraction
// ---------------------------------------------------------------------------

/// Rule 1: test-function pointers in `text`'s doc comments, in order.
fn fn_pointers_in(text: &str) -> Vec<FnPointer> {
    let mut found = Vec::new();
    for line in doc_prose(text) {
        // Backtick spans are the odd-indexed pieces of a split on '`'. An
        // unbalanced backtick therefore drops the rest of the line, which is
        // the conservative direction: this rule may only ever miss.
        for span in line.split('`').skip(1).step_by(2) {
            if let Some(pointer) = normalise(span) {
                found.push(pointer);
            }
        }
    }
    found
}

/// Normalise one backtick span into a pointer, or reject it.
fn normalise(span: &str) -> Option<FnPointer> {
    let token = span.trim();
    let token = token.strip_suffix("()").unwrap_or(token);
    let (token, glob) = match token.strip_suffix('*') {
        Some(stem) => (stem, true),
        None => (token, false),
    };
    let token = token.rsplit("::").next().unwrap_or(token);

    let shaped = token.starts_with(|c: char| c.is_ascii_lowercase())
        && token
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !shaped || token.matches('_').count() < MIN_UNDERSCORES {
        return None;
    }
    Some(FnPointer {
        name: token.to_owned(),
        glob,
    })
}

/// Rule 2: `tests/<...>.rs` pointers in `text`'s doc comments, in order.
fn path_pointers_in(text: &str) -> Vec<String> {
    const PREFIX: &str = "tests/";
    let mut found = Vec::new();
    for line in doc_prose(text) {
        let bytes = line.as_bytes();
        for (start, _) in line.match_indices(PREFIX) {
            // Must begin at a non-path boundary, so `not/a/tests/path.rs` and
            // `crates/antseal-core/tests/x.rs` are not mistaken for ours.
            let preceded_by_path_char = start > 0
                && matches!(bytes[start - 1], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'.' | b'-' | b'_');
            if preceded_by_path_char {
                continue;
            }
            let rest = &line[start + PREFIX.len()..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | '.')))
                .unwrap_or(rest.len());
            // Cut at the first `.rs` rather than requiring it at the end, so
            // a pointer that closes a sentence (`… tests/vector_index.rs.`)
            // is recognised.
            let run = &rest[..end];
            if let Some(dot) = run.find(".rs") {
                let candidate = &run[..dot + ".rs".len()];
                if dot > 0 {
                    found.push(format!("{PREFIX}{candidate}"));
                }
            }
        }
    }
    found
}

/// Every function name defined in `text`, doc comments excluded — a name that
/// only ever appears inside prose is not a definition of anything.
fn defined_fns(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for (index, _) in line.match_indices("fn ") {
            let preceded_by_word_char = index > 0 && {
                let before = line.as_bytes()[index - 1];
                before.is_ascii_alphanumeric() || before == b'_'
            };
            if preceded_by_word_char {
                continue;
            }
            let rest = &line[index + 3..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            let name = &rest[..end];
            if name.starts_with(|c: char| c.is_ascii_lowercase() || c == '_') && !name.is_empty() {
                found.push(name.to_owned());
            }
        }
    }
    found
}

/// The doc-comment prose of `text`: `///` and `//!` bodies, with fenced code
/// blocks dropped.
fn doc_prose(text: &str) -> Vec<&str> {
    let mut prose = Vec::new();
    let mut fenced = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let Some(body) = trimmed
            .strip_prefix("///")
            .or_else(|| trimmed.strip_prefix("//!"))
        else {
            continue;
        };
        if body.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if !fenced {
            prose.push(body);
        }
    }
    prose
}

// ---------------------------------------------------------------------------
// walking
// ---------------------------------------------------------------------------

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("{}: cannot read source: {err}", path.display()))
}

/// Every `.rs` file under this crate's `src/` and `tests/`.
fn rust_sources() -> Vec<PathBuf> {
    let root = Path::new(CRATE_ROOT);
    let mut found = Vec::new();
    let mut stack = vec![root.join("src"), root.join("tests")];
    while let Some(current) = stack.pop() {
        let entries = fs::read_dir(&current)
            .unwrap_or_else(|err| panic!("{}: cannot read directory: {err}", current.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|err| panic!("{}: cannot read entry: {err}", current.display()))
                .path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}
