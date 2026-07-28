//! The frozen Security-assumptions block cannot drift (tasks C20/Q12/C21).
//!
//! MVP-SPEC.md lines 99–104 require the security assumptions a permanent
//! format rests on to be a **signed-off decision, not an implicit one**. C20
//! authors that block in `docs/security-assumptions.md`; Q12 requires
//! `docs/threat-model.md` to carry it **verbatim**. Two copies of a frozen
//! text is exactly the shape that rots: someone edits the one they happened
//! to open, review does not diff the other, and six months later the
//! "frozen" block says two different things.
//!
//! So it is not left to review. This file is the enforcement, in the same
//! house style as `identifier_bans.rs` and the registry cross-check tests: it
//! reads the tracked files and asserts the claims mechanically.
//!
//! **C20** — the frozen AEAD rule appears *verbatim* as a module doc comment
//! in **both** `crypto/unit_aead.rs` and `crypto/manifest_aead.rs`, and in
//! the frozen block itself. Assumption class 4 (AEAD is confidentiality-only
//! and non-committing) is the one assumption a well-meaning refactor can
//! quietly invalidate — by deciding that a successful decryption is evidence
//! of anything — so the rule is planted where that refactor gets written, not
//! only where security documents get read.
//!
//! Whitespace and Markdown emphasis are normalized before comparison, so
//! rewrapping a doc comment is allowed and changing its words is not.

use std::fs;
use std::path::{Path, PathBuf};

/// The workspace root (this crate sits at `crates/antseal-core`).
const WORKSPACE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// C20's source document — the signed-off freeze.
const SOURCE_DOC: &str = "docs/security-assumptions.md";

const BEGIN_MARKER: &str = "<!-- BEGIN frozen-security-assumptions -->";
const END_MARKER: &str = "<!-- END frozen-security-assumptions -->";

/// The frozen rule of assumption class 4 (MVP-SPEC.md line 103, verbatim —
/// including its US spelling of "favor", which is the spec's).
const AEAD_RULE: &str =
    "A future refactor MUST NOT drop a content commitment in favor of trusting the AEAD.";

/// The two AEAD modules that must carry [`AEAD_RULE`] in their module docs.
const AEAD_MODULES: &[&str] = &[
    "crates/antseal-core/src/crypto/unit_aead.rs",
    "crates/antseal-core/src/crypto/manifest_aead.rs",
];

fn workspace_path(relative: &str) -> PathBuf {
    Path::new(WORKSPACE_ROOT).join(relative)
}

fn read(relative: &str) -> String {
    let path = workspace_path(relative);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: cannot read: {err}", path.display()))
}

/// The text strictly between the two markers, or a precise panic saying
/// which marker is missing or duplicated.
fn frozen_block(text: &str, origin: &str) -> String {
    let begins = text.matches(BEGIN_MARKER).count();
    let ends = text.matches(END_MARKER).count();
    assert_eq!(
        begins, 1,
        "{origin}: expected exactly one `{BEGIN_MARKER}`, found {begins}"
    );
    assert_eq!(
        ends, 1,
        "{origin}: expected exactly one `{END_MARKER}`, found {ends}"
    );

    let start = text
        .find(BEGIN_MARKER)
        .map(|at| at + BEGIN_MARKER.len())
        .unwrap_or_else(|| panic!("{origin}: begin marker vanished between checks"));
    let end = text
        .find(END_MARKER)
        .unwrap_or_else(|| panic!("{origin}: end marker vanished between checks"));
    assert!(
        start < end,
        "{origin}: the end marker precedes the begin marker"
    );
    text[start..end].to_string()
}

/// Rust module docs (`//!` lines) as flowing prose: prefix stripped,
/// Markdown emphasis removed, whitespace collapsed. Rewrapping a comment is
/// therefore invisible to these assertions; rewording it is not.
fn module_doc_prose(source: &str) -> String {
    let doc = source
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("//!"))
        .collect::<Vec<_>>()
        .join(" ");
    normalize(&doc)
}

/// Markdown prose reduced to its words: blockquote markers and list bullets
/// stripped line-wise, emphasis and code ticks removed, whitespace collapsed.
///
/// The line-wise blockquote strip is load-bearing, not cosmetic. The frozen
/// rule is quoted as a Markdown blockquote in the source document and as
/// running prose in the module docs; without it, the `>` that lands mid-
/// sentence when the quote wraps would make two identical sentences compare
/// unequal — which is a formatting difference masquerading as a drift.
fn normalize(text: &str) -> String {
    let words: Vec<&str> = text
        .lines()
        .map(|line| line.trim_start().trim_start_matches(['>', ' ']))
        .flat_map(str::split_whitespace)
        .collect();
    words.join(" ").replace("**", "").replace('`', "")
}

/// C20 accept: the MUST-NOT-trust-the-AEAD rule appears verbatim in the
/// `unit_aead.rs` / `manifest_aead.rs` module docs — the place a refactor
/// that would violate it gets written.
#[test]
fn the_aead_rule_appears_verbatim_in_both_aead_modules() {
    let rule = normalize(AEAD_RULE);
    for module in AEAD_MODULES {
        let prose = module_doc_prose(&read(module));
        assert!(
            prose.contains(&rule),
            "{module}: the frozen assumption-class-4 rule is missing from the \
             module docs. It must read, verbatim:\n\n    {AEAD_RULE}\n\n\
             (MVP-SPEC.md line 103; C20 accept. XChaCha20-Poly1305 is not \
             key-committing, so a successful decryption is evidence of \
             nothing — the commitments are what bind content.)"
        );
    }
}

/// C20 accept: the same rule is in the frozen block itself, so the block and
/// the module docs cannot disagree about what the rule says.
#[test]
fn the_aead_rule_is_in_the_frozen_block() {
    let block = normalize(&frozen_block(&read(SOURCE_DOC), SOURCE_DOC));
    assert!(
        block.contains(&normalize(AEAD_RULE)),
        "{SOURCE_DOC}: the frozen block must state the assumption-class-4 \
         rule verbatim:\n\n    {AEAD_RULE}"
    );
}

/// The markers exist and delimit a substantial block — a cheap guard against
/// someone "fixing" a later drift failure by emptying one side.
#[test]
fn the_source_document_delimits_a_substantial_frozen_block() {
    let block = frozen_block(&read(SOURCE_DOC), SOURCE_DOC);
    assert!(
        block.len() > 4_000,
        "{SOURCE_DOC}: the frozen block is only {} bytes — it covers five \
         assumption classes and cannot plausibly be that short. Emptying one \
         copy is not how a drift failure is fixed.",
        block.len()
    );
}
