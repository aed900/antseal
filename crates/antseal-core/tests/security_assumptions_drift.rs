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
//! Three claims, each an explicit acceptance criterion of its task:
//!
//! 1. **C20/Q12** — the text between the `frozen-security-assumptions`
//!    markers is **byte-identical** in `docs/security-assumptions.md` and
//!    `docs/threat-model.md`. No normalization is applied to this one: the
//!    task word is *verbatim*, so verbatim is what is checked.
//! 2. **C20** — the frozen AEAD rule appears verbatim as a module doc comment
//!    in **both** `crypto/unit_aead.rs` and `crypto/manifest_aead.rs`, and in
//!    the frozen block itself. Assumption class 4 (AEAD is
//!    confidentiality-only and non-committing) is the one assumption a
//!    well-meaning refactor can quietly invalidate — by deciding that a
//!    successful decryption is evidence of anything — so the rule is planted
//!    where that refactor gets written, not only where security documents get
//!    read.
//! 3. **C21** — the normative WASM zeroization caveat is present both as a
//!    doc comment on the crypto module root and in `docs/threat-model.md`.
//!    It is a residual risk with no mitigation, so the only thing that can go
//!    wrong with it is that someone deletes it.
//!
//! For claims 2 and 3, whitespace and Markdown emphasis are normalized before
//! comparison, so rewrapping a doc comment is allowed and changing its words
//! is not.

use std::fs;
use std::path::{Path, PathBuf};

/// The workspace root (this crate sits at `crates/antseal-core`).
const WORKSPACE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// C20's source document — the signed-off freeze.
const SOURCE_DOC: &str = "docs/security-assumptions.md";
/// Q12's threat model, which must carry the block verbatim.
const THREAT_MODEL: &str = "docs/threat-model.md";

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

/// C21's normative WASM caveat (MVP-SPEC.md line 143), in the wording carried
/// by the crypto module root and by the threat model.
const WASM_ZEROIZE_CAVEAT: &str = "The WASM verifier cannot guarantee zeroization for \
     bundle-supplied keys (k_u, k_m, salts) in browser memory.";

/// The crypto module root, which must carry [`WASM_ZEROIZE_CAVEAT`].
const CRYPTO_MODULE_ROOT: &str = "crates/antseal-core/src/crypto.rs";

/// C21's per-buffer audit, which the caveat's "why" lives in.
const ZEROIZATION_AUDIT: &str = "docs/zeroization-audit.md";

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

/// Q12 accept: the assumptions block in `docs/threat-model.md` matches C20's
/// source text **verbatim** — byte-identical between the markers, with no
/// normalization whatsoever. Editing one copy without the other fails here.
#[test]
fn threat_model_carries_the_frozen_block_verbatim() {
    let source = frozen_block(&read(SOURCE_DOC), SOURCE_DOC);
    let delivered = frozen_block(&read(THREAT_MODEL), THREAT_MODEL);
    if source == delivered {
        return;
    }

    // Locate the divergence so the failure names the edit, not just the fact.
    let first_difference = source
        .bytes()
        .zip(delivered.bytes())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| source.len().min(delivered.len()));
    let excerpt = |text: &str| {
        let from = text
            .char_indices()
            .map(|(at, _)| at)
            .take_while(|at| *at <= first_difference.saturating_sub(60))
            .last()
            .unwrap_or(0);
        text.get(from..)
            .unwrap_or(text)
            .chars()
            .take(160)
            .collect::<String>()
    };
    panic!(
        "the frozen Security-assumptions block has DRIFTED.\n\n  \
         {SOURCE_DOC} — C20, the signed-off source ({} bytes)\n  \
         {THREAT_MODEL} — Q12, must carry it verbatim ({} bytes)\n\n\
         first difference at byte {first_difference}:\n\n\
         source ......: {}\n\
         threat model : {}\n\n\
         Fix by copying C20's block over, not by editing the copy. If the \
         assumption itself changed, that is a format event: it starts with a \
         dated row in {SOURCE_DOC}'s change header.",
        source.len(),
        delivered.len(),
        excerpt(&source),
        excerpt(&delivered),
    );
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

/// The markers exist and delimit a substantial block in **both** documents —
/// a cheap guard against someone "fixing" a drift failure by emptying one
/// side, which would otherwise satisfy the byte-equality test perfectly.
#[test]
fn both_documents_delimit_a_substantial_frozen_block() {
    for document in [SOURCE_DOC, THREAT_MODEL] {
        let block = frozen_block(&read(document), document);
        assert!(
            block.len() > 4_000,
            "{document}: the frozen block is only {} bytes — it covers five \
             assumption classes and cannot plausibly be that short. Emptying \
             one copy is not how a drift failure is fixed.",
            block.len()
        );
    }
}

/// C21 accept: the WASM zeroization caveat is a doc comment on the crypto
/// module root **and** is delivered into the threat model.
///
/// It is a residual risk with no mitigation available at this layer, so the
/// documentation *is* the deliverable — which makes silent deletion the only
/// way it can regress.
#[test]
fn the_wasm_zeroize_caveat_is_on_the_module_root_and_in_the_threat_model() {
    let caveat = normalize(WASM_ZEROIZE_CAVEAT);

    let prose = module_doc_prose(&read(CRYPTO_MODULE_ROOT));
    assert!(
        prose.contains(&caveat),
        "{CRYPTO_MODULE_ROOT}: the C21 WASM zeroization caveat is missing from \
         the crypto module-root docs. It must read:\n\n    \
         {WASM_ZEROIZE_CAVEAT}\n\n(MVP-SPEC.md line 143.)"
    );

    let threat_model = normalize(&read(THREAT_MODEL));
    assert!(
        threat_model.contains(&caveat),
        "{THREAT_MODEL}: the C21 WASM zeroization caveat must be delivered into \
         the threat model (§2.10) as well as living on the crypto module root."
    );

    let audit = normalize(&read(ZEROIZATION_AUDIT));
    assert!(
        audit.contains(&caveat),
        "{ZEROIZATION_AUDIT}: the audit must state the caveat it is the \
         evidence for (residual risk R5)."
    );
}

/// Q12 accept: every M4 threat section named by the task is present as a
/// stub. The list is the point — a section that is missing cannot be noticed
/// as missing at M4, whereas a stub marked "not written" is a visible debt.
#[test]
fn every_m4_threat_section_is_enumerated() {
    /// The M4 sections Q12 requires, as `(anchor phrase, what it covers)`.
    const REQUIRED_SECTIONS: &[(&str, &str)] = &[
        ("2.1 Vault theft", "retroactive decryption, no rotation"),
        ("2.2 Vault loss", "reveal/restore lost forever"),
        (
            "2.3 Wallet linkability",
            "receipt exposes the paying wallet",
        ),
        (
            "2.4 Malicious verifier host",
            "the page can render any verdict",
        ),
        (
            "2.5 Coercion / compelled disclosure",
            "selective disclosure protects against recipients, not compulsion",
        ),
        ("2.6 Hostile bundles", "attacker-controlled parser input"),
        (
            "2.7 Sealer as adversary",
            "equivocation, out-of-context reveal",
        ),
        ("2.8 Size fingerprint", "structure metadata is visible"),
        (
            "2.9 Evidence independence",
            "no single anchor is load-bearing",
        ),
        (
            "2.10 WASM zeroization caveat",
            "browser memory cannot be wiped (C21)",
        ),
    ];

    let threat_model = read(THREAT_MODEL);
    for (heading, covers) in REQUIRED_SECTIONS {
        assert!(
            threat_model.contains(heading),
            "{THREAT_MODEL}: missing the required M4 section `{heading}` \
             ({covers}). Q12 enumerates every section so the M0 freeze happens \
             against a known map; deleting one hides a hole rather than \
             closing it."
        );
    }
}
