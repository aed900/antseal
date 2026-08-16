//! The committed verifier-page template, asserted where a runner exists.
//!
//! `verifier-web/` cannot be a Cargo member (D18 §4.2 — `.cargo/config.toml`'s
//! runner path hard-codes a two-level package depth), so a `verifier-web/tests/`
//! would have nothing to execute it. This crate is the nearest thing the
//! template is *about*: it supplies the glue and the module the template
//! inlines. The precedent is `carriage.rs`, which put a scan in the crate it
//! concerned rather than growing `antseal-core` a page concern (D131 §5 R8 (b)).
//!
//! # What is NOT here
//!
//! Assertions over the **built artifact** — D129 §5 R9 (1)–(7), the CSP over
//! real hashes, `SHA256SUMS` — live in `scripts/verifier-page-build.sh`, because
//! their subject does not exist until something builds it and a `cargo test`
//! that passes or fails on whether a build has happened is a test of the
//! working directory. Assertions needing a **browser** live in
//! `scripts/verifier-page-browser.mjs`. This file asserts only what is true of
//! the committed source.

use std::fs;
use std::path::PathBuf;

/// The page's source directory — one level above this crate's.
fn verifier_web() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../verifier-web")
        .canonicalize()
        .expect("verifier-web/ must exist — R23 authors the template in it")
}

fn template() -> String {
    fs::read_to_string(verifier_web().join("index.template.html"))
        .expect("verifier-web/index.template.html must exist (D131 §5 R1)")
}

/// The four token kinds the packaging step substitutes (D129 §5 R8).
///
/// The CSP-hash kind has two sites because the hashes land in two different
/// directives; every site is checked, and `verifier-page-pack.mjs` refuses a
/// build in which any of them survives.
const TOKENS: &[&str] = &[
    "__ANTSEAL_GLUE__",
    "__ANTSEAL_MODULE_BASE64__",
    "__ANTSEAL_MODULE_SHA256__",
    "__ANTSEAL_CSP_SCRIPT_HASHES__",
    "__ANTSEAL_CSP_STYLE_HASH__",
];

#[test]
fn the_template_carries_every_placeholder_the_packaging_step_substitutes() {
    let text = template();
    for token in TOKENS {
        assert!(
            text.contains(token),
            "the template no longer carries {token}. The packaging step substitutes it and \
             refuses an input that lacks it, so a rename here is a build that stops working \
             (D63 §5 R1 makes a second injection a hard error, never a silent no-op)."
        );
    }
}

#[test]
fn verifier_web_holds_exactly_the_template() {
    // D131 §5 R4/R5: the directory is SOURCE-ONLY. The built page goes to
    // `target/verifier-web/`, which `/target` already ignores, so no ignore
    // rule is added over a source directory and no rebuild ever lands in a
    // diff. This assertion is what enforces that, rather than discipline —
    // and it is also what keeps the wording scan's domain from drifting under
    // the wording scan.
    let mut found: Vec<String> = fs::read_dir(verifier_web())
        .expect("verifier-web/ must be readable")
        .map(|entry| {
            entry
                .expect("a readable entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    found.sort();
    assert_eq!(
        found,
        vec!["index.template.html".to_owned()],
        "verifier-web/ must hold exactly the template. A build output here would be committed \
         (a one-byte change costs a ~4.9 MB diff whose --stat reads '1 insertion(+)'), and a \
         second file would silently widen what the R18 wording scan covers."
    );
}

#[test]
fn the_template_declares_the_ruled_content_security_policy() {
    let text = template();
    // D129 §5 R6, literally. The policy lives in the artifact and never at the
    // host: the ruled host emits no security header of any kind and has no
    // configuration surface, so a policy there would be unhashed, unversioned,
    // unsigned and absent from every offline copy (D62 §3 R6).
    assert!(
        text.contains(r#"<meta http-equiv="Content-Security-Policy""#),
        "the template carries no CSP <meta>. R23 owns the policy and R25 must not strip it."
    );
    for directive in [
        "default-src 'none'",
        "'wasm-unsafe-eval'",
        "connect-src https:",
        "base-uri 'none'",
        "form-action 'none'",
    ] {
        assert!(
            text.contains(directive),
            "the policy is missing `{directive}` (D129 §5 R6)"
        );
    }
    // Scheme-only, NOT the six pinned hosts: a host allowlist blocks the user
    // override spec line 137 mandates, and blocks it undiagnosably — the page
    // sees the same TypeError and D66 §3 R4 forbids it naming a cause.
    assert!(
        !text.contains("connect-src https://"),
        "connect-src names hosts. D129 §5 R6 rules it scheme-only so a user-supplied https: \
         endpoint is not blocked in a way the page is forbidden from explaining."
    );
    for refused in ["'unsafe-inline'", "script-src 'unsafe-eval'"] {
        assert!(
            !text.contains(refused),
            "the policy carries {refused}, which D129 §6 refuses: hashes work for inline classic \
             AND inline module scripts in both engines, and 'unsafe-inline' is ignored when a \
             hash is present anyway."
        );
    }
}

#[test]
fn the_template_uses_no_style_attribute() {
    let text = template();
    // The policy itself blocks these (a `style-src` hash applies `style-src-attr`
    // too), so a style attribute would not be a cosmetic slip but a silently
    // dead one. Asserted here so it fails at review rather than in a browser.
    assert!(
        !text.contains(" style=\""),
        "the template uses a style= attribute. The page's own CSP blocks inline style attributes, \
         so it would silently do nothing — all styling belongs in the single inline <style>."
    );
}

#[test]
fn the_footer_advice_line_has_not_drifted_from_the_spec() {
    // D63 §5 R6 / §7 rule 5: MVP-SPEC.md line 139 mandates the footer carry
    // this sentence, and it is deliberately NOT in R18's frozen set (measured:
    // zero hits in tests/snapshots/verdict-wording.txt), so the page template
    // is its only home and this is its only guard.
    //
    // The comma is normative — SPEC-REVIEW.md:287's comma-less variant is not.
    let spec =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../MVP-SPEC.md"))
            .expect("MVP-SPEC.md must be readable");

    // Pull the sentence from the spec rather than restating it here: a literal
    // copied into this file would be a second source of truth that agrees on
    // the day it is written, which is the drift this test exists to catch.
    let quoted = spec
        .lines()
        .find(|line| line.contains("for high-stakes verification"))
        .and_then(|line| {
            let start = line.find("\"for high-stakes verification")?;
            let rest = &line[start + 1..];
            Some(rest[..rest.find('"')?].to_owned())
        })
        .expect("MVP-SPEC.md line 139 must carry the advice sentence in double quotes");

    // The spec spells the command in markdown code ticks and the page in a
    // <code> element. Compare the sentences, not the two markups.
    let want = quoted.replace('`', "");
    let advice = template();
    let start = advice
        .find("<p id=\"advice\">")
        .expect("the template must carry the advice line as #advice");
    let block = &advice[start..advice[start..].find("</p>").expect("unterminated #advice") + start];
    let got = block
        .replace("<p id=\"advice\">", "")
        .replace("<code>", "")
        .replace("</code>", "");

    assert_eq!(
        got.trim(),
        want.trim(),
        "the footer's advice line has drifted from MVP-SPEC.md line 139.\n  spec: {want}\n  page: {got}\n\
         Line 139 mandates the page footer display its build hash AND this sentence; it is not in \
         R18's frozen wording set, so nothing else guards it."
    );
}

/// The inner HTML of `<p id="…">…</p>`, or a panic naming the missing id.
fn paragraph(text: &str, id: &str) -> String {
    let open = format!("<p id=\"{id}\">");
    let start = text
        .find(&open)
        .unwrap_or_else(|| panic!("the template must carry #{id} as a <p> element"));
    let rest = &text[start + open.len()..];
    let end = rest
        .find("</p>")
        .unwrap_or_else(|| panic!("unterminated #{id}"));
    rest[..end].to_owned()
}

/// The longest run of ASCII-hex characters in `text` — the shape a digest
/// takes once the packaging step substitutes it.
fn longest_hex_run(text: &str) -> usize {
    let mut longest = 0;
    let mut current = 0;
    for ch in text.chars() {
        if ch.is_ascii_hexdigit() {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

/// **D136 §2 R12 — the footer digest is the MODULE's, and the label must say
/// so.**
///
/// The element renders `sha256(the wasm module)`. Under the label it shipped
/// with — `page build` — a reader performing the obvious check, comparing the
/// footer against the `SHA256SUMS` published beside the page, got a mismatch
/// on a **good** page: a file cannot contain its own hash, so page-carries-
/// module and you-fetched-that-page are two separate links (D136 §2 R10.1 and
/// R12) and the label is what tells a human which link this element is.
///
/// Two riders are asserted here rather than assumed:
///
/// - **the id does not move.** The CDP browser arm reads `#page-build` and is
///   passed `sha256(module)` by its caller, so a rename here unhooks it
///   silently.
/// - **the element carries exactly one value slot.** That arm asserts the
///   rendered text's *only* hex run is the module digest; a second hex-shaped
///   run in the label would make the assertion ambiguous after substitution.
///
/// `MVP-SPEC.md` line 139's *"its own build hash"* is the source of the
/// conflation. The spec is frozen, so this is recorded as a spec-versus-code
/// divergence owed to Q237 or the M4 docs row — flagged, never silently
/// diverged from.
#[test]
fn the_footer_names_the_module_not_the_page_as_the_subject_of_its_digest() {
    let text = template();
    assert!(
        text.contains(r#"id="page-build""#),
        "the footer digest element is no longer #page-build. The browser arm looks the element up \
         by that id and would report a missing element rather than a wrong digest (D136 §2 R12 \
         rider 1)."
    );

    let block = paragraph(&text, "page-build");
    assert_eq!(
        block.matches("<code>").count(),
        1,
        "the digest element must carry exactly one value slot, and it carries {}: {block}",
        block.matches("<code>").count()
    );
    assert!(
        block.contains("<code>__ANTSEAL_MODULE_SHA256__</code>"),
        "the value slot must be the module-digest placeholder the packaging step substitutes: \
         {block}"
    );

    let label = block.replace("<code>__ANTSEAL_MODULE_SHA256__</code>", "");
    let lowered = label.to_lowercase();
    assert!(
        lowered.contains("module"),
        "the label must name the MODULE, because that is whose digest this is. It reads `{}` \
         (D136 §2 R12).",
        label.trim()
    );
    assert!(
        !lowered.contains("page build"),
        "the label reads `{}` — `page build` is the shipped defect: it invites a comparison \
         against SHA256SUMS that fails on a correct page (D136 §2 R12).",
        label.trim()
    );
    assert!(
        longest_hex_run(&label) < 8,
        "the label around the value slot carries a {}-character hex run (`{}`). After \
         substitution the element must hold exactly ONE hex run — the module digest — or the \
         browser arm's \"its only hex run\" assertion has two candidates (D136 §2 R12 rider 1).",
        longest_hex_run(&label),
        label.trim()
    );
}

#[test]
fn the_template_never_calls_the_glues_default_init() {
    let text = template();
    // D129 §5 R2: the default init's `module_or_path === undefined` branch
    // derives a URL and fetches it. In a one-file page served from `file://`
    // that fetch is the whole failure mode the ruling exists to remove, so the
    // page calls `initSync({ module })` and the fetching path stays unreachable.
    assert!(
        text.contains("initSync({ module"),
        "the template does not call initSync({{ module }}) — it is not loading the module it carries"
    );
    assert!(
        !text.contains("__wbg_init("),
        "the template calls the glue's default init, which fetches the module over the network"
    );
}
