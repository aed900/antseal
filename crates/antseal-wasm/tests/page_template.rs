//! The committed verifier-page template, asserted where a runner exists.
//!
//! `verifier-web/` cannot be a Cargo member (D18 §4.2 — `.cargo/config.toml`'s
//! runner path hard-codes a two-level package depth), so a `verifier-web/tests/`
//! would have nothing to execute it. This crate is the nearest thing the
//! template is *about*: it supplies the glue and the module the template
//! inlines. The precedent is `carriage.rs`, which put a scan in the crate it
//! concerned rather than growing `antseal-core` a page concern (D131 §5 R8 (b)).
//!
//! # What is NOT here, and the ONE exception R96 added
//!
//! Assertions over the **built artifact** — D129 §5 R9 (1)–(7), the CSP over
//! real hashes, `SHA256SUMS` — live in `scripts/verifier-page-build.sh`, because
//! their subject does not exist until something builds it and a `cargo test`
//! that passes or fails on whether a build has happened is a test of the
//! working directory. Assertions needing a **browser** live in
//! `scripts/verifier-page-browser.mjs`.
//!
//! **The exception, recorded rather than left to be discovered.**
//! [`the_built_page_carries_the_footers_signing_key_element_byte_for_byte`] reads
//! `target/verifier-web/index.html` and goes **red** when it is absent. R96's
//! Accept row 2 requires the signing-key element to be measured *"on the built
//! artifact, not on the template alone"*, and a test that reads the template and
//! calls it the artifact is an assertion that cannot fail; a test that skips
//! when the artifact is missing is the same defect wearing a green tick.
//!
//! The cost is exactly the one the paragraph above names, and it is real: after
//! a `cargo clean` this lane is red until the page has been built once.
//! `scripts/local-gate.sh` runs `cargo test` **before**
//! `scripts/verifier-page-build.sh`, and its `run` helper records a failure and
//! carries on, so the first gate run on a cleaned tree reports this lane FAIL
//! **and then builds the page**, leaving the next run green. A bootstrap cost,
//! not a deadlock.
//!
//! If that cost is ever judged too high, the move is to hand the assertion to
//! `scripts/verifier-page-pack.mjs`, which already runs over the artifact and
//! already asserts it decomposes back to this template — not to soften this
//! test into a skip. Putting it there was outside R96's write scope.

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

// ---------------------------------------------------------------------------
// R96 — the signing key's publication target in the footer (D153 §1.6b)
// ---------------------------------------------------------------------------

/// The marker pair, named once.
///
/// Deliberately the **same** pair `README.md` carries.
/// `docs/signing/maintainer-key-procedure.md` §6 step 4 changes all four
/// publication locations *"in one act"*, so the publisher greps one string and
/// finds every locus rather than having to remember a second spelling for the
/// page.
const KEY_MARKER_BEGIN: &str = "BEGIN minisign-public-key";
const KEY_MARKER_END: &str = "END minisign-public-key";

/// The sentence the block carries while `maintainer-key-procedure.md` §5 has
/// not fired.
///
/// A **pin**, not a second source of truth: the copy may be rewritten, and the
/// rewrite is then a deliberate edit here rather than a silent one there.
const NO_KEY_SENTENCE: &str = "No signing key is published here yet.";

/// Every byte offset at which `needle` occurs.
fn offsets(text: &str, needle: &str) -> Vec<usize> {
    text.match_indices(needle).map(|(index, _)| index).collect()
}

/// The longest run of base64 characters — the shape a published minisign
/// public key takes, 56 of them unbroken.
fn longest_base64_run(text: &str) -> usize {
    let mut longest = 0;
    let mut current = 0;
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=' {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

/// The publication target: the bytes strictly between the two marker
/// **comments** — exactly the span §5 step 2 replaces.
///
/// # Why this is not one `contains`
///
/// `assert!(text.contains("BEGIN minisign-public-key"))` — the obvious form —
/// is green with the END marker deleted, green with the pair inverted, and
/// green with the pair empty. All three are a write target that no longer
/// works, and the third is one a publisher would paste a key *outside* of.
/// So: both markers, **exactly one** of each, and BEGIN strictly before END.
fn key_block(text: &str, subject: &str) -> String {
    let begins = offsets(text, KEY_MARKER_BEGIN);
    let ends = offsets(text, KEY_MARKER_END);
    assert_eq!(
        begins.len(),
        1,
        "{subject} carries {} `{KEY_MARKER_BEGIN}` marker(s), not exactly one. §5 step 2 writes \
         the key between ONE pair; a second pair makes the write target ambiguous and a missing \
         one makes it absent (R96 Accept row 1).",
        begins.len()
    );
    assert_eq!(
        ends.len(),
        1,
        "{subject} carries {} `{KEY_MARKER_END}` marker(s), not exactly one. A BEGIN with no END \
         is an unbounded write target: everything after it is inside the block (R96 Accept row 1).",
        ends.len()
    );
    assert!(
        begins[0] < ends[0],
        "{subject}: the marker pair is INVERTED — `{KEY_MARKER_END}` at byte {} precedes \
         `{KEY_MARKER_BEGIN}` at byte {}. There is no span between them to write a key into.",
        ends[0],
        begins[0]
    );
    let open_end = text[begins[0]..]
        .find("-->")
        .map(|index| begins[0] + index + 3)
        .unwrap_or_else(|| panic!("{subject}: the BEGIN marker is not inside an HTML comment"));
    let close_start = text[..ends[0]]
        .rfind("<!--")
        .unwrap_or_else(|| panic!("{subject}: the END marker is not inside an HTML comment"));
    assert!(
        open_end <= close_start,
        "{subject}: the two marker comments overlap — there is no block between them"
    );
    text[open_end..close_start].to_owned()
}

/// The whole `<p id="signing-key">…</p>` element, or a panic naming what is
/// missing.
fn signing_key_element(text: &str, subject: &str) -> String {
    const OPEN: &str = r#"<p id="signing-key">"#;
    let start = text.find(OPEN).unwrap_or_else(|| {
        panic!(
            "{subject} carries no {OPEN} element. It is the page footer's key publication target \
             (maintainer-key-procedure.md §5 step 2); without it three of the four locations have \
             a defined write target and this one does not (D153 §1.6b)."
        )
    });
    let rest = &text[start..];
    let end = rest
        .find("</p>")
        .unwrap_or_else(|| panic!("{subject}: #signing-key is unterminated"));
    rest[..end + 4].to_owned()
}

/// The BUILT page.
///
/// `scripts/verifier-page-build.sh` sets `OUT="target/verifier-web"` after
/// `cd`-ing to the repository root, so this path hangs off the **repo root**
/// and not off cargo's target directory: `CARGO_TARGET_DIR` moves cargo's
/// output and does not move the page build's.
fn built_page_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/verifier-web/index.html")
}

/// The built page's bytes, or a **red** naming how to produce them.
///
/// Never a fallback to the template and never a skip. R96's Accept row 2 says
/// *"measured on the built artifact, not on the template alone"*, and a check
/// that reads the template when the artifact is missing has measured the
/// template twice.
fn built_page() -> String {
    let path = built_page_path();
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "the built verifier page is not readable at {} ({error}).\n\
             This assertion's subject is the ARTIFACT, so a skip here would be R96's own defect \
             reproduced — the row exists because a check that cannot go red is not a check.\n\
             Build it:  scripts/verifier-page-build.sh --build-only\n\
             (See this file's header for why a `cargo clean` leaves this lane red until the page \
             has been built once, and why that is a bootstrap cost rather than a deadlock.)",
            path.display()
        )
    })
}

/// **R96 Accept rows 1 and 3, on the committed source.**
///
/// The block has exactly two legal states and this asserts it is in exactly
/// one of them, rather than asserting today's state as a permanent truth: a
/// test that pinned *"no key"* forever would go red on the publication act it
/// exists to serve, and a test that pinned only the sentence would stay green
/// over a page carrying a key underneath a line saying none is published.
#[test]
fn the_footer_carries_the_signing_keys_marker_pair_in_exactly_one_legal_state() {
    let text = template();

    // The element, and the element IN THE FOOTER — §5 step 2 names the footer,
    // and a key parked in the body would satisfy a bare `contains`.
    let element = signing_key_element(&text, "verifier-web/index.template.html");
    let footer_start = text
        .find("<footer>")
        .expect("the template must carry a <footer> — MVP-SPEC.md line 139 mandates its contents");
    let footer_end = text
        .find("</footer>")
        .expect("the template's <footer> is unterminated");
    let element_at = text.find(&element).expect("just located");
    assert!(
        footer_start < element_at && element_at < footer_end,
        "#signing-key is outside the <footer>. maintainer-key-procedure.md §5 step 2 names \
         *the page footer* as the publication location, not the page."
    );

    // Both markers, exactly one of each, in order — over the WHOLE template, so
    // a duplicate pair anywhere in the file is a failure and not a shadow.
    let block = key_block(&text, "verifier-web/index.template.html");
    assert!(
        !block.trim().is_empty(),
        "the marker pair is EMPTY. A publisher following §5 step 2 has nothing to replace and \
         nothing telling them a key is expected here; the page would silently carry an unlabelled \
         gap where key-custody.md §9's discovery copy should be."
    );
    // And the markers are the element's, not some other pair in the file.
    assert!(
        element.contains(KEY_MARKER_BEGIN) && element.contains(KEY_MARKER_END),
        "the marker pair is not inside #signing-key: {element}"
    );

    let says_none = block.contains(NO_KEY_SENTENCE);
    let key_shaped = longest_base64_run(&block) >= 40;
    assert_ne!(
        says_none, key_shaped,
        "the block between the markers is in NEITHER of its two legal states.\n  it reads: \
         {block:?}\n  While maintainer-key-procedure.md §5 has not fired the block carries \
         {NO_KEY_SENTENCE:?} and no key (R96 Accept row 3). Once §5 fires it carries the \
         56-character key and not that sentence. BOTH would publish a key under a line saying \
         none is published; NEITHER leaves §5 step 2's only write target unlabelled."
    );

    // D71 §2 R11, on the element's own copy. The four prohibitions are what
    // keeps this location honest about being DISCOVERY rather than an
    // independent check (key-custody.md §9), so they are asserted here rather
    // than left to scripts/check-copy-style.py, which polices the product
    // vocabulary (P1-P7) and knows nothing about this record.
    let lowered = element.to_lowercase();
    for (banned, why) in [
        ("verified", "item 1: not a verdict about the software"),
        ("revoked", "item 2: no revocation mechanism exists"),
        ("expired", "item 2: no expiry mechanism exists"),
        ("rollover", "item 2: no rollover mechanism exists"),
        (
            "independently verifiable",
            "item 3: same account as the downloads",
        ),
        (
            "independently checkable",
            "item 3: same account as the downloads",
        ),
        (
            "notar",
            "item 4 / MVP-SPEC.md line 28: never a notarial claim",
        ),
        ("legally", "item 4: no claim of legal effect"),
    ] {
        assert!(
            !lowered.contains(banned),
            "the footer's key copy says {banned:?}, which D71 §2 R11 forbids the release \
             documentation ({why}): {element}"
        );
    }
    // Item 3 has a positive half as well as a negative one: the copy has to
    // STATE the limit, because a bare key with no qualifier is read as a check.
    assert!(
        lowered.contains("rather than an independent check on"),
        "the footer's key copy no longer states what key-custody.md §9 prices this location at \
         — discovery, NOT independent, because the page, the README and the release assets are \
         one account (D71 §2 R11 item 3): {element}"
    );
}

/// **R96 Accept row 2 — measured on the BUILT ARTIFACT.**
///
/// The first assertion is the one that makes every assertion after it mean
/// something: the file read really is the packaged page and not a copy of the
/// template. Without it, `cp verifier-web/index.template.html
/// target/verifier-web/index.html` turns this whole test green, and *"measured
/// on the built artifact"* would have measured the template twice.
#[test]
fn the_built_page_carries_the_footers_signing_key_element_byte_for_byte() {
    let built = built_page();
    let path = built_page_path();
    let subject = format!("the built page {}", path.display());

    // 1. This is the ARTIFACT. Every substitution token is gone — true of a
    //    packaged page, false of the template it was packaged from.
    for token in TOKENS {
        assert!(
            !built.contains(token),
            "{subject} still carries the {token} placeholder, so it is the TEMPLATE and not a \
             built page. Everything below would be measuring the template a second time."
        );
    }

    // 2. The RENDERED page carries the element, in its FOOTER. This is R96
    //    Accept row 2 in its own words, and it names the element rather than
    //    the marker so a deletion reads as what it is.
    let built_element = signing_key_element(&built, &subject);
    let footer_start = built
        .find("<footer>")
        .unwrap_or_else(|| panic!("{subject} carries no <footer> — it is not the verifier page"));
    let footer_end = built
        .find("</footer>")
        .unwrap_or_else(|| panic!("{subject}: the <footer> is unterminated"));
    let element_at = built.find(&built_element).expect("just located");
    assert!(
        footer_start < element_at && element_at < footer_end,
        "{subject}: #signing-key is outside the <footer>. maintainer-key-procedure.md §5 step 2 \
         names *the page footer* at https://antseal.org/ as the publication location."
    );

    // 3. The marker pair survived packaging: exactly once each, and in order.
    let built_block = key_block(&built, &subject);

    // 4. Byte-for-byte the template's. This is the STALENESS check, and it is
    //    the reason step 1 is not enough on its own: a page built before the
    //    template's key block was edited is a published location that does not
    //    carry what the source says it carries, which for a publication
    //    location is the whole failure.
    let template_element = signing_key_element(&template(), "verifier-web/index.template.html");
    let template_block = key_block(&template(), "verifier-web/index.template.html");
    assert_eq!(
        built_block, template_block,
        "{subject}: the key block is not the template's — the artifact is STALE (or the packaging \
         step transformed it). Rebuild:  scripts/verifier-page-build.sh --build-only"
    );
    // The block alone would still match if the element AROUND it had been
    // renamed or unwrapped between the source and the artifact.
    assert_eq!(
        built_element, template_element,
        "{subject}: #signing-key is not the template's element verbatim. R96 Accept row 2 is a \
         statement about the RENDERED page — what a reader of https://antseal.org/ sees is what \
         maintainer-key-procedure.md §5 step 2 names."
    );
}
