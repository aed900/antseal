//! The page's neutralisation policy — this surface's half of D67 §3 R6's
//! value-vs-rendering split.
//!
//! # Why the policy is here and not in `antseal-core`
//!
//! `wording::redacted_file_line` takes an **already-escaped** path and says
//! why: *"the path is sealer-authored text that reaches a terminal or a DOM,
//! and the two surfaces neutralise different byte sets. This table spells the
//! sentence; the renderer decides what a control character looks like in its
//! own medium."* D67 §3 R8 puts the CLI's set in `antseal-cli` and keeps
//! `antseal-core` free of both, so core's WASM safety is untouched — and
//! D130 §3 R5 keeps it that way by making the escape a **caller-supplied
//! function** rather than a set core owns.
//!
//! # Why it is not in `boundary.rs`
//!
//! D130 §3 R5, explicitly: the policy lives in `crates/antseal-wasm/src/` so
//! the native gate — which compiles no `wasm-bindgen` at all (D18 §5 R3) —
//! type-checks and *executes* it. A policy inside the `cfg`-gated shim module
//! would be reachable only from a browser.
//!
//! # The set, and how it differs from the terminal's
//!
//! It is a **superset** of D67 §3 R3's closed set, extended by the two
//! characters that are a hazard in a DOM and not in a terminal:
//!
//! | class | terminal (D67 §3 R3) | this policy |
//! | --- | --- | --- |
//! | `\` and `"` | escaped | escaped — the notation needs its own escape character, and the table's quotes are the path's delimiter |
//! | LF, CR, TAB | `\n` `\r` `\t` | same |
//! | C0, DEL, C1 | `\u{…}` | same |
//! | bidi controls (ALM, LRM/RLM, LRE…RLO, LRI…PDI) | `\u{…}` | same |
//! | **U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR** | not a member | **`\u{…}`** |
//!
//! U+2028/U+2029 are line terminators to the DOM and to JS and are invisible
//! to a reader; a terminal treats them as ordinary characters, which is why
//! D67's set has no reason to carry them and this one does. Everything else
//! is identical, so two consequences follow and both are worth stating: on
//! any input containing neither separator the two surfaces render the
//! **same** string — a stronger property than D130 §1 (k) measured over the
//! R9 corpus alone — and where they do differ, they differ by design (D130 §3
//! R5; §7.3 records that no parity gate can see it).
//!
//! HTML metacharacters (`<`, `>`, `&`) are deliberately **not** touched. D129
//! requires every bundle-derived string to reach the DOM by `textContent`,
//! under which they are ordinary text; escaping them here would double-escape
//! visible content and would also invite the reading that this function is
//! what makes the page safe. It is not: `textContent` is.

/// Neutralise one sealer- or artifact-authored value for the page's DOM.
///
/// Total, allocation-bounded and independent of any host: the output is at
/// most eight bytes per input character, and no input can make it fail. It is
/// handed to `antseal-core` as the caller's policy — see
/// [`RenderedRedaction::new`] and [`RenderedVerdict::new`], both of which take
/// the function rather than the set.
///
/// [`RenderedRedaction::new`]:
///     antseal_core::verify::redaction::RenderedRedaction::new
/// [`RenderedVerdict::new`]:
///     antseal_core::verify::orchestration::RenderedVerdict::new
#[must_use]
pub fn escape_for_dom(value: &str) -> String {
    use core::fmt::Write as _;

    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if escapes_as_u(c) => {
                // `write!` to a `String` cannot fail; the result is discarded
                // for the same reason the CLI's escape discards it.
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// Membership in the `\u{…}` half of the policy.
///
/// LF, CR and TAB are members of C0 but take their short escapes above, as in
/// D67 §3 R3. The last row is this surface's own addition.
const fn escapes_as_u(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{001f}'   // C0
        | '\u{007f}'              // DEL
        | '\u{0080}'..='\u{009f}' // C1
        | '\u{061c}'              // ALM
        | '\u{200e}' | '\u{200f}' // LRM, RLM
        | '\u{202a}'..='\u{202e}' // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
        | '\u{2028}' | '\u{2029}' // LINE SEPARATOR, PARAGRAPH SEPARATOR
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_text_is_the_identity() {
        // D130 §1 (k) measured every path in the R9 corpus unchanged by
        // either policy. These are those paths.
        for path in [
            "archive/old.txt",
            "data/blob.bin",
            "data/empty.bin",
            "data/n6.bin",
            "data/one.bin",
            "mirror/bom.txt",
            "mirror/nfd.txt",
            "notes/intro.md",
            "notes/split.md",
            "CN=antseal mock TSA signer,O=antseal fixtures",
            "bitcoin-block-700113",
        ] {
            assert_eq!(escape_for_dom(path), path, "`{path}` must be untouched");
        }
    }

    #[test]
    fn a_newline_cannot_forge_a_row() {
        // The load-bearing half: the value becomes exactly one line, so a
        // path carrying a whole fake block row cannot become one.
        let hostile = "notes/a\n      unit 9 revealed: 10 byte(s) at offset 0 of 10 declared";
        let escaped = escape_for_dom(hostile);
        assert!(!escaped.contains('\n'), "{escaped}");
        assert!(escaped.starts_with("notes/a\\n"), "{escaped}");
    }

    #[test]
    fn the_delimiter_and_the_notation_hold() {
        // The table wraps the path in quotes, so `"` must not close them
        // early; and the escape character must itself be escaped or the
        // notation is ambiguous.
        assert_eq!(escape_for_dom(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_for_dom(r"a\u{a}b"), r"a\\u{a}b");
    }

    #[test]
    fn every_bidi_control_is_neutralised() {
        // Trojan Source: an RLO inside a path reverses everything after it,
        // so a rendered row can read as a different row entirely.
        for c in [
            '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
            '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ] {
            let escaped = escape_for_dom(&c.to_string());
            assert_eq!(escaped, format!("\\u{{{:x}}}", u32::from(c)));
            assert!(!escaped.contains(c));
        }
    }

    #[test]
    fn the_two_separators_are_this_surfaces_own_addition() {
        // The one place this policy is deliberately not D67 §3 R3: to a DOM
        // and to JS these terminate a line, and they are invisible.
        assert_eq!(escape_for_dom("a\u{2028}b"), "a\\u{2028}b");
        assert_eq!(escape_for_dom("a\u{2029}b"), "a\\u{2029}b");
    }

    #[test]
    fn html_metacharacters_are_left_alone() {
        // `textContent` is what makes them safe (D129); escaping them here
        // would double-escape visible text and misplace the guarantee.
        assert_eq!(escape_for_dom("<b>&amp;</b>"), "<b>&amp;</b>");
    }

    #[test]
    fn the_policy_is_total_over_hostile_input() {
        // No panic, no unbounded growth, and idempotent on its own output's
        // safety: whatever comes back carries none of the dangerous set.
        let mut hostile = String::new();
        for code in 0u32..0x3000 {
            if let Some(c) = char::from_u32(code) {
                hostile.push(c);
            }
        }
        let escaped = escape_for_dom(&hostile);
        assert!(escaped.chars().all(|c| !escapes_as_u(c) && c != '\n'));
        assert!(escaped.len() <= hostile.len() * 8);
    }
}
