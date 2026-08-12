//! Product identity that is a **deployment fact**, not a cryptographic one:
//! today, exactly one constant — the canonical verifier-page URL.
//!
//! `MVP-SPEC.md` line 139 (*Page provenance*) states the requirement this
//! module exists to make satisfiable:
//!
//! > **one canonical URL** used in all docs and printed by the CLI in
//! > `reveal` output
//!
//! `docs/decisions/D62-verifier-page-host-and-canonical-url.md` §3 R8 fixes
//! the value (`https://antseal.org/` — apex, `https`, trailing slash, no
//! `www`, no subdomain, no path), rules that the constant lands **ahead of
//! the deploy**, and puts its home here rather than inside the renderer that
//! prints it: unlike D67's `SNIPPET_UNAVAILABLE` (a rendering detail with one
//! consumer), this value has three surfaces — the CLI, the docs and the page
//! itself — so a grep for the concept must land in one obvious place.
//!
//! # Why not `antseal-core`
//!
//! Core is the verification library the page links through WASM and that
//! third parties may link. A deployment fact does not belong in a WASM-safe
//! crypto crate; a URL change must not become a core version bump; and the
//! page must never render its own address out of the library that produces
//! its verdicts (D62 §3 R8, §8). [`crate::reveal_out`] is the only Rust
//! consumer — measured in D62 §1 (k), where R16 disclaims the constant in its
//! own `Do`.
//!
//! # What this constant is *not*
//!
//! It is not a trust anchor. A page served from this URL is exactly as
//! trustworthy as its published build hash makes it (spec line 139: signed
//! releases, a reproducible `wasm-pack` build, the footer build-hash, and
//! *"for high-stakes verification, run `antseal verify` and compare
//! verdicts"*). D62 §3 R6 pushes every security property the page relies on
//! **inside** the hashed artifact, so nothing here — and nothing about the
//! host — is load-bearing for a verdict. The CLI prints it because a bundle
//! recipient needs somewhere to go, not because the address proves anything.
//!
//! # The docs half is a checker, not a type
//!
//! Markdown cannot import a Rust `const`, so D62 §3 R8 splits the rule:
//! **exactly one Rust definition** (this one) and **every occurrence
//! anywhere in the tree byte-equal to it**, enforced by a tree-wide scan
//! anchored on the pattern (`antseal\.[a-z]+`, any `https?://` bearing the
//! product name) with a named allow-list for the prose that legitimately
//! discusses other names. That scan is R26/Q28's to land; this module owes
//! it the single value and the shape test below.

/// The one canonical verifier-page URL — apex, `https`, trailing slash, no
/// `www`, no subdomain, no path (D62 §3 R8).
///
/// **Every other spelling in the repository must be byte-equal to this
/// one.** Do not build it from parts, do not append a path, and do not
/// re-spell it in a message: interpolate the constant.
pub const VERIFIER_URL: &str = "https://antseal.org/";

#[cfg(test)]
mod tests {
    use super::VERIFIER_URL;

    /// Why a candidate URL is not in D62 §3 R8's canonical form.
    ///
    /// A function over an **argument** rather than a check of the constant
    /// alone, so the shape rules can be *shown to reject* the forms D62
    /// names — an assertion that only ever sees the value it is defending
    /// cannot demonstrate that it is enforcing anything. Test-only because
    /// the production surface here is one `&str`: the tree-wide value-identity
    /// scan D62 §3 R8 also asks for is a mode of
    /// `scripts/check-traceability.py`, and is R26/Q28's to land.
    fn canonical_form_violation(url: &str) -> Option<&'static str> {
        let Some(rest) = url.strip_prefix("https://") else {
            return Some("scheme is not https");
        };
        if !rest.ends_with('/') {
            return Some("no trailing slash");
        }
        let host = &rest[..rest.len() - 1];
        if host.is_empty() {
            return Some("no host");
        }
        if host.contains('/') {
            return Some("carries a path");
        }
        if host.starts_with("www.") {
            return Some("www is not the apex");
        }
        if host.matches('.').count() != 1 {
            return Some("not an apex domain");
        }
        if host != host.to_ascii_lowercase() {
            return Some("host is not lowercase");
        }
        None
    }

    /// The ruled value, literally — the one place in this crate where the
    /// string is written twice on purpose, so a silent edit of the constant
    /// is a failing test rather than a quiet redirection of every bundle
    /// recipient (D62 §3 R8).
    #[test]
    fn the_canonical_url_is_exactly_d62s_value() {
        assert_eq!(VERIFIER_URL, "https://antseal.org/");
    }

    /// The shape rules, and each one shown red on a form D62 refuses.
    ///
    /// The counterexamples are **assembled from [`VERIFIER_URL`] itself**
    /// rather than written out, so this module's source contains no second
    /// spelling of the product's domain: D62 §3 R8's tree-wide scan is
    /// anchored on the *pattern* (`antseal\.[a-z]+`, any `https?://`
    /// bearing the product name) precisely so a stray `www.` or `http://`
    /// form is caught rather than merely not matched — and a checker that
    /// reddened on the module defining the value would be the D123 lesson
    /// repeated. The strings still exist at run time, which is what makes
    /// the rules demonstrably enforcing something.
    #[test]
    fn the_shape_rules_reject_every_form_d62_names() {
        assert_eq!(canonical_form_violation(VERIFIER_URL), None);
        let host = VERIFIER_URL
            .trim_start_matches("https://")
            .trim_end_matches('/');
        for (candidate, expected) in [
            (format!("http://{host}/"), "scheme is not https"),
            (format!("https://{host}"), "no trailing slash"),
            (format!("https://www.{host}/"), "www is not the apex"),
            (format!("https://verify.{host}/"), "not an apex domain"),
            (format!("https://{host}/verify/"), "carries a path"),
            (
                format!("https://{}/", host.to_ascii_uppercase()),
                "host is not lowercase",
            ),
        ] {
            assert_eq!(
                canonical_form_violation(&candidate),
                Some(expected),
                "{candidate} must be refused as `{expected}`"
            );
        }
    }
}
