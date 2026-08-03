//! The OpenTimestamps upgrade-URI allowlist (task **A42**; decision D54 §4).
//!
//! # Why an allowlist exists at all
//!
//! A14 issues `GET <pending-uri>/timestamp/<hex>` against a URI read out of a
//! **stored `.ots` artifact**. That artifact lives on disk in the vault and is
//! attacker-writable under a vault-tamper threat, and A15/U24's opportunistic
//! upgrade hook fires on **every CLI invocation**. So an unconstrained fetch
//! is a server-side request-forgery and deanonymisation surface: rewrite one
//! pending URI to `https://attacker.example` and the attacker learns the
//! moment the victim runs any antseal command, from that victim's own IP.
//!
//! # Stricter than upstream, on purpose
//!
//! upstream defends this with `DEFAULT_CALENDAR_WHITELIST`
//! (`python-opentimestamps/opentimestamps/calendar.py:150-154`), three
//! `fnmatch` globs. antseal pins the same three operator domains and matches
//! them as strict lowercase host **suffixes on a dot boundary**, with `https`
//! required and path, port, query, fragment and userinfo all forbidden. That
//! is strictly narrower than `fnmatch`, whose `*` also matches the empty
//! string — so upstream's `*.calendar.opentimestamps.org` admits the bare
//! `calendar.opentimestamps.org`, a name its operator does not run a calendar
//! on — and which is case-sensitive against a case-insensitive DNS name.
//!
//! # APPEND-ONLY
//!
//! [`OTS_UPGRADE_HOST_SUFFIXES`] may gain entries and may never lose one.
//! Removing a suffix strands **every already-stored `.ots`** whose pending
//! attestation names it: those anchors could never upgrade, and the bytes on
//! disk cannot be rewritten to name a different calendar because the
//! attestation is what the calendar returned. Adding one is an ordinary
//! reviewed change. The *submit* list carries no such constraint (D54 §5) —
//! a bundle carries its own pending URIs and is unaffected by changes to the
//! list of calendars new seals are sent to.
//!
//! # No error code is minted here
//!
//! A refusal is an *acquisition-time* refusal, and D90 already settled the
//! class: `AnchorHttpError` "deliberately has no `code()`", because the
//! error-code contract governs errors a **verifier** surfaces and an
//! acquisition failure never appears in a `.sealproof` verdict. A refused
//! upgrade URI means an upgrade did not happen; the stored artifact and every
//! verdict over it are unchanged.

use ureq::http::Uri;

/// Host suffixes a pending attestation's URI may name.
///
/// Matched as strict lowercase suffixes **on a dot boundary**: a host is
/// admitted when it ends with one of these AND the character before the match
/// exists — so `btc.calendar.catallaxy.com` is admitted and the bare
/// `calendar.catallaxy.com` is not.
///
/// **APPEND-ONLY.** Removing a suffix strands every stored `.ots` naming it.
/// See the module docs.
pub const OTS_UPGRADE_HOST_SUFFIXES: [&str; 3] = [
    ".calendar.opentimestamps.org",
    ".calendar.eternitywall.com",
    ".calendar.catallaxy.com",
];

/// Why an upgrade URI was refused.
///
/// A reason per rule rather than one boolean, so a diagnostic can say which
/// rule fired and a test can assert on it. Every variant is `&'static`-shaped:
/// nothing from the artifact reaches a message, because the artifact is the
/// attacker-controlled input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UpgradeUriRefusal {
    /// Not parseable as a URI at all.
    #[error("the pending attestation's URI is not a valid URI")]
    Unparseable,
    /// Scheme is not `https`.
    ///
    /// Plain HTTP is refused here even though RFC 3161 traffic is allowed to
    /// use it (D90 §6.6): a calendar reply is **unsigned**, so transport is
    /// its only integrity control, and an on-path attacker who can rewrite a
    /// plain-HTTP upgrade response can plant an arbitrary attestation.
    #[error("the URI's scheme must be https")]
    NotHttps,
    /// The authority carries userinfo.
    #[error("the URI must not carry userinfo")]
    Userinfo,
    /// The authority carries an explicit port.
    #[error("the URI must not carry a port")]
    Port,
    /// The URI carries a path, query or fragment.
    #[error("the URI must be scheme and host only: no path, query or fragment")]
    NotBareHost,
    /// No host at all.
    #[error("the URI has no host")]
    NoHost,
    /// The host is outside the pinned suffixes and outside any configured
    /// calendar's own host.
    #[error("the URI's host is not a pinned calendar and not a configured one")]
    HostNotAllowed,
}

/// Whether `uri` may be contacted for an upgrade — D54 §6.2's ruled signature.
///
/// `configured` is the user's calendar list (U4's `[anchors] ots_calendars`);
/// each entry widens the allowlist to **that host and its subdomains only**.
#[must_use]
pub fn upgrade_uri_allowed(uri: &str, configured: &[String]) -> bool {
    classify_upgrade_uri(uri, configured).is_ok()
}

/// The same decision, with the reason.
///
/// # Errors
///
/// [`UpgradeUriRefusal`], naming which rule the URI broke.
pub fn classify_upgrade_uri(uri: &str, configured: &[String]) -> Result<(), UpgradeUriRefusal> {
    // The raw string is inspected as well as the parsed URI, because
    // `http::Uri` normalises an authority-form URL's path to `/` — so a
    // parsed `path()` cannot distinguish `https://host` from `https://host/`,
    // and "the path must be empty" would silently become "the path must be
    // empty or a slash". Real calendars emit neither: all six committed
    // pending attestations carry a bare host.
    let scheme_and_rest = uri
        .split_once("://")
        .ok_or(UpgradeUriRefusal::Unparseable)?;
    if !scheme_and_rest.0.eq_ignore_ascii_case("https") {
        return Err(UpgradeUriRefusal::NotHttps);
    }
    let authority = scheme_and_rest.1;
    if authority.is_empty() {
        return Err(UpgradeUriRefusal::NoHost);
    }
    if authority.contains('@') {
        return Err(UpgradeUriRefusal::Userinfo);
    }
    if authority.contains('/') || authority.contains('?') || authority.contains('#') {
        return Err(UpgradeUriRefusal::NotBareHost);
    }

    // Parsed as well, so a host this code would accept but the HTTP client
    // would read differently cannot slip through the string check alone.
    let parsed: Uri = uri.parse().map_err(|_| UpgradeUriRefusal::Unparseable)?;
    if parsed.scheme_str() != Some("https") {
        return Err(UpgradeUriRefusal::NotHttps);
    }
    if parsed.port_u16().is_some() {
        return Err(UpgradeUriRefusal::Port);
    }
    let host = parsed.host().ok_or(UpgradeUriRefusal::NoHost)?;
    if host.is_empty() {
        return Err(UpgradeUriRefusal::NoHost);
    }
    // DNS is case-insensitive, so normalisation is correctness and not
    // convenience; upstream's case-sensitive `fnmatch` gets this wrong.
    let host = host.to_ascii_lowercase();

    if OTS_UPGRADE_HOST_SUFFIXES
        .iter()
        .any(|suffix| ends_on_dot_boundary(&host, suffix))
    {
        return Ok(());
    }
    if configured
        .iter()
        .filter_map(|calendar| configured_host(calendar))
        .any(|allowed| host == allowed || ends_on_dot_boundary(&host, &format!(".{allowed}")))
    {
        return Ok(());
    }
    Err(UpgradeUriRefusal::HostNotAllowed)
}

/// `host` ends with `suffix`, and `suffix` begins at a label boundary.
///
/// `suffix` always starts with `.`, so requiring `host.len() > suffix.len()`
/// is what rejects the bare suffix host: `calendar.catallaxy.com` does not end
/// with `.calendar.catallaxy.com`, and `evilcalendar.catallaxy.com` does not
/// either. The one case a naive `ends_with` on a dotless suffix would admit —
/// `notcalendar.catallaxy.com` matching `calendar.catallaxy.com` — is
/// structurally impossible here, and the test carries it anyway.
fn ends_on_dot_boundary(host: &str, suffix: &str) -> bool {
    host.len() > suffix.len() && host.ends_with(suffix)
}

/// The host of a configured calendar base URL, lowercased.
///
/// A configured entry is a *submit* URL and may legitimately carry a path
/// (`https://ots.btc.catallaxy.com`), so only its host is taken. An entry
/// that does not parse widens nothing rather than widening everything.
fn configured_host(calendar: &str) -> Option<String> {
    let parsed: Uri = calendar.parse().ok()?;
    let host = parsed.host()?;
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four real pending URIs D54 §1 recorded, three of which are also
    /// carried inside the committed `.timestamp` captures.
    const REAL_PENDING_URIS: [&str; 4] = [
        "https://alice.btc.calendar.opentimestamps.org",
        "https://bob.btc.calendar.opentimestamps.org",
        "https://finney.calendar.eternitywall.com",
        "https://btc.calendar.catallaxy.com",
    ];

    fn none() -> Vec<String> {
        Vec::new()
    }

    /// A42's Accept table, in both directions.
    ///
    /// The accepted rows are what stops this being a check that refuses
    /// everything; the refused rows are what stops it being a check that
    /// accepts everything. Both halves are required or the test is one-sided.
    #[test]
    fn the_allowlist_table_accepts_and_refuses_exactly_the_ruled_rows() {
        for uri in REAL_PENDING_URIS {
            assert!(
                upgrade_uri_allowed(uri, &none()),
                "{uri} is a real pending URI and must be accepted"
            );
        }

        // Uppercase: accepted, normalised. DNS is case-insensitive.
        assert!(upgrade_uri_allowed(
            "https://ALICE.BTC.Calendar.OpenTimestamps.ORG",
            &none()
        ));
        assert!(upgrade_uri_allowed(
            "HTTPS://btc.calendar.catallaxy.com",
            &none()
        ));

        let refused: &[(&str, UpgradeUriRefusal)] = &[
            // The bare suffix, with no dot boundary — A42's named case.
            (
                "https://calendar.catallaxy.com",
                UpgradeUriRefusal::HostNotAllowed,
            ),
            (
                "https://calendar.opentimestamps.org",
                UpgradeUriRefusal::HostNotAllowed,
            ),
            // A suffix glued to another label without a dot: what upstream's
            // `fnmatch` and a naive `ends_with` on a dotless suffix admit.
            (
                "https://evilcalendar.catallaxy.com",
                UpgradeUriRefusal::HostNotAllowed,
            ),
            // The suffix as a *prefix* of a longer registrable name.
            (
                "https://btc.calendar.catallaxy.com.evil.net",
                UpgradeUriRefusal::HostNotAllowed,
            ),
            // Plain HTTP.
            (
                "http://btc.calendar.catallaxy.com",
                UpgradeUriRefusal::NotHttps,
            ),
            // Another scheme entirely.
            (
                "file://btc.calendar.catallaxy.com",
                UpgradeUriRefusal::NotHttps,
            ),
            // Path, query, fragment — including the bare trailing slash,
            // which no real calendar emits (all six committed captures carry
            // a bare host) and which would make the `/timestamp/…` join
            // ambiguous.
            (
                "https://btc.calendar.catallaxy.com/",
                UpgradeUriRefusal::NotBareHost,
            ),
            (
                "https://btc.calendar.catallaxy.com/timestamp/aa",
                UpgradeUriRefusal::NotBareHost,
            ),
            (
                "https://btc.calendar.catallaxy.com?a=1",
                UpgradeUriRefusal::NotBareHost,
            ),
            (
                "https://btc.calendar.catallaxy.com#frag",
                UpgradeUriRefusal::NotBareHost,
            ),
            // Port.
            (
                "https://btc.calendar.catallaxy.com:8443",
                UpgradeUriRefusal::Port,
            ),
            // Userinfo — the shape that makes a host look like one thing to a
            // reader and another to a parser.
            (
                "https://btc.calendar.catallaxy.com@attacker.example",
                UpgradeUriRefusal::Userinfo,
            ),
            // Unrelated host.
            (
                "https://attacker.example",
                UpgradeUriRefusal::HostNotAllowed,
            ),
            // Structural nonsense.
            ("", UpgradeUriRefusal::Unparseable),
            ("btc.calendar.catallaxy.com", UpgradeUriRefusal::Unparseable),
            ("https://", UpgradeUriRefusal::NoHost),
        ];

        for (uri, expected) in refused {
            match classify_upgrade_uri(uri, &none()) {
                Err(reason) => assert_eq!(reason, *expected, "for {uri:?}"),
                Ok(()) => panic!("{uri:?} must be refused"),
            }
        }
    }

    /// A42's second Accept row: a configured calendar widens the allowlist to
    /// **that host and its subdomains only**.
    #[test]
    fn a_configured_calendar_widens_the_allowlist_only_to_itself() {
        let configured = vec!["https://cal.example.com".to_owned()];

        assert!(upgrade_uri_allowed("https://cal.example.com", &configured));
        assert!(upgrade_uri_allowed(
            "https://sub.cal.example.com",
            &configured
        ));

        for refused in [
            // A different registrable name entirely.
            "https://other.example.org",
            // The suffix-confusion attack, against the *configured* host this
            // time: `cal.example.com.evil.net` ends with `cal.example.com`
            // under a naive substring test.
            "https://cal.example.com.evil.net",
            // A sibling that merely shares a suffix without the dot boundary.
            "https://notcal.example.com",
            // The parent domain is not widened.
            "https://example.com",
        ] {
            assert!(
                !upgrade_uri_allowed(refused, &configured),
                "{refused} must not be admitted by configuring cal.example.com"
            );
        }

        // And configuring nothing widens nothing: the same URIs that the
        // configured list admits are refused without it.
        assert!(!upgrade_uri_allowed("https://cal.example.com", &none()));
    }

    /// A configured entry with a path — which a submit URL legitimately has —
    /// widens by host, not by URL.
    #[test]
    fn a_configured_calendar_with_a_path_still_widens_by_host() {
        let configured = vec!["https://ots.btc.catallaxy.com/submit".to_owned()];
        assert!(upgrade_uri_allowed(
            "https://ots.btc.catallaxy.com",
            &configured
        ));
        assert!(upgrade_uri_allowed(
            "https://a.ots.btc.catallaxy.com",
            &configured
        ));
        assert!(!upgrade_uri_allowed("https://catallaxy.com", &configured));
    }

    /// An unparseable configured entry widens **nothing** — never everything.
    ///
    /// The failure direction matters: a `configured_host` that returned an
    /// empty string on a bad entry would make `host.ends_with("."))` match
    /// broadly, and a malformed config line would open the allowlist.
    #[test]
    fn a_malformed_configured_entry_widens_nothing() {
        for junk in ["", "not a url", "https://", "://", "ftp://"] {
            let configured = vec![junk.to_owned()];
            assert!(
                !upgrade_uri_allowed("https://attacker.example", &configured),
                "{junk:?} must not widen the allowlist"
            );
            // …and the pinned suffixes still work, so the junk entry has not
            // broken the list either.
            assert!(upgrade_uri_allowed(
                "https://btc.calendar.catallaxy.com",
                &configured
            ));
        }
    }

    /// The pinned set is exactly D54's three, in D54's order.
    ///
    /// The count is asserted so that an *addition* is a deliberate edit here
    /// as well as in the constant; the append-only rule means a removal must
    /// never be made at all, and this test is where a removal is caught.
    #[test]
    fn the_pinned_suffix_set_is_the_ruled_one() {
        assert_eq!(
            OTS_UPGRADE_HOST_SUFFIXES,
            [
                ".calendar.opentimestamps.org",
                ".calendar.eternitywall.com",
                ".calendar.catallaxy.com",
            ]
        );
        for suffix in OTS_UPGRADE_HOST_SUFFIXES {
            assert!(
                suffix.starts_with('.'),
                "{suffix} must begin with the dot boundary it enforces"
            );
            assert_eq!(
                suffix.to_ascii_lowercase(),
                suffix,
                "{suffix} must be lowercase, since hosts are normalised before matching"
            );
        }
    }

    /// Every pending URI inside the **committed real captures** is admitted.
    ///
    /// Read out of the `.ots` bytes rather than transcribed, so the test
    /// exercises the strings a real calendar actually emitted — the exact
    /// values A14 will read back off disk.
    #[test]
    fn every_recorded_pending_uri_is_admitted() {
        const CAPTURES: [&[u8]; 3] = [
            crate::testing::replay::fixtures::CALENDAR_ALICE_A,
            crate::testing::replay::fixtures::CALENDAR_BOB_A,
            crate::testing::replay::fixtures::CALENDAR_CATALLAXY_A,
        ];
        let mut found = 0;
        for capture in CAPTURES {
            let text = String::from_utf8_lossy(capture);
            let start = text
                .find("https://")
                .expect("every pending payload has a URI");
            let uri: String = text[start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '/'))
                .collect();
            assert!(
                upgrade_uri_allowed(&uri, &none()),
                "the real pending URI {uri:?} must be admitted"
            );
            found += 1;
        }
        assert_eq!(found, 3, "all three captures must have been exercised");
    }
}
