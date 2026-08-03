//! Endpoint URLs, and the transport requirement over them (A3; task **A49**;
//! decision D90 §6.6).
//!
//! # The asymmetry, and why it is about signatures rather than hosts
//!
//! Anchor traffic splits into two classes with opposite transport needs, and
//! collapsing them either way breaks the product:
//!
//! - **RFC 3161 (A10) — the payload is signed and nonce-bound.** An on-path
//!   attacker cannot forge a token (no TSA key), cannot replay an old one
//!   (A8 checks nonce equality on the capture path), and cannot substitute
//!   another digest's token (`TSTInfo.messageImprint` must equal
//!   `anchor_digest`). Plain HTTP is therefore *safe* here — and it is also
//!   **required**: `timestamp.digicert.com:443` refuses connections (measured
//!   2026-08-02T19:35:51Z; port 80 is open and live), so a TLS-only substrate
//!   cannot reach one of the spec's two default TSAs (MVP-SPEC.md line 109).
//!   The residual cost is privacy, not integrity: a passive observer learns
//!   that this host stamped this 32-byte value at this time.
//! - **esplora and Arbitrum RPC (A16/A17) — the payload is unsigned.** Their
//!   results are trusted *because two independent endpoints agree*. Over
//!   plain HTTP one on-path attacker forges both halves and the must-agree
//!   primitive reports agreement on a lie. **Transport security is the only
//!   integrity control these two have**, so HTTPS is mandatory for them.
//!
//! [`TlsPolicy::RequiredExceptLoopback`] is the second rule. The carve-out is
//! **IP literals only** — `127.0.0.0/8` and `::1` — never the *name*
//! `localhost`, however conventionally it resolves: A24's stubs bind
//! `127.0.0.1:0`, so the carve-out costs the test path nothing (Q16's
//! no-real-endpoints policy stays satisfiable) and widens nothing in
//! production, where every endpoint is a public host. An attacker who can
//! make this process resolve a loopback *literal* somewhere else already owns
//! the process.
//!
//! Enforcement is deliberately at **two** points, and both are cheap:
//! [`Endpoint::parse`] at config-load time (A49: a bad `[verify]` override in
//! U4's config file fails before any seal or verify work begins), and again
//! inside [`HttpClient::send`](super::HttpClient::send) against the client's
//! own [`HttpPolicy::tls`](super::HttpPolicy::tls) — so an `Endpoint` parsed
//! under [`TlsPolicy::Optional`] still cannot be sent through the A16/A17
//! client that [`HttpPolicy::verify`](super::HttpPolicy::verify) builds.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use ureq::http::Uri;

/// Whether an endpoint must be reached over TLS.
///
/// The two arms are not interchangeable and must never be chosen by
/// convenience — see the module docs for the signature-based argument that
/// decides which is which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsPolicy {
    /// Plain HTTP is permitted. **Only** for payloads whose integrity is
    /// established cryptographically inside the payload itself: RFC 3161
    /// tokens (A10) and OpenTimestamps calendar traffic (A13/A14/A15).
    Optional,
    /// The URL scheme MUST be `https`, unless the host is a loopback **IP
    /// literal** (`127.0.0.0/8` or `::1`). Required for every endpoint whose
    /// reply is unsigned and is trusted only because two endpoints agree:
    /// esplora (A16) and Arbitrum RPC (A17).
    RequiredExceptLoopback,
}

impl TlsPolicy {
    /// Whether this policy admits `endpoint`.
    ///
    /// # Errors
    ///
    /// [`EndpointError::TlsRequired`] when the policy is
    /// [`TlsPolicy::RequiredExceptLoopback`] and the endpoint is neither
    /// `https` nor a loopback IP literal.
    pub fn admits(self, endpoint: &Endpoint) -> Result<(), EndpointError> {
        match self {
            Self::Optional => Ok(()),
            Self::RequiredExceptLoopback => {
                if endpoint.is_https() || endpoint.is_loopback_literal() {
                    Ok(())
                } else {
                    Err(EndpointError::TlsRequired {
                        endpoint: endpoint.url().to_owned(),
                    })
                }
            }
        }
    }
}

/// A validated anchor endpoint URL.
///
/// Construction is the only way to obtain one, so every URL that reaches the
/// substrate has already been parsed, scheme-checked and (under
/// [`TlsPolicy::RequiredExceptLoopback`]) transport-checked. The original
/// string is retained verbatim — it is exactly what is handed to `ureq`, so
/// nothing can drift between what was validated and what is dialled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    url: String,
    origin: String,
    https: bool,
    loopback_literal: bool,
}

impl Endpoint {
    /// Parse and validate `url` against `tls`.
    ///
    /// This is A49's config-load entry point: U4's `[verify]
    /// bitcoin_endpoints` / `arbitrum_endpoints` overrides are validated
    /// here, so a plain-`http://` override is refused when the config is
    /// read rather than when the first `verify --online` runs.
    ///
    /// # Errors
    ///
    /// - [`EndpointError::Invalid`] — unparseable, no scheme, a scheme other
    ///   than `http`/`https`, no host, or an authority carrying userinfo.
    /// - [`EndpointError::TlsRequired`] — `tls` is
    ///   [`TlsPolicy::RequiredExceptLoopback`] and the URL is plain HTTP to a
    ///   non-loopback-literal host.
    pub fn parse(url: &str, tls: TlsPolicy) -> Result<Self, EndpointError> {
        let invalid = |reason: &'static str| EndpointError::Invalid {
            endpoint: url.to_owned(),
            reason,
        };

        let uri: Uri = url.parse().map_err(|_| invalid("not a valid URI"))?;

        // `Uri`'s parser lower-cases known schemes (`HTTP://…` arrives as
        // `http`), which the `scheme_is_normalised_to_lowercase` test pins:
        // if that ever stops being true, that test reddens rather than this
        // comparison silently failing open.
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            Some(_) => return Err(invalid("scheme must be http or https")),
            None => return Err(invalid("no scheme (an endpoint must be an absolute URL)")),
        };

        let authority = uri.authority().ok_or_else(|| invalid("no host"))?;
        // Rejected outright rather than tolerated. `Uri::host()` does strip
        // userinfo correctly (probed: `http://127.0.0.1@evil.example/` reports
        // host `evil.example`), so this is not load-bearing for the loopback
        // carve-out — it is refused because a *pinned* endpoint has no
        // business carrying credentials, and because those credentials would
        // otherwise travel in cleartext on the `TlsPolicy::Optional` path.
        // A narrowing, never a widening.
        if authority.as_str().contains('@') {
            return Err(invalid("userinfo is not permitted in an endpoint URL"));
        }
        let host = uri.host().ok_or_else(|| invalid("no host"))?;
        if host.is_empty() {
            return Err(invalid("no host"));
        }

        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let endpoint = Self {
            url: url.to_owned(),
            origin: format!(
                "{}://{}:{port}",
                if https { "https" } else { "http" },
                host.to_ascii_lowercase()
            ),
            https,
            loopback_literal: host_is_loopback_literal(host),
        };
        tls.admits(&endpoint)?;
        Ok(endpoint)
    }

    /// The URL exactly as supplied — the bytes `ureq` is given.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// `scheme://host:port`, normalised — the identity two endpoints share
    /// when they are **one endpoint wearing two names**.
    ///
    /// This exists for [`crate::agree`], and the hazard is the one already
    /// recorded on [`AnchorHttpError::Redirected`](super::AnchorHttpError):
    /// A16's "both must succeed and agree" is a tautology across two URLs on
    /// one origin, and a tautology still reports agreement. Host case and the
    /// default port are folded in, because `HTTPS://Example.ORG` and
    /// `https://example.org:443` are the same server and a pair check that
    /// compared raw URLs would call them independent.
    ///
    /// It is deliberately **not** a same-operator test: `blockstream.info`
    /// and `mempool.space` are distinct origins and that is all this can
    /// establish. Two hostnames that resolve to one machine, or two services
    /// behind one CDN, are indistinguishable here — see [`crate::agree`] for
    /// what that leaves unguarded.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Whether the scheme is `https`.
    #[must_use]
    pub const fn is_https(&self) -> bool {
        self.https
    }

    /// Whether the host is a loopback **IP literal** — `127.0.0.0/8` or
    /// `::1`. The name `localhost` is deliberately **not** one (module docs).
    #[must_use]
    pub const fn is_loopback_literal(&self) -> bool {
        self.loopback_literal
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.url)
    }
}

/// `host` is an IP literal inside the loopback carve-out.
///
/// Strict by construction, and every strictness here fails **closed** (the
/// URL is then required to be https): `127.1` and `0x7f.0.0.1` are rejected
/// because `Ipv4Addr`'s parser demands four decimal octets, and
/// `::ffff:127.0.0.1` is rejected because `Ipv6Addr::is_loopback` is `== ::1`
/// and an IPv4-mapped address is not that.
fn host_is_loopback_literal(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        // `Uri::host()` keeps the brackets on an IPv6 literal (probed).
        return inner
            .parse::<Ipv6Addr>()
            .is_ok_and(|address| address.is_loopback());
    }
    host.parse::<Ipv4Addr>()
        .is_ok_and(|address| address.is_loopback())
}

/// An endpoint URL was refused before any socket work happened.
///
/// Distinct from [`AnchorHttpError`](super::AnchorHttpError) on purpose:
/// config-load validation cannot fail for a transport reason, and a type that
/// cannot represent one keeps the two failure surfaces from being confused at
/// the call site. The `Display` text of each arm is identical to the
/// `AnchorHttpError` arm it converts into, so a user sees the same sentence
/// whichever layer rejected the URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EndpointError {
    /// Not a usable endpoint URL at all.
    #[error("{endpoint}: not a usable endpoint URL ({reason})")]
    Invalid {
        /// The URL as supplied.
        endpoint: String,
        /// Which structural rule it broke.
        reason: &'static str,
    },
    /// Plain HTTP where the transport is the only integrity control.
    #[error("{endpoint}: this endpoint must be https (only loopback literals are exempt)")]
    TlsRequired {
        /// The URL as supplied.
        endpoint: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strict(url: &str) -> Result<Endpoint, EndpointError> {
        Endpoint::parse(url, TlsPolicy::RequiredExceptLoopback)
    }

    /// D90's verification obligation
    /// `tls_required_rejects_plain_http_for_public_hosts`, in **both**
    /// directions: a policy that rejected everything, or accepted
    /// everything, would pass a one-sided version of this.
    #[test]
    fn tls_required_rejects_plain_http_for_public_hosts() {
        let err = parse_strict("http://example.org/api").expect_err("plain http, public host");
        assert!(
            matches!(err, EndpointError::TlsRequired { ref endpoint } if endpoint == "http://example.org/api"),
            "{err:?}"
        );
        assert!(
            err.to_string().contains("must be https"),
            "the message must name the requirement: {err}"
        );

        let ok = parse_strict("https://example.org/api").expect("https, public host");
        assert!(ok.is_https());
        assert!(!ok.is_loopback_literal());

        // …and the same plain-HTTP URL is fine where the payload carries its
        // own integrity (A10's DigiCert path).
        let permitted = Endpoint::parse("http://example.org/api", TlsPolicy::Optional)
            .expect("Optional admits plain http");
        assert!(!permitted.is_https());
    }

    /// D90's `tls_required_exempts_loopback_literals_only`. The four
    /// negative cases are the ones an implementation that used
    /// `host.contains("127.0.0.1")` or `host == "localhost"` would get
    /// wrong.
    #[test]
    fn tls_required_exempts_loopback_literals_only() {
        for exempt in [
            "http://127.0.0.1:9/",
            "http://[::1]:9/",
            "http://127.0.0.1/",
            "http://127.255.255.254:8080/rpc",
        ] {
            let endpoint =
                parse_strict(exempt).unwrap_or_else(|e| panic!("{exempt} must pass: {e}"));
            assert!(endpoint.is_loopback_literal(), "{exempt}");
            assert!(!endpoint.is_https(), "{exempt}");
        }

        for refused in [
            // A name is not an IP literal, however it resolves.
            "http://localhost:9/",
            // A hostname that merely *contains* a loopback literal.
            "http://127.0.0.1.evil.example/",
            // An IPv4-mapped IPv6 address is not `::1`.
            "http://[::ffff:127.0.0.1]:9/",
            // Shorthand and hex forms libc would resolve to 127.0.0.1 but
            // `Ipv4Addr` will not parse: they fail CLOSED, i.e. https is
            // then required.
            "http://127.1/",
            "http://0x7f.0.0.1/",
            // Not loopback at all, one bit away from the /8.
            "http://126.255.255.255/",
            "http://128.0.0.1/",
        ] {
            let err = parse_strict(refused)
                .map(|e| format!("wrongly accepted {}", e.url()))
                .expect_err(refused);
            assert!(
                matches!(err, EndpointError::TlsRequired { .. }),
                "{refused}: {err:?}"
            );
        }
    }

    /// The negative half of the previous test, stated as an assertion rather
    /// than as a `panic!` in an `unwrap_or_else`, so the *error class* is
    /// pinned and not merely the failure.
    #[test]
    fn the_loopback_carve_out_cannot_be_widened_by_a_hostname() {
        for refused in [
            "http://localhost:9/",
            "http://127.0.0.1.evil.example/",
            "http://[::ffff:127.0.0.1]:9/",
            "http://127.1/",
        ] {
            match parse_strict(refused) {
                Err(EndpointError::TlsRequired { endpoint }) => assert_eq!(endpoint, refused),
                other => panic!("{refused} must be TlsRequired, got {other:?}"),
            }
        }
    }

    /// `Uri::host()` strips userinfo, so `http://127.0.0.1@evil.example/`
    /// reports `evil.example` and would already fail the carve-out. We reject
    /// it one step earlier anyway — and this test pins **which** rejection,
    /// so a future reader cannot conclude the carve-out was what saved us.
    #[test]
    fn userinfo_is_refused_before_the_carve_out_is_consulted() {
        for url in [
            "http://127.0.0.1@evil.example/",
            "http://evil.example@127.0.0.1/",
            "https://user:pw@example.org/",
        ] {
            match Endpoint::parse(url, TlsPolicy::Optional) {
                Err(EndpointError::Invalid { reason, .. }) => {
                    assert_eq!(reason, "userinfo is not permitted in an endpoint URL");
                }
                other => panic!("{url} must be Invalid(userinfo), got {other:?}"),
            }
        }
    }

    #[test]
    fn structurally_unusable_urls_are_refused_with_a_reason() {
        for (url, expected) in [
            ("ftp://example.org/", "scheme must be http or https"),
            (
                "example.org",
                "no scheme (an endpoint must be an absolute URL)",
            ),
            (
                "/just/a/path",
                "no scheme (an endpoint must be an absolute URL)",
            ),
            (
                "//example.org/x",
                "no scheme (an endpoint must be an absolute URL)",
            ),
            ("http://", "not a valid URI"),
            ("", "not a valid URI"),
        ] {
            match Endpoint::parse(url, TlsPolicy::Optional) {
                Err(EndpointError::Invalid { reason, endpoint }) => {
                    assert_eq!(reason, expected, "for {url:?}");
                    assert_eq!(endpoint, url);
                }
                other => panic!("{url:?} must be Invalid, got {other:?}"),
            }
        }
    }

    /// Pins the upstream normalisation `Endpoint::parse`'s scheme match
    /// depends on. If a future `http`/`ureq` stops lower-casing the scheme,
    /// this reddens — instead of `HTTPS://…` being silently classified as
    /// "not https" and then demanding TLS of a URL that already has it.
    #[test]
    fn scheme_is_normalised_to_lowercase() {
        let upper = parse_strict("HTTPS://example.org/").expect("HTTPS:// is https");
        assert!(upper.is_https());
        let upper_plain =
            Endpoint::parse("HTTP://127.0.0.1/", TlsPolicy::Optional).expect("HTTP:// parses");
        assert!(!upper_plain.is_https());
        assert!(upper_plain.is_loopback_literal());
    }

    /// The origin folds host case and the default port, and separates two
    /// genuinely different servers. Both directions, because an `origin` that
    /// returned a constant, or one that returned the whole URL, would each
    /// pass a one-sided version of this.
    #[test]
    fn the_origin_folds_case_and_default_port_but_not_distinct_hosts() {
        let same: &[&str] = &[
            "https://example.org/api",
            "https://example.org:443/api",
            "HTTPS://Example.ORG/other/path?q=1",
            "https://EXAMPLE.org",
        ];
        let expected = "https://example.org:443";
        for url in same {
            let endpoint = parse_strict(url).unwrap_or_else(|e| panic!("{url}: {e}"));
            assert_eq!(endpoint.origin(), expected, "{url}");
        }

        for (a, b) in [
            // Different host.
            ("https://blockstream.info/api", "https://mempool.space/api"),
            // Different port on one host is a different server.
            ("https://example.org/api", "https://example.org:8443/api"),
            // Scheme is part of the origin.
            ("https://127.0.0.1:9/", "http://127.0.0.1:9/"),
        ] {
            let first = parse_strict(a)
                .unwrap_or_else(|_| Endpoint::parse(a, TlsPolicy::Optional).expect("permissive"));
            let second = parse_strict(b)
                .unwrap_or_else(|_| Endpoint::parse(b, TlsPolicy::Optional).expect("permissive"));
            assert_ne!(first.origin(), second.origin(), "{a} vs {b}");
        }
    }

    /// The URL is carried through byte-for-byte: what was validated is what
    /// gets dialled.
    #[test]
    fn the_url_is_retained_verbatim() {
        let raw = "https://blockstream.info/api/block-height/0";
        let endpoint = parse_strict(raw).expect("valid");
        assert_eq!(endpoint.url(), raw);
        assert_eq!(endpoint.to_string(), raw);
    }

    /// `admits` is the second enforcement point: an `Endpoint` that was
    /// parsed under `Optional` must still be refused by a strict client.
    /// Without this, A49 would be a config-load-only rule and any code path
    /// that built an `Endpoint` some other way would bypass it.
    #[test]
    fn a_permissively_parsed_endpoint_is_still_refused_by_a_strict_policy() {
        let endpoint =
            Endpoint::parse("http://example.org/api", TlsPolicy::Optional).expect("Optional");
        let err = TlsPolicy::RequiredExceptLoopback
            .admits(&endpoint)
            .expect_err("strict policy must refuse it");
        assert!(matches!(err, EndpointError::TlsRequired { .. }), "{err:?}");
        TlsPolicy::Optional
            .admits(&endpoint)
            .expect("the permissive policy still admits it");
    }
}
