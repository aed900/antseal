//! The no-real-anchor-network gate (task **Q16**).
//!
//! # The defect this exists to close
//!
//! Before this module, "CI contacts no real anchor endpoint" was **prose**.
//! It was written down in at least five places — `crate::testing`,
//! `crate::testing::stub`, `crate::testing::replay` (not links: those
//! modules are `cfg(any(test, feature = "test-util"))`, so they do not exist
//! in a default rustdoc build),
//! `testdata/anchors/README.md` and `antseal-cli`'s `config_file` suite —
//! each asserting the policy holds *by construction*, because the stubs bind
//! `127.0.0.1:0` and a loopback listener cannot reach a public host.
//!
//! That argument is true about the stubs and says nothing about the tests.
//! A test does not have to use a stub. The recorded instance is on
//! [`crate::ots::engine`]'s `upgrade_pending_with` seam: the suite drove the
//! **production** upgrade path with the committed `.ots` artifact, whose
//! pending URIs are the *real* calendar hostnames, and A42's allowlist
//! admits them — so the suite contacted live calendars on every run, in CI
//! and on every contributor's machine, and **every assertion passed**. The
//! fix was a `#[cfg(test)]` seam, which is a convention: nothing stops the
//! next call site.
//!
//! A rate-limited third-party service being hammered by CI is a
//! terms-of-service problem before it is a flakiness problem (MVP-SPEC.md
//! line 189; SwissSign ~10/day, Sectigo ~15 s spacing, `zeitstempel.dfn.de`
//! non-commercial-only). So the policy needs a mechanism that makes the call
//! **fail**, not a paragraph that asks it not to happen.
//!
//! # What the gate is
//!
//! One predicate, consulted by [`HttpClient::attempt`](super::HttpClient) —
//! the single function in this workspace that dials a socket for anchor
//! traffic — before any address is resolved. When the gate is armed, an
//! endpoint that is not a loopback **IP literal** is refused with
//! [`AnchorHttpError::RealNetworkDenied`](super::AnchorHttpError), and no
//! DNS query, TCP connection or TLS handshake happens.
//!
//! The loopback carve-out is [`Endpoint::is_loopback_literal`](super::Endpoint::is_loopback_literal)'s, reused
//! deliberately rather than re-derived: A24's stubs bind `127.0.0.1:0`, so
//! the entire offline test surface is unaffected, and the *name*
//! `localhost` is not exempt however it resolves
//! ([`crate::http::endpoint`]).
//!
//! # Two arms, and why the first one has no off switch
//!
//! | build | armed by | can be disarmed? |
//! | --- | --- | --- |
//! | `cfg(test)` — this crate's own unit tests | the compiler | **no** |
//! | anything else | `ANTSEAL_NO_REAL_ANCHOR_NETWORK` | yes, by unsetting it or setting it to `0` |
//!
//! The `cfg(test)` arm reads no environment and offers no escape. That is
//! the whole point: an arming that CI has to remember to switch on is an
//! arming CI can forget, and a lane that forgets it is green and vacuous —
//! the failure mode this project has hit seven times in one wave. Every
//! `#[test]` in `antseal-anchor` is therefore gated by construction, and a
//! future test that dials `freetsa.org` fails on a machine with no network
//! and on a machine with one, identically.
//!
//! The environment arm covers what `cfg(test)` structurally cannot: **other
//! crates' integration-test binaries**, which link this crate's ordinary
//! (non-`cfg(test)`) build. `antseal-cli/tests/anchor_gate_prepay.rs` drives
//! the real submission gate through the real pipeline, and nothing in
//! `cfg(test)` reaches it. CI arms that arm workflow-wide and
//! `scripts/local-gate.sh` arms it for the local gate;
//! `scripts/ci-lanes.sh anchor-net-policy` fails if either stops doing so,
//! because an unarmed arm is exactly as good as no arm.
//!
//! It **fails closed**: any value other than `0` arms it, so
//! `ANTSEAL_NO_REAL_ANCHOR_NETWORK=ture` is a typo that over-protects
//! rather than one that silently opens the network.
//!
//! # How the real-endpoint smoke run is still possible
//!
//! A25's smoke deliberately has no flag here. It is not a `#[test]` and not
//! `#[ignore]`d — `--include-ignored` is one careless command away from
//! stamping a rate-limited TSA from CI. It is a script driving the shipped
//! CLI, in an environment that simply does not set the variable:
//! `docs/anchors/real-smoke-runbook.md`. Exclusion from gating CI is
//! structural rather than conditional, which is the same reason the devnet
//! E2E gate is a separately-invoked script rather than an `#[ignore]`d test.

use std::ffi::OsStr;

/// The environment variable that arms the gate outside `cfg(test)` builds.
///
/// Named on `.github/workflows/ci.yml`'s workflow-level `env:` (so every job
/// inherits it) and exported by `scripts/local-gate.sh`. Both are asserted
/// by `scripts/ci-lanes.sh anchor-net-policy`.
pub const NO_REAL_NETWORK_ENV: &str = "ANTSEAL_NO_REAL_ANCHOR_NETWORK";

/// The reason reported when the compiler armed the gate.
pub const REASON_TEST_BUILD: &str =
    "this is a cfg(test) build of antseal-anchor, where the Q16 policy has no off switch";

/// The reason reported when the environment armed the gate.
pub const REASON_ENVIRONMENT: &str =
    "ANTSEAL_NO_REAL_ANCHOR_NETWORK is set (unset it, or set it to 0, only outside CI)";

/// Why real-endpoint traffic is refused in this process, or [`None`] if it
/// is permitted.
///
/// Consulted per attempt rather than cached: a cache would make the value
/// depend on which test happened to run first, and the cost is one
/// `getenv` against a network round trip.
#[must_use]
pub fn deny_reason() -> Option<&'static str> {
    decide(cfg!(test), std::env::var_os(NO_REAL_NETWORK_ENV).as_deref())
}

/// [`deny_reason`]'s decision, as a pure function of its two inputs.
///
/// Split out so the environment arm is testable from inside a `cfg(test)`
/// build, where [`deny_reason`] can only ever return the `cfg(test)` answer.
/// The end-to-end proof that the environment arm actually reaches
/// [`HttpClient::attempt`](super::HttpClient) in a non-`cfg(test)` build is
/// `crates/antseal-anchor/tests/no_real_network.rs`, which spawns a child
/// process with and without the variable.
#[must_use]
pub fn decide(test_build: bool, env: Option<&OsStr>) -> Option<&'static str> {
    if test_build {
        return Some(REASON_TEST_BUILD);
    }
    match env {
        // Not armed: the ordinary product build, and A25's smoke run.
        None => None,
        // The one explicit off switch, so the smoke runbook can be executed
        // on a machine whose shell profile exports the variable.
        Some(value) if value == OsStr::new("0") => None,
        // Everything else arms it — including `""`, `"false"` and typos.
        // Failing closed is the only safe direction for a control whose
        // failure mode is abusing someone else's rate-limited service.
        Some(_) => Some(REASON_ENVIRONMENT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arbitrum::endpoints::{
        ARBITRUM_ONE_RESERVE_RPCS_CLI_ONLY, ARBITRUM_ONE_VERIFY_RPCS, ARBITRUM_SEPOLIA_VERIFY_RPCS,
    };
    use crate::esplora::DEFAULT_ESPLORA_ENDPOINTS;
    use crate::http::{
        AnchorHttpError, Endpoint, HttpClient, HttpMethod, HttpPolicy, HttpRequest, Idempotency,
        TlsPolicy,
    };
    use crate::ots::calendars::DEFAULT_OTS_CALENDARS;
    use crate::testing::stub::{StubReply, StubScript, StubServer};
    use crate::tsa::DEFAULT_TSA_URLS;
    use std::time::Instant;

    /// **Every real endpoint this product can dial by default**, by name.
    ///
    /// Read out of the production constants rather than re-typed, so a
    /// calendar or RPC added to any of those lists is covered here the day
    /// it lands. A whole new *list* is the case a value-walk cannot see, and
    /// that is `scripts/ci-lanes.sh anchor-net-policy` rule R3's job: it
    /// fails unless every URL-valued `pub const` in this crate is named in
    /// this file.
    fn every_default_endpoint() -> Vec<&'static str> {
        let mut all: Vec<&'static str> = Vec::new();
        all.extend(DEFAULT_TSA_URLS);
        all.extend(DEFAULT_OTS_CALENDARS);
        all.extend(DEFAULT_ESPLORA_ENDPOINTS);
        all.extend(ARBITRUM_ONE_VERIFY_RPCS);
        all.extend(ARBITRUM_SEPOLIA_VERIFY_RPCS);
        all.extend(ARBITRUM_ONE_RESERVE_RPCS_CLI_ONLY);
        all
    }

    fn request<'a>(endpoint: &'a Endpoint) -> HttpRequest<'a> {
        HttpRequest {
            endpoint,
            method: HttpMethod::Get,
            content_type: None,
            accept: None,
            body: &[],
            receive_cap_bytes: 4096,
            idempotency: Idempotency::SafeToRepeat,
        }
    }

    /// The headline assertion of Q16's Accept row 1, executed rather than
    /// asserted in prose: with the gate armed as it is in every `cargo test`
    /// run of this crate, **each** of the product's default anchor endpoints
    /// is refused, and refused *before a socket*.
    ///
    /// Non-vacuity is checked three ways, because a list that came back
    /// empty, or an error that happened to be `Resolve` because the host did
    /// not exist, would both look like a pass:
    ///
    /// 1. the walk is asserted non-empty and to contain the two spec-named
    ///    TSAs (MVP-SPEC.md line 109), so an emptied constant reddens;
    /// 2. the error must be exactly `RealNetworkDenied` — a real dial that
    ///    failed would be `Resolve`, `Connect`, `Tls` or `Status`;
    /// 3. the whole walk must finish well inside a single DNS timeout, so a
    ///    variant renamed onto a code path that *does* dial cannot pass.
    #[test]
    fn every_default_production_endpoint_is_refused_without_touching_the_network() {
        let endpoints = every_default_endpoint();
        assert!(
            endpoints.len() >= 11,
            "the default-endpoint walk collapsed to {} entries — it is the \
             non-vacuity of this whole test",
            endpoints.len()
        );
        assert!(
            endpoints.contains(&"https://freetsa.org/tsr")
                && endpoints.contains(&"http://timestamp.digicert.com"),
            "the spec's two default TSAs (MVP-SPEC.md line 109) are not in the walk: {endpoints:?}"
        );

        let client = HttpClient::new(HttpPolicy::seal());
        let started = Instant::now();
        for url in &endpoints {
            // `TlsPolicy::Optional` deliberately: the gate must be what
            // refuses these, not the transport policy. Under
            // `RequiredExceptLoopback` the plain-HTTP DigiCert URL would be
            // rejected as `TlsRequired` and this test would prove nothing
            // about the gate.
            let endpoint = Endpoint::parse(url, TlsPolicy::Optional)
                .unwrap_or_else(|error| panic!("{url} is not a parseable endpoint: {error}"));
            let error = client
                .send(&request(&endpoint))
                .expect_err("a real endpoint must be refused in a cfg(test) build");
            match error {
                AnchorHttpError::RealNetworkDenied {
                    ref endpoint,
                    reason,
                } => {
                    assert_eq!(endpoint, url);
                    assert_eq!(reason, REASON_TEST_BUILD);
                }
                other => panic!(
                    "{url} produced {other:?} instead of RealNetworkDenied — \
                     this call reached the network stack"
                ),
            }
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed.as_secs() < 2,
            "the walk over {} endpoints took {elapsed:?}; a refusal before the \
             socket is microseconds, so something dialled",
            endpoints.len()
        );
    }

    /// The positive control. A gate that refused *everything* would pass the
    /// test above while breaking the product, and would be invisible here
    /// because the rest of the suite is stub-driven anyway — so the
    /// admission is asserted directly.
    #[test]
    fn the_gate_still_admits_the_loopback_stubs_the_suite_runs_on() {
        let server =
            StubServer::spawn(StubScript::new().always(StubReply::body(200, b"ok".into())));
        let endpoint = Endpoint::parse(&server.base_url(), TlsPolicy::Optional).expect("stub url");
        let client = HttpClient::new(HttpPolicy::seal());
        let response = client
            .send(&request(&endpoint))
            .expect("a loopback IP literal is exempt and must still be dialled");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert_eq!(
            server.connections(),
            1,
            "the request must really have gone out"
        );
    }

    /// The carve-out is the *literal*, not the name — the same rule
    /// [`crate::http::endpoint`] applies, restated here because this gate is
    /// the second consumer of it and a divergence would be a hole.
    /// `127.0.0.1.evil.example` is the attack it is shaped against.
    #[test]
    fn the_carve_out_is_the_loopback_literal_and_not_a_host_that_merely_looks_like_one() {
        let client = HttpClient::new(HttpPolicy::seal());
        for url in [
            "http://localhost:8080/x",
            "http://127.0.0.1.evil.example/x",
            "https://not-127.0.0.1.example/x",
        ] {
            let endpoint = Endpoint::parse(url, TlsPolicy::Optional).expect("parseable");
            let error = client.send(&request(&endpoint)).expect_err(url);
            assert!(
                matches!(error, AnchorHttpError::RealNetworkDenied { .. }),
                "{url} was not refused by the gate: {error:?}"
            );
        }
    }

    /// The refusal is deterministic, so it must never be retried: three
    /// attempts against a rate-limited TSA is the abuse this task exists to
    /// prevent, and a `Retry` classification would produce exactly that if
    /// the gate were ever consulted per attempt on a live path.
    #[test]
    fn a_denied_endpoint_is_never_retried() {
        use crate::http::retry::{RetryVerdict, classify};
        let error = AnchorHttpError::RealNetworkDenied {
            endpoint: "https://freetsa.org/tsr".to_owned(),
            reason: REASON_TEST_BUILD,
        };
        for idempotency in [Idempotency::SafeToRepeat, Idempotency::AtMostOnceAfterSend] {
            assert_eq!(classify(&error, idempotency), RetryVerdict::Stop);
        }
    }

    /// [`decide`]'s environment arm, which [`deny_reason`] cannot reach from
    /// inside a `cfg(test)` build. The end-to-end half — that this decision
    /// actually reaches the dialling path in a non-`cfg(test)` build — is
    /// `tests/no_real_network.rs`.
    #[test]
    fn the_environment_arm_fails_closed() {
        assert_eq!(decide(true, None), Some(REASON_TEST_BUILD));
        assert_eq!(
            decide(true, Some(OsStr::new("0"))),
            Some(REASON_TEST_BUILD),
            "the cfg(test) arm has no off switch — that is its entire purpose"
        );

        assert_eq!(decide(false, None), None, "the ordinary product build");
        assert_eq!(
            decide(false, Some(OsStr::new("0"))),
            None,
            "`0` is the one sanctioned off switch (the A25 smoke runbook)"
        );
        for armed in ["1", "", "0 ", "00", "false", "no", "ture"] {
            assert_eq!(
                decide(false, Some(OsStr::new(armed))),
                Some(REASON_ENVIRONMENT),
                "{armed:?} must arm the gate: anything but a literal `0` fails closed"
            );
        }
    }
}
