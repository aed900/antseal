//! Q16's no-real-anchor-network gate, proven in a **non-`cfg(test)`** build.
//!
//! `crates/antseal-anchor/src/http/offline.rs` covers the `cfg(test)` arm and
//! covers [`decide`](antseal_anchor::http::offline::decide) as a pure
//! function. Neither can cover what actually matters for the rest of the
//! workspace: that the **environment** arm reaches the dialling path in the
//! crate's *ordinary* build — the one `antseal-cli/tests/*.rs` links, where
//! `cfg(test)` is false and `antseal_gate_prepay` drives the real submission
//! gate through the real pipeline.
//!
//! An integration-test target is exactly that build, which is why this file
//! is not a unit test.
//!
//! # Why a child process
//!
//! The gate reads the environment, and the workspace denies `unsafe_code`
//! (`Cargo.toml`, `[workspace.lints.rust]`), so `std::env::set_var` — `unsafe`
//! since edition 2024 — is unavailable, and would be racy across libtest's
//! threads even if it were not. The crate already solved this once for
//! `http::tests::the_agent_never_takes_a_proxy_from_the_environment`: the
//! parent re-executes the test binary with a controlled environment. This
//! reuses that pattern.
//!
//! # Why the probe host is what it is
//!
//! Both arms dial **the same** URL and differ only in the environment, so the
//! variable under test is the only variable. The host is
//! `q16-gate-probe.invalid` — RFC 2606 reserves `.invalid`, so it resolves
//! nowhere and can never be registered by anyone — on port 9 (discard), so
//! even under a wildcard-DNS captive portal the disarmed arm fails on connect
//! instead of reaching a service. **No real anchor endpoint is contacted by
//! this file in either arm**, which is the policy it exists to enforce and
//! would be absurd to violate while enforcing it.

use std::process::Command;

use antseal_anchor::http::offline::NO_REAL_NETWORK_ENV;
use antseal_anchor::http::{
    AnchorHttpError, Endpoint, HttpClient, HttpMethod, HttpPolicy, HttpRequest, HttpTimeouts,
    Idempotency, TlsPolicy,
};

/// Names which arm the child is playing, and doubles as the "am I a child at
/// all" marker so an accidental `--include-ignored` run fails loudly instead
/// of asserting nothing.
const MODE_ENV: &str = "ANTSEAL_Q16_CHILD_MODE";

/// See the module docs. Not a real host, and cannot become one.
const PROBE_URL: &str = "http://q16-gate-probe.invalid:9/probe";

fn probe() -> Result<(), AnchorHttpError> {
    let endpoint = Endpoint::parse(PROBE_URL, TlsPolicy::Optional).expect("the probe URL parses");
    let client = HttpClient::new(HttpPolicy {
        // Short, and one attempt: the disarmed arm has to actually fail on
        // the network, and this suite must not spend 30 s doing it.
        timeouts: HttpTimeouts::within(1_500),
        max_attempts: 1,
        tls: TlsPolicy::Optional,
    });
    client
        .send(&HttpRequest {
            endpoint: &endpoint,
            method: HttpMethod::Get,
            content_type: None,
            accept: None,
            body: &[],
            receive_cap_bytes: 1024,
            idempotency: Idempotency::SafeToRepeat,
        })
        .map(|_| ())
}

fn run_child(mode: &str, env_value: Option<&str>) -> String {
    let exe = std::env::current_exe().expect("the test binary's own path");
    let mut command = Command::new(exe);
    command
        .args(["--exact", "gate_child", "--ignored", "--nocapture"])
        .env(MODE_ENV, mode);
    match env_value {
        Some(value) => command.env(NO_REAL_NETWORK_ENV, value),
        None => command.env_remove(NO_REAL_NETWORK_ENV),
    };
    let output = command.output().expect("spawn the child test process");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "child ({mode}) failed:\n{combined}"
    );
    combined
}

/// The A/B that is the whole point: **one URL, two environments.**
///
/// Armed, the request must be refused by the gate. Disarmed, the *same*
/// request must reach the network stack and fail there. If the disarmed arm
/// also reported `RealNetworkDenied`, the gate would be something other than
/// the environment variable — and if the armed arm reported a transport
/// error, the arm CI depends on would not be wired at all.
#[test]
fn the_environment_arm_gates_the_dialling_path_in_a_non_cfg_test_build() {
    let armed = run_child("armed", Some("1"));
    assert!(
        armed.contains("VERDICT=denied"),
        "with {NO_REAL_NETWORK_ENV}=1 the child was not refused by the gate:\n{armed}"
    );

    let disarmed = run_child("disarmed", None);
    assert!(
        disarmed.contains("VERDICT=reached-network"),
        "with {NO_REAL_NETWORK_ENV} unset the gate still fired — it is not the \
         environment that arms it, so CI's arming proves nothing:\n{disarmed}"
    );

    // The sanctioned off switch the A25 smoke runbook relies on, so a
    // maintainer whose shell exports the variable can still execute it.
    let off = run_child("disarmed", Some("0"));
    assert!(
        off.contains("VERDICT=reached-network"),
        "{NO_REAL_NETWORK_ENV}=0 must disarm the gate (docs/anchors/real-smoke-runbook.md):\n{off}"
    );
}

/// The child half. `#[ignore]`d so it never runs in the ordinary pass: it is
/// meaningless without the environment its parent supplies, and says so by
/// failing rather than skipping.
#[test]
#[ignore = "driven as a subprocess by the_environment_arm_gates_the_dialling_path_in_a_non_cfg_test_build"]
fn gate_child() {
    let mode = std::env::var(MODE_ENV)
        .expect("ANTSEAL_Q16_CHILD_MODE: this test is only meaningful as its parent's child");

    match probe() {
        Ok(()) => panic!("{PROBE_URL} answered — it is a reserved name that must never resolve"),
        Err(AnchorHttpError::RealNetworkDenied { endpoint, reason }) => {
            assert_eq!(endpoint, PROBE_URL);
            assert!(!reason.is_empty(), "the refusal must name its arm");
            println!("VERDICT=denied reason={reason}");
            assert_eq!(mode, "armed", "the gate fired in the disarmed arm");
        }
        Err(other) => {
            println!("VERDICT=reached-network error={other:?}");
            assert_eq!(mode, "disarmed", "the gate did NOT fire in the armed arm");
        }
    }
}
