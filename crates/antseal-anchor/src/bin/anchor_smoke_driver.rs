//! The wire half of `scripts/anchor-smoke` (task **A25**; Q99, A127, V7.1).
//!
//! # Why this binary exists
//!
//! D118 §1.5 recorded that every real-endpoint capture in `testdata/anchors/`
//! was performed by hand with `curl`: *"antseal's submit and upgrade paths
//! have never spoken to a real calendar"*, and `docs/testing/verification-matrix.md`
//! row `V7.1` is `gap` for exactly that reason. A capture script built on
//! `curl` would reproduce the gap it exists to close. This binary is the
//! smallest surface through which `scripts/anchor-smoke` drives **antseal's
//! own clients**:
//!
//! | mode | production code driven |
//! | --- | --- |
//! | `submit` | [`antseal_anchor::ots::submit_to_calendars`] (A13) |
//! | `upgrade` | [`antseal_anchor::ots::pending_refs`] + [`antseal_anchor::ots::UpgradeTarget::from_pending_uri`] (A42) + [`antseal_anchor::ots::poll_upgrade`] (A14) |
//! | `tsa` | [`antseal_anchor::tsa::capture_one`] (A10) over `TsaRootStore::pinned()` |
//! | `esplora` | [`antseal_anchor::esplora::fetch_agreed_header`] (A16) |
//! | `arbitrum` | [`antseal_anchor::arbitrum::confirm_arbitrum_tx`] (A17) |
//! | `defaults` | prints the endpoint constants, so the script re-types none (runbook §3) |
//!
//! Every request goes through `HttpClient::send`, i.e. through the Q16
//! runtime gate in `http::offline` — armed, this binary can dial loopback IP
//! literals and nothing else, which is what `scripts/anchor-smoke selftest`
//! runs under.
//!
//! # Why it is `required-features = ["test-util"]`
//!
//! Two reasons, both structural. (1) The selftest's loopback upgrade poll
//! needs [`UpgradeTarget::loopback_for_tests`]: A42's allowlist deliberately
//! refuses `http://127.0.0.1:<port>`, and that constructor is the sanctioned
//! escape hatch, compiled only under `test-util`. (2) The gate-features
//! partition (D124-adjacent; `scripts/gate-features.sh`) requires every
//! feature to be compiled by a tier, so this binary rides the **existing**
//! `antseal-anchor/test-util` tier-1 feature rather than minting a new one.
//! Required CI is default-features-only (D90 decision 1), so no CI job builds
//! or runs this target; the local gate's tier 1 compiles and clippy-checks it.
//!
//! # Output protocol (consumed by `scripts/anchor-smoke`)
//!
//! Line-oriented `key=value` pairs on stdout. Variable-content values are
//! lowercase-hex-encoded (`*_hex`) so a line always splits on spaces. One
//! `event` line per HTTP exchange, carrying `url`, `http`, `outcome`,
//! `elapsed_ms` and `utc_unix`; body-bearing outcomes carry `body_hex`
//! (hashed by the script **from these bytes**, before any file is written —
//! runbook §4's "all four fields, at capture, never back-filled").
//!
//! Two honest limitations, recorded here rather than papered over:
//!
//! - **successes log `http=2xx`, not an exact figure.** The typed returns of
//!   `submit_to_calendars` / `poll_upgrade` / `capture_one` carry the
//!   response *class*, not the status code; `HttpResponse::status` documents
//!   the success arm as "the 2xx status code", and every committed capture
//!   answered exactly 200. Recording `200` here without seeing it would be a
//!   fabrication; recording `2xx` is what this process actually knows.
//! - **the two classified 404 bodies are not re-emitted.** D58 §7.4's
//!   discriminator consumes them (`UpgradePoll::NotYetConfirmed` /
//!   `NotFound` carry no bytes, deliberately — the classifier compares
//!   trimmed content, and the wire bytes differ between calendars by a
//!   trailing newline). Those events report `outcome=` only; the script
//!   records `bytes=- sha256=-` for them and its finish check knows the
//!   difference between "body consumed by the typed classifier" and "a body
//!   we failed to hash".
//!
//! # Exit codes
//!
//! `0` — a protocol-classified outcome was reached (including
//! `not-yet-confirmed`, `not-found`, `agreed-absent`, `unverifiable`: the
//! classification is the deliverable). `2` — local refusal or usage error,
//! nothing sent. `3` — an endpoint-level failure was recorded (transport,
//! unclassified status). `4` — refused by the no-real-anchor-network gate.
//! The script keys on **outcome tokens**, never on exit codes alone
//! (verify-a-failure-by-its-message).

use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use antseal_anchor::agree::{Agreement, EndpointPair};
use antseal_anchor::arbitrum::confirm::{ArbitrumConfirmation, confirm_arbitrum_tx};
use antseal_anchor::arbitrum::endpoints::{ARBITRUM_ONE_VERIFY_RPCS, ARBITRUM_SEPOLIA_VERIFY_RPCS};
use antseal_anchor::esplora::{DEFAULT_ESPLORA_ENDPOINTS, fetch_agreed_header};
use antseal_anchor::nonce::draw_request_nonce;
use antseal_anchor::ots::calendars::{DEFAULT_OTS_CALENDARS, OTS_SUBMIT_PATH, join};
use antseal_anchor::ots::{
    CalendarFailure, OTS_UPGRADE_PATH_PREFIX, UpgradePoll, UpgradeTarget, assemble, pending_refs,
    poll_upgrade, submit_to_calendars,
};
use antseal_anchor::tsa::{DEFAULT_TSA_URLS, TsaFailure, capture_one};
use antseal_anchor::{AnchorHttpError, Endpoint, HttpClient, HttpPolicy, TlsPolicy};
use antseal_core::anchor::request::{build_timestamp_req, canonical_request_nonce};
use antseal_core::anchor::roots::TsaRootStore;
use antseal_net::network::NetworkId;

/// Exit: local refusal / usage error — nothing was sent.
const EXIT_REFUSED: u8 = 2;
/// Exit: an endpoint-level failure was recorded (diagnose from the log).
const EXIT_ENDPOINT_FAILURE: u8 = 3;
/// Exit: the Q16 runtime gate refused the endpoint before any socket.
const EXIT_GATE_DENIED: u8 = 4;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("anchor-smoke-driver: {message}");
            ExitCode::from(EXIT_REFUSED)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let Some(mode) = args.first() else {
        return Err(usage());
    };
    let rest = &args[1..];
    match mode.as_str() {
        "defaults" => {
            print_defaults();
            Ok(ExitCode::SUCCESS)
        }
        "submit" => submit(rest),
        "upgrade" => upgrade(rest),
        "tsa" => tsa(rest),
        "esplora" => esplora(rest),
        "arbitrum" => arbitrum(rest),
        "--help" | "-h" | "help" => {
            println!("{}", usage());
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown mode `{other}`\n{}", usage())),
    }
}

fn usage() -> String {
    "usage: anchor-smoke-driver <mode> [--key value ...]\n\
     modes:\n\
       defaults                                   print the endpoint constants (read from the code)\n\
       submit   --digest-hex H --calendar URL     POST the 32 raw digest bytes via A13's client\n\
       upgrade  --digest-hex H --pending FILE     poll the pending attestation via A14's client\n\
                [--loopback-base URL]             (selftest only: A42 refuses loopback by design)\n\
       tsa      --digest-hex H --url URL          RFC 3161 exchange + full verification via A10,\n\
                                                  against TsaRootStore::pinned()\n\
       esplora  --height N --first URL --second URL   A16 must-agree header round\n\
       arbitrum --network arbitrum-one|arbitrum-sepolia --tx-hex H --first URL --second URL\n\
                                                  A17 must-agree receipt round\n\
     This is the wire half of scripts/anchor-smoke; run that, not this."
        .to_owned()
}

/// `--key value` lookup; every mode's arguments are pairs.
fn arg<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn require<'a>(args: &'a [String], key: &str) -> Result<&'a str, String> {
    arg(args, key).ok_or_else(|| format!("missing required argument {key}"))
}

/// The 32-byte digest, refused at any other length.
///
/// Runbook §4's silent-success guard: the bootstrap once submitted an
/// **empty** body (a broken hex→binary step) and the calendars answered
/// `200`. A submit path that does not check its own request length can stamp
/// nothing and look successful, so the length check runs before any request
/// — here **and** in `scripts/anchor-smoke`, independently.
fn digest32(args: &[String]) -> Result<[u8; 32], String> {
    let hex = require(args, "--digest-hex")?;
    let bytes = from_hex(hex)?;
    let len = bytes.len();
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        format!(
            "the digest must be exactly 32 bytes, got {len}: refusing before any request \
             (runbook §4 — an empty or short body can be stamped with a 200 and look successful)"
        )
    })
}

fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string ({} chars)", hex.len()));
    }
    let nibble = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            other => Err(format!("not a hex character: {:?}", char::from(other))),
        }
    };
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(out)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Seconds since the Unix epoch, saturating at 0 — never a panic source.
fn utc_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `http=` / `outcome=` / trailing fields for a transport-class error, and
/// the exit code it earns. `RealNetworkDenied` is separated so the script can
/// name the gate rather than mistake a policy refusal for endpoint rot.
fn http_error_fields(error: &AnchorHttpError) -> (String, u8) {
    match error {
        AnchorHttpError::RealNetworkDenied { reason, .. } => (
            format!(
                "http=denied outcome=denied-by-gate detail_hex={}",
                to_hex(reason.as_bytes())
            ),
            EXIT_GATE_DENIED,
        ),
        AnchorHttpError::Status { status, body, .. } => (
            format!(
                "http={status} outcome=unclassified-status bytes={} body_hex={}",
                body.len(),
                to_hex(body)
            ),
            EXIT_ENDPOINT_FAILURE,
        ),
        other => (
            format!(
                "http=000 outcome=transport detail_hex={}",
                to_hex(other.to_string().as_bytes())
            ),
            EXIT_ENDPOINT_FAILURE,
        ),
    }
}

fn print_defaults() {
    for url in DEFAULT_OTS_CALENDARS {
        println!("default kind=ots-calendar url={url}");
    }
    for url in DEFAULT_TSA_URLS {
        println!("default kind=tsa url={url}");
    }
    for url in DEFAULT_ESPLORA_ENDPOINTS {
        println!("default kind=esplora url={url}");
    }
    for url in ARBITRUM_ONE_VERIFY_RPCS {
        println!("default kind=arbitrum-one-rpc url={url}");
    }
    for url in ARBITRUM_SEPOLIA_VERIFY_RPCS {
        println!("default kind=arbitrum-sepolia-rpc url={url}");
    }
}

/// One calendar submission through A13's real client.
///
/// One calendar per invocation, deliberately: `submit_to_calendars` fans out
/// concurrently by design (D54), and the runbook §2 spacing that
/// `scripts/anchor-smoke` enforces is *between* invocations. A single-entry
/// list drives the identical per-calendar path (`submit_one` →
/// `submit_and_validate` → `HttpClient::send`) with no concurrency to space.
fn submit(args: &[String]) -> Result<ExitCode, String> {
    let digest = digest32(args)?;
    let calendar = require(args, "--calendar")?.to_owned();
    let url = join(&calendar, OTS_SUBMIT_PATH);
    println!("mode=submit");
    println!("request kind=submit url={url}");

    let client = HttpClient::new(HttpPolicy::seal());
    let started = Instant::now();
    let submission = submit_to_calendars(&client, &digest, std::slice::from_ref(&calendar));
    let elapsed = started.elapsed().as_millis();
    let now = utc_unix();

    let Some(attempt) = submission.attempts.first() else {
        return Err("submit_to_calendars returned no attempt for a one-calendar list".to_owned());
    };
    match &attempt.outcome {
        Ok(record) => {
            println!(
                "event url={url} http=2xx outcome=pending-accepted elapsed_ms={elapsed} \
                 utc_unix={now} uri={} commitment_hex={} bytes={} body_hex={}",
                record.uri,
                to_hex(&record.commitment),
                record.body.len(),
                to_hex(&record.body)
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(CalendarFailure::Http(error)) => {
            let (fields, code) = http_error_fields(error);
            println!("event url={url} {fields} elapsed_ms={elapsed} utc_unix={now}");
            Ok(ExitCode::from(code))
        }
        Err(other) => {
            // A 2xx arrived and the *artifact* was unusable — that calendar's
            // failure, classified by A13 (`unparseable`,
            // `no-pending-attestation`, `indeterminate-commitment`). The
            // response bytes were consumed by the validator; the class and
            // its message are the record.
            println!(
                "event url={url} http=2xx outcome={} detail_hex={} elapsed_ms={elapsed} \
                 utc_unix={now}",
                other.class(),
                to_hex(other.to_string().as_bytes())
            );
            Ok(ExitCode::from(EXIT_ENDPOINT_FAILURE))
        }
    }
}

/// One upgrade poll through A14's real client.
///
/// The pending file is a **raw calendar submit response** (the shape the
/// campaigns commit); it is wrapped in a one-branch container by
/// [`assemble`] — a legal `.ots`, through the real parser — and its pending
/// attestation's URI and ops-derived commitment are extracted by
/// [`pending_refs`]. The URI then passes A42's allowlist via
/// [`UpgradeTarget::from_pending_uri`] unless `--loopback-base` is given,
/// which uses the `test-util` escape hatch — A42 refuses loopback **by
/// design**, and the refusal path stays tested through the real constructor.
fn upgrade(args: &[String]) -> Result<ExitCode, String> {
    let digest = digest32(args)?;
    let pending_path = require(args, "--pending")?;
    let body = std::fs::read(pending_path)
        .map_err(|e| format!("cannot read pending file {pending_path}: {e}"))?;
    if body.is_empty() {
        return Err(format!("pending file {pending_path} is empty"));
    }

    let stored = assemble(&digest, std::slice::from_ref(&body));
    let refs = pending_refs(&stored, &digest)
        .map_err(|e| format!("{pending_path} does not parse against this digest: {e}"))?;
    let [pending] = refs.as_slice() else {
        return Err(format!(
            "{pending_path} carries {} upgradeable pending attestation(s); a committed \
             single-calendar capture carries exactly 1",
            refs.len()
        ));
    };

    let target = match arg(args, "--loopback-base") {
        Some(base) => UpgradeTarget::loopback_for_tests(base),
        None => UpgradeTarget::from_pending_uri(&pending.uri, &[])
            .map_err(|refusal| format!("A42 refused the pending URI: {refusal}"))?,
    };
    // The same composition `poll_upgrade` performs, reproduced for the log
    // line only — the poll itself builds its own URL from the same parts.
    let url = join(
        target.base(),
        &format!("{OTS_UPGRADE_PATH_PREFIX}{}", to_hex(&pending.commitment)),
    );
    println!("mode=upgrade");
    println!(
        "request kind=upgrade url={url} uri={} commitment_hex={}",
        pending.uri,
        to_hex(&pending.commitment)
    );

    let client = HttpClient::new(HttpPolicy::verify());
    let started = Instant::now();
    let poll = poll_upgrade(&client, &target, &pending.commitment);
    let elapsed = started.elapsed().as_millis();
    let now = utc_unix();

    let common = format!("elapsed_ms={elapsed} utc_unix={now}");
    match poll {
        UpgradePoll::Upgraded(upgraded) => {
            println!(
                "event url={url} http=2xx outcome=upgraded bytes={} body_hex={} {common}",
                upgraded.len(),
                to_hex(&upgraded)
            );
            Ok(ExitCode::SUCCESS)
        }
        // The two classified 404s: the calendar-behaviour classes the capture
        // must preserve (runbook §3.1). Their bodies are consumed by D58
        // §7.4's trimmed-content classifier and are not re-emitted — see the
        // module docs.
        UpgradePoll::NotYetConfirmed => {
            println!("event url={url} http=404 outcome=not-yet-confirmed {common}");
            Ok(ExitCode::SUCCESS)
        }
        UpgradePoll::NotFound => {
            println!("event url={url} http=404 outcome=not-found {common}");
            Ok(ExitCode::SUCCESS)
        }
        UpgradePoll::Empty => {
            println!("event url={url} http=2xx outcome=empty-200 {common}");
            Ok(ExitCode::from(EXIT_ENDPOINT_FAILURE))
        }
        // Transport and unclassified failures stay re-pollable and are never
        // promoted to `not-found` — `UpgradePoll` separates the arms by
        // construction, and this match preserves that separation into the log.
        UpgradePoll::Failed(error) => {
            let (fields, code) = http_error_fields(&error);
            println!("event url={url} {fields} {common}");
            Ok(ExitCode::from(code))
        }
    }
}

/// One RFC 3161 exchange plus **full verification** through A10's real path:
/// fresh CSPRNG nonce, `build_timestamp_req`, POST, `verify_token` with the
/// canonical nonce, chain validation against `TsaRootStore::pinned()` at the
/// token's own `genTime` (A32: no local clock decides anything).
fn tsa(args: &[String]) -> Result<ExitCode, String> {
    let digest = digest32(args)?;
    let endpoint = require(args, "--url")?;
    let nonce = draw_request_nonce().map_err(|e| format!("cannot draw a request nonce: {e}"))?;
    let request_bytes = build_timestamp_req(&digest, &nonce);
    println!("mode=tsa");
    // Printed before the exchange so the script can persist the `.tsq` even
    // if the exchange itself fails. The nonce is inside these bytes; it is
    // request material for a public digest, not secret material, and every
    // committed campaign stores it (`D60-tsa-*-req.tsq`).
    println!(
        "request kind=tsa url={endpoint} req_bytes={} req_body_hex={} nonce_canonical_hex={}",
        request_bytes.len(),
        to_hex(&request_bytes),
        to_hex(&canonical_request_nonce(&nonce))
    );

    let store = TsaRootStore::pinned();
    let fetch_date = utc_unix();
    let client = HttpClient::new(HttpPolicy::seal());
    let started = Instant::now();
    let outcome = capture_one(&client, &digest, endpoint, &nonce, store, fetch_date);
    let elapsed = started.elapsed().as_millis();
    let now = utc_unix();

    let common = format!("elapsed_ms={elapsed} utc_unix={now}");
    match outcome {
        Ok(capture) => {
            println!(
                "event url={endpoint} http=2xx outcome=verified state={:?} \
                 root_store_version={} root_label_hex={} gen_time_unix={} identity_hex={} \
                 bytes={} body_hex={} {common}",
                capture.state,
                capture.root_store_version,
                to_hex(capture.root_label.unwrap_or("-").as_bytes()),
                capture.gen_time_unix,
                to_hex(format!("{:?}", capture.identity).as_bytes()),
                capture.token.len(),
                to_hex(&capture.token)
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(TsaFailure::Http(error)) => {
            let (fields, code) = http_error_fields(&error);
            println!("event url={endpoint} {fields} {common}");
            Ok(ExitCode::from(code))
        }
        Err(failure) => {
            // `not-granted` / `unverifiable` / `untrusted-chain`: a 2xx
            // arrived and A10's verifier consumed it. The class and message
            // are the record; a verified token is the only outcome whose
            // bytes A10 hands back.
            println!(
                "event url={endpoint} http=2xx outcome={} detail_hex={} {common}",
                failure.class(),
                to_hex(failure.to_string().as_bytes())
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn parse_pair(args: &[String]) -> Result<EndpointPair, String> {
    let first = require(args, "--first")?;
    let second = require(args, "--second")?;
    // The CLI's own policy for these families (status.rs `pair()`): replies
    // are unsigned, so TLS is required — with the loopback-literal carve-out
    // that the selftest stubs live in.
    let parse = |url: &str| {
        Endpoint::parse(url, TlsPolicy::RequiredExceptLoopback).map_err(|e| e.to_string())
    };
    EndpointPair::new(parse(first)?, parse(second)?).map_err(|e| e.to_string())
}

/// One A16 must-agree round: each endpoint resolves height → hash → header
/// on its own, and agreement is over the extracted 80-byte header.
fn esplora(args: &[String]) -> Result<ExitCode, String> {
    let height: u64 = require(args, "--height")?
        .parse()
        .map_err(|e| format!("--height is not a u64: {e}"))?;
    let pair = parse_pair(args)?;
    println!("mode=esplora");
    println!(
        "request kind=esplora height={height} first={} second={}",
        pair.first().url(),
        pair.second().url()
    );

    let client = HttpClient::new(HttpPolicy::verify());
    let started = Instant::now();
    let agreement = fetch_agreed_header(&client, &pair, height);
    let elapsed = started.elapsed().as_millis();
    let now = utc_unix();
    let common = format!("elapsed_ms={elapsed} utc_unix={now}");

    match agreement {
        Agreement::Agreed(Some(header)) => {
            println!(
                "event kind=esplora height={height} outcome=agreed-header bytes={} \
                 header_hex={} {common}",
                header.len(),
                to_hex(&header)
            );
            Ok(ExitCode::SUCCESS)
        }
        Agreement::Agreed(None) => {
            println!("event kind=esplora height={height} outcome=agreed-absent {common}");
            Ok(ExitCode::SUCCESS)
        }
        Agreement::Disagreed { first, second } => {
            println!(
                "event kind=esplora height={height} outcome=disagreed detail_hex={} {common}",
                to_hex(format!("first={first:?} second={second:?}").as_bytes())
            );
            Ok(ExitCode::from(EXIT_ENDPOINT_FAILURE))
        }
        Agreement::Unavailable { failures } => {
            let joined = failures
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" | ");
            let code = unavailable_exit(&failures.iter().collect::<Vec<_>>());
            println!(
                "event kind=esplora height={height} outcome=unavailable failed={} \
                 detail_hex={} {common}",
                failures.len(),
                to_hex(joined.as_bytes())
            );
            Ok(ExitCode::from(code))
        }
    }
}

/// Gate denials outrank plain endpoint failures in the exit code, so a
/// policy refusal is never misread as endpoint rot.
fn unavailable_exit(failures: &[&antseal_anchor::agree::EndpointFailure]) -> u8 {
    use antseal_anchor::agree::EndpointFailure;
    let denied = failures.iter().any(|f| {
        matches!(
            f,
            EndpointFailure::Http(AnchorHttpError::RealNetworkDenied { .. })
        )
    });
    if denied {
        EXIT_GATE_DENIED
    } else {
        EXIT_ENDPOINT_FAILURE
    }
}

/// One A17 must-agree round: chain-id-guarded receipt fetch from both RPCs,
/// agreement over the **extracted tuple** (D55 §3 — the two ruled-in RPCs
/// return different JSON key sets for identical values, so byte comparison
/// would report a disagreement between two honest endpoints).
fn arbitrum(args: &[String]) -> Result<ExitCode, String> {
    let network = match require(args, "--network")? {
        "arbitrum-one" => NetworkId::ArbitrumOne,
        "arbitrum-sepolia" => NetworkId::ArbitrumSepolia,
        other => {
            return Err(format!(
                "--network must be arbitrum-one or arbitrum-sepolia, got {other}"
            ));
        }
    };
    let tx_bytes = from_hex(require(args, "--tx-hex")?.trim_start_matches("0x"))?;
    let len = tx_bytes.len();
    let tx_hash: [u8; 32] = tx_bytes
        .try_into()
        .map_err(|_| format!("--tx-hex must be 32 bytes, got {len}"))?;
    let pair = parse_pair(args)?;
    println!("mode=arbitrum");
    println!(
        "request kind=arbitrum tx=0x{} first={} second={}",
        to_hex(&tx_hash),
        pair.first().url(),
        pair.second().url()
    );

    let client = HttpClient::new(HttpPolicy::verify());
    let started = Instant::now();
    let confirmation = confirm_arbitrum_tx(&client, &pair, network, &tx_hash);
    let elapsed = started.elapsed().as_millis();
    let now = utc_unix();
    let common = format!("elapsed_ms={elapsed} utc_unix={now}");

    match confirmation {
        ArbitrumConfirmation::Agreed(facts) => {
            println!(
                "event kind=arbitrum outcome=agreed status={} block_number={} \
                 block_hash_hex={} {common}",
                facts.status,
                facts.block_number,
                to_hex(&facts.block_hash)
            );
            Ok(ExitCode::SUCCESS)
        }
        ArbitrumConfirmation::Absent => {
            println!("event kind=arbitrum outcome=agreed-absent {common}");
            Ok(ExitCode::SUCCESS)
        }
        ArbitrumConfirmation::Lagging { seen_by, facts } => {
            println!(
                "event kind=arbitrum outcome=lagging seen_by={seen_by} detail_hex={} {common}",
                to_hex(format!("{facts:?}").as_bytes())
            );
            Ok(ExitCode::from(EXIT_ENDPOINT_FAILURE))
        }
        ArbitrumConfirmation::Disagreed { first, second } => {
            println!(
                "event kind=arbitrum outcome=disagreed detail_hex={} {common}",
                to_hex(format!("first={first:?} second={second:?}").as_bytes())
            );
            Ok(ExitCode::from(EXIT_ENDPOINT_FAILURE))
        }
        ArbitrumConfirmation::Unavailable { failures } => {
            let joined = failures
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" | ");
            let code = unavailable_exit(&failures.iter().collect::<Vec<_>>());
            println!(
                "event kind=arbitrum outcome=unavailable failed={} detail_hex={} {common}",
                failures.len(),
                to_hex(joined.as_bytes())
            );
            Ok(ExitCode::from(code))
        }
    }
}
