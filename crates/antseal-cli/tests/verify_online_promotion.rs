//! **R100: `verify --online` promotes the real attested fixture, end to end** (D133 §8
//! item 3).
//!
//! The shipped binary verifies D133's attested bundle: F13's base bundle carrying A25's real
//! merged-and-upgraded `.ots`, whose upgrade group embeds the real header of Bitcoin block
//! 960767. A `config.toml` points `[verify] bitcoin_endpoints` at two loopback stubs that
//! replay the committed esplora captures of that block (`antseal_anchor::testing::replay`,
//! A112). Three rows, one `#[test]` each, so each plant below reddens exactly one of them:
//!
//! 1. **offline**: no `--online`. Exit 43 (`verify-unanchored`, D69 §3), no overlay, and
//!    neither stub is dialled although the config names both.
//! 2. **promotion**: `--online`, each stub replaying its own endpoint's capture. Exit 0, equal
//!    to `result.verdict.exit_code` (D69 §3 R7), the anchor `promoted` at block 960767's
//!    `nTime` (D56's O3), and each stub asked exactly the plan's two questions.
//! 3. **control**: `--online`, the second stub answering height 960767 with block 960768's
//!    real hash and header. Exit 43, `not-promoted` / `disagreed`. The control cannot be two
//!    captures of 960767: those bodies are byte-identical, as two honest endpoints' must be.
//!
//! **Why the binary rather than an in-process run.** `spawn::antseal()` arms Q16's gate in
//! the child, so a config-wiring regression that fell back to the pinned esplora pair would
//! be refused before DNS, and the promotion row would go red on its request lines. An
//! in-process run under a bare `cargo test -p antseal-cli` is unarmed (see `common/spawn.rs`),
//! and the same regression would dial the real pair. The binary also covers what an
//! in-process run cannot: argv, `config.toml` loaded from `ANTSEAL_DIR`, the `--json`
//! envelope and the process exit code.
//!
//! **Why the fixture is assembled here.** D133 R2 materialises the page's copy into
//! `target/` and never commits it, so reading it would make this suite depend on another
//! crate's test having run first. This file repeats D133 R4's public-API assembly from the
//! two frozen vectors instead, and pins the same 4 846 B that
//! `antseal-core/tests/page_fixtures.rs` pins as `ATTESTED_FIXTURE_LEN`, so a format change
//! reddens both suites.
//!
//! The human lines are not pinned here; `verdict-wording.txt` freezes them. These rows read
//! the `--json` keys the lines are rendered from.

#[path = "common/spawn.rs"]
mod spawn;

use std::path::PathBuf;
use std::process::Stdio;

use antseal_anchor::testing::replay::{
    RecordedEndpoint, attested_block, esplora_block_at, esplora_recorded_block, request_line,
};
use antseal_anchor::testing::stub::StubServer;
use antseal_core::bundle::{
    AnchorStatus, BundleV1, OpaqueBytes, OtsAnchor, OtsUpgrade, encode_bundle,
};
use serde_json::{Value, json};

/// The block A25's alice attestation landed in.
const HEIGHT: u64 = 960_767;
/// The block the control's second stub serves in its place: bob's, one block later.
const OTHER_HEIGHT: u64 = 960_768;
/// Block 960767's `nTime`: header bytes 68..72, little-endian. The promotion row re-derives
/// it from the committed capture before it asserts the promoted time.
const NTIME: u64 = 1_785_701_746;
/// D133 §1 (d)'s measured size, the same pin `antseal-core/tests/page_fixtures.rs` carries.
const FIXTURE_LEN: usize = 4_846;

fn vector(relative: &str) -> Value {
    let path = format!(
        "{}/../../testdata/vectors/v1/{relative}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: the committed vector document must exist: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: not valid JSON: {e}"))
}

fn case<'d>(document: &'d Value, section: &str, name: &str) -> &'d Value {
    document[section]["cases"]
        .as_array()
        .unwrap_or_else(|| panic!("{section}.cases is an array"))
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("case `{name}` is in the committed document"))
}

fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// D133 R3/R4's assembly, public API only: F13's `empty-anchor-unanchored` bundle carrying the
/// anchor vector's real merged-and-upgraded `.ots` with its real block-960767 upgrade group.
///
/// The receipt slot is emptied explicitly, as `page_fixtures.rs` does. With no receipt the
/// probe plan holds no transaction, so `--online` asks the Arbitrum pair nothing.
fn attested_ots_960767() -> Vec<u8> {
    let bundles = vector("bundle/bundle.json");
    let base = hex(
        case(&bundles, "expect", "empty-anchor-unanchored")["bundle_bytes"]
            .as_str()
            .expect("bundle_bytes"),
    );
    let anchors = vector("anchor/anchor.json");
    let upgraded = case(&anchors, "inputs", "ots-upgraded-offline");
    let artifact = hex(upgraded["artifact_hex"].as_str().expect("artifact_hex"));
    let group = &upgraded["upgrade"];
    let header: [u8; 80] = hex(group["block_header_hex"].as_str().expect("header hex"))
        .try_into()
        .expect("a block header is 80 bytes");
    let upgrade = OtsUpgrade::new(
        group["block_height"].as_u64().expect("block_height"),
        header,
        group["fetch_date_unix"].as_u64().expect("fetch_date_unix"),
    );

    let mut parts = BundleV1::decode(&base)
        .expect("the frozen base bundle decodes")
        .into_parts();
    parts.ots_anchors = vec![
        OtsAnchor::new(
            AnchorStatus::Attested,
            OpaqueBytes::from_vec(artifact),
            Some(upgrade),
        )
        .expect("a committed artifact is under the caps"),
    ];
    parts.receipt = None;
    let bytes = encode_bundle(&BundleV1::new(parts).expect("well-formed"))
        .expect("the rebuilt bundle encodes");
    assert_eq!(
        bytes.len(),
        FIXTURE_LEN,
        "D133 §1 (d) measured this assembly at {FIXTURE_LEN} B; the format or a frozen vector moved"
    );
    bytes
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "antseal-cli-r100-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create test dir");
        Self(dir)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The two esplora stubs: block 960767 as each endpoint recorded it, or, for the control,
/// the second endpoint answering height 960767 with block 960768's real hash and header.
fn stubs(agree: bool) -> (StubServer, StubServer) {
    let block = attested_block(HEIGHT).expect("block 960767 is committed");
    let first = StubServer::spawn(esplora_recorded_block(block, RecordedEndpoint::Blockstream));
    let second = if agree {
        StubServer::spawn(esplora_recorded_block(block, RecordedEndpoint::Mempool))
    } else {
        let other = attested_block(OTHER_HEIGHT).expect("block 960768 is committed");
        StubServer::spawn(esplora_block_at(
            HEIGHT,
            other.hash_hex(RecordedEndpoint::Mempool),
            other.header_hex(RecordedEndpoint::Mempool),
        ))
    };
    (first, second)
}

struct Run {
    code: Option<i32>,
    json: Value,
}

/// `antseal --json verify [--online] <fixture>`, with `[verify] bitcoin_endpoints` = the stubs.
fn run(dir: &TestDir, pair: (&StubServer, &StubServer), online: bool) -> Run {
    let vault = dir.0.join("vault");
    std::fs::create_dir_all(&vault).expect("vault dir");
    std::fs::write(
        vault.join("config.toml"),
        format!(
            "[verify]\nbitcoin_endpoints = [\"{}\", \"{}\"]\n",
            pair.0.base_url(),
            pair.1.base_url()
        ),
    )
    .expect("write config.toml");
    let bundle = dir.0.join("attested-ots-960767.sealproof");
    std::fs::write(&bundle, attested_ots_960767()).expect("write the fixture");

    let mut args = vec!["--json", "verify"];
    if online {
        args.push("--online");
    }
    let path = bundle.to_str().expect("a UTF-8 temp path");
    args.push(path);
    let out = spawn::antseal()
        .args(&args)
        .env("ANTSEAL_DIR", &vault)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn antseal");
    let json: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is one JSON document ({e}); stdout: {} / stderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    Run {
        code: out.status.code(),
        json,
    }
}

fn lines(stub: &StubServer) -> Vec<String> {
    stub.requests().iter().map(|r| request_line(r)).collect()
}

/// The two questions the probe plan asks one endpoint about block 960767: the height, then
/// the header of the hash that endpoint answered with.
fn questions(hash_hex: &[u8]) -> Vec<String> {
    let hash = std::str::from_utf8(hash_hex).expect("a committed hash body is ASCII hex");
    vec![
        format!("GET /block-height/{HEIGHT} HTTP/1.1"),
        format!("GET /block/{hash}/header HTTP/1.1"),
    ]
}

#[test]
fn offline_the_attested_fixture_is_unanchored_and_no_endpoint_is_dialled() {
    let dir = TestDir::new("offline");
    let (a, b) = stubs(true);
    let run = run(&dir, (&a, &b), false);
    assert_eq!(
        run.code,
        Some(43),
        "offline must be unanchored: {}",
        run.json
    );
    assert_eq!(run.json["result"]["verdict"]["exit_code"], 43);
    assert!(run.json["result"]["overlay"].is_null(), "{}", run.json);
    assert_eq!(
        run.json["result"]["report"]["anchors"][0]["state"],
        "attested"
    );
    assert!(
        a.requests().is_empty() && b.requests().is_empty(),
        "an offline verify dialled a configured endpoint: {:?} / {:?}",
        lines(&a),
        lines(&b)
    );
}

#[test]
fn promotion_an_agreeing_pair_promotes_the_attested_fixture_at_its_headers_time() {
    let block = attested_block(HEIGHT).expect("block 960767 is committed");
    let header = block
        .header_bytes(RecordedEndpoint::Blockstream)
        .expect("the capture is 160 hex characters");
    let time = u32::from_le_bytes(header[68..72].try_into().expect("four bytes"));
    assert_eq!(u64::from(time), NTIME, "NTIME is block 960767's own nTime");

    let dir = TestDir::new("agree");
    let (a, b) = stubs(true);
    let run = run(&dir, (&a, &b), true);
    assert_eq!(
        run.code,
        Some(0),
        "two agreeing endpoints must promote the attested anchor (exit 0); got {:?}: {}",
        run.code,
        run.json["result"]["overlay"]["anchor_outcomes"]
    );
    assert_eq!(
        run.json["result"]["verdict"]["exit_code"], 0,
        "D69 §3 R7: $? == verdict.exit_code"
    );
    assert_eq!(
        run.json["result"]["overlay"]["anchor_outcomes"][0]["class"],
        json!({"promoted": {"time_unix": NTIME, "height": HEIGHT, "source": "bitcoin-block-960767"}}),
    );
    assert_eq!(
        run.json["result"]["overlay"]["headline_impact"]["supplies"]["headline"]["time_unix"],
        NTIME
    );
    assert_eq!(
        run.json["result"]["report"]["anchors"][0]["state"], "attested",
        "D64 §2: the offline report is unchanged under --online"
    );

    // The endpoints asked were the configured stubs, disclosed as an override, in order.
    let endpoints = &run.json["result"]["overlay"]["endpoints"];
    assert_eq!(endpoints["overridden"], true, "{endpoints}");
    assert_eq!(endpoints["identities"][0], a.base_url(), "{endpoints}");
    assert_eq!(endpoints["identities"][1], b.base_url(), "{endpoints}");
    assert!(
        run.json["result"]["overlay"]["receipt"].is_null(),
        "the fixture carries no receipt, so no receipt probe runs: {}",
        run.json["result"]["overlay"]["receipt"]
    );
    assert_eq!(
        lines(&a),
        questions(block.hash_hex(RecordedEndpoint::Blockstream))
    );
    assert_eq!(
        lines(&b),
        questions(block.hash_hex(RecordedEndpoint::Mempool))
    );
}

#[test]
fn control_a_disagreeing_pair_promotes_nothing() {
    let dir = TestDir::new("disagree");
    let (a, b) = stubs(false);
    let run = run(&dir, (&a, &b), true);
    assert_eq!(
        run.code,
        Some(43),
        "a disagreeing pair must not promote: {}",
        run.json
    );
    assert_eq!(run.json["result"]["verdict"]["exit_code"], 43);
    assert_eq!(
        run.json["result"]["overlay"]["anchor_outcomes"][0]["class"],
        json!({"not-promoted": {"reason": "disagreed"}}),
    );
    assert_eq!(
        run.json["result"]["overlay"]["headline_impact"],
        "still-unanchored"
    );

    // The disagreement is the stubs' own answers: the second endpoint named block 960768's
    // hash for height 960767 and served that block's header.
    let block = attested_block(HEIGHT).expect("block 960767 is committed");
    let other = attested_block(OTHER_HEIGHT).expect("block 960768 is committed");
    assert_eq!(
        lines(&a),
        questions(block.hash_hex(RecordedEndpoint::Blockstream))
    );
    assert_eq!(
        lines(&b),
        questions(other.hash_hex(RecordedEndpoint::Mempool))
    );
}
