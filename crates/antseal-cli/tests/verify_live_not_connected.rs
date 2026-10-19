//! **R98 (D199) — `verify --live` over a storage client that never
//! connected.**
//!
//! In-process, default build, no network, no binary: [`degrade`] and
//! [`run_verify_live`] are compiled in both builds, and the K1 and K2 reasons
//! have pure producers (`antseal_net::network::{storage_gate,
//! upstream_state}`, built exactly as `backend.rs`'s own D191 degrade test
//! builds them). Each refused shape is handed to the one production
//! composition, `run_verify_live`, and must come back:
//!
//! - with the live section **`not-connected`**: no rows, every count zero,
//!   the frozen R18 line, and neither *"transport failure"* nor *"fetch
//!   failed"* — no fetch was made, so none is reported (D199 §2 R1/R2);
//! - with `--json`'s `live` member carrying that closed value
//!   (`"verdict":"not-connected"`, `"rows":[]`), and no reason text in the
//!   document (§2 R3);
//! - with the reason on the run's stderr note, escaped to one line, and never
//!   in the verdict document (`R79`; §2 R3);
//! - with the offline run's exit code (D69 §3 R6);
//! - with **zero** seam calls on the degraded backend — read from the
//!   backend's own instrument, `UnreachableBackend::calls`, which is why the
//!   connection future hands over a borrowed backend the test keeps.
//!
//! The control is keyed on the type, never on failures: a **connected**
//! client whose every fetch fails stays *Inconclusive*, row by row, with no
//! note.

use std::sync::Arc;

use antseal_cli::backend::degrade;
use antseal_cli::preview::escape_for_terminal;
use antseal_cli::verify_host::{CollectedInputs, run_verify_live};
use antseal_cli::verify_out::{VerifyRun, run_verify};
use antseal_core::bundle::BundleV1;
use antseal_core::test_util::bundle_fixtures::{Selection, StorageAddresses, build, shapes};
use antseal_core::verify::orchestration::{
    FetchFailureClass, LiveBlobOutcome, LiveLayerVerdict, VerifyModes,
};
use antseal_core::verify::{VerifyOptions, wording};
use antseal_net::network::{storage_gate, upstream_state};
use antseal_net::test_util::{Fault, Method, MockBackend, block_on};
use antseal_net::{
    Address, BalanceReport, Blob, CostQuote, PaymentReceipt, StorageBackend, StorageError,
};

/// `degrade`'s kind-neutral words (D191), which open every carried reason.
const NO_CONNECTION: &str = "no connection to the Autonomi network was made: ";

/// R6's three-file work with real S4 addresses, so a composition that
/// fetched would have real subjects to ask about.
fn linked_bundle() -> Vec<u8> {
    build(
        &shapes::multi_file().with_storage_addresses(StorageAddresses::Real),
        &Selection::all(3),
    )
    .bytes
}

fn options() -> VerifyOptions {
    VerifyOptions::new()
}

fn offline_run(bytes: &[u8]) -> VerifyRun {
    run_verify(
        bytes,
        &options(),
        VerifyModes::OFFLINE,
        &CollectedInputs::none(),
    )
    .expect("the fixture verifies offline")
}

/// How many fetches `collect_live` makes over this bundle: every embedded
/// unit ciphertext, then the encrypted manifest.
fn subjects(bytes: &[u8]) -> u64 {
    let bundle = BundleV1::decode(bytes).expect("the fixture decodes");
    (bundle.covered_reveals().len() + bundle.noncovered_reveals().len() + 1) as u64
}

/// The refused shapes that reach `degrade` through the binary and have a
/// pure producer — K1, K2 and K5 (D191 §1.2; K3 is refused earlier, as
/// usage, and K4 is upstream's own text) — as the connect seam reports them.
fn refused_kinds() -> Vec<(&'static str, String)> {
    let documentation_peer = std::net::SocketAddr::from(([192, 0, 2, 10], 10_000));
    let gate = storage_gate::verdict(
        storage_gate::decide(false, true, None),
        &[documentation_peer],
    )
    .expect_err("K1: an armed gate refuses a non-loopback peer");
    let upstream = upstream_state::verdict(upstream_state::Os::Other, |_| None)
        .expect_err("K2: no variable at all is upstream's panic case");
    vec![
        ("K1, the storage gate", gate.to_string()),
        ("K2, upstream's state directory", upstream.to_string()),
        (
            "K5, the bound",
            format!(
                "the connection attempt did not finish within {:?}",
                std::time::Duration::from_secs(60)
            ),
        ),
    ]
}

/// A `MockBackend` the test keeps a handle on, so its call counts and armed
/// faults can be read after the composition consumed the connection.
struct SharedMock(Arc<MockBackend>);

impl StorageBackend for SharedMock {
    async fn quote_batch(&self, blobs: &[Blob]) -> Result<CostQuote, StorageError> {
        self.0.quote_batch(blobs).await
    }

    async fn pay(&self, quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
        self.0.pay(quote).await
    }

    async fn finalize_batch(
        &self,
        receipt: &PaymentReceipt,
        blobs: &[Blob],
    ) -> Result<Vec<Address>, StorageError> {
        self.0.finalize_batch(receipt, blobs).await
    }

    async fn get_data(&self, address: Address) -> Result<Vec<u8>, StorageError> {
        self.0.get_data(address).await
    }

    async fn balances(&self) -> Result<BalanceReport, StorageError> {
        self.0.balances().await
    }
}

/// **The Accept (D199 §2 R1–R3), for K1, K2 and K5.** A storage client
/// antseal refused to start, or whose attempt failed or timed out, is named
/// as a connection not made — in human output by the closed R18 line, in
/// `--json` by the closed value, on stderr by its reason — and nothing is
/// fetched from it.
#[test]
fn a_client_that_never_connected_is_reported_not_connected_and_nothing_is_fetched() {
    let bytes = linked_bundle();
    assert!(
        subjects(&bytes) >= 3,
        "the bundle embeds ciphertexts, so a composition that fetched would make seam calls"
    );
    let offline = offline_run(&bytes);

    let kinds = refused_kinds();
    assert_eq!(
        kinds.len(),
        3,
        "K1, K2 and K5 — a sweep over an empty list is vacuous"
    );
    for (kind, reason) in kinds {
        let backend = degrade::<SharedMock>(
            "verify",
            Err(StorageError::Network {
                reason: reason.clone(),
            }),
        );
        assert_eq!(
            backend
                .degraded()
                .expect("a refused attempt degrades")
                .calls(),
            0,
            "{kind}: a fresh degraded backend"
        );

        let run = block_on(run_verify_live(
            &bytes,
            &options(),
            VerifyModes::OFFLINE,
            CollectedInputs::none(),
            async { &backend },
        ))
        .unwrap_or_else(|error| {
            panic!("{kind}: a connection not made must not end `verify --live`: {error}")
        });

        // The section: a closed state, no rows, every count zero.
        let section = run
            .outcome()
            .live()
            .expect("--live attaches a live section");
        assert_eq!(
            section.verdict,
            LiveLayerVerdict::NotConnected,
            "{kind}: {:?}",
            section.counts
        );
        assert!(section.rows.is_empty(), "{kind}: {:?}", section.rows);
        assert_eq!(
            section.counts,
            Default::default(),
            "{kind}: every count is zero"
        );

        // Nothing was fetched — the degraded backend's own instrument, which
        // also sees a fetch whose result was thrown away.
        assert_eq!(
            backend.degraded().expect("still degraded").calls(),
            0,
            "{kind}: the degraded backend was fetched from"
        );

        // Human output: the closed line, and no fetch failure for a fetch
        // never made.
        let rendered = run.render();
        assert!(
            rendered
                .iter()
                .any(|line| line.contains(wording::LIVE_NOT_CONNECTED_LINE)),
            "{kind}: the rendered storage layer names the connection not made: {rendered:#?}"
        );
        for absent in ["transport failure", "fetch failed"] {
            assert!(
                !rendered.iter().any(|line| line.contains(absent)),
                "{kind}: `{absent}` reported for a fetch never made: {rendered:#?}"
            );
        }

        // The reason is not antseal-authored: it reaches neither the verdict
        // document nor the `--json` result (R79; D199 §2 R3). Its leading
        // window is plain text, so its absence below is not an escaping
        // artefact.
        let window: String = reason.chars().take(30).collect();
        assert!(
            window.len() == 30 && window.chars().all(|c| c.is_ascii_graphic() || c == ' '),
            "{kind}: the needle window must be plain text to mean anything: {window:?}"
        );
        assert!(
            !rendered.iter().any(|line| line.contains(&window)),
            "{kind}: the reason leaked into the verdict document: {rendered:#?}"
        );
        let json = run.json().expect("the result serializes");
        for needle in [r#""verdict":"not-connected""#, r#""rows":[]"#] {
            assert!(
                json.contains(needle),
                "{kind}: `{needle}` is missing: {json}"
            );
        }
        assert!(
            !json.contains(&window),
            "{kind}: the reason leaked into the `--json` result: {json}"
        );

        // stderr: the reason, after D191's words, escaped to one line.
        let note = run
            .live_note()
            .unwrap_or_else(|| panic!("{kind}: a connection not made carries a stderr note"));
        assert_eq!(
            note,
            format!(
                "note: `verify --live` checked nothing — {}",
                escape_for_terminal(&format!("{NO_CONNECTION}{reason}"))
            ),
            "{kind}"
        );
        assert!(
            note.contains(&window) && !note.contains(['\n', '\r']),
            "{kind}: the note carries the reason on exactly one line: {note:?}"
        );

        // The exit code and the evidence are the offline run's (D69 §3 R6).
        assert_eq!(run.exit_code(), offline.exit_code(), "{kind}");
        assert_ne!(run.exit_code(), 23, "{kind}: never the network class");
        assert_eq!(
            run.outcome().report_bytes(),
            offline.outcome().report_bytes(),
            "{kind}: the offline report bytes, unchanged"
        );
    }
}

/// **A reason is adversary-shaped text** (a bootstrap peer, an upstream
/// error): one that carries a line break, a forged verdict sentence and a
/// bidi override reaches stderr as ONE escaped line, and the verdict document
/// still holds exactly the closed line — no forged row, no raw control.
#[test]
fn a_hostile_reason_reaches_stderr_as_one_escaped_line_and_never_the_verdict_document() {
    let forged = wording::live_all_persisted_line(4);
    let hostile = format!("peer said:\n{forged}\u{202e}\r");
    let backend = degrade::<SharedMock>("verify", Err(StorageError::Network { reason: hostile }));

    let run = block_on(run_verify_live(
        &linked_bundle(),
        &options(),
        VerifyModes::OFFLINE,
        CollectedInputs::none(),
        async { &backend },
    ))
    .expect("a connection not made must not end `verify --live`");

    let note = run
        .live_note()
        .expect("a connection not made carries a note");
    assert!(
        !note.contains(['\n', '\r', '\u{202e}']),
        "the note carries a raw control character: {note:?}"
    );
    assert!(
        note.starts_with("note: `verify --live` checked nothing — no connection to the Autonomi"),
        "{note:?}"
    );

    let rendered = run.render();
    assert!(
        !rendered.iter().any(|line| line.contains("peer said:")),
        "the reason leaked into the verdict document: {rendered:#?}"
    );
    assert!(
        !rendered.iter().any(|line| line.contains(&forged)),
        "a forged live verdict reached the verdict document: {rendered:#?}"
    );
    assert!(
        rendered
            .iter()
            .any(|line| line.contains(wording::LIVE_NOT_CONNECTED_LINE)),
        "{rendered:#?}"
    );
}

/// **The control, keyed on the type and not on failures** (D199 §3). A
/// CONNECTED client whose every fetch fails in the network class is the
/// other unreachable shape — a dead bootstrap connects on the pinned stack
/// (D170 §2 R2) — and it stays *Inconclusive*: one transport-failure row per
/// subject, every fault consumed, and no stderr note. A branch keyed on "every
/// fetch failed" instead of on the backend's type would render this
/// `not-connected`.
#[test]
fn a_connected_client_whose_every_fetch_fails_is_inconclusive_never_not_connected() {
    let bytes = linked_bundle();
    let subjects = subjects(&bytes);
    assert!(
        subjects >= 3,
        "several subjects, or the control says little"
    );
    let network = Arc::new(MockBackend::new());
    for _ in 0..subjects {
        network.arm_fault(Fault::NetworkOn(Method::GetData));
    }
    let backend = degrade("verify", Ok(SharedMock(Arc::clone(&network))));
    assert!(backend.degraded().is_none(), "the attempt connected");

    let run = block_on(run_verify_live(
        &bytes,
        &options(),
        VerifyModes::OFFLINE,
        CollectedInputs::none(),
        async { &backend },
    ))
    .expect("an unreachable network must not end `verify --live`");

    assert_eq!(network.armed_faults(), 0, "every armed fault fired");
    assert_eq!(
        network.calls(Method::GetData) as u64,
        subjects,
        "every subject was asked of the network exactly once"
    );
    let section = run
        .outcome()
        .live()
        .expect("--live attaches a live section");
    assert_eq!(
        section.verdict,
        LiveLayerVerdict::Inconclusive,
        "{:?}",
        section.counts
    );
    assert_eq!(section.rows.len() as u64, subjects, "{:?}", section.rows);
    for row in &section.rows {
        assert_eq!(
            row.outcome,
            LiveBlobOutcome::FetchFailed {
                class: FetchFailureClass::Transport,
            },
            "{row:?}"
        );
    }
    let rendered = run.render();
    assert!(
        rendered
            .iter()
            .any(|line| line.contains(&wording::live_inconclusive_line(subjects))),
        "{rendered:#?}"
    );
    assert!(
        !rendered
            .iter()
            .any(|line| line.contains(wording::LIVE_NOT_CONNECTED_LINE)),
        "a connected client was reported not connected: {rendered:#?}"
    );
    assert_eq!(run.live_note(), None, "a connected run carries no note");
    assert_eq!(run.exit_code(), offline_run(&bytes).exit_code());
}
