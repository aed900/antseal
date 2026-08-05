//! **A20's load-bearing Accept row: the abort precedes payment.**
//!
//! `seal_pipeline.rs` already proves that *a* refusing gate aborts before
//! `pay` — with a hand-written double that returns `Err` and does nothing
//! else. That test cannot see whether the gate the product actually injects
//! refuses in the same place, or refuses at all, or refuses only after doing
//! something irreversible. This file drives the **real** gate
//! ([`SubmitAnchorGate`]) through the **real** pipeline and asserts on the
//! backend's pay-call counter.
//!
//! Three properties, and the third is the one a weaker test would miss:
//!
//! 1. zero verified TSA tokens ⇒ the seal aborts and `pay` is never called;
//! 2. consent happened first, and the gate really ran (the stub recorded the
//!    request), so the abort is at the gate and not somewhere earlier;
//! 3. **the same wiring can reach `pay`** — otherwise (1) would be satisfied
//!    by a gate that always aborts, and the ordering claim would be vacuous.
//!
//! Q16: the TSA endpoint is a `127.0.0.1:0` stub. Nothing here can reach a
//! real endpoint, and the request counter proves the stub is the one that was
//! contacted.
//!
//! NON-SECRET: every fixture value is documented in `common`.

mod common;

use antseal_anchor::gate::AnchorGateError;
use antseal_anchor::http::{HttpClient, HttpPolicy};
use antseal_anchor::submit::{AnchorEndpoints, NetworkClass, SealGateFlags, SubmitAnchorGate};
use antseal_anchor::testing::stub::{StubReply, StubScript, StubServer};
use antseal_cli::pipeline::{
    NoBarriers, Pipeline, SealError, SealFile, SealJournal, SealRequest, SealResult, SealState,
};
use antseal_cli::vault::store::SealShapingFlags;
use antseal_core::anchor::roots::TsaRootStore;
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_net::NetworkId;
use antseal_net::test_util::{Method, MockBackend, block_on};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::{RecordingBackend, ScriptedConsent, with_journal};

const TEXT: &[u8] = b"alpha beta\r\n\r\ngamma delta\r\n";

fn seal_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn files() -> Vec<SealFile<'static>> {
    vec![SealFile {
        path_as_given: "notes.txt",
        path_absolute: "/w/notes.txt",
        bytes: TEXT,
        flags: FileFlags::new().with_split(SplitMode::BlankLines),
    }]
}

fn request<'a>(files: &'a [SealFile<'a>], degraded: bool) -> SealRequest<'a> {
    SealRequest {
        files,
        title: "a work".to_owned(),
        claimed_time_unix_secs: 1_800_000_000,
        app_version: "antseal-test/1".to_owned(),
        // `NetworkId::Devnet` and [`NetworkClass::Development`] agree, and the
        // agreement is deliberate: the minimum-anchor rule is
        // network-independent, and mixing the two would suggest the abort is
        // something a network setting produces. Only `--no-anchor` is
        // network-sensitive, and that path is covered by S13's own suite and
        // by the gate's unit tests.
        network: NetworkId::Devnet,
        no_anchor: false,
        degraded,
        dry_run: false,
        sig_policy: SigPolicy::hybrid(),
        shaping: SealShapingFlags::default(),
    }
}

/// A TSA endpoint that answers, correctly, with something that is not a token.
///
/// `503` rather than a dead socket: a refused connection is the easy case, and
/// this is the one where an implementation that counted HTTP round trips
/// instead of verified tokens would proceed.
fn unhelpful_tsa() -> StubServer {
    StubServer::spawn(StubScript::new().always(StubReply::body(
        503,
        b"timestamping is offline for maintenance".to_vec(),
    )))
}

fn endpoints(tsa: &StubServer) -> AnchorEndpoints {
    AnchorEndpoints {
        tsa_urls: vec![tsa.base_url()],
        // No calendars: A20's gate is TSA-only (D54 §3), and leaving the OTS
        // half empty keeps this file about the one property it is for.
        ots_calendars: Vec::new(),
    }
}

/// **A20 Accept: "Abort path demonstrably precedes payment."**
///
/// The real gate, the real pipeline, and a pay-call counter — not an `Err`
/// match.
#[test]
fn the_real_gate_aborts_before_pay_with_no_money_spent() {
    let files = files();
    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let consent = ScriptedConsent::always_yes();

    let tsa = unhelpful_tsa();
    let endpoints = endpoints(&tsa);
    let client = HttpClient::new(HttpPolicy::seal());
    let gate = SubmitAnchorGate::new(
        &client,
        &endpoints,
        TsaRootStore::pinned(),
        SealGateFlags::default(),
        NetworkClass::Development,
    )
    .with_fetch_date(1_800_000_000);

    let outcome = with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.seal(&request(&files, false), &mut seal_rng(41)))
    });

    // The abort is A20's, named, and carries the endpoint verbatim.
    let Err(SealError::AnchorGate(error)) = outcome else {
        panic!("expected an anchor-gate abort, got {outcome:?}");
    };
    let AnchorGateError::MinimumAnchor {
        attempted,
        ref failures,
    } = error
    else {
        panic!("expected the minimum-anchor arm, got {error:?}");
    };
    assert_eq!(attempted, 1);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].endpoint, tsa.base_url());
    assert!(error.to_string().contains("503"), "{error}");

    // ── The property this file exists for ──
    assert_eq!(backend.pay_calls(), 0, "pay was reached");
    assert_eq!(mock.payment_tx_count(), 0, "an EVM transaction landed");
    assert_eq!(mock.stored_count(), 0, "bytes were uploaded");
    let methods: Vec<Method> = mock.call_log().iter().map(|c| c.method).collect();
    assert_eq!(
        methods,
        vec![Method::QuoteBatch],
        "the only backend call before the gate is the quote"
    );

    // ── And the gate that refused is the real one, not a double ──
    //
    // `>= 1` rather than `== 1`: a 503 is a retryable class, so the substrate's
    // three-attempt ladder makes the exact count a statement about D90's retry
    // policy rather than about this test's subject.
    assert!(
        !tsa.requests().is_empty(),
        "the TSA stub was never contacted, so this proves nothing about the real gate"
    );
    assert_eq!(consent.calls(), 1, "consent runs before the gate");
}

/// **The non-vacuity control.** The identical wiring, with the gate allowed to
/// proceed, reaches `pay` exactly once and completes.
///
/// Without this, the assertion above would be equally true of a gate that
/// refuses unconditionally — and "the abort precedes payment" would be a
/// statement about a pipeline that can never pay at all.
///
/// `--force-degraded` is what makes the same zero-verified-token stage
/// proceed. A gate-*passing* run needs a TSA that answers the nonce this
/// process just drew, which needs the signing mock (A59); the ordering
/// property does not depend on which of the two produces the proceed.
#[test]
fn the_same_wiring_reaches_pay_when_the_gate_proceeds() {
    let files = files();
    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let consent = ScriptedConsent::always_yes();

    let tsa = unhelpful_tsa();
    let endpoints = endpoints(&tsa);
    let client = HttpClient::new(HttpPolicy::seal());
    let gate = SubmitAnchorGate::new(
        &client,
        &endpoints,
        TsaRootStore::pinned(),
        SealGateFlags {
            no_anchor: false,
            force_degraded: true,
        },
        NetworkClass::Development,
    )
    .with_fetch_date(1_800_000_000);

    let outcome = with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.seal(&request(&files, true), &mut seal_rng(42))).expect("the seal lands")
    });
    let SealResult::Sealed(sealed) = outcome else {
        panic!("a non-dry-run seal returns Sealed");
    };

    assert_eq!(backend.pay_calls(), 1, "pay is reachable through this gate");
    assert_eq!(mock.calls(Method::Pay), 1);
    assert!(mock.stored_count() > 0);
    assert!(!tsa.requests().is_empty(), "the same gate ran");
    assert!(!sealed.addresses.is_empty());
}

/// A gate abort leaves the work **pre-pay and resumable**, not half-sealed:
/// the journal still reads `Staged`.
#[test]
fn a_gate_abort_leaves_the_work_staged_and_resumable() {
    let files = files();
    let mock = MockBackend::new();
    let consent = ScriptedConsent::always_yes();

    let tsa = unhelpful_tsa();
    let endpoints = endpoints(&tsa);
    let client = HttpClient::new(HttpPolicy::seal());
    let gate = SubmitAnchorGate::new(
        &client,
        &endpoints,
        TsaRootStore::pinned(),
        SealGateFlags::default(),
        NetworkClass::Development,
    )
    .with_fetch_date(1_800_000_000);

    with_journal(|journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        let error = block_on(pipeline.seal(&request(&files, false), &mut seal_rng(43)))
            .expect_err("the gate refuses");
        assert!(matches!(error, SealError::AnchorGate(_)));

        // Every incomplete work in this binary's shared journal is still
        // `Staged`: nothing this file drove ever progressed past the gate.
        // A whole-list equality would instead be measuring how many tests ran.
        let incomplete = journal.incomplete_works().expect("enumerate");
        assert!(!incomplete.is_empty(), "the staged work is missing");
        assert!(
            incomplete
                .iter()
                .all(|(_, state)| *state == SealState::Staged),
            "a gate abort moved a work past Staged: {incomplete:?}"
        );
    });
    assert_eq!(mock.payment_tx_count(), 0);
}
