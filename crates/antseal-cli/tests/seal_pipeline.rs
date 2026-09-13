//! S12 + S13 acceptance suite: the normative order, the complete blob set,
//! ciphertext-only egress, plan-time validation, `--dry-run` as a truncated
//! prefix (D49), and the zero-anchor path with its mainnet guard.
//!
//! NON-SECRET: every fixture value is documented in `common`.

mod common;

use antseal_cli::pipeline::{
    Barrier, SealError, SealFile, SealJournal, SealRequest, SealResult, SealState,
    projected_ciphertext_len,
};
use antseal_cli::pipeline::{NoBarriers, Pipeline};
use antseal_cli::vault::store::SealShapingFlags;
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_core::manifest::{Manifest, ManifestBodyV1};
use antseal_net::test_util::{Method, MockBackend, block_on};
use antseal_net::{MAX_CHUNK_SIZE, NetworkId};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::{
    IsolatedVault, RecordingBackend, RecordingGate, ScriptedConsent, TraceBarriers, with_journal,
};

const TEXT: &[u8] = b"alpha beta\r\n\r\ngamma delta\r\n";
const BINARY: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80];

fn seal_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn files() -> Vec<SealFile<'static>> {
    vec![
        SealFile {
            path_as_given: "notes.txt",
            path_absolute: "/w/notes.txt",
            bytes: TEXT,
            flags: FileFlags::new().with_split(SplitMode::BlankLines),
        },
        SealFile {
            path_as_given: "blob.bin",
            path_absolute: "/w/blob.bin",
            bytes: BINARY,
            flags: FileFlags::new(),
        },
    ]
}

fn request<'a>(files: &'a [SealFile<'a>], network: NetworkId) -> SealRequest<'a> {
    SealRequest {
        files,
        title: "a work".to_owned(),
        claimed_time_unix_secs: 1_800_000_000,
        app_version: "antseal-test/1".to_owned(),
        network,
        no_anchor: false,
        degraded: false,
        dry_run: false,
        sig_policy: SigPolicy::hybrid(),
        shaping: SealShapingFlags::default(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// The normative order (S12 accept row 1)
// ─────────────────────────────────────────────────────────────────────

/// **S12 accept**: the quote covers the full blob set including the
/// encrypted manifest; no backend call precedes journaling of staged bytes;
/// pay precedes finalize; the receipt journal precedes finalize.
#[test]
fn the_happy_path_runs_the_normative_order_over_the_full_blob_set() {
    let files = files();
    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let barriers = TraceBarriers::new();

    let outcome = with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &barriers);
        block_on(pipeline.seal(&request(&files, NetworkId::Devnet), &mut seal_rng(1)))
            .expect("seal completes")
    });
    let SealResult::Sealed(outcome) = outcome else {
        panic!("a non-dry-run seal returns Sealed");
    };

    // Two paragraph units + a raw mirror (CRLF != LF) for the text file,
    // one unit for the binary file, plus the encrypted manifest.
    let quote = backend.last_quote().expect("a quote");
    assert_eq!(quote.blobs.len(), 5, "quote covers every blob");
    assert_eq!(outcome.addresses.len(), 5);
    assert_eq!(mock.stored_count(), 5);

    // Ordering, read from the mock's own call log.
    let log = mock.call_log();
    let methods: Vec<Method> = log.iter().map(|c| c.method).collect();
    assert_eq!(
        methods,
        vec![Method::QuoteBatch, Method::Pay, Method::FinalizeBatch],
        "quote → pay → finalize, once each"
    );

    // Barriers, in execution order.
    assert_eq!(
        barriers.crossed(),
        vec![
            Barrier::PostPlanValidation,
            Barrier::PostStagingJournal,
            Barrier::PostQuote,
            Barrier::PostConsent,
            Barrier::PostAnchor,
            Barrier::PostPayPreReceiptJournal,
            Barrier::PostReceiptJournalPreFinalize,
            Barrier::PostFinalizePreComplete,
        ]
    );

    with_journal(|journal| {
        assert_eq!(
            journal.state(&outcome.seal_id).expect("state"),
            SealState::Complete
        );
        assert_eq!(
            journal
                .recorded_identity(&outcome.seal_id)
                .expect("identity")
                .work_id,
            Some(outcome.work_id)
        );
    });
}

/// **S12 accept**: the addresses recorded in the manifest's unit table are
/// the addresses the backend returned — the S4 precomputation and the
/// network agree, with no post-hoc patching of the manifest.
#[test]
fn manifest_unit_addresses_equal_the_finalize_returned_addresses() {
    let files = files();
    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    let outcome = with_journal(|journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        let SealResult::Sealed(outcome) =
            block_on(pipeline.seal(&request(&files, NetworkId::Devnet), &mut seal_rng(2)))
                .expect("seal")
        else {
            panic!("expected Sealed");
        };
        let manifest = journal
            .manifest(&outcome.seal_id)
            .expect("read")
            .expect("journaled");
        let envelope = Manifest::decode(&manifest).expect("decodes");
        let body = ManifestBodyV1::decode(envelope.body_bytes()).expect("body decodes");

        let mut recorded: Vec<[u8; 32]> = Vec::new();
        for file in body.files() {
            for unit in file.units() {
                recorded.push(*unit.address().as_bytes());
            }
        }
        (outcome, recorded)
    });
    let (outcome, recorded) = outcome;

    // The manifest's units, then the encrypted manifest itself — the
    // canonical blob order.
    let returned: Vec<[u8; 32]> = outcome.addresses.iter().map(|a| a.to_bytes()).collect();
    assert_eq!(
        recorded,
        returned[..recorded.len()],
        "every unit address in the manifest is what the network returned"
    );
    assert_eq!(recorded.len() + 1, returned.len(), "plus the manifest blob");
}

/// **S12 accept**: only AEAD ciphertext reaches the backend. Asserted from
/// the outside — no plaintext fragment of any input file appears in any
/// uploaded blob.
#[test]
fn only_ciphertext_ever_reaches_the_backend() {
    let files = files();
    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        block_on(pipeline.seal(&request(&files, NetworkId::Devnet), &mut seal_rng(3)))
            .expect("seal");
    });

    let uploaded = backend.uploaded.borrow();
    let blobs = uploaded.last().expect("one finalize call");
    for needle in [
        &b"alpha beta"[..],
        &b"gamma delta"[..],
        // The manifest's own plaintext markers: the title and app version.
        &b"a work"[..],
        &b"antseal-test/1"[..],
        // Recorded paths must never leave the machine in the clear.
        &b"notes.txt"[..],
        &b"blob.bin"[..],
    ] {
        for blob in blobs {
            assert!(
                !blob.windows(needle.len()).any(|w| w == needle),
                "plaintext {:?} found in an uploaded blob",
                String::from_utf8_lossy(needle)
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Plan validation (S12 accept row 2; D32)
// ─────────────────────────────────────────────────────────────────────

/// **S12 accept / D32**: an over-cap blob fails before any journal write,
/// consent render, anchor submission or backend call — and the text
/// variant names `--split`.
#[test]
fn an_over_cap_text_file_fails_before_every_side_effect_and_names_split() {
    // One paragraph, larger than the chunk cap: no split point exists, so
    // even with `--split` requested it stays one unit.
    let big = vec![b'a'; MAX_CHUNK_SIZE + 4096];
    let files = [SealFile {
        path_as_given: "huge.txt",
        path_absolute: "/w/huge.txt",
        bytes: &big,
        flags: FileFlags::new(),
    }];

    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let barriers = TraceBarriers::new();

    let vault = IsolatedVault::create("over-cap");
    let before = vault.fingerprint();
    vault.with_journal(|journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &barriers);
        match block_on(pipeline.seal(&request(&files, NetworkId::Devnet), &mut seal_rng(4))) {
            Err(SealError::BlobExceedsChunkCap {
                projected_len,
                split_hint,
                ..
            }) => {
                assert!(projected_len > MAX_CHUNK_SIZE as u64);
                assert!(split_hint, "a text unit suggests --split");
            }
            other => panic!("expected the cap error, got {other:?}"),
        }
    });

    assert_eq!(mock.call_log().len(), 0, "no backend call");
    assert_eq!(gate.calls(), 0, "no anchor submission");
    assert_eq!(consent.calls(), 0, "no consent render");
    assert!(
        barriers.crossed().is_empty(),
        "the failure precedes even the post-plan-validation barrier"
    );
    assert_eq!(before, vault.fingerprint(), "no journal write");
}

/// An over-cap **binary** file gets the recorded product limit, not a
/// `--split` suggestion it could not act on.
#[test]
fn an_over_cap_binary_file_is_a_recorded_product_limit() {
    // 0xFF is never valid UTF-8 — NUL bytes would have made this "text".
    let big = vec![0xFFu8; MAX_CHUNK_SIZE + 4096];
    let files = [SealFile {
        path_as_given: "huge.bin",
        path_absolute: "/w/huge.bin",
        bytes: &big,
        flags: FileFlags::new(),
    }];
    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();

    with_journal(|journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        let err = block_on(pipeline.seal(&request(&files, NetworkId::Devnet), &mut seal_rng(5)))
            .expect_err("over cap");
        let rendered = err.to_string();
        assert!(!rendered.contains("--split"));
        assert!(rendered.contains("not supported in v1"));
    });
}

/// The D32 size arithmetic, at the exact boundary: the largest storable
/// unit plaintext is 4 MiB − 257 B, and one byte more is over.
#[test]
fn the_cap_arithmetic_matches_d32_at_the_boundary() {
    let max_plaintext = 4_194_047_u64;
    assert_eq!(projected_ciphertext_len(max_plaintext), 4_194_064);
    assert!(projected_ciphertext_len(max_plaintext) <= MAX_CHUNK_SIZE as u64);
    assert!(projected_ciphertext_len(max_plaintext + 1) > MAX_CHUNK_SIZE as u64);
}

/// An empty file list is refused before anything happens.
#[test]
fn an_empty_work_is_refused() {
    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    with_journal(|journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        assert!(matches!(
            block_on(pipeline.seal(&request(&[], NetworkId::Devnet), &mut seal_rng(6))),
            Err(SealError::EmptyWork)
        ));
    });
    assert_eq!(mock.call_log().len(), 0);
}

// ─────────────────────────────────────────────────────────────────────
// --dry-run (S12 accept row 4; D49)
// ─────────────────────────────────────────────────────────────────────

/// **D49**: a dry-run quotes and stops — exactly one backend call
/// (`quote_batch`), zero anchor submissions, zero payment, zero upload,
/// and a byte-identical vault.
#[test]
fn a_dry_run_quotes_and_stops_with_a_byte_identical_vault() {
    let files = files();
    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let barriers = TraceBarriers::new();

    let vault = IsolatedVault::create("dry-run");
    let before = vault.fingerprint();
    let report = vault.with_journal(|journal| {
        let mut req = request(&files, NetworkId::Devnet);
        req.dry_run = true;
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &barriers);
        match block_on(pipeline.seal(&req, &mut seal_rng(7))).expect("dry run") {
            SealResult::DryRun(report) => report,
            SealResult::Sealed(_) => panic!("a dry run must not seal"),
        }
    });
    let after = vault.fingerprint();

    assert_eq!(before, after, "D49: zero vault mutation");
    let methods: Vec<Method> = mock.call_log().iter().map(|c| c.method).collect();
    assert_eq!(
        methods,
        vec![Method::QuoteBatch],
        "exactly one backend call class"
    );
    assert_eq!(gate.calls(), 0, "no anchor submission");
    assert_eq!(consent.calls(), 0, "no consent prompt");
    assert_eq!(mock.payment_tx_count(), 0);
    assert_eq!(mock.stored_count(), 0);

    // The report is a real quote over the real blob set.
    assert_eq!(report.blob_count, 5);
    assert_eq!(report.quote.blobs.len(), 5);
    assert_eq!(report.units_per_file, vec![3, 1]);
    assert!(report.ciphertext_bytes > 0);

    // And it stopped at exactly the D49 truncation barrier.
    assert_eq!(
        barriers.crossed(),
        vec![
            Barrier::PostPlanValidation,
            Barrier::PostStagingJournal,
            Barrier::PostQuote
        ]
    );
}

/// Plan-validation errors fire identically under `--dry-run` — that is the
/// flag's rehearsal value (D49 Decision 1).
#[test]
fn a_dry_run_fires_every_plan_validation_error_identically() {
    let big = vec![b'a'; MAX_CHUNK_SIZE + 4096];
    let files = [SealFile {
        path_as_given: "huge.txt",
        path_absolute: "/w/huge.txt",
        bytes: &big,
        flags: FileFlags::new(),
    }];
    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    with_journal(|journal| {
        let mut req = request(&files, NetworkId::Devnet);
        req.dry_run = true;
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        assert!(matches!(
            block_on(pipeline.seal(&req, &mut seal_rng(8))),
            Err(SealError::BlobExceedsChunkCap { .. })
        ));
    });
    assert_eq!(mock.call_log().len(), 0);
}

// ─────────────────────────────────────────────────────────────────────
// S13 — the zero-anchor path and its mainnet guard
// ─────────────────────────────────────────────────────────────────────

/// **S13 accept**: `--no-anchor` + `arbitrum-one` returns a distinct error
/// with zero network side effects, **even when the library is driven
/// directly** — the CLI check cannot be bypassed.
#[test]
fn no_anchor_on_mainnet_is_refused_at_the_library_level() {
    let files = files();
    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let barriers = TraceBarriers::new();

    let vault = IsolatedVault::create("mainnet-guard");
    let before = vault.fingerprint();
    vault.with_journal(|journal| {
        let mut req = request(&files, NetworkId::ArbitrumOne);
        req.no_anchor = true;
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &barriers);
        match block_on(pipeline.seal(&req, &mut seal_rng(9))) {
            Err(SealError::NoAnchorOnMainnet) => {}
            other => panic!("expected the mainnet guard, got {other:?}"),
        }
    });

    assert_eq!(mock.call_log().len(), 0, "zero network side effects");
    assert_eq!(gate.calls(), 0);
    assert_eq!(consent.calls(), 0);
    assert!(barriers.crossed().is_empty());
    assert_eq!(before, vault.fingerprint());

    // The guard fires before even the dry-run path, which is otherwise
    // side-effect-free — it is a plan-validation rule, not a payment rule.
    with_journal(|journal| {
        let mut req = request(&files, NetworkId::ArbitrumOne);
        req.no_anchor = true;
        req.dry_run = true;
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        assert!(matches!(
            block_on(pipeline.seal(&req, &mut seal_rng(10))),
            Err(SealError::NoAnchorOnMainnet)
        ));
    });
}

/// The guard is network-specific: the same flags are fine on the two
/// development networks (that is what the flag is *for*).
#[test]
fn no_anchor_is_allowed_on_the_development_networks() {
    for (seed, network) in [(21u8, NetworkId::Devnet), (22, NetworkId::ArbitrumSepolia)] {
        let files = files();
        let mock = MockBackend::new();
        // A refusing gate: if the pipeline called it, the seal would fail.
        let gate = RecordingGate::refusing();
        let consent = ScriptedConsent::always_yes();

        let outcome = with_journal(|journal| {
            let mut req = request(&files, network);
            req.no_anchor = true;
            let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
            block_on(pipeline.seal(&req, &mut seal_rng(seed))).expect("zero-anchor seal completes")
        });
        let SealResult::Sealed(outcome) = outcome else {
            panic!("expected Sealed");
        };

        assert_eq!(
            gate.calls(),
            0,
            "S13: no anchor-submission call occurs in no-anchor mode"
        );
        assert_eq!(mock.stored_count(), 5);
        with_journal(|journal| {
            let identity = journal
                .recorded_identity(&outcome.seal_id)
                .expect("identity");
            assert!(identity.unanchored, "the work records UNANCHORED");
            assert_eq!(identity.network, network.as_str());
        });
    }
}

/// **S12 accept**: an anchor-gate refusal aborts before `pay` — zero EVM
/// transactions, and the work stays pre-pay and resumable.
#[test]
fn an_anchor_gate_refusal_aborts_before_pay_with_no_evm_tx() {
    let files = files();
    let mock = MockBackend::new();
    let backend = RecordingBackend::new(&mock);
    let gate = RecordingGate::refusing();
    let consent = ScriptedConsent::always_yes();

    with_journal(|journal| {
        let pipeline = Pipeline::new(&backend, &gate, journal, &consent, &NoBarriers);
        assert!(matches!(
            block_on(pipeline.seal(&request(&files, NetworkId::Devnet), &mut seal_rng(12))),
            Err(SealError::AnchorGate(_))
        ));
    });

    assert_eq!(gate.calls(), 1);
    assert_eq!(backend.pay_calls(), 0, "pay was never reached");
    assert_eq!(mock.payment_tx_count(), 0, "no EVM tx");
    assert_eq!(mock.stored_count(), 0);
    // The quote happened (it precedes consent), and nothing after pay did.
    let methods: Vec<Method> = mock.call_log().iter().map(|c| c.method).collect();
    assert_eq!(methods, vec![Method::QuoteBatch]);
}

/// Consent is asked **before** the anchor gate: nothing is submitted on a
/// user's behalf before they agree (MVP-SPEC.md line 34).
#[test]
fn consent_precedes_the_anchor_gate() {
    let files = files();
    let mock = MockBackend::new();
    let gate = RecordingGate::refusing();
    let consent = ScriptedConsent::always_declines();

    with_journal(|journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        assert!(matches!(
            block_on(pipeline.seal(&request(&files, NetworkId::Devnet), &mut seal_rng(13))),
            Err(SealError::ConsentDeclined(_))
        ));
    });

    assert_eq!(consent.calls(), 1);
    assert_eq!(
        gate.calls(),
        0,
        "a declined seal submits nothing to any anchor endpoint"
    );
    assert_eq!(mock.payment_tx_count(), 0);
}

/// A killed seal leaves the journal exactly where the barrier says, and the
/// staged bytes are durable — the handover point to S11's resume.
///
/// **A vault of its own, because the shared one made this test race its
/// neighbours** (wave 35: hosted `ci` run `34783405059` failed here with
/// `planned` on a documentation-only commit). The work under test is found by
/// enumerating incomplete works and taking the `Staged` one; in the binary's
/// shared vault a sibling test's seal can be `Staged` at that instant with its
/// plan not yet readable, so the enumeration could pick the wrong work. In an
/// isolated vault there is exactly one incomplete work, and the test says so.
#[test]
fn a_kill_after_staging_leaves_a_resumable_work() {
    let files = files();
    let mock = MockBackend::new();
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let kill = common::KillAt::new(Barrier::PostStagingJournal);
    let vault = IsolatedVault::create("kill-after-staging");

    vault.with_journal(|journal| {
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &kill);
        assert!(matches!(
            block_on(pipeline.seal(&request(&files, NetworkId::Devnet), &mut seal_rng(14))),
            Err(SealError::KilledAtBarrier(Barrier::PostStagingJournal))
        ));
    });

    assert_eq!(mock.call_log().len(), 0, "no backend call before the kill");
    vault.with_journal(|journal| {
        let incomplete = journal.incomplete_works().expect("enumerate");
        assert_eq!(
            incomplete.len(),
            1,
            "an isolated vault holds exactly the one killed work, so the resume \
             candidate below cannot be a neighbour's: {incomplete:?}"
        );
        let (seal_id, state) = incomplete
            .iter()
            .copied()
            .find(|(_, state)| *state == Some(SealState::Staged))
            .expect("the killed work is a resume candidate");
        assert_eq!(state, Some(SealState::Staged));
        let plan = journal.plan(&seal_id).expect("read").expect("planned");
        assert_eq!(plan.unit_count, 4);
        assert!(plan.manifest_bytes.is_some());
        antseal_cli::pipeline::verify_all_staged(journal, &seal_id)
            .expect("every staged blob is durable and intact");
    });
}

/// **S13 accept, mock half**: a zero-anchor seal is representable as
/// UNANCHORED — the empty anchor set aggregates to zero headline-eligible
/// anchors, which is the verdict the M1 E2E asserts on a devnet-sealed
/// work (S17 does the devnet half; this pins the shape a `--no-anchor`
/// seal actually produces).
#[test]
fn a_zero_anchor_seal_is_representable_as_unanchored() {
    use antseal_core::verify::aggregate::aggregate_anchors;

    let files = files();
    let mock = MockBackend::new();
    let gate = RecordingGate::refusing();
    let consent = ScriptedConsent::always_yes();

    let outcome = with_journal(|journal| {
        let mut req = request(&files, NetworkId::Devnet);
        req.no_anchor = true;
        let pipeline = Pipeline::new(&mock, &gate, journal, &consent, &NoBarriers);
        let SealResult::Sealed(outcome) =
            block_on(pipeline.seal(&req, &mut seal_rng(31))).expect("zero-anchor seal")
        else {
            panic!("expected Sealed");
        };
        outcome
    });

    // The work carries no anchors at all — nothing was submitted, so
    // nothing was persisted to anchor a verifier could evaluate.
    let aggregate = aggregate_anchors(&[]);
    assert!(aggregate.is_unanchored(), "zero headline-eligible anchors");
    assert_eq!(aggregate.total_anchors(), 0);
    assert_eq!(aggregate.headline_time_unix(), None);

    with_journal(|journal| {
        assert!(
            journal
                .recorded_identity(&outcome.seal_id)
                .expect("identity")
                .unanchored
        );
        // The manifest itself is complete and decodable — an UNANCHORED
        // seal is a normal seal with an empty anchor set, not a degraded
        // artifact.
        let manifest = journal
            .manifest(&outcome.seal_id)
            .expect("read")
            .expect("journaled");
        let envelope = Manifest::decode(&manifest).expect("decodes");
        let body = ManifestBodyV1::decode(envelope.body_bytes()).expect("body decodes");
        assert_eq!(body.files().len(), 2);
        assert_eq!(body.units_total(), 4);
    });
}
