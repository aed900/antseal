//! **R79 — the storage boundary is not a byte channel into a display line.**
//!
//! The online layer closes this channel at its source (`antseal-anchor`'s
//! `EndpointFailure` carries a `&'static str` and two `u64`s; core's
//! `ProbeFailureClass` is a closed three-value class). Until R79 the storage
//! layer did the opposite: `StorageError::Network { reason }` travelled four
//! hops — `PersistenceOutcome::FetchError` → `LiveBlobOutcome::FetchFailed` →
//! `wording::live_blob_fetch_error_line` → the rendered row — with no
//! taxonomy, no cap and no classification key.
//!
//! R79's ruling is arm (a): **the closed class wins, and it is closed at the
//! source.** This file is the test that keeps it closed. It drives a
//! [`StorageBackend`] whose error `Display` is deliberately hostile — an LF,
//! a frozen verdict sentence, and a long run of bytes — through the real
//! [`live_check`], the real bridge and the real renderer, and asserts that
//! **none of it arrives**.
//!
//! # Why the backend is written here rather than reusing `MockBackend`
//!
//! `StorageBackend` is a **public trait**, so its implementations are not a
//! closed set and never will be: the bound has to hold at the boundary, not
//! at one adapter's good behaviour. A hostile implementor is the honest
//! adversary model, and writing one is four lines per method.
//!
//! # Why the assertion runs all the way to `LiveSection`
//!
//! Asserting on `PersistenceOutcome` alone would prove only that this crate
//! stopped storing the string — not that no later hop puts it back. The
//! rendered row is the thing a user reads, so it is the thing the test reads.

use antseal_core::anchor::model::OnlineEvidence;
use antseal_core::test_util::bundle_fixtures::{Selection, build, shapes};
use antseal_core::verify::orchestration::{
    LiveBlobOutcome, LiveInputs, OnlineInputs, VerifyHost, VerifyModes, verify_with_host,
};
use antseal_core::verify::overlay::{ProbeEndpoints, ProbeLog};
use antseal_core::verify::{VerifyOptions, wording};
use antseal_net::test_util::block_on;
use antseal_net::{
    Address, BalanceReport, Blob, CostQuote, FetchFailureClass, LiveSubject, PaymentReceipt,
    PersistenceOutcome, StorageBackend, StorageError, StorageRecord, UnitKindTag,
    fetch_failure_class, live_check, live_inputs,
};

// ─────────────────────────────────────────────────────────────────────
// the hostile backend
// ─────────────────────────────────────────────────────────────────────

/// A long run of bytes — over any plausible display width, so a row that
/// carried it would be unmistakable.
const LONG_RUN: usize = 4096;

/// The `reason` a hostile storage boundary would choose, carrying all three
/// hazards R79's Accept names at once.
///
/// The middle line is `UNANCHORED_BANNER` verbatim: a *frozen verdict
/// sentence*. If a rendered row ever carried it, a reader scrolling the live
/// section would see antseal's own strongest negative verdict apparently
/// stated by antseal, sourced from a stranger's error message.
fn hostile_reason() -> String {
    format!(
        "connection reset\n{}\n{}",
        wording::UNANCHORED_BANNER,
        "A".repeat(LONG_RUN)
    )
}

/// Every operation fails, and every failure carries [`hostile_reason`].
struct HostileBackend;

impl HostileBackend {
    fn refuse() -> StorageError {
        StorageError::Network {
            reason: hostile_reason(),
        }
    }
}

impl StorageBackend for HostileBackend {
    async fn quote_batch(&self, _blobs: &[Blob]) -> Result<CostQuote, StorageError> {
        Err(Self::refuse())
    }

    async fn pay(&self, _quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
        Err(Self::refuse())
    }

    async fn finalize_batch(
        &self,
        _receipt: &PaymentReceipt,
        _blobs: &[Blob],
    ) -> Result<Vec<Address>, StorageError> {
        Err(Self::refuse())
    }

    async fn get_data(&self, _address: Address) -> Result<Vec<u8>, StorageError> {
        Err(Self::refuse())
    }

    async fn balances(&self) -> Result<BalanceReport, StorageError> {
        Err(Self::refuse())
    }
}

/// A backend that refuses reads with a **store-path** error — the class no
/// read should ever produce, and the second arm of the wildcard-free mapping.
struct MisbehavingBackend;

impl StorageBackend for MisbehavingBackend {
    async fn quote_batch(&self, _blobs: &[Blob]) -> Result<CostQuote, StorageError> {
        Err(StorageError::ProofsExpired)
    }

    async fn pay(&self, _quote: &CostQuote) -> Result<PaymentReceipt, StorageError> {
        Err(StorageError::ProofsExpired)
    }

    async fn finalize_batch(
        &self,
        _receipt: &PaymentReceipt,
        _blobs: &[Blob],
    ) -> Result<Vec<Address>, StorageError> {
        Err(StorageError::ProofsExpired)
    }

    async fn get_data(&self, _address: Address) -> Result<Vec<u8>, StorageError> {
        Err(StorageError::StrandedPayment {
            landed_tx_count: 2,
            reason: hostile_reason(),
        })
    }

    async fn balances(&self) -> Result<BalanceReport, StorageError> {
        Err(StorageError::ProofsExpired)
    }
}

// ─────────────────────────────────────────────────────────────────────
// the harness — the real bridge, the real renderer
// ─────────────────────────────────────────────────────────────────────

/// A host that reports exactly the live rows it was given.
struct LiveOnlyHost(LiveInputs);

impl VerifyHost for LiveOnlyHost {
    fn online_inputs(&self) -> OnlineInputs {
        OnlineInputs::new(
            OnlineEvidence::new(),
            ProbeLog::new(ProbeEndpoints::new(Vec::new(), false)),
        )
    }

    fn live_inputs(&self) -> LiveInputs {
        self.0.clone()
    }
}

/// Drive one record through `live_check` over `backend`, then through the
/// production bridge and R21's renderer, and return the rendered rows.
fn rendered_rows<B: StorageBackend>(backend: &B) -> Vec<(String, LiveBlobOutcome, String)> {
    let ciphertext = vec![0xC7u8; 272];
    let records = [StorageRecord::new(
        LiveSubject::Unit {
            unit_id: 7,
            kind: UnitKindTag::Normal,
        },
        Address::from_bytes([0x11; 32]),
        &ciphertext,
    )];
    let report = block_on(live_check(backend, &records)).expect("one record is not empty");

    let bytes = build(&shapes::multi_file(), &Selection::all(3)).bytes;
    let host = LiveOnlyHost(live_inputs(&report));
    let outcome = verify_with_host(
        &bytes,
        &VerifyOptions::new(),
        VerifyModes::new().with_live(),
        &host,
        // Identity: this test is about what reaches the renderer, never about
        // what the renderer then neutralises. An escaping closure could hide
        // the very bytes under test behind a `\n`.
        &|value: &str| value.to_owned(),
    )
    .expect("the R6 fixture verifies");

    outcome
        .live()
        .expect("--live was requested, so a section renders")
        .rows
        .iter()
        .map(|row| (row.subject.clone(), row.outcome.clone(), row.line.clone()))
        .collect()
}

/// Every fragment of the hostile string that must not survive the crossing.
fn forbidden_fragments() -> Vec<(&'static str, String)> {
    vec![
        ("the LF", "\n".to_owned()),
        (
            "the frozen verdict sentence",
            wording::UNANCHORED_BANNER.to_owned(),
        ),
        ("the long byte run", "A".repeat(LONG_RUN)),
        ("the leading clause", "connection reset".to_owned()),
    ]
}

// ─────────────────────────────────────────────────────────────────────
// the rows
// ─────────────────────────────────────────────────────────────────────

/// **R79's Accept row 2, arm (a) form: none of it reaches the line.**
#[test]
fn a_hostile_backend_error_reaches_no_part_of_the_rendered_live_row() {
    // The premise is load-bearing: if the fixture string were empty or short,
    // every assertion below would pass for the wrong reason.
    let hostile = hostile_reason();
    assert!(hostile.contains('\n'), "the fixture carries an LF");
    assert!(
        hostile.contains(wording::UNANCHORED_BANNER),
        "the fixture carries a frozen verdict sentence"
    );
    assert!(
        hostile.len() > LONG_RUN,
        "the fixture carries a long byte run: {} B",
        hostile.len()
    );

    let rows = rendered_rows(&HostileBackend);
    assert_eq!(rows.len(), 1, "one record, one row");
    let (subject, outcome, line) = &rows[0];

    assert_eq!(subject, "unit 7");
    assert_eq!(
        outcome,
        &LiveBlobOutcome::FetchFailed {
            class: FetchFailureClass::Transport,
        },
        "the outcome carries the class itself and nothing else (R89: there is \
         no longer a slot a label — or anything else — could be written into)"
    );

    for (what, fragment) in forbidden_fragments() {
        assert!(
            !line.contains(&fragment),
            "{what} reached the rendered live row: {line:?}"
        );
    }

    // Still exactly one line, and exactly the line the wording table spells
    // for this class — which is the positive half: proving nothing arrived is
    // not the same as proving the row still says something true.
    assert_eq!(line.lines().count(), 1, "one row is one line: {line:?}");
    assert_eq!(
        line,
        &wording::live_blob_fetch_error_line(
            "unit 7",
            wording::live_fetch_failure_class_label(FetchFailureClass::Transport)
        )
    );
}

/// The store-path arm of the wildcard-free mapping renders its own class, and
/// leaks nothing either — a second `StorageError` variant, a second reason
/// string, one closed vocabulary.
#[test]
fn a_store_path_error_on_a_read_renders_its_own_class_and_leaks_nothing() {
    let rows = rendered_rows(&MisbehavingBackend);
    let (_, outcome, line) = &rows[0];

    assert_eq!(
        outcome,
        &LiveBlobOutcome::FetchFailed {
            class: FetchFailureClass::BackendRefused,
        }
    );
    assert_ne!(
        wording::live_fetch_failure_class_label(FetchFailureClass::BackendRefused),
        wording::live_fetch_failure_class_label(FetchFailureClass::Transport),
        "the two classes are distinguishable in the rendering, not only in the type"
    );
    for (what, fragment) in forbidden_fragments() {
        assert!(
            !line.contains(&fragment),
            "{what} reached the row: {line:?}"
        );
    }
    assert_eq!(line.lines().count(), 1);
}

/// **The type-level half.** The rendered row is one hop's worth of evidence;
/// this is the reason no later hop can reintroduce the channel: the value
/// `antseal-net` produces has no free-form slot at all, and the whole class
/// set is a closed list of `&'static str`.
#[test]
fn the_fetch_failure_vocabulary_is_finite_and_static() {
    // A sweep that cannot fail is this project's dominant defect class, so
    // the operand's size is asserted before it is swept.
    assert_eq!(
        FetchFailureClass::ALL.len(),
        2,
        "the sweep below is vacuous if ALL shrinks; grow or shrink it deliberately"
    );

    let mut labels: Vec<&'static str> = Vec::new();
    let mut tokens: Vec<&'static str> = Vec::new();
    for class in FetchFailureClass::ALL {
        let label = wording::live_fetch_failure_class_label(class);
        assert!(!label.is_empty(), "{class:?} renders as nothing");
        assert!(
            !label.contains('\n'),
            "{class:?}'s label is not one line: {label:?}"
        );
        labels.push(label);
        tokens.push(class.token());
    }
    labels.sort_unstable();
    labels.dedup();
    tokens.sort_unstable();
    tokens.dedup();
    assert_eq!(labels.len(), FetchFailureClass::ALL.len(), "labels collide");
    assert_eq!(tokens.len(), FetchFailureClass::ALL.len(), "tokens collide");
}

/// The classifier is total over `StorageError` **and** keeps the
/// answer-vs-failure split: only `NotFound` is an answer.
///
/// The list below is written out rather than derived, so a new variant makes
/// this test's count wrong at the same moment it makes
/// `fetch_failure_class` fail to compile.
#[test]
fn only_a_negative_answer_classifies_as_no_failure() {
    let all = [
        StorageError::Quote { reason: "r".into() },
        StorageError::Payment { reason: "r".into() },
        StorageError::InsufficientAnt {
            required_atto: 1,
            available_atto: 0,
        },
        StorageError::InsufficientGas {
            required_wei: 1,
            available_wei: 0,
        },
        StorageError::Finalize { reason: "r".into() },
        StorageError::StrandedPayment {
            landed_tx_count: 1,
            reason: "r".into(),
        },
        StorageError::ProofsExpired,
        StorageError::NotFound {
            address: Address::from_bytes([0xAA; 32]),
        },
        StorageError::Network { reason: "r".into() },
    ];
    assert_eq!(all.len(), 9, "the S2 taxonomy's full variant list");

    let answers: Vec<&StorageError> = all
        .iter()
        .filter(|error| fetch_failure_class(error).is_none())
        .collect();
    assert_eq!(answers.len(), 1, "exactly one variant is an answer");
    assert!(matches!(answers[0], StorageError::NotFound { .. }));

    assert_eq!(
        fetch_failure_class(&StorageError::Network { reason: "r".into() }),
        Some(FetchFailureClass::Transport)
    );
    assert_eq!(
        fetch_failure_class(&StorageError::ProofsExpired),
        Some(FetchFailureClass::BackendRefused)
    );
}

/// The report is structured data for `--json`, and R79 must not have turned
/// the class into a new place for bytes to hide: the serialized outcome
/// carries a token, and the hostile string is nowhere in it.
#[test]
fn the_serialized_outcome_carries_a_token_and_not_the_backend_string() {
    let ciphertext = vec![0xC7u8; 272];
    let records = [StorageRecord::new(
        LiveSubject::EncryptedManifest,
        Address::from_bytes([0x22; 32]),
        &ciphertext,
    )];
    let report = block_on(live_check(&HostileBackend, &records)).expect("one record");

    assert_eq!(
        report.rows[0].persistence.outcome,
        PersistenceOutcome::FetchError {
            class: FetchFailureClass::Transport,
        }
    );

    let json = serde_json::to_string(&report).expect("the report serializes");
    assert!(
        json.contains("Transport"),
        "the machine-readable class is present: {json}"
    );
    for (what, fragment) in forbidden_fragments() {
        assert!(
            !json.contains(&fragment),
            "{what} reached the serialized report"
        );
    }
}
