//! S15 — the `--live` persistence primitive: re-fetch and byte-compare.
//!
//! [`check_persistence`] takes `[(Address, expected_ciphertext_bytes)]`,
//! re-fetches each address through [`StorageBackend::get_data`], compares
//! the returned bytes against the caller's copy, and returns a structured
//! per-blob [`PersistenceReport`].
//!
//! # What this proves, and what it does not
//!
//! A `--live` check answers exactly one question: *are the bytes this
//! evidence refers to still retrievable from the network, unchanged?* It
//! is **advisory**. Under project rule 4 a `.sealproof` bundle verifies
//! fully offline; evidence validity never depends on Autonomi
//! availability, so a `not-found` or `fetch-error` row here is a
//! statement about the network at this moment, never about the proof.
//! R's verdict layer renders it as its own storage-linkage section and
//! must not let it overwrite the offline verdict (R20/R21).
//!
//! # Design rules (normative for this module)
//!
//! - **Trait-only.** The primitive rides [`StorageBackend`] and nothing
//!   else, so it compiles and tests on `MockBackend` in the default
//!   feature set and runs unchanged against `AntCoreBackend` on a devnet
//!   (S15 accept row 3). It is CLI-side by design — the WASM verifier
//!   page has no network layer.
//! - **No whole-call failure.** Every per-blob failure is *data*
//!   ([`PersistenceOutcome::NotFound`], [`PersistenceOutcome::FetchError`]),
//!   never an early return: a report about ten blobs must not be lost
//!   because the third one timed out.
//! - **One fetch per distinct address.** Duplicated addresses (the same
//!   ciphertext referenced twice) are fetched once and compared against
//!   every expectation naming them; distinct addresses are visited in
//!   first-appearance order, so the call sequence is deterministic and
//!   assertable.
//! - **Lengths, offsets and closed classes only.** Report values are
//!   counts, lengths, byte offsets and [`FetchFailureClass`] — never blob
//!   bytes, never key material (project rule 6), and **never free-form
//!   text from the storage boundary** (R79: a report row reaches a
//!   display line, and an adversary must not choose its bytes any more
//!   than one may at the online boundary). The compared values are AEAD
//!   ciphertext the caller already holds and the network already serves,
//!   so the comparison is a plain `==`: nothing secret is being tested,
//!   and constant-time comparison would buy nothing here (contrast the
//!   tag/commitment checks in `antseal-core`).
//!
//! # Consumers
//!
//! R11 wraps this manifest-shaped for M1 and bundle-shaped at M3
//! (R11/R21); the M1 devnet E2E calls it directly through library APIs.
//! Implemented **once, here** — R11 does not fetch again.

// R11 — the verify-side wrapper over this primitive: labelled,
// manifest-shaped, verdict-summarized. It builds this module's input
// list and interprets its output; it never fetches (S15 note:
// "implement once here, consume there").
pub mod manifest;

use std::collections::BTreeMap;

use crate::{Address, StorageBackend, StorageError};

/// Why a live fetch could not be completed — a **closed** class over the
/// [`StorageError`] variants a read can produce.
///
/// # R79's ruling: one discipline governs both network boundaries
///
/// antseal has two boundaries at which a remote party's failure becomes a
/// line a user reads, and until this row they followed opposite rules for the
/// same hazard.
///
/// - The **online** boundary closes the channel: `antseal-anchor`'s
///   `EndpointFailure` carries a `&'static str` reason and two `u64`s and
///   nothing else (*"no adversary-controlled bytes can reach a log line
///   through it"*, `agree.rs`), and it narrows again to core's closed
///   [`ProbeFailureClass`], whose doc states the rule in the strongest
///   available form.
/// - The **storage** boundary did the opposite: [`StorageError::Network`]'s
///   free-form `reason` travelled four hops to a display line with no
///   taxonomy, no cap and no classification key.
///
/// **The ruling is R79 arm (a): the closed class wins, and it is closed
/// here, at the source.** Three measurements decide it:
///
/// 1. **The provenance is the reverse of what it looks like.** On the online
///    side the only free-form text that reaches a line is
///    `EndpointProbeFailure::endpoint` — *the verifier's own configured URL*.
///    On the storage side, `AntCoreBackend::get_data` maps upstream through
///    `map_ant_error`, whose **final arm is a wildcard**: `other =>
///    StorageError::Network { reason: format!("{other}") }`. That renders the
///    whole of `ant_core::data::Error`, several of whose variants carry
///    remote-supplied `String`s (`Protocol`, `InvalidData`, `Network`,
///    `RemotePut { source: ProtocolError }`). So the channel the online layer
///    refuses is the one the storage layer had, and R79's arm (c) — *"the
///    storage boundary is the verifier's own client"* — is refuted by
///    measurement rather than merely unchosen.
/// 2. **[`StorageBackend`] is a public trait.** Any implementation, present
///    or future, chooses these bytes. A bound that depends on one adapter's
///    good behaviour is not a bound.
/// 3. **Escaping answers the wrong question.** D67 §3 R6's value-vs-rendering
///    split answers *"can this forge a row"*; it never answers *"should this
///    channel exist"*, which is what the online layer already answered `no`
///    to, in the same tree, for the same reason. Arm (b) would have kept two
///    rules for one hazard with one of them merely softened.
///
/// # What this ruling costs, stated rather than hidden
///
/// One bit of information is lost, and it is worth naming: today
/// `AntCoreBackend::get_data` reports its own BLAKE3 re-check failure
/// (*"network returned bytes whose … address does not match … — integrity
/// failure"*) through the same [`StorageError::Network`] variant as a plain
/// timeout, so the two are indistinguishable **by variant** and this class
/// cannot separate them. That distinction existed only inside the free-form
/// string; recovering it needs a [`StorageError`] variant of its own, which
/// is an S2-taxonomy event and not this row's. Recorded here so the next
/// reader does not mistake the loss for an oversight — and note that for a
/// live row the two mean the same thing: no usable answer arrived.
///
/// # The other half of the ruling, and what is still owed
///
/// The remaining widening is a **type-precision** debt, not an open channel:
/// core's `LiveBlobOutcome::FetchFailed` still holds a `String`, which after
/// this change can only ever hold [`Self::label`]'s output. Tightening it to
/// carry this class — and moving the label into `verify::wording` beside
/// [`ProbeFailureClass`]'s — belongs in `antseal-core` and is named on
/// R79's row.
///
/// [`ProbeFailureClass`]: antseal_core::verify::overlay::ProbeFailureClass
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FetchFailureClass {
    /// No usable answer arrived from the network: transport failure, timeout,
    /// unreachable peers, or an answer this client refused
    /// ([`StorageError::Network`]).
    Transport,
    /// The backend refused the read for a reason that is not about reaching
    /// the network at all — a quote, payment or store-path failure surfacing
    /// from an operation that neither quotes, pays nor stores. It is a
    /// statement about the backend, never about the address.
    BackendRefused,
}

impl FetchFailureClass {
    /// Every class, in declaration order — the sweep operand for the label
    /// test ([`ProbeFailureClass::ALL`]'s pattern).
    ///
    /// [`ProbeFailureClass::ALL`]:
    ///     antseal_core::verify::overlay::ProbeFailureClass::ALL
    pub const ALL: [Self; 2] = [Self::Transport, Self::BackendRefused];

    /// Classify one storage-boundary failure, **while the variant is still in
    /// hand** — never by re-parsing a rendered string.
    ///
    /// `None` means the error is a negative *answer* rather than a failure to
    /// get one ([`StorageError::NotFound`]): the network said "no such
    /// chunk", which is evidence-relevant and gets
    /// [`PersistenceOutcome::NotFound`], not a failure class. Returning the
    /// split from one function is deliberate — it is the only match over
    /// [`StorageError`] on this path, so the two outcomes cannot drift apart
    /// and a new variant forces one decision rather than two.
    ///
    /// **Wildcard-free** (the discipline R11 applied to
    /// [`UnitKindTag`](crate::UnitKindTag)): a new [`StorageError`] variant
    /// fails to compile here rather than falling into a catch-all — which is
    /// exactly how the free-form channel this class replaces was opened, one
    /// layer up, by `map_ant_error`'s `other =>` arm.
    #[must_use]
    pub const fn of(error: &StorageError) -> Option<Self> {
        match error {
            // An answer, not a failure to get one.
            StorageError::NotFound { .. } => None,
            StorageError::Network { .. } => Some(Self::Transport),
            StorageError::Quote { .. }
            | StorageError::Payment { .. }
            | StorageError::InsufficientAnt { .. }
            | StorageError::InsufficientGas { .. }
            | StorageError::Finalize { .. }
            | StorageError::StrandedPayment { .. }
            | StorageError::ProofsExpired => Some(Self::BackendRefused),
        }
    }

    /// The display word for this class — the **one** place a live fetch
    /// failure is spelled, wildcard-free so a third class cannot land
    /// unnamed.
    ///
    /// It lives here rather than in `antseal-core`'s `verify::wording`
    /// because the class is this crate's own taxonomy over this crate's own
    /// error type, exactly as
    /// [`probe_failure_class_label`] is core's over core's; the courier
    /// between them (`verify_host.rs`'s `blob_outcome`) authors nothing. The
    /// end state named on R79's row moves both the class and this function
    /// into core beside `LiveBlobOutcome`; until then this is the single
    /// spelling and the label is a `&'static str` so no other value can
    /// occupy the slot.
    ///
    /// `Transport`'s word is `probe_failure_class_label`'s for the same
    /// class, and the R18-frozen row already renders it
    /// (`tests/snapshots/verdict-wording.txt`, via
    /// `live_blob_fetch_error_line("unit 7", "transport failure")`), so this
    /// ruling moves no frozen byte.
    ///
    /// [`probe_failure_class_label`]:
    ///     antseal_core::verify::wording::probe_failure_class_label
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Transport => "transport failure",
            Self::BackendRefused => "the backend refused the read",
        }
    }

    /// This class's stable machine token — wildcard-free (the L2 discipline).
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::BackendRefused => "backend-refused",
        }
    }
}

/// How one expected blob fared against the network.
///
/// The four outcomes S15 names: present-and-identical, present-but-
/// different, not-found, fetch-error. `NotFound` is deliberately **not**
/// folded into `FetchError`: the network answering "no such chunk" is an
/// evidence-relevant fact, while a transport failure is a statement about
/// the caller's connectivity ([`StorageError::NotFound`] vs
/// [`StorageError::Network`] draw the same line at the trait boundary).
///
/// Serialized externally tagged (serde default, matching the house
/// convention recorded on the receipt envelope).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PersistenceOutcome {
    /// The network returned exactly the expected bytes.
    Identical,
    /// The network returned bytes, and they differ from the expectation.
    ///
    /// Under the content-addressing rule (D32: address = BLAKE3-256 of
    /// the ciphertext) this should be unreachable for an honest network
    /// — reaching it means either the caller's expectation does not
    /// belong to this address, or the responder is not honouring content
    /// addressing. Both are worth surfacing loudly, which is why this is
    /// its own outcome rather than a flavour of "not found".
    Different {
        /// Length of what the network returned.
        fetched_len: u64,
        /// Offset of the first differing byte; when one side is a strict
        /// prefix of the other, the length of that common prefix. Always
        /// well defined, since this outcome means the byte strings are
        /// unequal.
        first_diff_offset: u64,
    },
    /// The network answered, negatively: nothing is stored at this
    /// address.
    NotFound,
    /// The fetch could not be completed (transport class, or any other
    /// backend failure that is not a negative answer).
    ///
    /// **Carries a closed class, never free-form detail — R79's ruling, and
    /// the whole of it is argued on [`FetchFailureClass`].** The taxonomy is
    /// the contract: this is what a caller matches on, this is what renders,
    /// and no byte chosen by the far end of the connection can occupy the
    /// slot. It is the same discipline core's
    /// [`ProbeFailureClass`](antseal_core::verify::overlay::ProbeFailureClass)
    /// states for the online boundary — **read the two together; neither doc
    /// is complete without the other, and that is why each names the other.**
    ///
    /// Until R79 the field was a `String` holding whatever the backend
    /// adapter's error `Display` produced, which on the ant-core path is
    /// `format!("{other}")` over a wildcard arm. The hostile-string test
    /// `crates/antseal-net/tests/live_display_channel.rs` is what keeps this
    /// closed: it drives a backend whose error `Display` carries an LF, a
    /// frozen verdict sentence and a long byte run all the way to the
    /// rendered line, and asserts none of it arrives.
    FetchError {
        /// Which class of failure — the classification key *and* the only
        /// thing that renders.
        class: FetchFailureClass,
    },
}

impl PersistenceOutcome {
    /// Whether this outcome is the only one that confirms persistence.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        matches!(self, Self::Identical)
    }
}

/// One row of a [`PersistenceReport`]: an expectation and its verdict.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlobPersistence {
    /// The address that was re-fetched.
    pub address: Address,
    /// Length of the caller's expected ciphertext, in bytes.
    pub expected_len: u64,
    /// What the network said.
    pub outcome: PersistenceOutcome,
}

/// Aggregate counts over a [`PersistenceReport`] — the shape a verdict
/// line or a `--json` envelope summarizes from.
///
/// The four counts partition `total` exactly (asserted in tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct PersistenceSummary {
    /// Rows checked.
    pub total: u64,
    /// Rows whose bytes came back identical.
    pub identical: u64,
    /// Rows whose bytes came back different.
    pub different: u64,
    /// Rows the network had nothing for.
    pub not_found: u64,
    /// Rows whose fetch failed.
    pub fetch_error: u64,
}

/// The result of a `--live` persistence check: one row per expectation,
/// **in the order the expectations were supplied**.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistenceReport {
    /// Per-blob rows, positionally aligned with the input slice.
    pub blobs: Vec<BlobPersistence>,
    /// Distinct addresses actually fetched — one `get_data` call each.
    /// Lets a caller (or a test) reason about network cost without
    /// re-deriving it from `blobs`.
    pub fetches: u64,
}

impl PersistenceReport {
    /// Count the rows by outcome.
    #[must_use]
    pub fn summary(&self) -> PersistenceSummary {
        let mut summary = PersistenceSummary {
            total: self.blobs.len() as u64,
            ..PersistenceSummary::default()
        };
        for blob in &self.blobs {
            match blob.outcome {
                PersistenceOutcome::Identical => summary.identical += 1,
                PersistenceOutcome::Different { .. } => summary.different += 1,
                PersistenceOutcome::NotFound => summary.not_found += 1,
                PersistenceOutcome::FetchError { .. } => summary.fetch_error += 1,
            }
        }
        summary
    }

    /// Whether **every** row came back identical.
    ///
    /// Vacuously true for an empty check — the caller decides whether an
    /// empty expectation set is meaningful (R11 rejects it).
    #[must_use]
    pub fn all_identical(&self) -> bool {
        self.blobs.iter().all(|blob| blob.outcome.is_identical())
    }
}

/// Re-fetch every expected blob and byte-compare it (S15).
///
/// Never fails as a whole: per-blob failures are rows. An empty input
/// yields an empty report and performs **zero** network calls.
///
/// Duplicated addresses cost one fetch, shared by every row naming them
/// (so two rows with the same address but different expectations can
/// legitimately disagree — that is a caller bug the report will show
/// rather than hide).
pub async fn check_persistence<B: StorageBackend>(
    backend: &B,
    expected: &[(Address, &[u8])],
) -> PersistenceReport {
    // Group rows by address, preserving first-appearance order, so the
    // fetch sequence is deterministic and each distinct address costs
    // exactly one `get_data`.
    let mut groups: Vec<(Address, Vec<usize>)> = Vec::new();
    let mut seen: BTreeMap<Address, usize> = BTreeMap::new();
    for (row, (address, _)) in expected.iter().enumerate() {
        match seen.get(address) {
            Some(&group) => groups[group].1.push(row),
            None => {
                seen.insert(*address, groups.len());
                groups.push((*address, vec![row]));
            }
        }
    }

    let mut outcomes: Vec<Option<PersistenceOutcome>> = vec![None; expected.len()];
    for (address, rows) in &groups {
        // One fetch, then compare it against every expectation naming
        // this address. The fetched copy is dropped before the next
        // address is visited, so peak memory stays at one chunk.
        let fetched = backend.get_data(*address).await;
        for &row in rows {
            let outcome = match &fetched {
                Ok(bytes) => compare(bytes, expected[row].1),
                // R79: classified from the VARIANT, while it is still in
                // hand. `FetchFailureClass::of` owns both halves of the
                // answer-vs-failure split, so there is one wildcard-free
                // match over `StorageError` on this path and the error's
                // `Display` is never consulted at all.
                Err(error) => match FetchFailureClass::of(error) {
                    None => PersistenceOutcome::NotFound,
                    Some(class) => PersistenceOutcome::FetchError { class },
                },
            };
            outcomes[row] = Some(outcome);
        }
    }

    let blobs = expected
        .iter()
        .zip(outcomes)
        .map(|(&(address, bytes), outcome)| BlobPersistence {
            address,
            expected_len: bytes.len() as u64,
            // Every row belongs to exactly one group and every group was
            // visited, so this is total by construction; the fallback
            // keeps the primitive panic-free regardless (project rule:
            // library code does not unwrap). Under R79 the fallback can no
            // longer smuggle a bespoke sentence into a display line either —
            // there is no free-form slot to put one in, so an unreachable
            // internal state renders as the ordinary "nothing was
            // established" row rather than as prose no wording table owns.
            outcome: outcome.unwrap_or(PersistenceOutcome::FetchError {
                class: FetchFailureClass::Transport,
            }),
        })
        .collect();

    PersistenceReport {
        blobs,
        fetches: groups.len() as u64,
    }
}

/// Byte-compare a fetched blob against its expectation.
fn compare(fetched: &[u8], expected: &[u8]) -> PersistenceOutcome {
    if fetched == expected {
        return PersistenceOutcome::Identical;
    }
    let first_diff_offset = fetched
        .iter()
        .zip(expected)
        .position(|(a, b)| a != b)
        // Unequal with no differing byte in the common prefix ⇒ one side
        // is a strict prefix of the other; the divergence is where the
        // shorter one ends.
        .unwrap_or_else(|| fetched.len().min(expected.len()));
    PersistenceOutcome::Different {
        fetched_len: fetched.len() as u64,
        first_diff_offset: first_diff_offset as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{Fault, Method, MockBackend, block_on};
    use crate::{Blob, StorageBackend};

    /// Store `payloads` through the full quote→pay→finalize path and
    /// return their addresses (the shape a real seal leaves behind).
    fn seal(mock: &MockBackend, payloads: &[&[u8]]) -> Vec<Address> {
        let blobs: Vec<Blob> = payloads
            .iter()
            .map(|bytes| Blob::new(bytes.to_vec()).expect("test blob under cap"))
            .collect();
        block_on(async {
            let quote = mock.quote_batch(&blobs).await.expect("quote");
            let receipt = mock.pay(&quote).await.expect("pay");
            mock.finalize_batch(&receipt, &blobs)
                .await
                .expect("finalize")
        })
    }

    #[test]
    fn freshly_stored_blobs_report_identical() {
        let mock = MockBackend::new();
        let payloads: [&[u8]; 3] = [b"alpha", b"bravo-bravo", b""];
        let addresses = seal(&mock, &payloads);

        let expected: Vec<(Address, &[u8])> = addresses
            .iter()
            .copied()
            .zip(payloads.iter().copied())
            .collect();
        let report = block_on(check_persistence(&mock, &expected));

        assert!(report.all_identical(), "{report:?}");
        assert_eq!(report.blobs.len(), 3);
        assert_eq!(report.fetches, 3);
        let summary = report.summary();
        assert_eq!(summary.identical, 3);
        assert_eq!(summary.total, 3);
        for (row, address) in report.blobs.iter().zip(&addresses) {
            assert_eq!(row.address, *address);
            assert_eq!(row.outcome, PersistenceOutcome::Identical);
        }
    }

    #[test]
    fn a_never_uploaded_address_reports_not_found() {
        let mock = MockBackend::new();
        let absent = Address::from_bytes([0x5a; 32]);
        let report = block_on(check_persistence(
            &mock,
            &[(absent, b"whatever".as_slice())],
        ));

        assert_eq!(report.blobs.len(), 1);
        assert_eq!(report.blobs[0].outcome, PersistenceOutcome::NotFound);
        assert_eq!(report.blobs[0].expected_len, 8);
        assert!(!report.all_identical());
        assert_eq!(report.summary().not_found, 1);
    }

    #[test]
    fn a_corrupted_expectation_reports_different_with_the_divergence_offset() {
        let mock = MockBackend::new();
        let stored: &[u8] = b"the-real-ciphertext";
        let addresses = seal(&mock, &[stored]);

        // Same length, one flipped byte at offset 4.
        let mut corrupted = stored.to_vec();
        corrupted[4] = b'!';
        let report = block_on(check_persistence(
            &mock,
            &[(addresses[0], corrupted.as_slice())],
        ));
        assert_eq!(
            report.blobs[0].outcome,
            PersistenceOutcome::Different {
                fetched_len: stored.len() as u64,
                first_diff_offset: 4,
            }
        );
        assert_eq!(report.summary().different, 1);

        // Truncated expectation: no differing byte in the common prefix,
        // so the divergence is where the shorter side ends.
        let report = block_on(check_persistence(&mock, &[(addresses[0], &stored[..7])]));
        assert_eq!(
            report.blobs[0].outcome,
            PersistenceOutcome::Different {
                fetched_len: stored.len() as u64,
                first_diff_offset: 7,
            }
        );
        assert_eq!(report.blobs[0].expected_len, 7);
    }

    #[test]
    fn a_transport_failure_reports_fetch_error_and_never_aborts_the_report() {
        let mock = MockBackend::new();
        let payloads: [&[u8]; 3] = [b"one", b"two", b"three"];
        let addresses = seal(&mock, &payloads);
        // One-shot fault: the FIRST get_data fails, the rest succeed.
        mock.arm_fault(Fault::DuringGetData);

        let expected: Vec<(Address, &[u8])> = addresses
            .iter()
            .copied()
            .zip(payloads.iter().copied())
            .collect();
        let report = block_on(check_persistence(&mock, &expected));

        assert_eq!(report.blobs.len(), 3, "no row was dropped");
        assert!(matches!(
            report.blobs[0].outcome,
            PersistenceOutcome::FetchError { .. }
        ));
        assert_eq!(report.blobs[1].outcome, PersistenceOutcome::Identical);
        assert_eq!(report.blobs[2].outcome, PersistenceOutcome::Identical);
        let summary = report.summary();
        assert_eq!(summary.fetch_error, 1);
        assert_eq!(summary.identical, 2);
    }

    /// A not-found answer and a transport failure are different
    /// outcomes, not two renderings of one.
    #[test]
    fn not_found_and_fetch_error_are_distinct_outcomes() {
        let mock = MockBackend::new();
        let absent = Address::from_bytes([0x11; 32]);
        let quiet = block_on(check_persistence(&mock, &[(absent, b"x".as_slice())]));
        mock.arm_fault(Fault::NetworkOn(Method::GetData));
        let loud = block_on(check_persistence(&mock, &[(absent, b"x".as_slice())]));

        assert_eq!(quiet.blobs[0].outcome, PersistenceOutcome::NotFound);
        assert!(matches!(
            loud.blobs[0].outcome,
            PersistenceOutcome::FetchError { .. }
        ));
        assert_ne!(quiet.blobs[0].outcome, loud.blobs[0].outcome);
    }

    #[test]
    fn rows_keep_input_order_and_duplicates_cost_one_fetch() {
        let mock = MockBackend::new();
        let payloads: [&[u8]; 2] = [b"first-blob", b"second-blob"];
        let addresses = seal(&mock, &payloads);
        let before = mock.calls(Method::GetData);

        // b, a, b, a — duplicated, and out of storage order.
        let expected: Vec<(Address, &[u8])> = vec![
            (addresses[1], payloads[1]),
            (addresses[0], payloads[0]),
            (addresses[1], payloads[1]),
            (addresses[0], payloads[0]),
        ];
        let report = block_on(check_persistence(&mock, &expected));

        assert_eq!(report.fetches, 2, "two distinct addresses");
        assert_eq!(mock.calls(Method::GetData) - before, 2);
        assert_eq!(report.blobs.len(), 4);
        let order: Vec<Address> = report.blobs.iter().map(|row| row.address).collect();
        assert_eq!(
            order,
            vec![addresses[1], addresses[0], addresses[1], addresses[0]]
        );
        assert!(report.all_identical());
    }

    /// Two rows on one address with different expectations: the shared
    /// fetch is compared against each, so the disagreement is visible.
    #[test]
    fn duplicate_rows_are_compared_independently() {
        let mock = MockBackend::new();
        let stored: &[u8] = b"shared-bytes";
        let addresses = seal(&mock, &[stored]);
        let report = block_on(check_persistence(
            &mock,
            &[(addresses[0], stored), (addresses[0], b"wrong".as_slice())],
        ));

        assert_eq!(report.fetches, 1);
        assert_eq!(report.blobs[0].outcome, PersistenceOutcome::Identical);
        assert!(matches!(
            report.blobs[1].outcome,
            PersistenceOutcome::Different { .. }
        ));
    }

    #[test]
    fn an_empty_check_makes_no_network_calls() {
        let mock = MockBackend::new();
        let report = block_on(check_persistence(&mock, &[]));

        assert!(report.blobs.is_empty());
        assert_eq!(report.fetches, 0);
        assert_eq!(mock.calls(Method::GetData), 0);
        assert_eq!(report.summary(), PersistenceSummary::default());
        assert!(report.all_identical(), "vacuously true; R11 rejects empty");
    }

    /// The four counts partition the row set exactly — the invariant a
    /// rendered verdict line depends on.
    #[test]
    fn the_summary_counts_partition_the_rows() {
        let mock = MockBackend::new();
        let payloads: [&[u8]; 2] = [b"kept", b"kept-too"];
        let addresses = seal(&mock, &payloads);
        mock.arm_fault(Fault::DuringGetData);
        let absent = Address::from_bytes([0x77; 32]);

        // Row 0 trips the one-shot fault; then identical, different,
        // not-found.
        let expected: Vec<(Address, &[u8])> = vec![
            (addresses[0], payloads[0]),
            (addresses[1], payloads[1]),
            (absent, b"nothing-here".as_slice()),
        ];
        let mut expected = expected;
        expected.push((addresses[1], b"not-the-stored-bytes".as_slice()));
        let report = block_on(check_persistence(&mock, &expected));

        let summary = report.summary();
        assert_eq!(summary.total, 4);
        assert_eq!(
            summary.identical + summary.different + summary.not_found + summary.fetch_error,
            summary.total
        );
        assert_eq!(summary.fetch_error, 1);
        assert_eq!(summary.not_found, 1);
        // Rows 1 and 3 share address[1]: one fetch, one identical, one
        // different.
        assert_eq!(summary.identical, 1);
        assert_eq!(summary.different, 1);
        assert_eq!(report.fetches, 3);
    }

    /// The report is structured data for R's verdict rendering and the
    /// `--json` envelope: it survives a serde round trip, and no blob
    /// bytes ride along (project rule 6 — lengths and offsets only).
    #[test]
    fn the_report_round_trips_through_serde_and_carries_no_blob_bytes() {
        let mock = MockBackend::new();
        let secretish: &[u8] = b"CIPHERTEXT-BYTES-THAT-MUST-NOT-APPEAR";
        let addresses = seal(&mock, &[secretish]);
        let absent = Address::from_bytes([0x33; 32]);
        let expected: Vec<(Address, &[u8])> = vec![
            (addresses[0], secretish),
            (
                addresses[0],
                b"CIPHERTEXT-BYTES-THAT-MUST-NOT-APPEARx".as_slice(),
            ),
            (absent, b"CIPHERTEXT-BYTES-THAT-MUST-NOT-APPEAR".as_slice()),
        ];
        let report = block_on(check_persistence(&mock, &expected));

        let json = serde_json::to_string(&report).expect("report serializes");
        let back: PersistenceReport = serde_json::from_str(&json).expect("report deserializes");
        assert_eq!(back, report);

        assert!(
            !json.contains("CIPHERTEXT"),
            "no blob bytes in the report: {json}"
        );
        // The outcome names are the machine-readable classification keys.
        assert!(json.contains("Identical") && json.contains("Different"));
        assert!(json.contains("NotFound"));

        let summary_json = serde_json::to_string(&report.summary()).expect("summary serializes");
        let summary_back: PersistenceSummary =
            serde_json::from_str(&summary_json).expect("summary deserializes");
        assert_eq!(summary_back, report.summary());
    }
}
