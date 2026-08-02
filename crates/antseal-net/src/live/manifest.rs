//! R11 — the verify-side live-check wrapper over S15's primitive.
//!
//! S15 ([`super::check_persistence`]) answers "are these bytes still at
//! these addresses?" for an anonymous list of pairs. R11 adds the two
//! things a verifier needs on top and **nothing else**:
//!
//! 1. **Labels.** Each row names the storage record it is about — a unit
//!    (work-global `unit_id` + kind) or the encrypted-manifest blob — so
//!    a verdict can say *which* blob is gone.
//! 2. **A verdict-shaped summary.** [`LiveVerdict`] collapses the row
//!    outcomes to one storage-layer word for the verify report's
//!    storage-linkage section.
//!
//! Fetching is implemented **once**, in S15; this module builds S15's
//! input list and interprets its output. Nothing here talks to a network.
//!
//! # Scope at M1 — manifest-shaped only
//!
//! [`records_from_manifest`] is the M1 shape: a manifest unit table plus
//! the ciphertexts the caller holds. The M3 bundle-shaped adapter (a
//! bundle's embedded ciphertexts + its encrypted-manifest record) is
//! deliberately **not** written here; it plugs in through the public
//! [`StorageRecord::new`] constructor without touching this code, which
//! is why that constructor exists.
//!
//! # This verdict is not *the* verdict
//!
//! [`LiveVerdict`] is a **storage-layer** summary. It is not R17's
//! headline verdict, it is not an eligibility class, it contributes no
//! code to the frozen error-code universe, and it never enters
//! `REPORT_VERSION`'s bytes. R20/R21 render it as its own section at M3,
//! where — per project rule 4 — it stays advisory and never overwrites
//! the offline verdict: a bundle whose ciphertext has fallen off the
//! network is still a valid proof of what existed when.
//!
//! # What this does *not* check
//!
//! R11 does **not** recompute addresses from ciphertext. It asks whether
//! the network still serves the bytes the caller expects *at the address
//! the manifest records*. Proving that those bytes hash to that address
//! is S4's rule applied by the storage-linkage stage (R20) — a separate,
//! offline check. Keeping them apart means a `Different` row here is
//! unambiguous: the network's copy is not the caller's copy.

use std::collections::BTreeMap;

use antseal_core::manifest::{ManifestBodyV1, UnitEntry, UnitKind};

use super::{BlobPersistence, PersistenceSummary, check_persistence};
use crate::{Address, StorageBackend};

/// A live check could not be assembled or run.
///
/// Assembly failures only — every *per-blob* outcome is data on the
/// report, never an error (S15's rule, inherited).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LiveCheckError {
    /// The manifest lists a unit the caller supplied no ciphertext for —
    /// the check would silently under-report persistence.
    #[error("no ciphertext supplied for unit {unit_id}: a live check must cover every unit")]
    MissingCiphertext {
        /// Work-global unit id (manifest order).
        unit_id: u64,
    },
    /// The caller supplied a ciphertext for a unit this manifest does not
    /// list — the two inputs describe different works.
    #[error(
        "ciphertext supplied for unit {unit_id}, which this manifest does not list: the unit \
         table and the ciphertext map describe different works"
    )]
    UnexpectedCiphertext {
        /// The unit id present in the map but absent from the table.
        unit_id: u64,
    },
    /// A live check with no records would report "all persisted"
    /// vacuously. Refused so an empty input can never read as evidence.
    #[error("nothing to check: a live check needs at least one storage record")]
    NothingToCheck,
}

/// Which stored blob a row is about.
///
/// The kind tag is this crate's own (`antseal-core`'s wire
/// [`UnitKind`] carries no serde derives, and adding them would touch a
/// frozen format type for a reporting convenience). Conversion is
/// exhaustive, so a new wire variant fails to compile here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UnitKindTag {
    /// An ordinary unit in the file's tiling domain.
    Normal,
    /// The file's raw mirror (raw byte domain).
    RawMirror,
}

impl From<UnitKind> for UnitKindTag {
    fn from(kind: UnitKind) -> Self {
        match kind {
            UnitKind::Normal => Self::Normal,
            UnitKind::RawMirror => Self::RawMirror,
        }
    }
}

/// The storage record a live-check row refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LiveSubject {
    /// One unit's ciphertext blob.
    Unit {
        /// Work-global unit id (manifest order) — the id `reveal --units`
        /// takes and every per-unit derivation keys on.
        unit_id: u64,
        /// Normal or raw mirror.
        kind: UnitKindTag,
    },
    /// The work's encrypted-manifest blob.
    EncryptedManifest,
}

/// One labelled expectation: a subject, where its ciphertext should be,
/// and the copy to compare against.
///
/// Borrows its ciphertext — a live check over a whole work must not
/// duplicate every blob in memory.
#[derive(Debug, Clone, Copy)]
pub struct StorageRecord<'a> {
    subject: LiveSubject,
    address: Address,
    ciphertext: &'a [u8],
}

impl<'a> StorageRecord<'a> {
    /// Build a record directly.
    ///
    /// The extension point for shapes this module does not build itself
    /// — notably M3's bundle-shaped adapter, which reads the same
    /// subjects out of a `.sealproof` bundle instead of a manifest.
    #[must_use]
    pub const fn new(subject: LiveSubject, address: Address, ciphertext: &'a [u8]) -> Self {
        Self {
            subject,
            address,
            ciphertext,
        }
    }

    /// What this record is about.
    #[must_use]
    pub const fn subject(&self) -> LiveSubject {
        self.subject
    }

    /// Where the ciphertext should be.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }
}

/// Build the live-check record list from a manifest unit table plus the
/// ciphertexts the caller holds (the M1 shape).
///
/// Rows come out in **work-global manifest order** (files in order, each
/// file's units in order — raw mirrors included, since a mirror is a
/// stored blob like any other), with the encrypted-manifest record, when
/// supplied, appended last.
///
/// Coverage is **exact**: every unit in the table must have a ciphertext
/// and every supplied ciphertext must belong to the table. A live check
/// that quietly skipped units would report "all persisted" while proving
/// less than it claims.
///
/// # Errors
///
/// [`LiveCheckError::MissingCiphertext`] /
/// [`LiveCheckError::UnexpectedCiphertext`] — the unit table and the
/// ciphertext map disagree, each naming the offending unit id.
pub fn records_from_manifest<'a>(
    body: &ManifestBodyV1,
    unit_ciphertexts: &'a BTreeMap<u64, Vec<u8>>,
    encrypted_manifest: Option<(Address, &'a [u8])>,
) -> Result<Vec<StorageRecord<'a>>, LiveCheckError> {
    let units: Vec<&UnitEntry> = body
        .files()
        .iter()
        .flat_map(|file| file.units().iter())
        .collect();

    let mut records = Vec::with_capacity(units.len() + usize::from(encrypted_manifest.is_some()));
    for unit in &units {
        let unit_id = unit.unit_id();
        let ciphertext = unit_ciphertexts
            .get(&unit_id)
            .ok_or(LiveCheckError::MissingCiphertext { unit_id })?;
        records.push(StorageRecord::new(
            LiveSubject::Unit {
                unit_id,
                kind: unit.kind().into(),
            },
            Address::from(*unit.address()),
            ciphertext.as_slice(),
        ));
    }

    // The other direction of the coverage rule: a ciphertext for a unit
    // this manifest never lists means the caller composed two different
    // works.
    if unit_ciphertexts.len() > units.len() {
        let listed: BTreeMap<u64, ()> = units.iter().map(|u| (u.unit_id(), ())).collect();
        for &unit_id in unit_ciphertexts.keys() {
            if !listed.contains_key(&unit_id) {
                return Err(LiveCheckError::UnexpectedCiphertext { unit_id });
            }
        }
    }

    if let Some((address, bytes)) = encrypted_manifest {
        records.push(StorageRecord::new(
            LiveSubject::EncryptedManifest,
            address,
            bytes,
        ));
    }
    Ok(records)
}

/// One row: what was checked, and what the network said.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LiveCheckRow {
    /// The storage record this row is about.
    pub subject: LiveSubject,
    /// S15's per-blob result for it.
    pub persistence: BlobPersistence,
}

/// The storage-layer word for a whole live check.
///
/// **Precedence, normative:** the worst *established fact* wins, and
/// uncertainty rules only when nothing negative was established —
/// `Divergent` > `SomeMissing` > `Inconclusive` > `AllPersisted`. So a
/// check that establishes one missing blob says `SomeMissing` even if
/// other rows could not be fetched: "at least one blob is gone" stays
/// true regardless of what the unreachable rows would have said, and the
/// per-outcome counts on [`LiveCheckReport::summary`] carry the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LiveVerdict {
    /// Every record came back byte-identical.
    AllPersisted,
    /// At least one address served bytes that are not the expected ones
    /// — under content addressing (D32) that should be impossible, so it
    /// outranks every other outcome.
    Divergent,
    /// No divergence, but at least one record is not on the network.
    SomeMissing,
    /// Nothing negative was established, but at least one fetch failed:
    /// the check could not be completed.
    Inconclusive,
}

impl LiveVerdict {
    /// Whether every record was confirmed present and identical.
    #[must_use]
    pub const fn is_all_persisted(&self) -> bool {
        matches!(self, Self::AllPersisted)
    }

    /// Derive the verdict from S15's counts, by the precedence above.
    #[must_use]
    fn from_summary(summary: PersistenceSummary) -> Self {
        if summary.different > 0 {
            Self::Divergent
        } else if summary.not_found > 0 {
            Self::SomeMissing
        } else if summary.fetch_error > 0 {
            Self::Inconclusive
        } else {
            Self::AllPersisted
        }
    }
}

/// A completed live check: labelled rows, counts, one verdict.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LiveCheckReport {
    /// One row per record, in the order the records were supplied.
    pub rows: Vec<LiveCheckRow>,
    /// S15's per-outcome counts (they partition `rows`).
    pub summary: PersistenceSummary,
    /// The storage-layer verdict.
    pub verdict: LiveVerdict,
    /// Distinct addresses fetched — one `get_data` each.
    pub fetches: u64,
}

impl LiveCheckReport {
    /// The subjects that are not confirmed persistent, in row order —
    /// what a rendered verdict line lists.
    #[must_use]
    pub fn unconfirmed(&self) -> Vec<LiveSubject> {
        self.rows
            .iter()
            .filter(|row| !row.persistence.outcome.is_identical())
            .map(|row| row.subject)
            .collect()
    }
}

/// Run a live check over labelled records (R11).
///
/// Delegates every fetch to S15's [`check_persistence`] — one `get_data`
/// per distinct address — then labels the rows and derives the verdict.
///
/// # Errors
///
/// [`LiveCheckError::NothingToCheck`] when `records` is empty: an empty
/// check would report `AllPersisted` vacuously.
pub async fn live_check<B: StorageBackend>(
    backend: &B,
    records: &[StorageRecord<'_>],
) -> Result<LiveCheckReport, LiveCheckError> {
    if records.is_empty() {
        return Err(LiveCheckError::NothingToCheck);
    }

    let expected: Vec<(Address, &[u8])> = records
        .iter()
        .map(|record| (record.address, record.ciphertext))
        .collect();
    let report = check_persistence(backend, &expected).await;
    let summary = report.summary();

    // S15 guarantees one row per expectation, in input order — so the
    // zip below is total and the labels stay aligned.
    let rows: Vec<LiveCheckRow> = records
        .iter()
        .zip(report.blobs)
        .map(|(record, persistence)| LiveCheckRow {
            subject: record.subject,
            persistence,
        })
        .collect();

    Ok(LiveCheckReport {
        rows,
        summary,
        verdict: LiveVerdict::from_summary(summary),
        fetches: report.fetches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{Fault, Method, MockBackend, block_on};
    use crate::{Blob, PersistenceOutcome, StorageBackend};
    use antseal_core::manifest::fixtures;

    /// The fixtures' addresses are `[seed; 32]` patterns
    /// (`manifest::fixtures::address`), so a mock whose address rule is
    /// "first byte, repeated 32×" lets a test store ciphertext at the
    /// exact address a fixture manifest records — no address plumbing,
    /// and the manifest stays the untouched frozen fixture.
    fn seeded_address(bytes: &[u8]) -> Address {
        Address::from_bytes([bytes.first().copied().unwrap_or(0); 32])
    }

    fn seeded_mock() -> MockBackend {
        MockBackend::new().with_address_fn(seeded_address)
    }

    /// Ciphertext for a unit whose manifest address is `[seed; 32]`: the
    /// first byte is `seed` (that is all `seeded_address` reads), and the
    /// body is deliberately **unlike** the address pattern — otherwise
    /// the "no blob bytes in the report" assertion below could not tell a
    /// leaked ciphertext from a serialized address of repeated `seed`s.
    /// Length varies by unit id so the blobs differ from each other.
    fn ciphertext_for(unit: &UnitEntry) -> Vec<u8> {
        let seed = unit.address().as_bytes()[0];
        let mut bytes = vec![seed];
        bytes.extend((0..64 + unit.unit_id()).map(|i| 0xC7u8 ^ (i as u8)));
        bytes
    }

    /// Every unit of `body`, ciphertext included, keyed by unit id.
    fn ciphertexts(body: &ManifestBodyV1) -> BTreeMap<u64, Vec<u8>> {
        body.files()
            .iter()
            .flat_map(|file| file.units().iter())
            .map(|unit| (unit.unit_id(), ciphertext_for(unit)))
            .collect()
    }

    /// Store `bytes` in the mock at its seeded address (a real
    /// quote→pay→finalize, so the store path is the same one a seal
    /// uses).
    fn seal(mock: &MockBackend, payloads: &[Vec<u8>]) -> Vec<Address> {
        let blobs: Vec<Blob> = payloads
            .iter()
            .map(|bytes| Blob::new(bytes.clone()).expect("test blob under cap"))
            .collect();
        block_on(async {
            let quote = mock.quote_batch(&blobs).await.expect("quote");
            let receipt = mock.pay(&quote).await.expect("pay");
            mock.finalize_batch(&receipt, &blobs)
                .await
                .expect("finalize")
        })
    }

    // ── the builder (pure — no backend) ──────────────────────────────

    #[test]
    fn the_builder_covers_every_unit_in_manifest_order_including_raw_mirrors() {
        let body = fixtures::text_with_mirror_body();
        let map = ciphertexts(&body);
        let records = records_from_manifest(&body, &map, None).expect("complete coverage");

        assert_eq!(records.len(), 3, "two normal units + the raw mirror");
        let subjects: Vec<LiveSubject> = records.iter().map(StorageRecord::subject).collect();
        assert_eq!(
            subjects,
            vec![
                LiveSubject::Unit {
                    unit_id: 0,
                    kind: UnitKindTag::Normal
                },
                LiveSubject::Unit {
                    unit_id: 1,
                    kind: UnitKindTag::Normal
                },
                LiveSubject::Unit {
                    unit_id: 2,
                    kind: UnitKindTag::RawMirror
                },
            ],
            "work-global manifest order, mirror last (D23), kinds labelled"
        );
        // Addresses come from the manifest, never recomputed.
        for (record, unit) in records
            .iter()
            .zip(body.files().iter().flat_map(|f| f.units().iter()))
        {
            assert_eq!(record.address(), Address::from(*unit.address()));
        }
    }

    #[test]
    fn the_builder_spans_every_file_of_a_multi_file_work() {
        let body = fixtures::multi_file_split_body();
        let map = ciphertexts(&body);
        let records = records_from_manifest(&body, &map, None).expect("complete coverage");

        assert!(body.files().len() > 1, "fixture is multi-file");
        assert_eq!(records.len() as u64, body.units_total());
        let ids: Vec<u64> = records
            .iter()
            .map(|r| match r.subject() {
                LiveSubject::Unit { unit_id, .. } => unit_id,
                LiveSubject::EncryptedManifest => unreachable!("no manifest record supplied"),
            })
            .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "unit ids are the manifest-order ordinals");
    }

    #[test]
    fn the_encrypted_manifest_record_is_appended_last() {
        let body = fixtures::binary_single_unit_body();
        let map = ciphertexts(&body);
        let address = Address::from_bytes([0xEE; 32]);
        let records = records_from_manifest(&body, &map, Some((address, b"encrypted-manifest")))
            .expect("complete coverage");

        let last = records.last().expect("nonempty");
        assert_eq!(last.subject(), LiveSubject::EncryptedManifest);
        assert_eq!(last.address(), address);
        assert_eq!(records.len(), map.len() + 1);
    }

    #[test]
    fn a_unit_with_no_ciphertext_is_refused_by_unit_id() {
        let body = fixtures::text_with_mirror_body();
        let mut map = ciphertexts(&body);
        map.remove(&1);
        let err = records_from_manifest(&body, &map, None).expect_err("incomplete coverage");
        assert_eq!(err, LiveCheckError::MissingCiphertext { unit_id: 1 });
    }

    #[test]
    fn a_ciphertext_for_an_unlisted_unit_is_refused_by_unit_id() {
        let body = fixtures::text_with_mirror_body();
        let mut map = ciphertexts(&body);
        map.insert(99, vec![0xAB; 16]);
        let err = records_from_manifest(&body, &map, None).expect_err("extra ciphertext");
        assert_eq!(err, LiveCheckError::UnexpectedCiphertext { unit_id: 99 });
    }

    // ── driving the check ────────────────────────────────────────────

    #[test]
    fn a_fully_persisted_work_verdicts_all_persisted() {
        let body = fixtures::text_with_mirror_body();
        let map = ciphertexts(&body);
        let mock = seeded_mock();
        let payloads: Vec<Vec<u8>> = map.values().cloned().collect();
        let stored = seal(&mock, &payloads);

        // The seal really did land on the manifest's addresses.
        let records = records_from_manifest(&body, &map, None).expect("coverage");
        for record in &records {
            assert!(mock.contains(record.address()), "{:?}", record.subject());
        }
        assert_eq!(stored.len(), records.len());

        let report = block_on(live_check(&mock, &records)).expect("nonempty");
        assert_eq!(report.verdict, LiveVerdict::AllPersisted);
        assert!(report.verdict.is_all_persisted());
        assert_eq!(report.rows.len(), 3);
        assert_eq!(report.summary.identical, 3);
        assert_eq!(report.fetches, 3);
        assert!(report.unconfirmed().is_empty());
        for (row, record) in report.rows.iter().zip(&records) {
            assert_eq!(row.subject, record.subject(), "labels stay aligned");
            assert_eq!(row.persistence.outcome, PersistenceOutcome::Identical);
        }
    }

    #[test]
    fn a_never_stored_unit_verdicts_some_missing_and_is_named() {
        let body = fixtures::text_with_mirror_body();
        let map = ciphertexts(&body);
        let mock = seeded_mock();
        // Store everything except the raw mirror (unit 2).
        let payloads: Vec<Vec<u8>> = map
            .iter()
            .filter(|(id, _)| **id != 2)
            .map(|(_, bytes)| bytes.clone())
            .collect();
        seal(&mock, &payloads);

        let records = records_from_manifest(&body, &map, None).expect("coverage");
        let report = block_on(live_check(&mock, &records)).expect("nonempty");

        assert_eq!(report.verdict, LiveVerdict::SomeMissing);
        assert_eq!(report.summary.not_found, 1);
        assert_eq!(
            report.unconfirmed(),
            vec![LiveSubject::Unit {
                unit_id: 2,
                kind: UnitKindTag::RawMirror
            }],
            "the verdict names which blob is gone"
        );
    }

    #[test]
    fn a_diverging_blob_verdicts_divergent() {
        let body = fixtures::binary_single_unit_body();
        let map = ciphertexts(&body);
        let mock = seeded_mock();
        let payloads: Vec<Vec<u8>> = map.values().cloned().collect();
        seal(&mock, &payloads);

        // The caller's copy of unit 0 is one byte short of the stored one.
        let mut corrupted = map.clone();
        let entry = corrupted.get_mut(&0).expect("unit 0");
        entry.pop();
        let records = records_from_manifest(&body, &corrupted, None).expect("coverage");
        let report = block_on(live_check(&mock, &records)).expect("nonempty");

        assert_eq!(report.verdict, LiveVerdict::Divergent);
        assert_eq!(report.summary.different, 1);
        assert!(matches!(
            report.rows[0].persistence.outcome,
            PersistenceOutcome::Different { .. }
        ));
    }

    #[test]
    fn an_unreachable_network_verdicts_inconclusive() {
        let body = fixtures::binary_single_unit_body();
        let map = ciphertexts(&body);
        let mock = seeded_mock();
        let payloads: Vec<Vec<u8>> = map.values().cloned().collect();
        seal(&mock, &payloads);
        mock.arm_fault(Fault::NetworkOn(Method::GetData));

        let records = records_from_manifest(&body, &map, None).expect("coverage");
        let report = block_on(live_check(&mock, &records)).expect("nonempty");

        assert_eq!(report.verdict, LiveVerdict::Inconclusive);
        assert_eq!(report.summary.fetch_error, 1);
        assert_eq!(report.unconfirmed().len(), 1);
    }

    /// The documented precedence, exercised on mixed reports: the worst
    /// established fact wins; uncertainty rules only when nothing
    /// negative was established.
    #[test]
    fn the_verdict_precedence_is_divergent_then_missing_then_inconclusive() {
        let body = fixtures::text_with_mirror_body();
        let map = ciphertexts(&body);

        // missing + fetch-error ⇒ SomeMissing (a fact outranks a gap).
        let mock = seeded_mock();
        let stored: Vec<Vec<u8>> = map
            .iter()
            .filter(|(id, _)| **id != 2)
            .map(|(_, b)| b.clone())
            .collect();
        seal(&mock, &stored);
        mock.arm_fault(Fault::DuringGetData); // one-shot: hits unit 0
        let records = records_from_manifest(&body, &map, None).expect("coverage");
        let report = block_on(live_check(&mock, &records)).expect("nonempty");
        assert_eq!(report.summary.fetch_error, 1);
        assert_eq!(report.summary.not_found, 1);
        assert_eq!(report.verdict, LiveVerdict::SomeMissing);

        // divergent + missing + fetch-error ⇒ Divergent.
        let mock = seeded_mock();
        seal(&mock, &stored);
        mock.arm_fault(Fault::DuringGetData);
        let mut corrupted = map.clone();
        corrupted.get_mut(&1).expect("unit 1").push(0xFF);
        let records = records_from_manifest(&body, &corrupted, None).expect("coverage");
        let report = block_on(live_check(&mock, &records)).expect("nonempty");
        assert_eq!(report.summary.different, 1);
        assert_eq!(report.summary.not_found, 1);
        assert_eq!(report.summary.fetch_error, 1);
        assert_eq!(report.verdict, LiveVerdict::Divergent);
    }

    #[test]
    fn an_empty_record_list_is_refused_rather_than_reported_as_persisted() {
        let mock = seeded_mock();
        let err = block_on(live_check(&mock, &[])).expect_err("empty is refused");
        assert_eq!(err, LiveCheckError::NothingToCheck);
        assert_eq!(mock.calls(Method::GetData), 0);
    }

    /// The encrypted-manifest blob is checked like any other record
    /// (R11 accept row 3) and is named in the verdict when it is gone.
    #[test]
    fn the_encrypted_manifest_blob_is_checked_and_named() {
        let body = fixtures::binary_single_unit_body();
        let map = ciphertexts(&body);
        let mock = seeded_mock();
        let payloads: Vec<Vec<u8>> = map.values().cloned().collect();
        seal(&mock, &payloads);

        // Present: sealed through the same mock, so its address is real.
        let manifest_bytes = vec![0xEEu8; 128];
        let manifest_address = seal(&mock, std::slice::from_ref(&manifest_bytes))[0];
        let records = records_from_manifest(
            &body,
            &map,
            Some((manifest_address, manifest_bytes.as_slice())),
        )
        .expect("coverage");
        let report = block_on(live_check(&mock, &records)).expect("nonempty");
        assert_eq!(report.verdict, LiveVerdict::AllPersisted);
        assert_eq!(
            report.rows.last().expect("nonempty").subject,
            LiveSubject::EncryptedManifest
        );

        // Absent: only the manifest blob is missing.
        let absent = Address::from_bytes([0x7F; 32]);
        let records = records_from_manifest(&body, &map, Some((absent, manifest_bytes.as_slice())))
            .expect("coverage");
        let report = block_on(live_check(&mock, &records)).expect("nonempty");
        assert_eq!(report.verdict, LiveVerdict::SomeMissing);
        assert_eq!(report.unconfirmed(), vec![LiveSubject::EncryptedManifest]);
    }

    /// Verdict-shaped output for R's rendering and `--json`: it survives
    /// a serde round trip and carries no blob bytes (project rule 6).
    #[test]
    fn the_report_round_trips_through_serde_and_carries_no_blob_bytes() {
        let body = fixtures::text_with_mirror_body();
        let map = ciphertexts(&body);
        let mock = seeded_mock();
        let payloads: Vec<Vec<u8>> = map.values().cloned().collect();
        seal(&mock, &payloads);
        let records = records_from_manifest(&body, &map, None).expect("coverage");
        let report = block_on(live_check(&mock, &records)).expect("nonempty");

        let json = serde_json::to_string(&report).expect("serializes");
        let back: LiveCheckReport = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, report);
        assert!(json.contains("AllPersisted"));
        assert!(json.contains("RawMirror"), "kinds are machine-readable");
        // Not one ciphertext rides along: each blob's own serde rendering
        // (its leading bytes are enough to identify it) is absent.
        for ciphertext in map.values() {
            let rendered = serde_json::to_string(ciphertext).expect("bytes serialize");
            let probe = &rendered[..rendered.len().min(24)];
            assert!(
                !json.contains(probe),
                "blob bytes leaked into the report: {probe}"
            );
        }
    }
}
