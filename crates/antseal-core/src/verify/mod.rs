//! Bundle verification: report model + error taxonomy (task R1).
//!
//! This module owns the *types* of the verification pipeline:
//!
//! - [`VerificationReport`] — the deterministic, serializable statement a
//!   successful verification produces (byte format:
//!   `docs/decisions/D29-report-byte-format.md`; the native↔WASM
//!   bit-match contract for Q4/Q5);
//! - [`VerifyError`] / [`VerifyFailures`] — the typed failure taxonomy
//!   and its rendering collection (error mode:
//!   `docs/decisions/D27-verify-error-mode.md`: fail-fast first-error is
//!   normative, collection is a rendering aid whose first element equals
//!   the fail-fast error).
//!
//! The stage layer starts here too:
//!
//! - [`structural`] (task R3) — the manifest/bundle-shape invariants of
//!   MVP-SPEC.md line 121 ([`check_structural`]): exact lengths of every
//!   disclosed salt/seed/node hash, referential integrity, the per-file
//!   tiling invariant with its raw-mirror exemption, and `path_commit`
//!   recomputation. R5 runs this stage **before** the per-unit stages.
//!
//! - [`unit_stages`] (task R2) — the per-revealed-unit evidence pipeline
//!   ([`verify_revealed_unit`]): AEAD decrypt with the bundle-supplied
//!   `k_u`, padding verify + length-first strip, `true_length` ↔
//!   byte-range binding, and the content-binding dispatch (`unit_commit`
//!   vs the G13 `fine_root` seam), in the normative order of MVP-SPEC.md
//!   lines 91/114/118/121.
//!
//! - [`file_stages`] (task R4) — the file-level stage
//!   ([`check_file_stages`]): reveal-shape classification (derived, never
//!   declared — decision D28), partial-reveal isolation, the full-reveal
//!   cross-checks (concatenation → `canon_commit`/`raw_commit`, fine-tree
//!   rebuild → `fine_root`), and the raw-mirror ↔ canonical binding. R5
//!   runs this stage **after** the per-unit stages, since it consumes
//!   their verified bytes.
//!
//! - [`coherence`] (task R5) — the bundle ↔ manifest rules neither F8
//!   nor F5 can decide alone ([`check_coherence`]): decision D80's
//!   touched-file coverage, and the agreement between a unit's reveal
//!   section and the way the signed manifest binds it. Runs as the tail
//!   of the structural stage.
//!
//! - [`pipeline`] (task R5) — the orchestration itself:
//!   [`verify_bundle`] (fail-fast, normative) and
//!   [`verify_bundle_collecting`] (rendering), over the **frozen** stage
//!   order of MVP-SPEC.md lines 116–118: F strict decode →
//!   [`check_structural`] + [`check_coherence`] →
//!   [`verify_revealed_unit`] per revealed unit (R2) →
//!   [`check_file_stages`] (R4) → `sig_policy`/signature stage (C14) →
//!   anchor stage (M0: `absent` per artifact). [`VerifyStage`] is that
//!   order as a value. Everything in this module is WASM-safe: pure
//!   data, no I/O, no async.
//!
//! - [`aggregate`] (task A1) — the minimal anchor aggregate over a
//!   report's per-anchor slots: the headline-eligibility predicate and
//!   the zero-headline-eligible (UNANCHORED) flag, so the M1 E2E can
//!   library-verify a `--no-anchor` seal before A18 (M2) and R17 (M3).
//!   Derived data only — never part of the serialized report bytes.

pub mod aggregate;
pub mod coherence;
pub mod error;
pub mod file_stages;
pub mod pipeline;
pub mod report;
pub mod structural;
pub mod unit_stages;

pub use aggregate::{AnchorAggregate, aggregate_anchors, headline_eligible};
pub use coherence::{
    CoherenceBundleView, CoherenceUnit, RevealSection, RevealedUnitRef, check_coherence,
    check_reveal_sections, check_touched_coverage,
};
pub use error::{
    BindingMode, ContentCommitKind, FullRevealMaterial, LengthField, TilingViolationKind,
    VerifyError, VerifyFailures,
};
pub use file_stages::{
    CANONICALIZATION_SEAM_CODES, FileCanonMode, FileFineTree, FileRevealKind, FileRevealShape,
    FileRevealSummary, FileStageBundleView, FileStageManifestView, FileUnitEntry, FileView,
    FullRevealEvidence, FullRevealFineTree, FullRevealMaterialEntry, MirrorCandidate,
    PartialRevealEvidence, RevealCensus, VerifiedUnitBytes, check_concat_commit, check_file_stages,
    check_fine_root_rebuild, check_full_reveal_content, check_raw_mirror, classify_file_reveal,
    concat_non_mirror_bytes, participates_in_concat, resolve_raw_mirror,
};
pub use pipeline::{VerifyOptions, VerifyStage, verify_bundle, verify_bundle_collecting};
pub use report::{
    AnchorKind, AnchorResult, AnchorState, Digest32, EvidenceLayerResult, FileReveal,
    REPORT_VERSION, RawMirrorReveal, ReportEncodeError, RevealSet, SignatureScheme,
    StorageLinkageResult, SupportingEvidenceResult, UnitSpan, UnrevealedFilePlaceholder,
    VerificationReport, WorkMetadata,
};
pub use structural::{
    BundleView, DisclosedField, FileEntry, ManifestView, TouchedFile, UnitEntry, UnitKind,
    check_disclosed_lengths, check_field_length, check_manifest_refs, check_path_commits,
    check_reveal_refs, check_structural, check_tiling,
};
pub use unit_stages::{
    ContentBinding, FineRangeCheck, FineTreeError, RevealedUnitInput, verify_revealed_unit,
};

#[cfg(test)]
mod tests {
    use super::error::all_error_exemplars;
    use super::*;

    /// A report with every field non-trivially populated: all 7 anchor
    /// states, both anchor kinds, a partial reveal with blackout spans,
    /// a full reveal with a raw mirror, and a committed placeholder
    /// file. Built from scratch on every call so determinism tests
    /// compare two independent constructions.
    fn fully_populated_report() -> VerificationReport {
        let mut work_id = [0u8; 32];
        for (i, byte) in work_id.iter_mut().enumerate() {
            *byte = u8::try_from(i).expect("index fits in u8");
        }
        VerificationReport {
            report_version: REPORT_VERSION,
            work: WorkMetadata {
                work_id: Digest32(work_id),
                title: "Chapter 1 — \"draft\"".to_owned(),
                format_version: 1,
                app_version: "0.0.0-test".to_owned(),
                claimed_time_informational_only: Some("2026-07-27T00:00:00Z".to_owned()),
                signature_scheme: SignatureScheme::HybridPq,
            },
            evidence: EvidenceLayerResult {
                passed: true,
                units_verified: 3,
            },
            storage_linkage: StorageLinkageResult::NotEvaluated,
            anchors: vec![
                AnchorResult {
                    kind: AnchorKind::Tsa,
                    state: AnchorState::Proven,
                    verified_time_unix: Some(1_785_000_000),
                    source: Some("https://freetsa.org/tsr".to_owned()),
                    fetch_date: Some("2026-07-27".to_owned()),
                },
                AnchorResult {
                    kind: AnchorKind::Tsa,
                    state: AnchorState::ValidAtStampingCertSinceExpired,
                    verified_time_unix: Some(1_785_000_600),
                    source: Some("http://timestamp.digicert.com".to_owned()),
                    fetch_date: Some("2026-07-27".to_owned()),
                },
                AnchorResult {
                    kind: AnchorKind::Ots,
                    state: AnchorState::Attested,
                    verified_time_unix: None,
                    source: Some("calendar.example".to_owned()),
                    fetch_date: Some("2026-07-27".to_owned()),
                },
                AnchorResult {
                    kind: AnchorKind::Ots,
                    state: AnchorState::Pending,
                    verified_time_unix: None,
                    source: None,
                    fetch_date: None,
                },
                AnchorResult {
                    kind: AnchorKind::Tsa,
                    state: AnchorState::InternallyConsistentOnly,
                    verified_time_unix: None,
                    source: None,
                    fetch_date: None,
                },
                AnchorResult {
                    kind: AnchorKind::Ots,
                    state: AnchorState::Invalid,
                    verified_time_unix: None,
                    source: None,
                    fetch_date: None,
                },
                AnchorResult {
                    kind: AnchorKind::Tsa,
                    state: AnchorState::Absent,
                    verified_time_unix: None,
                    source: None,
                    fetch_date: None,
                },
            ],
            supporting_evidence: SupportingEvidenceResult::None,
            reveal: RevealSet {
                files: vec![
                    FileReveal {
                        file_id: 0,
                        path: "pitch/chapter-1.md".to_owned(),
                        total_size: 1024,
                        fully_revealed: false,
                        revealed_spans: vec![UnitSpan {
                            unit_id: 1,
                            start: 256,
                            end: 640,
                        }],
                        unrevealed_spans: vec![
                            UnitSpan {
                                unit_id: 0,
                                start: 0,
                                end: 256,
                            },
                            UnitSpan {
                                unit_id: 2,
                                start: 640,
                                end: 1024,
                            },
                        ],
                        raw_mirror: None,
                    },
                    FileReveal {
                        file_id: 1,
                        path: "notes.txt".to_owned(),
                        total_size: 300,
                        fully_revealed: true,
                        revealed_spans: vec![UnitSpan {
                            unit_id: 3,
                            start: 0,
                            end: 300,
                        }],
                        unrevealed_spans: vec![],
                        raw_mirror: Some(RawMirrorReveal {
                            unit_id: 4,
                            raw_size: 305,
                        }),
                    },
                ],
                unrevealed_files: vec![UnrevealedFilePlaceholder {
                    file_id: 2,
                    size: 49_152,
                }],
            },
        }
    }

    /// [`fully_populated_report`] with the receipt arm rendered, and
    /// **differing from it in nothing else** (R69, D105 ruling 4).
    ///
    /// `SupportingEvidenceResult::ArbitrumReceipt` landed at R12 with a
    /// standalone spelling pin (`report.rs`) and no whole-report artifact —
    /// pinned or otherwise — that contained it. A standalone pin cannot show
    /// the `"supporting_evidence":` key, the object sitting where a string
    /// sat, or the sibling ordering `anchors → supporting_evidence → reveal`
    /// that D29 rule 1 is about; only a composed literal shows those.
    ///
    /// Built by struct update from the control so the difference is
    /// *structurally* one field rather than a promise: the two snapshots are a
    /// differential pair, and
    /// `receipt_snapshot_differs_from_the_control_only_at_supporting_evidence`
    /// holds them to it. The control keeps rendering
    /// `"supporting_evidence":"none"` in composition — that is worth pinning
    /// on its own account, and it is what this twin is differential against,
    /// so **do not mutate the control into a receipt-bearing one**.
    ///
    /// The operands are `report.rs`'s, deliberately shared rather than
    /// re-typed, so the standalone pin and this one cannot be satisfied
    /// separately.
    fn fully_populated_report_with_receipt() -> VerificationReport {
        VerificationReport {
            supporting_evidence: SupportingEvidenceResult::ArbitrumReceipt {
                block_number: report::RECEIPT_FIXTURE_BLOCK_NUMBER,
                transaction_count: report::RECEIPT_FIXTURE_TRANSACTION_COUNT,
            },
            ..fully_populated_report()
        }
    }

    /// D29: two serializations — of the same instance and of two
    /// independently built equal reports — are byte-identical.
    #[test]
    fn serialization_is_deterministic() {
        let report = fully_populated_report();
        let first = report.to_canonical_json().expect("report serializes");
        let second = report.to_canonical_json().expect("report serializes");
        assert_eq!(first, second, "same instance must serialize identically");

        let rebuilt = fully_populated_report();
        assert_eq!(report, rebuilt);
        let third = rebuilt.to_canonical_json().expect("report serializes");
        assert_eq!(
            first, third,
            "independent constructions must serialize identically"
        );
    }

    /// Fixed-fixture snapshot: pins the exact canonical bytes of the
    /// fully populated report. Any change to field order, naming, wire
    /// names, or encoding shows up as a diff here — pre-Q14 that is a
    /// deliberate re-snapshot (D29); post-Q14 it is a format version
    /// bump.
    ///
    /// It also pins `report_version` itself, so this is a coupled edit of
    /// [`REPORT_VERSION`] — recorded there. Being a `#[cfg(test)]` unit
    /// test it runs on **both** targets (`cargo test -p antseal-core --lib
    /// --target wasm32-unknown-unknown` is the `wasm32-core-tests` lane),
    /// where stdout is discarded and a panic is a bare trap. R32 found it
    /// that way: a missed re-snapshot presents as "the test binary
    /// trapped", with the readable message only on the native run.
    #[test]
    fn snapshot_bytes_are_stable() {
        let bytes = fully_populated_report()
            .to_canonical_json()
            .expect("report serializes");
        let actual = String::from_utf8(bytes).expect("canonical JSON is UTF-8");
        assert_eq!(
            actual, EXPECTED_CANONICAL_JSON,
            "canonical report bytes drifted"
        );
    }

    /// The same snapshot with the receipt arm rendered — the tree's only
    /// artifact that shows `arbitrum-receipt` **in composition** (R69).
    ///
    /// What reddens it: deleting the arm (a compile error first), renaming
    /// `block_number`/`transaction_count`, reordering them, changing the
    /// enum's serde representation or its kebab-case spelling, and moving
    /// `supporting_evidence` relative to its siblings. Like its control this
    /// is a `#[cfg(test)]` unit test, so it runs on wasm32 too — where a
    /// failure is a bare trap with no test name, and this native run is the
    /// readable reproduction.
    #[test]
    fn snapshot_with_receipt_bytes_are_stable() {
        let bytes = fully_populated_report_with_receipt()
            .to_canonical_json()
            .expect("report serializes");
        let actual = String::from_utf8(bytes).expect("canonical JSON is UTF-8");
        assert_eq!(
            actual, EXPECTED_CANONICAL_JSON_WITH_RECEIPT,
            "canonical report bytes drifted (receipt-bearing twin)"
        );
    }

    /// The two snapshots are a **differential pair**: literal against literal,
    /// with no serializer in the loop.
    ///
    /// This is the check that keeps the twin honest. `snapshot_bytes_...`
    /// above compares a constant to whatever the code emits, and a lane that
    /// re-pins it by pasting the new output satisfies it while learning
    /// nothing — the exact failure mode a pin exists to prevent. Comparing the
    /// two *constants* cannot be satisfied that way: it fails unless the only
    /// difference between control and twin is the `supporting_evidence` value,
    /// which is D105 §5.3's checkable prediction (+63 B: `"none"` is 6 bytes,
    /// the rendered receipt is 69) and its kill criterion 3.
    #[test]
    fn receipt_snapshot_differs_from_the_control_only_at_supporting_evidence() {
        let control_slot = r#""supporting_evidence":"none""#;
        let receipt_slot = r#""supporting_evidence":{"arbitrum-receipt":{"block_number":271828182,"transaction_count":2}}"#;
        assert_eq!(
            EXPECTED_CANONICAL_JSON.matches(control_slot).count(),
            1,
            "the control snapshot no longer renders exactly one `none` slot"
        );
        assert_eq!(
            EXPECTED_CANONICAL_JSON.replace(control_slot, receipt_slot),
            EXPECTED_CANONICAL_JSON_WITH_RECEIPT,
            "the twin differs from the control somewhere other than \
             `supporting_evidence` — fix the fixture, not the constant \
             (D105 kill criterion 3)"
        );
        assert_eq!(
            EXPECTED_CANONICAL_JSON_WITH_RECEIPT.len() - EXPECTED_CANONICAL_JSON.len(),
            63,
            "D105 §5.3 predicts +63 bytes at one value and nowhere else"
        );
    }

    /// The empty-anchor / UNANCHORED shape is representable from day one
    /// (MVP-SPEC.md line 153: empty-anchor vectors are an M0
    /// requirement; R17 aggregates UNANCHORED from zero
    /// headline-eligible anchors).
    #[test]
    fn empty_anchor_report_is_representable() {
        let mut report = fully_populated_report();
        report.anchors = vec![];
        report.work.signature_scheme = SignatureScheme::NotEvaluated;
        let json = String::from_utf8(report.to_canonical_json().expect("report serializes"))
            .expect("canonical JSON is UTF-8");
        assert!(json.contains("\"anchors\":[]"), "{json}");
        assert!(json.contains("\"not-evaluated\""), "{json}");
    }

    /// No secret material in any Display/Debug/serialized output.
    ///
    /// The types cannot even carry `W`/`k_u`/salts/seeds (no such
    /// fields — the module-level policy in `report.rs`); this test
    /// guards the property with dummy secret patterns: the hex encodings
    /// below stand in for W (0xa5…), k_u (0xb6…), unit_salt (0xc7…),
    /// file_salt (0xd8…) and s_root (0xe9…) of a hypothetical leak, and
    /// must appear nowhere in the formatted report, errors, failures, or
    /// canonical bytes. Secret-suggesting key names are asserted absent
    /// from the wire form too.
    #[test]
    fn no_secret_material_in_display_debug_or_json() {
        let dummy_secret_hex = [
            "a5a5a5a5a5a5a5a5", // W
            "b6b6b6b6b6b6b6b6", // k_u
            "c7c7c7c7c7c7c7c7", // unit_salt
            "d8d8d8d8d8d8d8d8", // file_salt
            "e9e9e9e9e9e9e9e9", // s_root
        ];

        let report = fully_populated_report();
        let json = String::from_utf8(report.to_canonical_json().expect("report serializes"))
            .expect("canonical JSON is UTF-8");
        let report_debug = format!("{report:?}");

        // The receipt-bearing twin sweeps alongside the control, so the arm
        // is covered by project rule 6 from the moment it is rendered in
        // composition rather than at whatever the next sweep turns out to be
        // (R69). A receipt carries a block number and a transaction count and
        // nothing else, but "the value cannot leak" is a property to assert,
        // not to reason about once and forget.
        let receipt_report = fully_populated_report_with_receipt();
        let receipt_json = String::from_utf8(
            receipt_report
                .to_canonical_json()
                .expect("report serializes"),
        )
        .expect("canonical JSON is UTF-8");
        let receipt_debug = format!("{receipt_report:?}");

        let mut failures = VerifyFailures::new(VerifyError::UnitDecryptFailed { unit_id: 1 });
        for e in all_error_exemplars() {
            failures.push(e);
        }
        let failures_debug = format!("{failures:?}");
        let failures_display = failures.to_string();
        let error_text: String = all_error_exemplars()
            .iter()
            .map(|e| format!("{e} {e:?}"))
            .collect();

        for surface in [
            &json,
            &receipt_json,
            &report_debug,
            &receipt_debug,
            &failures_debug,
            &failures_display,
            &error_text,
        ] {
            for secret in dummy_secret_hex {
                assert!(
                    !surface.contains(secret),
                    "secret pattern {secret} leaked into output"
                );
            }
        }

        // The wire form must not even *name* secret-bearing concepts as
        // keys — a regression tripwire against someone adding a salt or
        // key field to the report model.
        for wire_form in [&json, &receipt_json] {
            for forbidden in ["salt", "seed", "k_u", "k_m", "secret", "nonce"] {
                assert!(
                    !wire_form.contains(forbidden),
                    "serialized report contains forbidden substring {forbidden:?}"
                );
            }
        }
    }

    /// Pinned canonical bytes of `fully_populated_report()` (see
    /// `snapshot_bytes_are_stable`).
    const EXPECTED_CANONICAL_JSON: &str = r#"{"report_version":1,"work":{"work_id":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","title":"Chapter 1 — \"draft\"","format_version":1,"app_version":"0.0.0-test","claimed_time_informational_only":"2026-07-27T00:00:00Z","signature_scheme":"hybrid-pq"},"evidence":{"passed":true,"units_verified":3},"storage_linkage":"not-evaluated","anchors":[{"kind":"tsa","state":"proven","verified_time_unix":1785000000,"source":"https://freetsa.org/tsr","fetch_date":"2026-07-27"},{"kind":"tsa","state":"valid-at-stamping-cert-since-expired","verified_time_unix":1785000600,"source":"http://timestamp.digicert.com","fetch_date":"2026-07-27"},{"kind":"ots","state":"attested","verified_time_unix":null,"source":"calendar.example","fetch_date":"2026-07-27"},{"kind":"ots","state":"pending","verified_time_unix":null,"source":null,"fetch_date":null},{"kind":"tsa","state":"internally-consistent-only","verified_time_unix":null,"source":null,"fetch_date":null},{"kind":"ots","state":"invalid","verified_time_unix":null,"source":null,"fetch_date":null},{"kind":"tsa","state":"absent","verified_time_unix":null,"source":null,"fetch_date":null}],"supporting_evidence":"none","reveal":{"files":[{"file_id":0,"path":"pitch/chapter-1.md","total_size":1024,"fully_revealed":false,"revealed_spans":[{"unit_id":1,"start":256,"end":640}],"unrevealed_spans":[{"unit_id":0,"start":0,"end":256},{"unit_id":2,"start":640,"end":1024}],"raw_mirror":null},{"file_id":1,"path":"notes.txt","total_size":300,"fully_revealed":true,"revealed_spans":[{"unit_id":3,"start":0,"end":300}],"unrevealed_spans":[],"raw_mirror":{"unit_id":4,"raw_size":305}}],"unrevealed_files":[{"file_id":2,"size":49152}]}}"#;

    /// Pinned canonical bytes of `fully_populated_report_with_receipt()` (see
    /// `snapshot_with_receipt_bytes_are_stable`). Identical to
    /// [`EXPECTED_CANONICAL_JSON`] but for the `supporting_evidence` value —
    /// asserted, not asserted-by-eye, in
    /// `receipt_snapshot_differs_from_the_control_only_at_supporting_evidence`.
    const EXPECTED_CANONICAL_JSON_WITH_RECEIPT: &str = r#"{"report_version":1,"work":{"work_id":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","title":"Chapter 1 — \"draft\"","format_version":1,"app_version":"0.0.0-test","claimed_time_informational_only":"2026-07-27T00:00:00Z","signature_scheme":"hybrid-pq"},"evidence":{"passed":true,"units_verified":3},"storage_linkage":"not-evaluated","anchors":[{"kind":"tsa","state":"proven","verified_time_unix":1785000000,"source":"https://freetsa.org/tsr","fetch_date":"2026-07-27"},{"kind":"tsa","state":"valid-at-stamping-cert-since-expired","verified_time_unix":1785000600,"source":"http://timestamp.digicert.com","fetch_date":"2026-07-27"},{"kind":"ots","state":"attested","verified_time_unix":null,"source":"calendar.example","fetch_date":"2026-07-27"},{"kind":"ots","state":"pending","verified_time_unix":null,"source":null,"fetch_date":null},{"kind":"tsa","state":"internally-consistent-only","verified_time_unix":null,"source":null,"fetch_date":null},{"kind":"ots","state":"invalid","verified_time_unix":null,"source":null,"fetch_date":null},{"kind":"tsa","state":"absent","verified_time_unix":null,"source":null,"fetch_date":null}],"supporting_evidence":{"arbitrum-receipt":{"block_number":271828182,"transaction_count":2}},"reveal":{"files":[{"file_id":0,"path":"pitch/chapter-1.md","total_size":1024,"fully_revealed":false,"revealed_spans":[{"unit_id":1,"start":256,"end":640}],"unrevealed_spans":[{"unit_id":0,"start":0,"end":256},{"unit_id":2,"start":640,"end":1024}],"raw_mirror":null},{"file_id":1,"path":"notes.txt","total_size":300,"fully_revealed":true,"revealed_spans":[{"unit_id":3,"start":0,"end":300}],"unrevealed_spans":[],"raw_mirror":{"unit_id":4,"raw_size":305}}],"unrevealed_files":[{"file_id":2,"size":49152}]}}"#;
}
