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
//! The orchestration itself —
//! `verify_bundle(bytes, opts) -> Result<VerificationReport, VerifyError>`
//! and `verify_bundle_collecting(..) -> Result<_, VerifyFailures>` — is
//! task R5 and lands here later, over the stage order of MVP-SPEC.md
//! lines 116–118: F strict decode → [`check_structural`] (R3) →
//! [`verify_revealed_unit`] per revealed unit (R2) →
//! [`check_file_stages`] (R4) → `sig_policy`/signature stage (C14) →
//! anchor stage. Everything in this module is WASM-safe: pure data, no
//! I/O, no async.

pub mod error;
pub mod file_stages;
pub mod report;
pub mod structural;
pub mod unit_stages;

pub use error::{
    ContentCommitKind, FullRevealMaterial, LengthField, TilingViolationKind, VerifyError,
    VerifyFailures,
};
pub use file_stages::{
    FileCanonMode, FileFineTree, FileRevealKind, FileRevealShape, FileRevealSummary,
    FileStageBundleView, FileStageManifestView, FileUnitEntry, FileView, FullRevealEvidence,
    FullRevealFineTree, FullRevealMaterialEntry, PartialRevealEvidence, RevealCensus,
    VerifiedUnitBytes, check_concat_commit, check_file_stages, check_fine_root_rebuild,
    check_full_reveal_content, check_raw_mirror, classify_file_reveal, concat_non_mirror_bytes,
    participates_in_concat,
};
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
            &report_debug,
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
        for forbidden in ["salt", "seed", "k_u", "k_m", "secret", "nonce"] {
            assert!(
                !json.contains(forbidden),
                "serialized report contains forbidden substring {forbidden:?}"
            );
        }
    }

    /// Pinned canonical bytes of `fully_populated_report()` (see
    /// `snapshot_bytes_are_stable`).
    const EXPECTED_CANONICAL_JSON: &str = r#"{"report_version":0,"work":{"work_id":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","title":"Chapter 1 — \"draft\"","format_version":1,"app_version":"0.0.0-test","claimed_time_informational_only":"2026-07-27T00:00:00Z","signature_scheme":"hybrid-pq"},"evidence":{"passed":true,"units_verified":3},"storage_linkage":"not-evaluated","anchors":[{"kind":"tsa","state":"proven","verified_time_unix":1785000000,"source":"https://freetsa.org/tsr","fetch_date":"2026-07-27"},{"kind":"tsa","state":"valid-at-stamping-cert-since-expired","verified_time_unix":1785000600,"source":"http://timestamp.digicert.com","fetch_date":"2026-07-27"},{"kind":"ots","state":"attested","verified_time_unix":null,"source":"calendar.example","fetch_date":"2026-07-27"},{"kind":"ots","state":"pending","verified_time_unix":null,"source":null,"fetch_date":null},{"kind":"tsa","state":"internally-consistent-only","verified_time_unix":null,"source":null,"fetch_date":null},{"kind":"ots","state":"invalid","verified_time_unix":null,"source":null,"fetch_date":null},{"kind":"tsa","state":"absent","verified_time_unix":null,"source":null,"fetch_date":null}],"supporting_evidence":"none","reveal":{"files":[{"file_id":0,"path":"pitch/chapter-1.md","total_size":1024,"fully_revealed":false,"revealed_spans":[{"unit_id":1,"start":256,"end":640}],"unrevealed_spans":[{"unit_id":0,"start":0,"end":256},{"unit_id":2,"start":640,"end":1024}],"raw_mirror":null},{"file_id":1,"path":"notes.txt","total_size":300,"fully_revealed":true,"revealed_spans":[{"unit_id":3,"start":0,"end":300}],"unrevealed_spans":[],"raw_mirror":{"unit_id":4,"raw_size":305}}],"unrevealed_files":[{"file_id":2,"size":49152}]}}"#;
}
