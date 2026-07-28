//! The [`VerificationReport`] model (task R1).
//!
//! A report exists **only for a bundle that passed the evidence
//! pipeline** — failures are typed errors, never report content (D27 §4).
//! Its serialized bytes are a byte contract: Q4 golden vectors commit
//! expected report bytes and Q5 requires the wasm32 build to bit-match
//! native output (MVP-SPEC.md lines 167/169). Serialization rules are
//! decided in `docs/decisions/D29-report-byte-format.md` (RECOMMENDED at
//! R1; frozen at the Q14 format-freeze gate):
//!
//! - struct **field declaration order is the wire order** — reordering,
//!   adding, or removing a field here is a report-format change;
//! - **no `HashMap`** (or any randomized container) — `Vec`/`BTreeMap`
//!   only (the current model needs no maps at all);
//! - **no floats** — integers and strings only;
//! - **no conditional field presence** (`skip_serializing_if` banned) —
//!   absence is `null` or an explicit state variant;
//! - compact JSON via [`VerificationReport::to_canonical_json`]; binary
//!   data as lowercase hex; enum wire names kebab-case (spec-aligned).
//!
//! **Secret-material policy (normative for this module):** no field of
//! this model may ever carry `W`, unit keys `k_u`, `k_m`, any salt
//! (`unit_salt`/`path_salt`/`file_salt`), or any GGM seed (`s_root`,
//! covering seeds). Verification *consumes* those; the report records
//! only public statement data (ids, sizes, spans, states, digests that
//! are already public). `super::tests` asserts non-leakage over a fully
//! populated report.

use core::fmt;

use serde::Serialize;

/// Version of the report serialization itself (first field of every
/// report). **`1` — the version Q14 freezes** (D29 rule 8; task R32).
///
/// It was `0` while D29 was a recommendation. R32 moved it to `1` *before*
/// the Q14 gate flips `status frozen`, because afterwards
/// `scripts/vector-freeze.sh --update` refuses to change an existing digest
/// and the same edit becomes a report-format version bump rather than a
/// pre-freeze re-snapshot.
///
/// # Coupled edits — everything a future bump must carry with it
///
/// Bumping this constant is a **format event**, never a chore. Exactly
/// three things move with it, and the third is the one that surprises
/// people:
///
/// 1. **`testdata/vectors/v1/report/verification-reports.json`** — this is
///    the first field of every serialized report, so all 21 pinned byte
///    strings change at once. Re-emit with
///    `cargo test -p antseal-core --features test-util --test report_vectors
///    -- --ignored emit_report_vector_document`, then
///    `scripts/vector-freeze.sh --update`. *Enforced*: the vector executor
///    recomputes `expect.report_version` and fails on a bump without a
///    re-emit, and after Q14 the freeze checker refuses the changed digest.
///    No prose anywhere quotes the numeral — checked at R32 — so there is
///    no documentation row to keep in step.
/// 2. **`EXPECTED_CANONICAL_JSON` in `super::tests`** — D29's fixed-fixture
///    snapshot, which pins the whole report as one string literal starting
///    `{"report_version":N`. *Not* enforced by anything else, and the way
///    it fails is the trap: it is a `#[cfg(test)]` unit test, so it runs in
///    the `wasm32-core-tests` lane too, where stdout is discarded and the
///    failure is a bare "the test binary trapped: unreachable" with no test
///    name. R32 lost time to exactly that. Reproduce with
///    `cargo test -p antseal-core --lib` for a readable message.
/// 3. **Nothing in `wasm-bitmatch`.** `TRANSCRIPT_VERSION` and
///    `EXPECTED_TRANSCRIPT_VERSION` read as coupled to this constant and
///    are not: they version the bit-match *transcript envelope*, which
///    carries no report field and aggregates the recomputed digests of all
///    seven vector kinds. A report bump changes what the transcript
///    *contains*, never its schema. See `crates/wasm-bitmatch/src/lib.rs`.
pub const REPORT_VERSION: u32 = 1;

/// A 32-byte digest (e.g. `work_id = SHA-256(body)`), serialized and
/// displayed as 64 lowercase hex characters (D29 rule: binary data is
/// lowercase hex — JSON has no byte-string type).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Digest32(pub [u8; 32]);

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest32({self})")
    }
}

impl Serialize for Digest32 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Encoding the report to its canonical bytes failed.
///
/// Structurally unreachable for these types (no maps, no non-string
/// keys, infallible `Serialize` impls) but surfaced as a typed error —
/// library code never unwraps.
#[derive(Debug, thiserror::Error)]
#[error("verification report could not be encoded as canonical JSON")]
pub struct ReportEncodeError(#[source] serde_json::Error);

/// The verdict-bearing data model produced by a successful
/// `verify_bundle` run (R5 populates it; R17 aggregates verdicts from
/// it; R18/R19 render it; R22 returns its canonical bytes to the page).
///
/// Field order is the wire order (D29).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationReport {
    /// Report-serialization version ([`REPORT_VERSION`]).
    pub report_version: u32,
    /// Work-level metadata as verified from the bundle.
    pub work: WorkMetadata,
    /// Evidence-layer outcome (MVP-SPEC.md line 118) — the layer that
    /// alone carries the evidentiary verdict.
    pub evidence: EvidenceLayerResult,
    /// Storage-linkage-layer slot (MVP-SPEC.md line 119) — distinct from
    /// the evidence layer; "storage is the product's bonus, not its
    /// proof". [`StorageLinkageResult::NotEvaluated`] until R20 (M3).
    pub storage_linkage: StorageLinkageResult,
    /// Per-anchor result slots, absent-tolerant from day one: an empty
    /// list (the empty-anchor golden vector, MVP-SPEC.md line 153) and
    /// all-`absent` states are both representable — the UNANCHORED
    /// outcome (MVP-SPEC.md line 137) aggregates from exactly this data
    /// in R17. At M0 the anchor stage reports `absent` per anchor; A18
    /// populates real states at M2 (via R12).
    pub anchors: Vec<AnchorResult>,
    /// Supporting-evidence slot: the Arbitrum receipt is **not an
    /// anchor** and never enters `anchors` (MVP-SPEC.md line 110; R12
    /// routes it here, R17 keeps it headline-ineligible).
    pub supporting_evidence: SupportingEvidenceResult,
    /// Redaction/reveal-set data — what was revealed, where it sits, and
    /// what remains hidden (drives R19's redaction view and the page
    /// DOM).
    pub reveal: RevealSet,
}

impl VerificationReport {
    /// The canonical, deterministic byte form of this report (D29):
    /// compact JSON, struct-declaration field order, lowercase-hex
    /// binary, kebab-case enum names. Two serializations of equal
    /// reports are byte-identical; native and wasm32 builds must
    /// bit-match (Q5). Also the payload for CLI `--json` (R21/U30) and
    /// the page binding (R22) — one serialization path everywhere.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, ReportEncodeError> {
        serde_json::to_vec(self).map_err(ReportEncodeError)
    }
}

/// Work-level metadata, verified from the manifest embedded in the
/// bundle (MVP-SPEC.md line 98).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkMetadata {
    /// `work_id = SHA-256(body)`, recomputed by the verifier over the
    /// embedded body bytes as received (MVP-SPEC.md line 75).
    pub work_id: Digest32,
    /// Sealer-chosen title (embedded in the plaintext manifest; visible
    /// to every bundle recipient by design).
    pub title: String,
    /// Manifest/bundle **format** version the bundle declares.
    pub format_version: u32,
    /// Sealer **app** version recorded in the manifest body.
    pub app_version: String,
    /// The sealer-asserted claimed time, verbatim from the manifest.
    ///
    /// **Informational only — never verified, never headline-eligible.**
    /// The field name carries the marker into the serialized bytes so no
    /// consumer can miss it. R17 excludes it from the headline input set
    /// at the type level; R18 renders it subordinate, labeled "asserted
    /// by sealer — NOT verified" (MVP-SPEC.md line 137).
    pub claimed_time_informational_only: Option<String>,
    /// Signature-scheme label slot (MVP-SPEC.md line 97: verdicts label
    /// "hybrid (PQ)" vs "Ed25519-only"). C14 supplies the datum at
    /// integration; [`SignatureScheme::NotEvaluated`] until then.
    pub signature_scheme: SignatureScheme,
}

/// Signature-scheme label for the verdict (wire names kebab-case).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureScheme {
    /// Signature stage not yet wired (pre-C14 integration slot).
    NotEvaluated,
    /// Hybrid Ed25519 + ML-DSA-65 per `sig_policy` ("hybrid (PQ)").
    HybridPq,
    /// Ed25519-only `sig_policy` (the ML-DSA WASM-probe fallback).
    Ed25519Only,
    /// A `sig_policy` that is registered and satisfied but is neither of
    /// the two named shapes — today only ML-DSA-65 alone, tomorrow any
    /// future registered algorithm set.
    ///
    /// It exists because [`PolicyLabel::Other`] exists and is reachable:
    /// F5 accepts any non-empty, duplicate-free, registered policy, so a
    /// manifest may legitimately declare `sig_policy = [ml-dsa-65]`.
    /// Collapsing that into [`Self::NotEvaluated`] would report "we did
    /// not check the signatures" about a bundle whose signatures were
    /// checked and passed — the one thing a verdict label must never do.
    /// R18 renders it as the policy's own algorithm list rather than a
    /// slogan.
    ///
    /// [`PolicyLabel::Other`]: crate::crypto::sig_policy::PolicyLabel::Other
    Other,
}

/// Evidence-layer outcome (MVP-SPEC.md line 118). A report is only
/// emitted when the evidence pipeline passed (D27 §4), so `passed` is
/// `true` in every emitted report — kept explicit so the serialized
/// format states its claim rather than implying it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceLayerResult {
    /// Whether the evidence layer passed (always `true` in an emitted
    /// report; see the type-level docs).
    pub passed: bool,
    /// Number of revealed units that were decrypted, padding-checked,
    /// and content-bound (R2 stages).
    pub units_verified: u64,
}

/// Storage-linkage-layer result slot (MVP-SPEC.md line 119), rendered
/// distinctly from the evidence layer and never gating it.
///
/// R20 (M3) adds the evaluated arm (per-blob offline address
/// recomputation results); until then the slot reports not-evaluated —
/// a pre-Q14 extension per D29.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageLinkageResult {
    /// Stage not implemented/run yet (M0–M2).
    NotEvaluated,
}

/// Which anchoring mechanism produced an anchor artifact
/// (MVP-SPEC.md lines 106–110). The Arbitrum receipt is deliberately
/// not representable here — it is not an anchor
/// ([`SupportingEvidenceResult`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnchorKind {
    /// OpenTimestamps calendar attestation (`.ots`, Bitcoin-backed).
    Ots,
    /// RFC 3161 timestamp token from a TSA.
    Tsa,
}

/// Per-anchor verdict state (MVP-SPEC.md lines 127–135; one authoritative
/// wording set is R18's — this is the datum, not the wording). Wire
/// names are the spec's own kebab-case state names. Headline eligibility
/// ([H]) is R17's aggregation concern, not encoded here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnchorState {
    /// TSA token valid against the pinned root store, or an OTS anchor
    /// `--online`-confirmed against Bitcoin block H. [H]
    Proven,
    /// TSA token whose chain was valid at its genTime but whose cert has
    /// since expired — still independently proven. [H]
    ValidAtStampingCertSinceExpired,
    /// Upgraded OTS with embedded header; not headline-eligible offline,
    /// `--online` promotes to `proven`.
    Attested,
    /// OTS submitted but not yet upgraded to a Bitcoin attestation.
    Pending,
    /// Well-formed token/attestation that does not chain to a pinned
    /// root (TSA) or match online (OTS); never headline-eligible.
    InternallyConsistentOnly,
    /// Signature/op check failed.
    Invalid,
    /// Anchor not present.
    Absent,
}

/// One per-anchor result slot: state, verified time, artifact metadata,
/// and fetch date — all absent-tolerant (M0 reports carry `Absent` state
/// and `None` everywhere; A18/R12 populate real data at M2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorResult {
    /// Which anchoring mechanism this slot describes.
    pub kind: AnchorKind,
    /// Offline verdict state for this anchor.
    pub state: AnchorState,
    /// Independently verified time as Unix seconds (UTC), populated only
    /// for time-proving states (`proven`,
    /// `valid-at-stamping-cert-since-expired`). Integer per D29's
    /// no-floats rule. Never the claimed time.
    pub verified_time_unix: Option<i64>,
    /// Artifact metadata: the anchor's source identity when known (TSA
    /// URL / calendar identity, as recorded in the bundle artifact).
    pub source: Option<String>,
    /// Fetch date recorded in the bundle for this artifact
    /// (sealer-recorded metadata; rendered with the anchor per
    /// MVP-SPEC.md line 127+), verbatim string form.
    pub fetch_date: Option<String>,
}

/// Supporting-evidence slot — a class wholly separate from anchors,
/// never headline-eligible (MVP-SPEC.md line 110: "supporting evidence —
/// no independently proven time").
///
/// R12 (M2) adds the receipt arm when a bundle opts the Arbitrum receipt
/// in; until then the slot reports none — a pre-Q14 extension per D29.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportingEvidenceResult {
    /// No supporting evidence embedded (also the M0 stage stub).
    None,
}

/// The redaction/reveal-set data: which bytes of which files were
/// revealed, and what remains hidden — with position and total size
/// **always** present (MVP-SPEC.md line 121: "Every reveal displays
/// position + total size (anti-out-of-context guardrail)"). The model
/// makes the guardrail structural: spans carry positions, files carry
/// total sizes, placeholders carry sizes — a renderer cannot omit what
/// the data always provides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevealSet {
    /// Touched files (at least one unit revealed), in manifest file
    /// order.
    pub files: Vec<FileReveal>,
    /// Untouched files, as committed placeholders (MVP-SPEC.md line 121:
    /// "unrevealed files render as committed placeholders (size only,
    /// path withheld)").
    pub unrevealed_files: Vec<UnrevealedFilePlaceholder>,
}

/// Reveal state of one touched file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileReveal {
    /// `file_id` — LE64 index into the manifest file table
    /// (MVP-SPEC.md line 76).
    pub file_id: u64,
    /// The disclosed path, verified against `path_commit` — present for
    /// every touched file (a reveal that touches a file always carries
    /// `{path, path_salt}`, MVP-SPEC.md line 114).
    pub path: String,
    /// The file's total size in its commitment domain (canonical bytes
    /// for text, raw bytes for binary — the tiling domain,
    /// MVP-SPEC.md line 98). The anti-out-of-context denominator.
    pub total_size: u64,
    /// Whether every non-mirror unit of the file is revealed (R4's
    /// classification; mirrors ride along only in this state).
    pub fully_revealed: bool,
    /// Revealed non-mirror unit spans, sorted by `start` — each span's
    /// position within `[0, total_size)`.
    pub revealed_spans: Vec<UnitSpan>,
    /// Unrevealed non-mirror unit spans, sorted by `start` — rendered as
    /// sized blackout blocks (MVP-SPEC.md line 121). Unit boundaries are
    /// public structure metadata by design (MVP-SPEC.md line 95).
    pub unrevealed_spans: Vec<UnitSpan>,
    /// The file's revealed raw-mirror unit, when one rode along with a
    /// full reveal (raw byte domain — outside the tiling spans above;
    /// MVP-SPEC.md line 92).
    pub raw_mirror: Option<RawMirrorReveal>,
}

/// One unit's byte-range: half-open `[start, end)` in the file's
/// commitment domain; size = `end - start`, position = `start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UnitSpan {
    /// Work-global unit id (MVP-SPEC.md line 76).
    pub unit_id: u64,
    /// Inclusive start byte offset.
    pub start: u64,
    /// Exclusive end byte offset.
    pub end: u64,
}

/// A revealed raw-mirror unit (raw byte domain).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RawMirrorReveal {
    /// Work-global unit id of the mirror unit.
    pub unit_id: u64,
    /// The raw file size = the mirror's `true_length`
    /// (MVP-SPEC.md line 92).
    pub raw_size: u64,
}

/// Committed placeholder for an unrevealed file: **size only, path
/// withheld** ("file #3 — 48 KB"). This type must never gain a path,
/// snippet, or any content-derived field (MVP-SPEC.md line 121; R19
/// asserts placeholders leak nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UnrevealedFilePlaceholder {
    /// `file_id` ordinal (public structure metadata; drives the
    /// "file #N" rendering).
    pub file_id: u64,
    /// Total size in the file's commitment domain — the only datum a
    /// placeholder exposes.
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest32_is_lowercase_hex_in_display_debug_and_json() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("index fits in u8");
        }
        let digest = Digest32(bytes);
        let hex = digest.to_string();
        assert_eq!(hex.len(), 64);
        assert_eq!(&hex[..8], "00010203");
        assert_eq!(&hex[56..], "1c1d1e1f");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(format!("{digest:?}"), format!("Digest32({hex})"));
        let json = serde_json::to_string(&digest).expect("digest serializes");
        assert_eq!(json, format!("\"{hex}\""));
    }

    #[test]
    fn anchor_states_use_spec_kebab_wire_names() {
        // The wire names are the spec's own state names (MVP-SPEC.md
        // lines 129–135) — pinned here so a rename is a loud event.
        let states = [
            (AnchorState::Proven, "\"proven\""),
            (
                AnchorState::ValidAtStampingCertSinceExpired,
                "\"valid-at-stamping-cert-since-expired\"",
            ),
            (AnchorState::Attested, "\"attested\""),
            (AnchorState::Pending, "\"pending\""),
            (
                AnchorState::InternallyConsistentOnly,
                "\"internally-consistent-only\"",
            ),
            (AnchorState::Invalid, "\"invalid\""),
            (AnchorState::Absent, "\"absent\""),
        ];
        for (state, expected) in states {
            let json = serde_json::to_string(&state).expect("state serializes");
            assert_eq!(json, expected);
        }
        assert_eq!(
            serde_json::to_string(&SignatureScheme::Ed25519Only).expect("scheme serializes"),
            "\"ed25519-only\""
        );
        assert_eq!(
            serde_json::to_string(&StorageLinkageResult::NotEvaluated).expect("slot serializes"),
            "\"not-evaluated\""
        );
        assert_eq!(
            serde_json::to_string(&SupportingEvidenceResult::None).expect("slot serializes"),
            "\"none\""
        );
        assert_eq!(
            serde_json::to_string(&AnchorKind::Ots).expect("kind serializes"),
            "\"ots\""
        );
    }
}
