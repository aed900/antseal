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
//! **Value-space policy — R-VAL (normative for this module; D105 §6):**
//! every value report v1 can serialize must be exercised by a committed
//! assertion that renders it **inside a whole canonical report**, and the
//! report's enums must be **enumerable**, so that "every value" is a
//! checkable quantity rather than a hand-maintained list.
//!
//! The second half is the enforceable one, and every enum in this module
//! carries the same triple for it (Q127): a `const ALL`, a wildcard-free
//! `wire_name()` — so a variant added here is a **compile error**, not a
//! missing row — and a sweep over `ALL` asserting `serde`'s actual bytes.
//! The sweeps compare the ordered spelling list against a hand-written
//! literal, so a lane that grows `ALL` is stopped a second time until the new
//! value's spelling is written down. The first half is discharged by the
//! whole-report artifacts: the 21 pinned R9 report vectors and, for values no
//! committed vector produces, D29's fixed-fixture snapshots in `super::tests`
//! (`EXPECTED_CANONICAL_JSON` and its receipt-bearing and linkage-bearing
//! twins). Standalone bytes
//! cannot show a value's key, the sibling ordering rule 1 is about, or an
//! object sitting where a string sat (D105 §5.3), which is why the rule says
//! *in composition* rather than *somewhere*.
//!
//! The rule exists because the tree's only other instrument here answers the
//! same way to two different questions: **zero moved pins is a correct
//! *format* signal and an empty *coverage* signal** (D105 §4.3). A value
//! nothing renders is byte-indistinguishable from a value addition that is
//! safe. [`SupportingEvidenceResult::ArbitrumReceipt`] shipped that way
//! (R12, found by inspection at R69); [`SignatureScheme::Other`] had been
//! sitting in the same hole since R5 and was found by Q127 — constructed at
//! one site, rendered by none of the 21 pinned reports and by no assertion in
//! the tree.
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
    /// Work-level metadata read from the manifest embedded in the bundle
    /// — one field of which this crate verified, and five of which it
    /// reproduced. See [`WorkMetadata`]; this line claimed all six were
    /// verified until R73.
    pub work: WorkMetadata,
    /// Evidence-layer outcome (MVP-SPEC.md line 118) — the layer that
    /// alone carries the evidentiary verdict.
    pub evidence: EvidenceLayerResult,
    /// Storage-linkage-layer slot (MVP-SPEC.md line 119) — distinct from
    /// the evidence layer; "storage is the product's bonus, not its
    /// proof". R20 (M3) added the evaluated arm; a run that does not ask
    /// for the stage still reports
    /// [`StorageLinkageResult::NotEvaluated`].
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

/// Work-level metadata read from the manifest embedded in the bundle
/// (MVP-SPEC.md line 98).
///
/// # Six fields; two of them are verifier statements
///
/// This doc said *"verified from the manifest"* and the field that holds
/// it said *"as verified from the bundle"* until R73 measured the group
/// and found **one** verified statement **about the work**. C14's landing
/// made it **two**, and this heading is corrected here rather than left as
/// arithmetic for the reader (R87) — the count sat one paragraph above the
/// field whose doc falsified it.
///
/// - [`WorkMetadata::work_id`] is **recomputed**, not read.
/// - [`WorkMetadata::signature_scheme`] is **checked**: the pipeline's
///   stage 5 runs on every verify, so the label reports a `sig_policy`
///   whose signatures were verified and passed.
/// - [`WorkMetadata::format_version`] is **decoder-enforced**: a body
///   declaring any other version never reaches a report.
/// - [`WorkMetadata::title`], [`WorkMetadata::app_version`] and
///   [`WorkMetadata::claimed_time_informational_only`] are the sealer's
///   own text, reproduced verbatim and checked against nothing.
///
/// Both verifier statements are **self-consistency** results until they are
/// compared with something the bundle did not supply: `work_id` digests
/// bytes the bundle handed over, and the signatures are checked against
/// pubkeys the same body declares. That is a real check and it is not an
/// external binding — the same distinction `work_id`'s own doc draws.
///
/// Every one of these lives inside the body that `work_id` digests, so
/// none can be edited without moving the work identity. That binds their
/// **integrity**, never their **truth**: a sealer may write any title,
/// build string or claimed time and seal it perfectly consistently.
/// [`WorkMetadata::claimed_time_informational_only`] carries the caveat
/// in its own field name and is the pattern the others were brought up
/// to (R73) — no field's doc here may claim a check the pipeline does
/// not perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkMetadata {
    /// `work_id = SHA-256(body)`, **recomputed** by the verifier over the
    /// embedded body bytes as received (MVP-SPEC.md line 75) — never
    /// copied out of a field the sealer wrote.
    ///
    /// The one value in this group a recipient can act on, and it acts by
    /// comparison: a work id obtained independently of the bundle either
    /// equals this one or does not, and a substituted body does not
    /// survive that. On its own, recomputing a digest over bytes the
    /// bundle supplied proves only self-consistency — the comparison is
    /// where the evidence is.
    pub work_id: Digest32,
    /// Sealer-chosen title, reproduced verbatim from the plaintext
    /// manifest (visible to every bundle recipient by design).
    ///
    /// **A sealer claim — nothing verifies it.** No stage compares it to
    /// the revealed content, and a work may be titled anything its sealer
    /// likes. Editing it moves [`WorkMetadata::work_id`], which binds the
    /// string to the work identity but says nothing about whether it
    /// describes the work.
    pub title: String,
    /// Manifest/bundle **format** version.
    ///
    /// The one field here the decoder *enforced* rather than reproduced:
    /// a body declaring anything but `FORMAT_VERSION_V1` is rejected with
    /// `ManifestError::UnsupportedFormatVersion` before any report exists
    /// (`crates/antseal-core/src/manifest/body.rs:1298`), and the value
    /// rendered here is that accepted constant (`body.rs:1180`) rather
    /// than the bundle's own bytes. It therefore cannot disagree with
    /// what this build parsed — but it is a statement about the parse,
    /// not about the work.
    pub format_version: u32,
    /// Sealer **app** version recorded in the manifest body.
    ///
    /// **A sealer claim — informational only, never verdict-bearing**
    /// (MVP-SPEC.md line 98). The producing build is unattested: any
    /// sealer may write any string here and nothing downstream reads it.
    /// That note existed only on the accessor
    /// (`crates/antseal-core/src/manifest/body.rs:1184`) and did not
    /// reach the report until R73 put it here.
    pub app_version: String,
    /// The sealer-asserted claimed time, verbatim from the manifest.
    ///
    /// **Informational only — never verified, never headline-eligible.**
    /// The field name carries the marker into the serialized bytes so no
    /// consumer can miss it. R17 excludes it from the headline input set
    /// at the type level; R18 renders it subordinate, labeled "asserted
    /// by sealer — NOT verified" (MVP-SPEC.md line 137).
    pub claimed_time_informational_only: Option<String>,
    /// Signature-scheme label (MVP-SPEC.md line 97: verdicts label
    /// "hybrid (PQ)" vs "Ed25519-only").
    ///
    /// **C14 has landed and supplies the datum on every verify.** The
    /// pipeline's stage 5 calls `check_signatures` unconditionally — no
    /// option, no `cfg`, no branch — and its result is this field, so what
    /// is recorded here is a **verifier statement**: the label of a
    /// `sig_policy` whose signatures were checked and passed. That is
    /// precisely why [`SignatureScheme::Other`] exists rather than
    /// collapsing into [`SignatureScheme::NotEvaluated`].
    ///
    /// **No production path writes [`SignatureScheme::NotEvaluated`] into
    /// this field.** It stays representable and serialized because
    /// [`SignatureScheme::ALL`] and [`SignatureScheme::wire_name`] are
    /// frozen report-v1 surface (D105); see that variant's own doc for what
    /// it is and which tests construct it. A renderer that does meet the
    /// value must still not let it read as "unsigned" or as "signatures
    /// failed" — it says nothing in either direction — but no report this
    /// pipeline emits carries it. This paragraph replaces a promise that
    /// C14 was still pending, which outlived C14 by the length of R87.
    pub signature_scheme: SignatureScheme,
}

/// Signature-scheme label for the verdict (wire names kebab-case).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureScheme {
    /// **Representable, serialized, and produced by no production path.**
    ///
    /// This was the pre-C14 integration slot. C14 wired the stage, the
    /// pipeline runs it on every verify, and no code path outside
    /// `#[cfg(test)]` assigns this value — measured across `crates/` for
    /// R87, which also found the count wrong on its own row: **three** test
    /// sites construct it, not one.
    ///
    /// - `verify::tests::empty_anchor_report_is_representable`
    /// - `verify::overlay::tests::report_bytes_are_byte_identical_whether_or_not_the_overlay_computation_runs`
    /// - `verify::verdict::tests::a_claimed_time_earlier_than_every_anchor_cannot_move_the_headline`
    ///
    /// So do not read "unreachable" as "dead" and delete it:
    /// [`Self::ALL`] and [`Self::wire_name`] are frozen report-v1 surface,
    /// removing a variant is a **format event** under D105 rather than a
    /// tidy-up, and the three tests above would fail to compile.
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
    /// **No renderer can name the algorithms, and the vagueness belongs to
    /// report v1 rather than to the wording.** This label is the whole of
    /// what the report carries about the policy — there is no algorithm
    /// list beside it — so R18's row states the *shape* (neither of the two
    /// named schemes; its signatures were checked and passed) and names no
    /// algorithm, and its wildcard-free label match is the pin. **R77**
    /// ruled it that way against the two alternatives: carrying the list
    /// would add a [`WorkMetadata`] field, which is a FORMAT EVENT costing
    /// `REPORT_VERSION` (D105 §2.4), refused on cost; and declaring a
    /// CLI/page divergence was refused on a **false premise** — both
    /// surfaces run this crate's verification over the same bundle bytes,
    /// `VerifyOutcome` hands the manifest to neither of them, and either
    /// could re-decode `sig_policy` through the public
    /// [`SealProof`](crate::bundle::SealProof), so there is no asymmetry to
    /// declare.
    ///
    /// [`PolicyLabel::Other`]: crate::crypto::sig_policy::PolicyLabel::Other
    Other,
}

impl SignatureScheme {
    /// Every scheme label, in declaration order — which is the wire order of
    /// the enum's values.
    ///
    /// rustc checks this literal against the declared length, so `ALL` can
    /// never be shorter *than it claims*; no construction on stable can check
    /// that the claim equals the variant count. Two things do that job
    /// instead, and both are outside this const: [`Self::wire_name`]'s
    /// wildcard-free match (a new variant fails to compile) and the hand-
    /// written spelling list in
    /// `signature_scheme_wire_names_are_the_serialized_spellings` (a grown
    /// `ALL` fails the sweep until the new spelling is written down). See the
    /// module docs, R-VAL.
    pub const ALL: [Self; 4] = [
        Self::NotEvaluated,
        Self::HybridPq,
        Self::Ed25519Only,
        Self::Other,
    ];

    /// This label's serialized spelling — the kebab-case name `serde` emits.
    ///
    /// Written as an exhaustive, wildcard-free match so a new label fails
    /// compilation here rather than reaching a report that nothing renders.
    /// That is not hypothetical for this enum: [`Self::Other`] has existed
    /// since R5, is constructed at exactly one site
    /// (`verify/pipeline.rs`, from `PolicyLabel::Other`), and until Q127 the
    /// spelling `"other"` appeared in **no** pinned report byte and **no**
    /// assertion anywhere in the tree — the R69 shape, in a second enum,
    /// undetected because an unrendered value moves no pin (D105 §4.3).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::NotEvaluated => "not-evaluated",
            Self::HybridPq => "hybrid-pq",
            Self::Ed25519Only => "ed25519-only",
            Self::Other => "other",
        }
    }
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
/// **Not-evaluated is neither a claim nor a verdict**: the stage did not
/// run, so this says nothing in either direction about where the work is
/// stored — and nothing here ever gates the evidence layer, because
/// "storage is the product's bonus, not its proof".
///
/// # What the evaluated arm counts, and what it deliberately does not
///
/// [`Evaluated`](Self::Evaluated) is R20's arm: for each unit ciphertext the
/// **bundle embeds**, BLAKE3-256 of those bytes against the address the
/// signed manifest records for that unit; and once for the manifest, the
/// address of the blob its own `{nonce, k_m}` reproduce. Three fields, and
/// the split between them is load-bearing: a unit-address mismatch and a
/// manifest-address mismatch are different findings about different bytes,
/// so they must be different *values* here, not one shared counter that
/// renders alike. See [`super::storage_linkage`] for the stage.
///
/// Unrevealed units are not counted at all. They have no ciphertext in the
/// bundle, so there is nothing to recompute — the layer's claim is about the
/// bytes present, and the reveal set in the same report already says how many
/// units those are. A count of what was *not* checked would be a new field
/// carrying information the report can already derive.
///
/// # Adding an arm here is a value addition, not a field addition
///
/// This doc said the slot was "a pre-Q14 extension per D29" until
/// **D105**. Q14 executed on 2026-07-28, so it was false when read and
/// false when written down: there is no open pre-freeze window.
///
/// What is true is that the freeze does not close this enum. D29 rule 1
/// fixes the declaration order of the report's **struct** fields; a new
/// enum *variant* moves no struct's field list, and `storage_linkage`
/// serializes in every report either way (D29 rule 4). So an arm added
/// here is a VALUE ADDITION and `REPORT_VERSION` stays `1` — the same
/// class, and the same reasoning, as
/// [`SupportingEvidenceResult::ArbitrumReceipt`].
///
/// D29's Consequences bullet names "R20's storage-linkage arm" as a
/// pre-Q14 *field* addition. That was a guess about an undesigned task,
/// and the same bullet's other guess — "R12's anchor detail" — was
/// measured wrong when R12 landed (D94 §2). D105 rules the test that
/// decides it: **a report change is a value addition iff no struct
/// report v1 could already serialize gains, loses or reorders a field.**
/// An arm that instead adds a field to this or any other frozen struct
/// is a FORMAT EVENT and costs a report-version bump.
///
/// Whatever lands here must arrive with a committed assertion that
/// renders it inside a whole canonical report — D105 ruling 4; the
/// receipt arm did not, and that is the whole of why R69 exists. R20's arm
/// arrives with one: `EXPECTED_CANONICAL_JSON_WITH_LINKAGE` in
/// `super::tests`, the third of D29's fixed-fixture literals, differential
/// against the control at this value and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageLinkageResult {
    /// The stage did not run: this build did not evaluate storage linkage
    /// (every report emitted before R20, and any run that does not ask for
    /// the stage). Says nothing about where the work is stored.
    NotEvaluated,
    /// The offline stage ran (R20): every embedded ciphertext, and the
    /// manifest, recomputed and compared against the addresses the bundle
    /// records.
    ///
    /// **Not a verdict.** Any combination of these values leaves the
    /// evidence layer exactly as it was; the pipeline enforces that by
    /// running the stage after every evidence stage and by giving it no way
    /// to report failure (see [`super::storage_linkage`]).
    Evaluated {
        /// Embedded unit ciphertexts whose BLAKE3-256 address equals the
        /// address the manifest records for that unit.
        units_matched: u64,
        /// Embedded unit ciphertexts whose recomputed address differs from
        /// the recorded one — including any whose bytes are over the chunk
        /// cap and therefore have no v1 address at all (D32).
        units_mismatched: u64,
        /// Whether the blob rebuilt from the embedded plaintext manifest
        /// under the storage record's own `{nonce, k_m}` addresses to the
        /// address that record claims.
        manifest_matched: bool,
    },
}

/// The one `units_matched` operand every artifact that renders
/// [`StorageLinkageResult::Evaluated`] is built from (D105 §5.3's sharing
/// rule, applied to this arm): the standalone byte pin, the `ALL` sweep and
/// the whole-report snapshot cannot be satisfied separately.
#[cfg(test)]
pub(crate) const LINKAGE_FIXTURE_UNITS_MATCHED: u64 = 3;

/// The shared `units_mismatched` operand — see
/// [`LINKAGE_FIXTURE_UNITS_MATCHED`]. Non-zero on purpose: an all-zero
/// fixture would render the same bytes whether the field were populated or
/// left at its default.
#[cfg(test)]
pub(crate) const LINKAGE_FIXTURE_UNITS_MISMATCHED: u64 = 1;

/// The shared `manifest_matched` operand — see
/// [`LINKAGE_FIXTURE_UNITS_MATCHED`].
#[cfg(test)]
pub(crate) const LINKAGE_FIXTURE_MANIFEST_MATCHED: bool = false;

impl StorageLinkageResult {
    /// Every storage-linkage value, in declaration order.
    ///
    /// **`#[cfg(test)]` since R20, and for [`SupportingEvidenceResult::ALL`]'s
    /// reason rather than a new one.** [`Self::Evaluated`] is a struct
    /// variant, so an array of *values* needs operands, and the tree has
    /// exactly one linkage operand triple — the `LINKAGE_FIXTURE_*` consts
    /// above, shared precisely so this sweep, the standalone byte pin and the
    /// whole-report snapshot cannot be satisfied separately. Minting
    /// non-test operands to keep the const public would create a *second*
    /// linkage fixture, which is the drift sharing exists to prevent.
    ///
    /// Removing it from the public API costs no caller: like the other `ALL`
    /// arrays here, this one's only consumer is its own sweep, and a sweep of
    /// the whole tree at R20 found no other reference.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 2] = [
        Self::NotEvaluated,
        Self::Evaluated {
            units_matched: LINKAGE_FIXTURE_UNITS_MATCHED,
            units_mismatched: LINKAGE_FIXTURE_UNITS_MISMATCHED,
            manifest_matched: LINKAGE_FIXTURE_MANIFEST_MATCHED,
        },
    ];

    /// This value's serialized **tag** — kebab-case, as `serde` emits it.
    ///
    /// Deliberately not "the value's spelling", for
    /// [`SupportingEvidenceResult::wire_name`]'s reason: since R20 this enum
    /// has both shapes, a bare string for the unit variant and an externally
    /// tagged object for the struct variant, and the tag is the part common
    /// to both that a value-space sweep can assert.
    ///
    /// Wildcard-free, so a third value cannot land unnamed here, and cannot
    /// be named without `storage_linkage_wire_names_are_the_serialized_spellings`
    /// demanding the spelling be written down (R-VAL). The type doc above
    /// requires whatever lands to arrive with an assertion rendering it
    /// inside a whole canonical report; this is the half a compiler can
    /// enforce.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::NotEvaluated => "not-evaluated",
            Self::Evaluated { .. } => "evaluated",
        }
    }
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

impl AnchorKind {
    /// Every anchor kind, in declaration order.
    ///
    /// The receipt is deliberately not here and never will be — it is not an
    /// anchor (MVP-SPEC.md line 110), and this array is a second place that
    /// says so. A third kind entering the taxonomy is a spec event, and this
    /// const plus [`Self::wire_name`] make it a loud one.
    pub const ALL: [Self; 2] = [Self::Ots, Self::Tsa];

    /// This kind's serialized spelling — the kebab-case name `serde` emits.
    ///
    /// The crate already had a wildcard-free match on this enum
    /// (`AnchorArtifacts::count_for`), but it returns *counts*: it makes a
    /// third kind a compile error and says nothing about how the third kind
    /// would be spelled in a report. This accessor is the spelling half, and
    /// `anchor_kind_wire_names_are_the_serialized_spellings` is the sweep that
    /// holds it to `serde`'s bytes (R-VAL, D105 §6).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Ots => "ots",
            Self::Tsa => "tsa",
        }
    }
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

impl AnchorState {
    /// Every state, in the spec's order (MVP-SPEC.md lines 129–135) — which
    /// is also the wire enum's value order (registry §6.1).
    pub const ALL: [Self; 7] = [
        Self::Proven,
        Self::ValidAtStampingCertSinceExpired,
        Self::Attested,
        Self::Pending,
        Self::InternallyConsistentOnly,
        Self::Invalid,
        Self::Absent,
    ];

    /// This state's serialized spelling — the kebab-case name `serde` emits,
    /// and (deliberately) byte-identical to the wire enum's
    /// `AnchorStatus::registry_value_name`.
    ///
    /// The two enums are independent by design: the report is a *separate,
    /// non-wire* format (D27/D29) and a verifier derives its own state rather
    /// than copying the sealer's. But both freeze at Q14 (D84 §7), and
    /// nothing bound their spellings to each other until the registry freeze
    /// test's assertion C10 — a desynchronisation would have shipped one
    /// taxonomy under two names.
    ///
    /// Written as an exhaustive, wildcard-free match so a new variant fails
    /// compilation here as well as in the report.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::ValidAtStampingCertSinceExpired => "valid-at-stamping-cert-since-expired",
            Self::Attested => "attested",
            Self::Pending => "pending",
            Self::InternallyConsistentOnly => "internally-consistent-only",
            Self::Invalid => "invalid",
            Self::Absent => "absent",
        }
    }
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
    /// The anchor's source identity when known — **derived by the verifier
    /// from artifact content it has itself parsed, never copied from a
    /// bundle field**.
    ///
    /// The wire format carries no source string for either kind: D8 §1
    /// removed the TSA one from v1 (a sealer's claim, bound by nothing in an
    /// unsigned bundle) and there never was an OTS one. At M2, A18/R12 fill
    /// this from:
    ///
    /// - **TSA** — the verified certificate chain: the signer certificate's
    ///   subject / the ESSCertID-bound identity, evaluated against the
    ///   pinned root store (MVP-SPEC.md line 109). For [`AnchorState::Proven`]
    ///   or [`AnchorState::ValidAtStampingCertSinceExpired`] that is a
    ///   *verified* identity; for [`AnchorState::InternallyConsistentOnly`]
    ///   or [`AnchorState::Invalid`] it is a *claimed* one read from the same
    ///   token and MUST render as such — the state already says the chain did
    ///   not close, so the rendering discipline is inherited, not invented.
    /// - **OTS** — the `.ots` attestations, which name their calendars.
    ///
    /// M0/M1 leave it `None` throughout: the pipeline parses no artifact byte
    /// and deliberately copies no bundle-recorded anchor metadata.
    pub source: Option<String>,
    /// The capture instant the **sealer** recorded for this artifact —
    /// registry §7.9 key 3 (TSA, `req`) and §7.8 key 4 (OTS, inside the D79
    /// upgrade group, hence `None` on an un-upgraded `.ots`).
    ///
    /// **Sealer-written and bound by nothing**: the bundle is unsigned and
    /// `anchor_digest` covers the manifest envelope, not the anchor
    /// sections. Nothing may ever compare it to anything — D59 §6(a) makes
    /// that a normative prohibition in *any* direction, off a measurement of
    /// a capture machine 129 s slow.
    ///
    /// # Rendering (D95, format-permanent for report v1)
    ///
    /// Rendered in **every** state that emits a slot, `invalid` included,
    /// with **no state condition**: the field's trustworthiness does not vary
    /// with the verdict, so a state gate would publish the false implicature
    /// that a visible date had been corroborated by the state beside it.
    /// The form is `u64::to_string()` — **decimal POSIX seconds**, no
    /// separator, no timezone, no date form — the same spelling
    /// [`WorkMetadata::claimed_time_informational_only`] froze at Q14 over
    /// the same kind of value.
    ///
    /// The honesty obligation that creates is discharged by a **label**
    /// (R18's wording set, in the `claimed_time` register of MVP-SPEC.md
    /// line 137), never by conditional presence. **R18 landed that label**:
    /// [`wording::fetch_date_line`] is the one row every renderer uses — it
    /// takes no [`AnchorState`], so the label cannot vary with the verdict,
    /// and it says outright that the date is not evidence for the state above
    /// (the reading a refuted anchor invites). It is snapshot-frozen under
    /// `invalid` in `tests/verdict_wording.rs`.
    ///
    /// [`wording::fetch_date_line`]: super::wording::fetch_date_line
    ///
    /// MVP-SPEC.md names fetch dates at lines 108 and 114 only, both as
    /// *bundle content*; there is no spec line requiring this rendering, and
    /// this doc said otherwise until 2026-08-06 (**R73**).
    pub fetch_date: Option<String>,
}

/// Supporting-evidence slot — a class wholly separate from anchors,
/// never headline-eligible (MVP-SPEC.md line 110: "supporting evidence —
/// no independently proven time").
///
/// R12 (M2) added the [`ArbitrumReceipt`](Self::ArbitrumReceipt) arm: a
/// bundle that opted the receipt in renders it **here**, and nowhere else.
///
/// # This enum is where A19 stops being a convention
///
/// [`AnchorKind`] has no receipt variant and [`AnchorResult`] is only ever
/// built from an [`AnchorVerdict`](crate::anchor::model::AnchorVerdict), so
/// the receipt has no route into `anchors` to begin with. What this type adds
/// is the other direction: the arm it *does* have carries **no time field and
/// no state field** — not a null one, none — so "supporting evidence — no
/// independently proven time" is a property of the shape rather than of a
/// renderer remembering it. `verified_time_unix` cannot be read off a receipt
/// because there is nothing to read.
///
/// The two recorded values are the ones registry §7.10 already calls
/// display-only and never verdict-bearing. The advisory two-RPC confirmation
/// (A17/D55) is deliberately **absent**: it is an overlay on an overlay, it
/// moves nothing, and `verify_bundle` performs no online step at all.
///
/// # Adding this arm moved no pinned byte — a format signal, not a coverage one
///
/// All 21 R9 report vectors carry `"supporting_evidence":"none"` — no
/// committed vector opts a receipt in — and a unit variant's serialization is
/// unchanged by the existence of a sibling. Q14 froze the declaration order of
/// report **v1**'s **struct** fields (D29 rule 1); this adds a *value*, not a
/// field, and the slot is present in every report either way (D29 rule 4).
/// D105 states the test both slots are ruled by, so the rule has one home
/// rather than two paraphrases.
///
/// The heading above says two things at once, and R12 wrote down only the
/// first. Zero moved pins is a **correct format signal** — a format event
/// moves all 21 report cases and all 26 `REPORT_DIGEST_BY_SHAPE` rows (R32
/// measured exactly that at `report_version` 0 → 1), so zero is affirmative
/// evidence this was not one. It is also an **empty coverage signal**, because
/// a value nothing renders moves zero pins too; the tree has no second signal,
/// which is why this arm shipped with nothing red and nothing wrong (D105
/// §4.3). The coverage half is discharged separately, by the receipt-bearing
/// twin of D29's fixed-fixture snapshot in `verify/mod.rs`
/// (`EXPECTED_CANONICAL_JSON_WITH_RECEIPT`), which is the only artifact in the
/// tree that renders this arm inside a whole canonical report — R69.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportingEvidenceResult {
    /// No supporting evidence embedded (also the M0 stage stub).
    None,
    /// The bundle carries an Arbitrum payment receipt (**A19**).
    ///
    /// No on-chain datum contains `anchor_digest`, so this proves payment
    /// and existence-by-block, never *this* work's time.
    ArbitrumReceipt {
        /// The recorded Arbitrum block number — display-only, unverified in
        /// v1 (registry §7.10 key 1).
        block_number: u64,
        /// How many transaction hashes the receipt records.
        transaction_count: u64,
    },
}

impl SupportingEvidenceResult {
    /// Every supporting-evidence value, in declaration order.
    ///
    /// **`#[cfg(test)]`, and that is a decision rather than an oversight.**
    /// [`Self::ArbitrumReceipt`] is a struct variant, so an array of *values*
    /// needs operands, and the tree has exactly one canonical receipt operand
    /// pair — [`RECEIPT_FIXTURE_BLOCK_NUMBER`] and
    /// [`RECEIPT_FIXTURE_TRANSACTION_COUNT`], shared precisely so the
    /// standalone pin and the whole-report snapshot cannot be satisfied
    /// separately (D105 §5.3). Minting non-test operands so this const could
    /// be public would create a **second** receipt fixture, which is the
    /// exact drift that sharing exists to prevent, and would put two
    /// arbitrary numbers into the crate's public API for no caller: like the
    /// other `ALL` arrays here, this one's only consumer is its sweep.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 2] = [
        Self::None,
        Self::ArbitrumReceipt {
            block_number: RECEIPT_FIXTURE_BLOCK_NUMBER,
            transaction_count: RECEIPT_FIXTURE_TRANSACTION_COUNT,
        },
    ];

    /// This value's serialized **tag** — kebab-case, as `serde` emits it.
    ///
    /// Deliberately not "the value's spelling": a unit variant renders as the
    /// bare string `"none"`, and the struct variant renders as the externally
    /// tagged object `{"arbitrum-receipt":{…}}`. The tag is the part common to
    /// both shapes and the part a value-space sweep can assert, which is why
    /// `supporting_evidence_wire_names_are_the_serialized_tags` asserts *the
    /// string or a one-key object keyed by it* rather than one uniform shape
    /// (Q127: the sweep must be exhaustive, not uniform). The receipt's
    /// operands are pinned elsewhere — standalone by
    /// `the_receipt_arm_carries_no_time_and_no_state`, in composition by the
    /// receipt-bearing snapshot in `super::tests`.
    ///
    /// Wildcard-free, so a third value cannot land unnamed here — the R69
    /// shape this enum is the reason for.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ArbitrumReceipt { .. } => "arbitrum-receipt",
        }
    }
}

/// The one `block_number` every test that renders the receipt arm uses.
///
/// Two assertions pin this arm and they live in different modules: the
/// standalone spelling test below, and the whole-report snapshot
/// `EXPECTED_CANONICAL_JSON_WITH_RECEIPT` in `verify/mod.rs`. Sharing the
/// operand is what makes them move **together** — with two hand-copied
/// literals a future edit could re-pin one and leave the other green while
/// the two disagreed about what "the receipt fixture" is (D105 §5.3).
#[cfg(test)]
pub(crate) const RECEIPT_FIXTURE_BLOCK_NUMBER: u64 = 271_828_182;

/// The one `transaction_count` every test that renders the receipt arm uses;
/// see [`RECEIPT_FIXTURE_BLOCK_NUMBER`].
#[cfg(test)]
pub(crate) const RECEIPT_FIXTURE_TRANSACTION_COUNT: u64 = 2;

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
    ///
    /// **A manifest-declared figure** — the sealer's datum, structurally
    /// constrained but never independently measured. `check_tiling`
    /// (`crates/antseal-core/src/verify/structural.rs:307`) requires the
    /// file's non-mirror units to be sorted, non-overlapping, and to
    /// exactly tile `[0, total_size)`, so the number cannot disagree with
    /// the manifest's own unit table; and every span in
    /// [`FileReveal::revealed_spans`] opened against its commitment, so
    /// those ranges are backed by bytes the verifier has actually seen.
    /// Neither check reaches the unrevealed remainder: a self-consistent
    /// overstatement there is contradicted by nothing in the bundle.
    /// Render it as declared — it is the denominator a reader needs, not
    /// a figure the verifier vouches for.
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
    ///
    /// `Some` **implies `fully_revealed`**, and the producer enforces it
    /// (R53): rows 9–10 — the `raw_commit` opening and the
    /// `canonicalize_v(raw) == canonical` binding — run only for a full
    /// reveal, so this is the one state in which the mirror's bytes are
    /// proven to be the file's original bytes. A mirror revealed alongside
    /// a *partial* reveal is verified as a unit but deliberately not
    /// reported here: presenting it as "the original file" would promote
    /// unbound bytes (2026-07-31 review, finding 8).
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
    /// placeholder exposes, and the **sealer's** datum.
    ///
    /// Weaker than [`FileReveal::total_size`], which at least has opened
    /// units under part of it: a wholly unrevealed file has no opened
    /// unit at all, so agreement with the manifest's own unit table
    /// (`check_tiling`,
    /// `crates/antseal-core/src/verify/structural.rs:307`) is the *only*
    /// constraint on this number, and nothing outside the manifest can
    /// contradict it. Render it as declared, never as measured.
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

    /// **A19 through the report's own bytes** (R12).
    ///
    /// Two claims, and the second is the one that has to be checked on the
    /// *serialized form* rather than on the type: the receipt's rendering
    /// contains no time and no state. A future field named `verified_time_unix`
    /// or `state` on this arm — the natural way to "make the receipt render
    /// like the others" — fails here before it reaches a renderer.
    ///
    /// The `"none"` half is pinned in the row above; this pins the arm that
    /// exists alongside it, so adding the variant cannot have changed what a
    /// receipt-free report says.
    ///
    /// This is the **standalone** pin: it can never show the
    /// `"supporting_evidence":` key, the object sitting where a string sat, or
    /// the sibling ordering D29 rule 1 is about. Those need a whole-report
    /// literal, and that is `EXPECTED_CANONICAL_JSON_WITH_RECEIPT` in
    /// `verify/mod.rs` — built on the same two operands (D105 §5.3).
    #[test]
    fn the_receipt_arm_carries_no_time_and_no_state() {
        let json = serde_json::to_string(&SupportingEvidenceResult::ArbitrumReceipt {
            block_number: RECEIPT_FIXTURE_BLOCK_NUMBER,
            transaction_count: RECEIPT_FIXTURE_TRANSACTION_COUNT,
        })
        .expect("slot serializes");
        assert_eq!(
            json,
            r#"{"arbitrum-receipt":{"block_number":271828182,"transaction_count":2}}"#
        );
        for forbidden in [
            "time", "state", "proven", "anchor", "verified", "genTime", "gen_time",
        ] {
            assert!(
                !json.contains(forbidden),
                "the receipt's rendering names `{forbidden}` — MVP-SPEC.md line 110 gives it \
                 no independently proven time, and A19 makes that structural"
            );
        }
    }

    /// `wire_name()` is what `serde` actually emits, for every state.
    ///
    /// Without this the accessor would be a second, hand-maintained spelling
    /// table that could drift from the bytes — exactly the "second authority"
    /// shape the wire registry excludes elsewhere. `AnchorState::ALL` makes
    /// the sweep exhaustive, and the wildcard-free match in `wire_name`
    /// makes a new variant a compile error rather than a missing row.
    ///
    /// This was the tree's only enum with that triple until Q127 gave the
    /// other four the same one; the four sweeps below are its siblings.
    #[test]
    fn wire_name_is_the_serialized_spelling() {
        for state in AnchorState::ALL {
            let json = serde_json::to_string(&state).expect("state serializes");
            assert_eq!(
                json,
                format!("\"{}\"", state.wire_name()),
                "{state:?}: wire_name() disagrees with serde"
            );
        }
    }

    /// One value, one bare string, no second table: `serde`'s **bytes** are
    /// the authority and `wire_name()` is checked against them.
    ///
    /// Deliberately not a parse-and-compare: R-VAL is a statement about what
    /// the report *emits*, and reading the bytes back with a deserializer
    /// would assert a round trip instead (no report type derives
    /// `Deserialize`, and D105 §8 makes deriving one a re-open trigger).
    fn assert_serializes_as_bare_spelling<T: Serialize + fmt::Debug>(value: &T, wire_name: &str) {
        let json = serde_json::to_string(value).expect("value serializes");
        assert_eq!(
            json,
            format!("\"{wire_name}\""),
            "{value:?}: wire_name() disagrees with serde"
        );
    }

    /// Every [`SignatureScheme`] value is swept — **and this is the one that
    /// found something** (Q127).
    ///
    /// [`SignatureScheme::Other`] has been constructible since R5 and is
    /// produced at one pipeline site, yet before this test no committed
    /// assertion rendered `"other"`: not one of the 21 pinned report vectors
    /// (20 carry `hybrid-pq`, 1 `ed25519-only`), not the fixed-fixture
    /// snapshots, not a hand-written row. It moved no pin because a value
    /// nothing emits moves no pin, and that is indistinguishable from safety
    /// by pin count alone (D105 §4.3).
    ///
    /// The spelling list is compared against a hand-written literal on
    /// purpose. `ALL` growing by one fails that comparison on **length**
    /// before any spelling is examined, so the lane that mints the fifth
    /// scheme has to write its wire name down here — which is the smallest
    /// committed assertion R-VAL will accept, and strictly more than
    /// `assert_eq!(ALL.len(), 4)` would say (rustc already knows that).
    #[test]
    fn signature_scheme_wire_names_are_the_serialized_spellings() {
        let spellings: Vec<&str> = SignatureScheme::ALL
            .iter()
            .map(|scheme| scheme.wire_name())
            .collect();
        assert_eq!(
            spellings,
            ["not-evaluated", "hybrid-pq", "ed25519-only", "other"],
            "the signature-scheme value space moved; a new value must be \
             written down here and rendered in a whole report (R-VAL)"
        );
        for scheme in SignatureScheme::ALL {
            assert_serializes_as_bare_spelling(&scheme, scheme.wire_name());
        }
    }

    /// Every [`StorageLinkageResult`] value is swept — and the sweep did
    /// what it was built for.
    ///
    /// It held one value from Q127 until R20, and the degenerate case was the
    /// point: the `evaluated` arm arrived at a slot that already had the
    /// triple, and this literal is what refused to stay green when it did.
    /// The name is kept from that era deliberately — three records cite it —
    /// even though the assertion is now the tag-or-object one
    /// [`SupportingEvidenceResult`]'s sweep uses, exhaustive without being
    /// uniform (Q127).
    #[test]
    fn storage_linkage_wire_names_are_the_serialized_spellings() {
        let spellings: Vec<&str> = StorageLinkageResult::ALL
            .iter()
            .map(|slot| slot.wire_name())
            .collect();
        assert_eq!(
            spellings,
            ["not-evaluated", "evaluated"],
            "the storage-linkage value space moved; a new value must be \
             written down here and rendered in a whole report (R-VAL)"
        );
        for slot in StorageLinkageResult::ALL {
            let json = serde_json::to_string(&slot).expect("value serializes");
            let tag = slot.wire_name();
            let bare = format!("\"{tag}\"");
            let tagged = format!("{{\"{tag}\":");
            assert!(
                json == bare || (json.starts_with(&tagged) && json.ends_with('}')),
                "{slot:?}: serde emits {json}, which is neither the bare \
                 spelling {bare} nor an object keyed by `{tag}`"
            );
        }
    }

    /// **The layer separation through the report's own bytes** (R20).
    ///
    /// The arm's three fields exist so that "a unit ciphertext does not
    /// address to its recorded address" and "the manifest blob does not" are
    /// different *values*, not one shared counter. Collapsing them into a
    /// single `mismatches` total — the natural tidy-up — makes R20's
    /// unit-mismatch and manifest-mismatch fixtures render identically, and
    /// fails here before it reaches a renderer.
    ///
    /// The second claim is the one that has to be checked on the serialized
    /// form: nothing in this arm's rendering claims a verdict. A field named
    /// `passed`, `verified` or `proven` would read as one beside
    /// `evidence.passed` in the same object, which is exactly the confusion
    /// MVP-SPEC.md line 118 forbids.
    ///
    /// This is the **standalone** pin: it can never show the
    /// `"storage_linkage":` key, the object sitting where a string sat, or
    /// the sibling ordering D29 rule 1 is about. Those need a whole-report
    /// literal, and that is `EXPECTED_CANONICAL_JSON_WITH_LINKAGE` in
    /// `verify/mod.rs` — built on the same three operands.
    #[test]
    fn the_evaluated_arm_separates_the_manifest_from_the_units() {
        let json = serde_json::to_string(&StorageLinkageResult::Evaluated {
            units_matched: LINKAGE_FIXTURE_UNITS_MATCHED,
            units_mismatched: LINKAGE_FIXTURE_UNITS_MISMATCHED,
            manifest_matched: LINKAGE_FIXTURE_MANIFEST_MATCHED,
        })
        .expect("slot serializes");
        assert_eq!(
            json,
            r#"{"evaluated":{"units_matched":3,"units_mismatched":1,"manifest_matched":false}}"#
        );

        // The same total, split the other way: a distinct value, so a
        // renderer cannot present the two findings alike.
        let manifest_only = serde_json::to_string(&StorageLinkageResult::Evaluated {
            units_matched: LINKAGE_FIXTURE_UNITS_MATCHED + LINKAGE_FIXTURE_UNITS_MISMATCHED,
            units_mismatched: 0,
            manifest_matched: false,
        })
        .expect("slot serializes");
        assert_ne!(json, manifest_only);

        for forbidden in ["passed", "verified", "proven", "valid", "evidence"] {
            assert!(
                !json.contains(forbidden),
                "the storage-linkage rendering names `{forbidden}` — MVP-SPEC.md \
                 line 118 gives this layer no verdict to carry"
            );
        }
    }

    /// Every [`AnchorKind`] value is swept.
    ///
    /// Both spellings are already pinned inside whole reports (the vectors
    /// and the fixed-fixture snapshot render `ots` and `tsa`), so what this
    /// adds is the *enumerability* half: a third kind is a compile error at
    /// `AnchorKind::wire_name` and a red list here, rather than a value that
    /// happens to be covered because some fixture happens to carry it.
    #[test]
    fn anchor_kind_wire_names_are_the_serialized_spellings() {
        let spellings: Vec<&str> = AnchorKind::ALL
            .iter()
            .map(|kind| kind.wire_name())
            .collect();
        assert_eq!(
            spellings,
            ["ots", "tsa"],
            "the anchor-kind taxonomy moved; a new kind must be written down \
             here and rendered in a whole report (R-VAL)"
        );
        for kind in AnchorKind::ALL {
            assert_serializes_as_bare_spelling(&kind, kind.wire_name());
        }
    }

    /// Every [`SupportingEvidenceResult`] value is swept — and this sweep is
    /// **exhaustive without being uniform**.
    ///
    /// [`SupportingEvidenceResult::None`] renders as the bare string
    /// `"none"`; [`SupportingEvidenceResult::ArbitrumReceipt`] is a struct
    /// variant and renders as the externally tagged object
    /// `{"arbitrum-receipt":{…}}`. A sweep insisting on one shape would have
    /// to exclude the arm it exists to cover, so the assertion is *the bare
    /// spelling or a one-key object keyed by the tag* — which still fails on
    /// a renamed tag, a changed serde representation, or an arm that starts
    /// rendering as something else entirely.
    ///
    /// The receipt's operands are not re-typed here: `ALL` is built from the
    /// shared fixture consts, so this sweep, the standalone byte pin and the
    /// whole-report snapshot all move together (D105 §5.3).
    #[test]
    fn supporting_evidence_wire_names_are_the_serialized_tags() {
        let tags: Vec<&str> = SupportingEvidenceResult::ALL
            .iter()
            .map(|value| value.wire_name())
            .collect();
        assert_eq!(
            tags,
            ["none", "arbitrum-receipt"],
            "the supporting-evidence value space moved; a new value must be \
             written down here and rendered in a whole report (R-VAL)"
        );
        for value in SupportingEvidenceResult::ALL {
            let json = serde_json::to_string(&value).expect("value serializes");
            let tag = value.wire_name();
            let bare = format!("\"{tag}\"");
            let tagged = format!("{{\"{tag}\":");
            assert!(
                json == bare || (json.starts_with(&tagged) && json.ends_with('}')),
                "{value:?}: serde emits {json}, which is neither the bare \
                 spelling {bare} nor an object keyed by `{tag}`"
            );
        }
    }
}
