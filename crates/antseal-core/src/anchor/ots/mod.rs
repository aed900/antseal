//! The in-house `.ots` codec (task **A11**) and the embedded Bitcoin header
//! check (task **A12**).
//!
//! # Why this is in-house
//!
//! `opentimestamps =0.2.0` is **adopted in no form** — not pinned, not
//! wrapped, not vendored (`docs/decisions/D58-opentimestamps-viability.md`).
//! The register framed the question as portability and the contingency as
//! vendoring, and D58 overturned both: the crate *does* compile on `=1.92.0`
//! and on `wasm32-unknown-unknown`, and vendoring is not cheaper than writing
//! because the crate is edition 2015 and every line that would need to change
//! is a line. It was decided on **measured behaviour**, and each measurement
//! is a regression test in this module:
//!
//! | input | what the crate did | the test here |
//! | --- | --- | --- |
//! | **80 B** | uncatchable `SIGABRT` — `vec![0; attacker_varint]` asked for 549 755 813 887 bytes | `tests::unknown_attestation_with_huge_declared_length_is_rejected_not_aborted` |
//! | **102 B** | a second `SIGABRT` — the operand was capped, the *running value* was not, and hexlify doubles it | `tests::hexlify_chain_cannot_grow_the_running_value` |
//! | **87 B** | panicked in debug, **parsed to a different answer in release** | `tests::thirteen_byte_varint_is_rejected` + `tests::ots_module_contains_no_runtime_shift` |
//! | **90 B** | reported a **different attestation set** than `python-opentimestamps` from identical bytes | `tests::attestation_payload_length_is_authoritative` |
//!
//! The 80- and 102-byte aborts are `handle_alloc_error`, **not** panics:
//! `catch_unwind` cannot intercept them, and in WASM they are module traps.
//! No wrapper could have helped — `from_reader` fuses parse, op execution and
//! recursion into one call, so any pre-filter enforcing A11's limits *is* the
//! parser (D58 §5). Cost of writing it instead: **+0 packages**, against the
//! crate's +13.
//!
//! The fourth is the one that matters most, and it would matter even if the
//! aborts were all fixed: sealer-authored bytes showing different anchors to
//! different verifiers is precisely what antseal exists to deny.
//!
//! # Two rules that look like one
//!
//! A11's `Do` originally treated unknown ops and unknown attestation types
//! alike. They are not alike, and the difference is structural (D58 §12.2):
//!
//! - an unknown **attestation** payload is length-prefixed, so it can be
//!   skipped and surfaces as [`OtsAttestation::UnknownType`] — carried as
//!   evidence, never verified, its payload bytes deliberately not retained;
//! - an unknown **op tag carries no length**, so it cannot be skipped at all
//!   and fails the artifact with [`OtsError::UnknownOp`];
//! - a **registered-but-unimplemented** op *can* be skipped — it is one bare
//!   wire byte — so it makes the subtree below it indeterminate and every
//!   attestation there carries `None`.
//!
//! Per **F3**, unknown is *not* over-limit in any of the three cases.
//!
//! # Where this may be called from
//!
//! The anchor stage only (rule F1). Nothing here is reachable from
//! `SealProof::decode`, and an over-limit artifact fails **that anchor
//! alone**, as `invalid` (rules F2/F3).

mod error;
mod exec;
mod header;
mod limits;
mod parse;

pub use error::{OtsError, PayloadDefect};
pub use header::{
    EmbeddedHeader, check_embedded_header, header_commits, header_time_unix, merkle_root_of,
};
pub use limits::{
    MAX_OTS_ATTESTATION_PAYLOAD_BYTES, MAX_OTS_ATTESTATIONS, MAX_OTS_BRANCH_WIDTH, MAX_OTS_DEPTH,
    MAX_OTS_OPERAND_BYTES, MAX_OTS_OPS, MAX_OTS_VALUE_BYTES,
};

/// A parsed and executed `.ots` artifact.
///
/// It carries attestations and nothing else. In particular it has **no
/// `stamped_digest` field**, and that is deliberate rather than an omission:
/// D58 §10.2 makes `anchor_digest` a *required parameter* of [`parse_ots`],
/// so the digest-commitment comparison happens inside the parser, before the
/// walk, and a wrong-digest `.ots` can never be used as a work amplifier.
/// D91 §6.4 rules that D56's rule O2 therefore **names an outcome rather than
/// adding a second check**, and says so explicitly: *"Do not add a
/// `stamped_digest` field to make O2 literally executable."*
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtsArtifact {
    /// Every attestation node in the file, in document order.
    ///
    /// Every node is reported even when its value is indeterminate, so a
    /// `.ots` that mixes a verifiable branch with one behind an unimplemented
    /// op still yields the verifiable half — which is what makes "sibling
    /// subtrees are unaffected" true in the type rather than in prose.
    pub attestations: Vec<OtsAttestation>,
}

/// One attestation node, with the value the ops derive at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtsAttestation {
    /// A calendar attestation.
    Pending {
        /// The calendar's URI, as the payload spells it.
        uri: String,
        /// The ops-derived value at this node — the string A14 puts in the
        /// upgrade URL. `None` when the path here crossed a
        /// registered-but-unimplemented op, so the value is indeterminate and
        /// this attestation is unverifiable. Measured 44 bytes for all six
        /// A25 captures.
        commitment: Option<Vec<u8>>,
    },
    /// A Bitcoin attestation.
    Bitcoin {
        /// The attested block height.
        height: u64,
        /// The ops-derived value at this node, `None` under the same
        /// condition as [`Self::Pending::commitment`]. A12 byte-compares it
        /// with the embedded 80-byte header's merkle-root field; a length
        /// other than 32 fails that compare naturally, so the parser does not
        /// assert one.
        merkle_root: Option<Vec<u8>>,
    },
    /// An attestation type this verifier does not know.
    ///
    /// Skipped structurally — its payload is length-prefixed — carried as
    /// evidence, never verified. **The payload bytes are deliberately not
    /// retained**; only the length is. This is what keeps
    /// `internally-consistent-only` reachable for OTS (D56 rule O9): the
    /// OpenTimestamps attestation registry is open-ended, Litecoin and
    /// Ethereum calendars exist, and an `.ots` merged from a calendar antseal
    /// does not implement is exactly this shape. Calling it `invalid` would
    /// accuse an honest artifact of forgery; calling it `pending` would offer
    /// `status --upgrade`, which can never help.
    UnknownType {
        /// The 8-byte attestation type tag.
        tag: [u8; 8],
        /// The declared payload length, at most
        /// [`MAX_OTS_ATTESTATION_PAYLOAD_BYTES`].
        payload_len: u32,
    },
}

/// Parse a `.ots` artifact and execute its op DAG against the digest it must
/// stamp.
///
/// # The check order is frozen (D58 §10.3)
///
/// | order | check | code |
/// | --- | --- | --- |
/// | 0 | *(verify stage 1, F's)* `input.len() > MAX_OTS_BYTES` | `bundle-ots-too-large` |
/// | 1 | 31-byte magic | `anchor-ots-bad-magic` |
/// | 2 | version varuint `== 1` | `anchor-ots-unsupported-version` |
/// | 3 | digest-type tag `== 0x08` | `anchor-ots-unsupported-digest-type` |
/// | 4 | 32 digest bytes present | `anchor-ots-truncated` |
/// | 5 | **start digest `== anchor_digest`** | `anchor-ots-digest-mismatch` |
/// | 6 | walk the DAG, limits below | per limit |
/// | 7 | input fully consumed | `anchor-ots-trailing-bytes` |
///
/// and inside the walk, per child: **f** width; then for an op **b** depth,
/// **c** op count, **d** operand length *(before reading)*, **e** resulting
/// value length *(before allocating)*; for an attestation **g** count, **h**
/// payload length *(before allocating)*, **i** payload consumed by its own
/// parse; with **a** the 9-byte varuint bound and **j** any read past the end
/// of input, everywhere.
///
/// # `anchor_digest` is a parameter, not an option
///
/// The signature makes *"parse without checking the digest"* unspellable.
/// Step 5 sits ahead of the walk because every attestation in the file
/// descends from the start digest, so the equality on that one header field
/// **is** the commitment check — and a wrong-digest `.ots` therefore costs
/// one 32-byte comparison and can never amplify work.
///
/// # No total-size cap of its own, and it must not grow one
///
/// `MAX_OTS_BYTES` fires in verify stage 1 over the bundle field, and A28
/// bounds A13's merged file; a third would be the duplicate A11's Accept has
/// a review item against (D58 §10.3 rule 5). Safety does not depend on it:
/// an arbitrarily long run of `0x08` dies at [`MAX_OTS_OPS`], of `0xff` at
/// [`MAX_OTS_BRANCH_WIDTH`], of `0x00`-attestations at
/// [`MAX_OTS_ATTESTATIONS`].
///
/// # Errors
///
/// Any [`OtsError`]. Every one renders **that anchor alone** `invalid`
/// (rule F2/F3). This function never panics and never aborts, on any input.
pub fn parse_ots(bytes: &[u8], anchor_digest: &[u8; 32]) -> Result<OtsArtifact, OtsError> {
    parse::parse_measured(bytes, anchor_digest).map(|(artifact, _)| artifact)
}

/// [`parse_ots`], plus the structural shape the walk observed.
///
/// The quantities the seven (b)-class limits bound, measured **by the parser
/// itself**. It exists so that the F4 registry's *"measured against"* cells
/// are never filled from a second implementation that could drift from the
/// one that enforces them — and specifically so that **A25's re-measurement**
/// of the four bootstrapped `upgraded/` rows, once the two-day OTS cycle
/// completes, is a call rather than a rewrite (D58 §9.5, §13.1).
///
/// # Errors
///
/// Exactly [`parse_ots`]'s. This is the same walk; `parse_ots` drops the
/// shape.
pub fn parse_ots_measured(
    bytes: &[u8],
    anchor_digest: &[u8; 32],
) -> Result<(OtsArtifact, OtsShape), OtsError> {
    parse::parse_measured(bytes, anchor_digest)
}

/// What a `.ots` artifact actually measures, against the seven limits.
///
/// Every field is the *maximum observed*, except [`Self::ops`] and
/// [`Self::attestations`], which are totals — matching what each limit
/// bounds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OtsShape {
    /// Total op steps across every branch — bounded by [`MAX_OTS_OPS`].
    pub ops: u32,
    /// Longest root-to-attestation path in op edges, root at 0 — bounded by
    /// [`MAX_OTS_DEPTH`]. An attestation is a leaf hanging off a node, not a
    /// node of its own, so it does not add a level (D58 §9.3).
    pub max_depth: u32,
    /// Most children any one fork node has — bounded by
    /// [`MAX_OTS_BRANCH_WIDTH`].
    pub max_width: u32,
    /// Attestation nodes in the file — bounded by [`MAX_OTS_ATTESTATIONS`].
    pub attestations: u32,
    /// Longest append/prepend operand — bounded by
    /// [`MAX_OTS_OPERAND_BYTES`].
    pub max_operand_bytes: u32,
    /// Longest running value, the start digest included — bounded by
    /// [`MAX_OTS_VALUE_BYTES`]. Steps under an indeterminate value
    /// contribute nothing, because nothing is materialised there.
    pub max_value_bytes: u32,
    /// Longest attestation payload — bounded by
    /// [`MAX_OTS_ATTESTATION_PAYLOAD_BYTES`].
    pub max_attestation_payload_bytes: u32,
}

// ── committed fixtures ───────────────────────────────────────────────────
//
// `include_bytes!` rather than `fs::read`: the `wasm32-core-tests` lane
// executes this crate's `--lib` unit tests on `wasm32-unknown-unknown`, which
// has no filesystem (P14), and D58 §11's last row requires native and wasm32
// to agree on every fixture and every rejection code.

/// The 3-calendar merged pending `.ots` for golden-vector digest A, built by
/// D58 §7.3's recipe from the A25 captures and committed by A11.
#[cfg(test)]
const MERGED_A: &[u8] =
    include_bytes!("../../../../../testdata/anchors/A25-bootstrap/merged-A.ots");

/// The same for digest B.
#[cfg(test)]
const MERGED_B: &[u8] =
    include_bytes!("../../../../../testdata/anchors/A25-bootstrap/merged-B.ots");

/// A **real** upgraded mainnet proof over Bitcoin blocks 449397 and 449399.
///
/// **Provenance, stated because the margin it feeds is bootstrapped and not
/// measured:** these bytes are the `LARGE_TEST` constant from
/// `opentimestamps-0.2.0/src/lib.rs`, not an A25 capture. The two-day OTS
/// pending → upgraded cycle started 2026-08-02T19:16Z and cannot complete
/// before 2026-08-04, so **A25 must re-measure the four `upgraded/` F4 rows
/// against the real fixture and append** (D58 §9.5, §13.1).
#[cfg(test)]
const UPGRADED_LARGE_TEST: &[u8] = include_bytes!(
    "../../../../../testdata/anchors/A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots"
);

/// Every committed `.ots` fixture, for checks that quantify over all of them.
#[cfg(test)]
const ALL_OTS_FIXTURES: &[&[u8]] = &[MERGED_A, MERGED_B, UPGRADED_LARGE_TEST];

/// Golden-vector digest A — the digest `merged-A.ots` stamps.
#[cfg(test)]
const DIGEST_A: [u8; 32] =
    *include_bytes!("../../../../../testdata/anchors/A25-bootstrap/digest-A.bin");

/// Golden-vector digest B.
#[cfg(test)]
const DIGEST_B: [u8; 32] =
    *include_bytes!("../../../../../testdata/anchors/A25-bootstrap/digest-B.bin");

/// The digest `UPGRADED_LARGE_TEST` stamps, read out of its own header.
#[cfg(test)]
const DIGEST_LARGE_TEST: [u8; 32] = [
    0x6f, 0xd9, 0xc1, 0xc4, 0xf0, 0x96, 0xb7, 0x7e, 0x6d, 0x44, 0x57, 0xba, 0xc1, 0xc7, 0xf5, 0x10,
    0x10, 0xd3, 0x18, 0xdb, 0x48, 0x3f, 0x28, 0x68, 0xd3, 0x79, 0x58, 0x43, 0xf0, 0x98, 0xd3, 0x78,
];

#[cfg(test)]
mod tests;
