//! **A2** — the anchor artifact and verdict data model.
//!
//! Four things live here, and nothing else. No parsing (A5/A11), no chain
//! validation (A9), no state machine (A18) — those consume these types.
//!
//! 1. **What a verifier may read out of an anchor artifact**
//!    ([`OtsArtifactView`], [`TsaArtifactView`], [`ReceiptArtifact`],
//!    [`AnchorArtifacts`]). Borrowed views over the *already decoded* F-layer
//!    types, deliberately narrower than the wire: `status` is not on them.
//! 2. **The per-anchor verdict datum** ([`AnchorVerdict`]) over the frozen
//!    seven states, with the invariants of
//!    `docs/decisions/D53-chain-invalid-at-gentime.md` §4 built into the
//!    constructors rather than checked afterwards.
//! 3. **Online evidence** ([`OnlineEvidence`]) — the agreed results a host
//!    (CLI via `antseal-anchor`, or the page's JS) feeds into WASM-safe core.
//!    Core never fetches.
//! 4. **Capture records** ([`TsaCaptureRecord`], [`OtsCaptureRecord`]) — what
//!    U persists in the vault at seal time.
//!
//! # The seven states are frozen, and this module mints none
//!
//! [`AnchorState`] (`crate::verify::report`) and `AnchorStatus`
//! (`crate::bundle::registry`) are the report-side and wire-side spellings of
//! MVP-SPEC.md's taxonomy, pinned to each other by the registry freeze test's
//! assertion C10. A2 defines the *artifact* model that feeds them; it does not
//! redefine them, and [`spec_line`] records where each one is specified.
//!
//! # WASM-safety
//!
//! Pure data. No clock (`verify_at` is a parameter of A18's evaluator, not a
//! field here), no I/O, no randomness. [`OnlineEvidence`] is constructible
//! from literals, which is the property that lets the page do its own fetches
//! in JS and hand the results in
//! (`docs/decisions/D90-anchor-http-substrate.md`).

use std::collections::BTreeMap;

use crate::bundle::registry::BLOCK_HEADER_LEN;
use crate::bundle::schema::{
    BundleV1, OpaqueBytes, OtsAnchor, OtsUpgrade, ReceiptRecord, TsaAnchor,
};
use crate::verify::report::AnchorResult;

pub use crate::verify::aggregate::headline_eligible;
pub use crate::verify::report::{AnchorKind, AnchorState};

// ---------------------------------------------------------------------------
// the taxonomy, cited
// ---------------------------------------------------------------------------

/// The MVP-SPEC.md line that **defines** `state`.
///
/// The verdict taxonomy is the seven-item list under "Verifier web page"
/// (MVP-SPEC.md line 127 introduces it; lines 129–135 are the states). A2's
/// Accept requires the model to cite the spec line for each state; putting the
/// citation in a `const fn` rather than only in prose makes it checkable, and
/// [`tests::spec_line_points_at_the_states_own_definition`] checks it against
/// the file.
///
/// Written as a wildcard-free match, so an eighth state is a compile error
/// here as well as in [`headline_eligible`].
#[must_use]
pub const fn spec_line(state: AnchorState) -> u32 {
    match state {
        // 129: "`proven` **[H]** — a TSA token valid against the pinned root
        // store, or an OTS anchor `--online`-confirmed against Bitcoin
        // block H."
        AnchorState::Proven => 129,
        // 130: "`valid-at-stamping-cert-since-expired` **[H]** — TSA token
        // whose signature verifies and whose chain was valid at its genTime
        // but whose cert has since expired; still carries its
        // independently-proven stamping time (aging bundles must not silently
        // rot), so it remains headline-eligible."
        AnchorState::ValidAtStampingCertSinceExpired => 130,
        // 131: "`attested` — upgraded OTS, header embedded, **not**
        // headline-eligible offline; `--online` promotes it to `proven`."
        AnchorState::Attested => 131,
        // 132: "`pending` — OTS not yet upgraded (…the same-day-reveal case
        // every demo hits)."
        AnchorState::Pending => 132,
        // 133: "`internally-consistent-only` — a well-formed
        // token/attestation that does not chain to a pinned root (TSA) or
        // match online (OTS): cryptographically well-formed but not
        // independently anchored; never headline-eligible."
        //
        // D56 corrects this line's *parenthetical trigger* for OTS (the
        // "match online" clause collides with lines 108/168, which win): the
        // OTS trigger is an `.ots` committing `anchor_digest` whose every
        // attestation is of a type this verifier cannot evaluate. The
        // definition — "cryptographically well-formed but not independently
        // anchored" — is unchanged, and it is the definition this model
        // encodes.
        AnchorState::InternallyConsistentOnly => 133,
        // 134: "`invalid` — signature/op check fails."
        AnchorState::Invalid => 134,
        // 135: "`absent` — anchor not present."
        AnchorState::Absent => 135,
    }
}

// ---------------------------------------------------------------------------
// artifact views (registry §§7.8–7.10)
// ---------------------------------------------------------------------------

/// One OpenTimestamps artifact, **as a verifier is entitled to read it**
/// (MVP-SPEC.md line 108; registry §7.8).
///
/// A borrowed view over F's decoded [`OtsAnchor`], not a second copy of it:
/// the `.ots` bytes and the D79 upgrade group are the artifact, and F already
/// owns their wire shape and their D10 byte caps.
///
/// # What is deliberately missing
///
/// **`status`.** Registry §7.8 key 0 is sealer-recorded and MVP-SPEC.md
/// line 121 makes the sealer an adversary — "the verifier derives its own
/// state". Dropping the field from the evaluation input turns "the verifier
/// believed the sealer's status" from a rule someone must remember into a
/// value that cannot be spelled. It is still on [`OtsAnchor`] for the sealer,
/// the journal, and R's "what the sealer claimed" rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtsArtifactView<'a> {
    ots: &'a [u8],
    upgrade: Option<&'a OtsUpgrade>,
}

impl<'a> OtsArtifactView<'a> {
    /// View a decoded bundle artifact.
    #[must_use]
    pub fn from_anchor(anchor: &'a OtsAnchor) -> Self {
        Self {
            ots: anchor.ots().as_slice(),
            upgrade: anchor.upgrade(),
        }
    }

    /// Build a view from raw parts — for A11/A12/A18 fixtures that need an
    /// artifact without assembling a whole `.sealproof`.
    #[must_use]
    pub const fn from_parts(ots: &'a [u8], upgrade: Option<&'a OtsUpgrade>) -> Self {
        Self { ots, upgrade }
    }

    /// The raw `.ots` bytes. Opaque until A11 executes them.
    #[must_use]
    pub const fn ots(&self) -> &'a [u8] {
        self.ots
    }

    /// The D79 upgrade group — attested height, the 80-byte block header, and
    /// the fetch date — present together or not at all.
    ///
    /// Its presence is **not** keyed on the sealer's `status` (registry §7.8,
    /// D79), so `Some` here is a statement about the artifact's shape and
    /// nothing else. D56 rule O8 is written over exactly this: an upgrade
    /// group with no evaluable Bitcoin attestation is well-formed v1 and
    /// renders `invalid`, not "malformed".
    #[must_use]
    pub const fn upgrade(&self) -> Option<&'a OtsUpgrade> {
        self.upgrade
    }
}

/// One RFC 3161 TSA artifact, as a verifier is entitled to read it
/// (MVP-SPEC.md line 109; registry §7.9).
///
/// Same discipline as [`OtsArtifactView`]: a borrowed view, and no `status`.
///
/// The certificates are **intermediates only**. A bundle-supplied chain can
/// never close against a bundle-supplied root (MVP-SPEC.md line 109), so this
/// type has no root slot to be tempted by — the trust anchors come from A6's
/// pinned store and nowhere else (D53 §5(c): the natural one-certificate-pool
/// implementation silently turns a sealer-written self-signed chain into
/// `proven`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsaArtifactView<'a> {
    token: &'a [u8],
    intermediates: &'a [OpaqueBytes],
    fetch_date: u64,
}

impl<'a> TsaArtifactView<'a> {
    /// View a decoded bundle artifact.
    #[must_use]
    pub fn from_anchor(anchor: &'a TsaAnchor) -> Self {
        Self {
            token: anchor.token().as_slice(),
            intermediates: anchor.intermediates(),
            fetch_date: anchor.fetch_date(),
        }
    }

    /// Build a view from raw parts — for A5/A8/A9/A18 fixtures.
    #[must_use]
    pub const fn from_parts(
        token: &'a [u8],
        intermediates: &'a [OpaqueBytes],
        fetch_date: u64,
    ) -> Self {
        Self {
            token,
            intermediates,
            fetch_date,
        }
    }

    /// The DER `TimeStampResp`/token. Opaque until A5 parses it.
    #[must_use]
    pub const fn token(&self) -> &'a [u8] {
        self.token
    }

    /// The DER intermediate certificates, in the order the bundle carried
    /// them.
    ///
    /// **Order carries no meaning** (registry §8): it is a builder rule with
    /// no parse check, which is why D53 §3 writes every chain rule as an
    /// existential over the whole candidate-path set rather than "the first
    /// path that…", and why the resulting state must be invariant under
    /// permutation of this slice.
    pub fn intermediates(&self) -> impl ExactSizeIterator<Item = &'a [u8]> {
        self.intermediates.iter().map(OpaqueBytes::as_slice)
    }

    /// How many intermediates the artifact carries.
    ///
    /// Bounded by `MAX_INTERMEDIATE_COUNT` (frozen D10 row 8), already
    /// enforced in verify stage 1 — consumed by name, never redefined. The
    /// **maximum length of a path being validated** is a different, genuinely
    /// open A5 limit (`docs/format/anchor-artifact-limits.md` §4); D53 §3
    /// requires the path enumerator to bound its search by the second, not by
    /// this one.
    #[must_use]
    pub const fn intermediate_count(&self) -> usize {
        self.intermediates.len()
    }

    /// The instant the sealer received the `TimeStampResp` — POSIX seconds
    /// UTC (registry §7.9 key 3).
    ///
    /// **Not** the token's `genTime`: `genTime` is inside the DER and is the
    /// *provable* time; this is metadata about the sealer's own clock. There
    /// is no ordering rule between the two, in either direction (registry
    /// §7.8's three non-rules bind key 3 identically; D59 §4 measured a dev
    /// machine 129 s slow and made the tempting `gen_time <= fetch_date`
    /// check a normative prohibition).
    #[must_use]
    pub const fn fetch_date(&self) -> u64 {
        self.fetch_date
    }
}

/// The fixed class of an Arbitrum payment receipt.
///
/// One variant, deliberately. MVP-SPEC.md line 110: the receipt renders as
/// "supporting evidence — no independently proven time", because no on-chain
/// datum contains `anchor_digest`. A one-variant enum is how "the receipt was
/// classified as an anchor" stops being a mistake anyone can make: there is no
/// other value to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReceiptClass {
    /// Supporting evidence; never an anchor, never headline-eligible.
    SupportingEvidenceNoProvenTime,
}

/// The Arbitrum receipt, as a **classification-only** view (MVP-SPEC.md
/// line 110; registry §7.10).
///
/// The type-level half of A19's separation: this view exposes no time, no
/// [`AnchorState`], and no conversion to either. Its [`ReceiptClass`] is
/// fixed. The payload stays opaque — registry §7.10 puts its internal layout
/// outside v1 wire format on purpose, and nothing in a v1 verdict may depend
/// on it.
#[derive(Debug, Clone, Copy)]
pub struct ReceiptArtifact<'a> {
    record: &'a ReceiptRecord,
}

impl<'a> ReceiptArtifact<'a> {
    /// View a decoded receipt record.
    #[must_use]
    pub const fn from_record(record: &'a ReceiptRecord) -> Self {
        Self { record }
    }

    /// The receipt's class — fixed, and unchangeable by any field it carries.
    #[must_use]
    pub const fn class(&self) -> ReceiptClass {
        ReceiptClass::SupportingEvidenceNoProvenTime
    }

    /// The Keccak-256 EVM transaction hashes, in capture order.
    #[must_use]
    pub fn transaction_hashes(&self) -> &'a [[u8; 32]] {
        self.record.tx_hashes()
    }

    /// The Arbitrum One block number of the earliest-confirmed transaction —
    /// display-only, unverified in v1, never verdict-bearing (registry
    /// §7.10 key 1).
    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.record.block_number()
    }

    /// Length of the opaque A/S capture payload. The bytes themselves are not
    /// exposed here: this view is classification-only.
    #[must_use]
    pub fn payload_len(&self) -> u64 {
        self.record.payload().len()
    }
}

/// Every anchor artifact one bundle carries, as evaluation input.
///
/// The one place that answers "does this bundle carry an artifact of kind
/// K?" — which is the question [`AnchorState::Absent`] is the answer to
/// (D53 §4a).
#[derive(Debug, Clone, Copy)]
pub struct AnchorArtifacts<'a> {
    ots: &'a [OtsAnchor],
    tsa: &'a [TsaAnchor],
    receipt: Option<&'a ReceiptRecord>,
}

impl<'a> AnchorArtifacts<'a> {
    /// Take the anchor sections of a decoded bundle.
    #[must_use]
    pub fn from_bundle(bundle: &'a BundleV1<'_>) -> Self {
        Self {
            ots: bundle.ots_anchors(),
            tsa: bundle.tsa_anchors(),
            receipt: bundle.receipt(),
        }
    }

    /// Build from raw sections — for fixtures that do not need a bundle.
    #[must_use]
    pub const fn from_parts(
        ots: &'a [OtsAnchor],
        tsa: &'a [TsaAnchor],
        receipt: Option<&'a ReceiptRecord>,
    ) -> Self {
        Self { ots, tsa, receipt }
    }

    /// The OTS artifacts, in wire order.
    pub fn ots(&self) -> impl ExactSizeIterator<Item = OtsArtifactView<'a>> {
        self.ots.iter().map(OtsArtifactView::from_anchor)
    }

    /// The TSA artifacts, in wire order.
    pub fn tsa(&self) -> impl ExactSizeIterator<Item = TsaArtifactView<'a>> {
        self.tsa.iter().map(TsaArtifactView::from_anchor)
    }

    /// The opt-in Arbitrum receipt. **Not an anchor** — it is deliberately
    /// unreachable from [`Self::count_for`] and from any [`AnchorKind`],
    /// because [`AnchorKind`] has no receipt variant (MVP-SPEC.md line 110).
    #[must_use]
    pub fn receipt(&self) -> Option<ReceiptArtifact<'a>> {
        self.receipt.map(ReceiptArtifact::from_record)
    }

    /// How many artifacts of `kind` the bundle carries.
    #[must_use]
    pub const fn count_for(&self, kind: AnchorKind) -> usize {
        match kind {
            AnchorKind::Ots => self.ots.len(),
            AnchorKind::Tsa => self.tsa.len(),
        }
    }

    /// The `absent` verdict for `kind` — `Some` **iff** the bundle carries no
    /// artifact of that kind.
    ///
    /// This is the whole of [`AnchorState::Absent`]'s reachability from M2
    /// onward, and it is a ruling rather than a convenience (D53 §4a):
    ///
    /// > `AnchorState::Absent` is what `evaluate_anchors` returns for a query
    /// > about an anchor **kind** the bundle does not carry — not for an
    /// > artifact — and R12 emits no `AnchorResult` slot for it.
    ///
    /// Every *artifact* lands in one of the other six states, F3 included
    /// ("not `absent` — the artifact is present"). Returning `None` here when
    /// artifacts exist is what keeps the two readings from being confused, and
    /// [`AnchorVerdict::to_anchor_result`] is what keeps the pinned
    /// `"anchors":[]` byte string from moving.
    #[must_use]
    pub fn absent_verdict(&self, kind: AnchorKind) -> Option<AnchorVerdict> {
        (self.count_for(kind) == 0).then(|| AnchorVerdict::absent(kind))
    }
}

// ---------------------------------------------------------------------------
// online evidence (D56 §3, D55)
// ---------------------------------------------------------------------------

/// The **agreed** result of the must-agree esplora pair (A16) for one block
/// height (MVP-SPEC.md line 137: "two pinned default endpoints per source,
/// results must agree").
///
/// # There is no failure variant, and that is the enforcement mechanism
///
/// D56 §3 rules that `--online` attempted-but-unreachable and
/// `--online` attempted-but-disagreeing both leave an anchor at `attested`,
/// unchanged from the offline evaluation — a cryptographic verdict must not
/// move with network weather, and MVP-SPEC.md line 137 already requires the
/// online overlay to be "distinct from the offline cryptographic verdict".
///
/// The ruling is enforced **structurally**: unreachable and disagreeing are
/// represented by *the absence of the entry* in [`OnlineEvidence`], so a state
/// machine cannot branch on a failure it has no way to receive.
/// `antseal-anchor` keeps A16's richer typed outcome for the overlay; it
/// simply has nothing to hand core.
///
/// The match in [`Self::agreement_with`] is wildcard-free so that adding a
/// third variant — the natural way this ruling would be undone — does not
/// compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnlineBlockResult {
    /// Both endpoints returned this byte-identical 80-byte header.
    Header([u8; BLOCK_HEADER_LEN as usize]),
    /// Both endpoints agreed there is **no block at this height**.
    ///
    /// Agreed absence is evidence, not the lack of it: it refutes an `.ots`
    /// claiming a height beyond the chain tip, which would otherwise render
    /// `attested` for ever (D56 §3, rule O7).
    NoSuchBlock,
}

impl OnlineBlockResult {
    /// Compare this agreed result with a bundle-embedded header.
    ///
    /// **This is only the online half of D56's rules O3/O6/O7.** Rule O3
    /// additionally requires `header_commits` — that the `.ots` ops derive the
    /// header's merkle root at the attested height (A12). Promoting on
    /// [`HeaderAgreement::Matches`] alone would reach `proven` on a real,
    /// fetchable block that has no relation to the seal, which is exactly the
    /// conjunction D56 §5 spells out.
    #[must_use]
    pub fn agreement_with(
        &self,
        embedded_header: &[u8; BLOCK_HEADER_LEN as usize],
    ) -> HeaderAgreement {
        match self {
            Self::Header(fetched) if fetched == embedded_header => HeaderAgreement::Matches,
            Self::Header(_) => HeaderAgreement::Differs,
            Self::NoSuchBlock => HeaderAgreement::NoSuchBlock,
        }
    }
}

/// How an agreed online result compares with a bundle-embedded block header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderAgreement {
    /// The fetched header is byte-identical to the embedded one (D56 rule O3's
    /// online half).
    Matches,
    /// The fetched header differs — a refutation from agreed evidence
    /// (D56 rule O6).
    Differs,
    /// Both endpoints agreed the height holds no block (D56 rule O7).
    NoSuchBlock,
}

/// Agreed block evidence, keyed by height.
///
/// `BTreeMap` rather than `HashMap` for the reason D29 gives the report:
/// iteration order must not vary between runs, or between native and wasm32.
///
/// A distinct type from [`OnlineEvidence`] on purpose. D55 requires that the
/// Arbitrum receipt evidence reach core "in a field that no `AnchorState` arm
/// reads"; the type-level form of that is a view the anchor rules take which
/// **cannot name** the receipt.
///
/// **That makes it an obligation on A18, not a property of this type alone:**
/// its per-anchor rules must take `&BlockEvidence`. An `evaluate_anchors` that
/// takes `&OnlineEvidence` and reaches through it compiles fine and gives the
/// separation up silently — nothing here can stop it, which is why it is
/// written down where A18's implementer will read it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockEvidence {
    blocks: BTreeMap<u64, OnlineBlockResult>,
}

impl BlockEvidence {
    /// Empty evidence — the offline case, and the case of a probe that
    /// reached nothing or whose endpoints disagreed (D56 §3).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an agreed result for `height`.
    #[must_use]
    pub fn with_block(mut self, height: u64, result: OnlineBlockResult) -> Self {
        self.blocks.insert(height, result);
        self
    }

    /// The agreed result for `height`, if the host supplied one.
    #[must_use]
    pub fn block(&self, height: u64) -> Option<OnlineBlockResult> {
        self.blocks.get(&height).copied()
    }

    /// How many heights carry agreed evidence.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether any agreed evidence was supplied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// The agreed facts about one Arbitrum transaction (D55).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptFacts {
    /// EVM receipt status byte (1 = success).
    pub status: u8,
    /// The block the transaction was confirmed in.
    pub block_number: u64,
    /// That block's hash.
    pub block_hash: [u8; 32],
}

/// The **agreed** result of the must-agree Arbitrum RPC pair (A17/D55).
///
/// Same structural rule as [`OnlineBlockResult`], for the same reason:
/// unavailable, lagging and disagreeing endpoints are the *absence* of the
/// entry, never a variant of it. `antseal-anchor`'s richer `ArbitrumConfirmation`
/// (D55 §4) keeps those cases for the overlay and projects only agreement into
/// core.
///
/// Nothing here is verdict-bearing. The receipt is supporting evidence
/// (MVP-SPEC.md line 110) and this type has no path to an [`AnchorState`] or
/// to a verified time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptConfirmation {
    /// Both endpoints agreed on these facts.
    Agreed(ReceiptFacts),
    /// Both endpoints agreed the transaction is not on chain.
    NotOnChain,
}

/// Everything a host learned online, as input to verification.
///
/// Constructible with **no network access** — it is data, and every field can
/// be written from literals. That is what lets the verifier page do its own
/// fetches in JS and feed the results to WASM-safe core (D90), and what lets
/// A18's tests cover the online rules without a socket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OnlineEvidence {
    blocks: BlockEvidence,
    receipt: Option<ReceiptConfirmation>,
}

impl OnlineEvidence {
    /// No online evidence at all — the offline verification path, and the
    /// path a failed or disagreeing probe takes (D56 §3).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an agreed block result.
    #[must_use]
    pub fn with_block(mut self, height: u64, result: OnlineBlockResult) -> Self {
        self.blocks = self.blocks.with_block(height, result);
        self
    }

    /// Record the agreed Arbitrum confirmation.
    #[must_use]
    pub fn with_receipt(mut self, confirmation: ReceiptConfirmation) -> Self {
        self.receipt = Some(confirmation);
        self
    }

    /// The block evidence — the **only** online input any [`AnchorState`] rule
    /// may read (D55 §4).
    #[must_use]
    pub const fn blocks(&self) -> &BlockEvidence {
        &self.blocks
    }

    /// The agreed Arbitrum confirmation, for the receipt's advisory overlay.
    ///
    /// No anchor rule reads this. The receipt is not an anchor and cannot
    /// become one (MVP-SPEC.md line 110; A19).
    #[must_use]
    pub const fn receipt(&self) -> Option<ReceiptConfirmation> {
        self.receipt
    }
}

// ---------------------------------------------------------------------------
// the verdict datum
// ---------------------------------------------------------------------------

/// An anchor's source identity, and whether the verifier **established** it.
///
/// D53 §4 fixes the distinction: for the two headline-eligible states the
/// identity comes from the validated certificate path and is *verified*; for
/// `internally-consistent-only` and `invalid` the same bytes yield a *claimed*
/// identity that "MUST render as such". The constructors below choose the
/// variant from the state, so a claimed identity presented as verified is not
/// a bug anyone can write.
///
/// The wire format carries no source string for either kind (D8 §1 removed the
/// TSA one; there never was an OTS one), so this is always the verifier's own
/// reading of an artifact it parsed, never a bundle field copied through.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AnchorSource {
    /// Established by the verifier's own checks against material it trusts.
    Verified(String),
    /// Read out of the artifact, bound to nothing. Renders as claimed (R18).
    Claimed(String),
}

impl AnchorSource {
    /// The identity string, whichever kind it is.
    #[must_use]
    pub fn identity(&self) -> &str {
        match self {
            Self::Verified(s) | Self::Claimed(s) => s,
        }
    }

    /// Whether the verifier established this identity.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified(_))
    }
}

/// The machine-readable code for **why** an anchor rendered
/// [`AnchorState::Invalid`].
///
/// # This must never enter `VerificationReport`
///
/// D53 §6 is explicit, and it is the constraint that keeps M2 from being a
/// report-format event: `AnchorResult` has exactly five fields and report v1 is
/// frozen (D29/R32; Q14). Adding a sixth for the diagnostic would bump
/// `REPORT_VERSION` and re-emit all 21 pinned byte strings. The code therefore
/// lives on [`AnchorVerdict`], which the CLI holds, and
/// [`AnchorVerdict::to_anchor_result`] **drops** it. Its price is recorded
/// rather than hidden: the verifier page cannot render the diagnostic, because
/// R22 hands the page only the report's canonical bytes.
///
/// # Who mints the codes
///
/// Not A2. The erroring task owns its code — A5 (strict DER/CMS), A8 (token
/// intrinsics), A9 (chain validation), A11 (`.ots` execution) — and the code is
/// the same `&'static str` its own error type's `code()` returns
/// (`docs/testing/error-code-contract.md` §1). This type is the slot, not the
/// registry, and it validates no prefix **deliberately**: D53 §7 mints
/// `anchor-…` codes and requires an `anchor-` prefix row, while D58 §10.4
/// mints `ots-…` codes under a new `ots-` prefix and predicts a sibling
/// `tsa-`. Both are RESOLVED, on the same day, and they disagree; baking
/// either into a constructor would silently pick a winner. The A38 prefix
/// registration is where that gets settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AnchorDiagnostic(&'static str);

impl AnchorDiagnostic {
    /// Wrap a stable error code.
    #[must_use]
    pub const fn new(code: &'static str) -> Self {
        Self(code)
    }

    /// The stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

/// One anchor's verdict — the wording-free datum A18 produces, R12 projects
/// into the report, and R18 renders.
///
/// Fields are private and every constructor is state-specific, because the
/// invariants of D53 §4 are cheaper to make unrepresentable than to check:
///
/// - **Only the two headline-eligible states accept a time.** `attested`,
///   `pending`, `internally-consistent-only`, `invalid` and `absent` have no
///   constructor parameter for one. This matters more than it looks:
///   `aggregate_anchors` already ignores times on ineligible slots, so a
///   wrongly populated `verified_time_unix` would be **invisible to every
///   existing test** (D53 §4a, D56 §5 — "only this test can see it"). Here
///   there is nothing to see, because there is nothing to write.
/// - **Only `invalid` accepts a diagnostic** ([`AnchorDiagnostic`]).
/// - **`absent` accepts nothing at all** — no source, no fetch date, no time.
/// - The source's verified/claimed kind is chosen by the state, not by the
///   caller ([`AnchorSource`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorVerdict {
    kind: AnchorKind,
    state: AnchorState,
    verified_time_unix: Option<i64>,
    source: Option<AnchorSource>,
    fetch_date: Option<String>,
    diagnostic: Option<AnchorDiagnostic>,
}

impl AnchorVerdict {
    /// **`proven`** [H] — "a TSA token valid against the pinned root store, or
    /// an OTS anchor `--online`-confirmed against Bitcoin block H"
    /// (MVP-SPEC.md line 129).
    ///
    /// `verified_time_unix` is the token's `TSTInfo.genTime` (D53 rule C1) or,
    /// for OTS, the `nTime` of the **online-agreed** header — never of the
    /// embedded one, which would reinstate exactly the offline forgeable time
    /// the online gate exists to prevent, and would do so invisibly since the
    /// two headers are equal on every honest bundle (D56 §5).
    #[must_use]
    pub fn proven(
        kind: AnchorKind,
        verified_time_unix: i64,
        source: Option<String>,
        fetch_date: Option<String>,
    ) -> Self {
        Self {
            kind,
            state: AnchorState::Proven,
            verified_time_unix: Some(verified_time_unix),
            source: source.map(AnchorSource::Verified),
            fetch_date,
            diagnostic: None,
        }
    }

    /// **`valid-at-stamping-cert-since-expired`** [H] — the chain was valid at
    /// `genTime` but every valid path has since expired at the caller's
    /// verification time (MVP-SPEC.md line 130; D53 rule C2).
    ///
    /// Headline-eligible on purpose: it "still carries its independently-proven
    /// stamping time", and `verified_time_unix` is that `genTime`. Aging
    /// bundles must not silently rot (MVP-SPEC.md lines 109/130).
    #[must_use]
    pub fn valid_at_stamping_cert_since_expired(
        kind: AnchorKind,
        verified_time_unix: i64,
        source: Option<String>,
        fetch_date: Option<String>,
    ) -> Self {
        Self {
            kind,
            state: AnchorState::ValidAtStampingCertSinceExpired,
            verified_time_unix: Some(verified_time_unix),
            source: source.map(AnchorSource::Verified),
            fetch_date,
            diagnostic: None,
        }
    }

    /// **`attested`** — "upgraded OTS, header embedded, **not**
    /// headline-eligible offline; `--online` promotes it to `proven`"
    /// (MVP-SPEC.md line 131; D56 rule O4).
    ///
    /// **Takes no time, by construction.** A lone embedded header's
    /// proof-of-work is self-referential — an attacker picks its own `nBits`,
    /// so a minimal-difficulty forged header mines in seconds — which is why
    /// MVP-SPEC.md line 108 gates Bitcoin online and why a forged header can
    /// never produce an offline headline time. This is also the state an
    /// `--online` probe that reached nothing, or whose endpoints disagreed,
    /// leaves the anchor in (D56 §3).
    #[must_use]
    pub fn attested(kind: AnchorKind, source: Option<String>, fetch_date: Option<String>) -> Self {
        Self {
            kind,
            state: AnchorState::Attested,
            verified_time_unix: None,
            source: source.map(AnchorSource::Claimed),
            fetch_date,
            diagnostic: None,
        }
    }

    /// **`pending`** — "OTS not yet upgraded" (MVP-SPEC.md line 132; D56 rule
    /// O5) — the same-day-reveal case every demo hits.
    ///
    /// Best-evidence-wins puts this above every refutation (D56 §4): a relay
    /// holding an **unsigned** bundle can append a forged Bitcoin branch, and
    /// under refutation-wins that would be a downgrade-to-forgery-accusation
    /// primitive exercisable by anyone who forwards a bundle.
    #[must_use]
    pub fn pending(kind: AnchorKind, source: Option<String>, fetch_date: Option<String>) -> Self {
        Self {
            kind,
            state: AnchorState::Pending,
            verified_time_unix: None,
            source: source.map(AnchorSource::Claimed),
            fetch_date,
            diagnostic: None,
        }
    }

    /// **`internally-consistent-only`** — "cryptographically well-formed but
    /// not independently anchored" (MVP-SPEC.md line 133).
    ///
    /// Reached by a **TSA** artifact whose candidate paths reach no pinned root
    /// at all, bundle-supplied roots included (D53 rule C6), and by an **OTS**
    /// artifact that commits `anchor_digest` but whose every branch ends in an
    /// op or attestation type this verifier cannot evaluate (D56 rule O9 — the
    /// correction to line 133's parenthetical; an OTS anchor that *fails* an
    /// online match is `invalid`, and one whose online match could not be
    /// performed stays `attested`).
    ///
    /// The state carries a **positive claim**: everything checkable has been
    /// checked and passed, and the only missing ingredient is an external trust
    /// anchor. That is why an artifact we refused to finish reading is
    /// `invalid` and not this (`docs/format/anchor-artifact-limits.md` rule
    /// F3), and why D53 §3 puts the token-intrinsic checks (T2) strictly ahead
    /// of every chain rule.
    #[must_use]
    pub fn internally_consistent_only(
        kind: AnchorKind,
        source: Option<String>,
        fetch_date: Option<String>,
    ) -> Self {
        Self {
            kind,
            state: AnchorState::InternallyConsistentOnly,
            verified_time_unix: None,
            source: source.map(AnchorSource::Claimed),
            fetch_date,
            diagnostic: None,
        }
    }

    /// **`invalid`** — "signature/op check fails" (MVP-SPEC.md line 134).
    ///
    /// The partition principle both M2 decisions share: an anchor is `invalid`
    /// **iff** the artifact makes a claim the verifier can refute from material
    /// it already trusts — its pinned roots, the artifact's own bytes, or
    /// agreed online evidence (D53 §2, D56 §1). An over-limit artifact is here
    /// too, and only ever fails its own anchor (limit rules F1–F3).
    ///
    /// The `diagnostic` names which refutation. It is required: this is the one
    /// state where "why" is not recoverable from the state name, and
    /// D53 §8 shows the consequence — `verdict:invalid` is claimed by exactly
    /// one tamper row, so every other row that renders `Invalid` must pin a
    /// code instead.
    #[must_use]
    pub fn invalid(
        kind: AnchorKind,
        diagnostic: AnchorDiagnostic,
        source: Option<String>,
        fetch_date: Option<String>,
    ) -> Self {
        Self {
            kind,
            state: AnchorState::Invalid,
            verified_time_unix: None,
            source: source.map(AnchorSource::Claimed),
            fetch_date,
            diagnostic: Some(diagnostic),
        }
    }

    /// **`absent`** — "anchor not present" (MVP-SPEC.md line 135).
    ///
    /// Returned for a **kind** the bundle carries no artifact of, never for an
    /// artifact (D53 §4a; [`AnchorArtifacts::absent_verdict`]), and
    /// [`Self::to_anchor_result`] emits no report slot for it.
    #[must_use]
    pub const fn absent(kind: AnchorKind) -> Self {
        Self {
            kind,
            state: AnchorState::Absent,
            verified_time_unix: None,
            source: None,
            fetch_date: None,
            diagnostic: None,
        }
    }

    /// Which anchoring mechanism this verdict describes.
    #[must_use]
    pub const fn kind(&self) -> AnchorKind {
        self.kind
    }

    /// The verdict state.
    #[must_use]
    pub const fn state(&self) -> AnchorState {
        self.state
    }

    /// Whether this verdict can carry the headline time (MVP-SPEC.md's `[H]`
    /// marker). Delegates to A1's single predicate — there is no second
    /// eligibility table.
    #[must_use]
    pub const fn is_headline_eligible(&self) -> bool {
        headline_eligible(self.state)
    }

    /// The independently verified time, Unix seconds UTC.
    ///
    /// `Some` for exactly the two headline-eligible states, by construction.
    #[must_use]
    pub const fn verified_time_unix(&self) -> Option<i64> {
        self.verified_time_unix
    }

    /// The source identity, and whether it was verified.
    #[must_use]
    pub const fn source(&self) -> Option<&AnchorSource> {
        self.source.as_ref()
    }

    /// The artifact's recorded fetch date, verbatim.
    #[must_use]
    pub fn fetch_date(&self) -> Option<&str> {
        self.fetch_date.as_deref()
    }

    /// The diagnostic code — `Some` only for [`AnchorState::Invalid`].
    #[must_use]
    pub const fn diagnostic(&self) -> Option<AnchorDiagnostic> {
        self.diagnostic
    }

    /// Project into a report slot — the primitive R12 is to wire into the
    /// pipeline at M2. Nothing calls it yet: `verify::pipeline`'s M0 stub
    /// still emits one `absent` slot per *artifact*, which is why the 21
    /// pinned report vectors are unchanged by A2.
    ///
    /// `None` for [`AnchorState::Absent`]: a kind with no artifact emits **no**
    /// `AnchorResult` (D53 §4a). The rejected alternative — a fixed `ots`+`tsa`
    /// slot pair, `absent` when the kind has none — would rewrite the pinned
    /// `"anchors":[]` string and the one report vector that carries anchor
    /// slots, i.e. a frozen-byte change and a `REPORT_VERSION` bump, for a
    /// cosmetic gain.
    ///
    /// The [`AnchorDiagnostic`] is **dropped** here, and that is load-bearing
    /// (D53 §6): `AnchorResult` has five fields and report v1 is frozen.
    ///
    /// The match on the state is wildcard-free so an eighth state has to decide
    /// explicitly whether it emits a slot.
    #[must_use]
    pub fn to_anchor_result(&self) -> Option<AnchorResult> {
        let emits_slot = match self.state {
            AnchorState::Proven
            | AnchorState::ValidAtStampingCertSinceExpired
            | AnchorState::Attested
            | AnchorState::Pending
            | AnchorState::InternallyConsistentOnly
            | AnchorState::Invalid => true,
            AnchorState::Absent => false,
        };
        emits_slot.then(|| AnchorResult {
            kind: self.kind,
            state: self.state,
            verified_time_unix: self.verified_time_unix,
            source: self.source.as_ref().map(|s| s.identity().to_owned()),
            fetch_date: self.fetch_date.clone(),
        })
    }
}

/// Project a run of verdicts into the report's `anchors` array (R12).
///
/// `absent` verdicts contribute nothing, so a bundle with no anchors
/// serializes `"anchors":[]` — itself a pinned byte string.
#[must_use]
pub fn project_anchor_results(verdicts: &[AnchorVerdict]) -> Vec<AnchorResult> {
    verdicts
        .iter()
        .filter_map(AnchorVerdict::to_anchor_result)
        .collect()
}

// ---------------------------------------------------------------------------
// capture records (what U persists in the vault)
// ---------------------------------------------------------------------------

/// What the sealer recorded when it obtained one RFC 3161 token (U9 persists
/// it in the work record's `anchors/<slot>` payload).
///
/// Capture-side only: none of it is verdict-bearing, and a bundle recipient
/// never sees this struct — it sees the token, whose `TSTInfo` already carries
/// the nonce and the provable `genTime`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaCaptureRecord {
    /// `anchor_digest` = SHA-256 of the full manifest bytes — what was
    /// stamped.
    pub anchor_digest: [u8; 32],
    /// The TSA endpoint the request went to.
    pub endpoint: String,
    /// The RFC 3161 request nonce, exactly as sent (DER INTEGER content
    /// octets). PUBLIC BY CONSTRUCTION: the TSA echoes it into the signed
    /// TSTInfo, so every bundle carrying this token already publishes it.
    /// Never secret material; never derived from `W`.
    ///
    /// Exactly 8 bytes (D59 §4). Generated in `antseal-anchor` from the OS
    /// CSPRNG — **no RNG enters `antseal-core`**; this is data.
    pub request_nonce: [u8; 8],
    /// The instant the `TimeStampResp` was received — POSIX seconds UTC. No
    /// ordering relation to the token's `genTime` may ever be checked
    /// (D59 §4: measured, and a normative prohibition).
    pub fetch_date: u64,
}

/// One calendar submission inside an [`OtsCaptureRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtsCalendarSubmission {
    /// The calendar's URL, as configured (MVP-SPEC.md line 108: "≥2 public
    /// calendars").
    pub calendar_url: String,
    /// The instant the submission completed — POSIX seconds UTC.
    pub submitted_date: u64,
}

/// What the sealer recorded when it stamped `anchor_digest` against the OTS
/// calendars, and what it learned on a later upgrade poll.
///
/// The per-calendar *pending* detail lives here rather than on
/// [`OtsArtifactView`] deliberately: inside a bundle the calendars are named by
/// the `.ots` attestations themselves, so reading them is A11's parse and not a
/// field the artifact model can expose without one. This record is the
/// sealer's own capture log, which the vault has structurally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtsCaptureRecord {
    /// What was stamped.
    pub anchor_digest: [u8; 32],
    /// One entry per calendar the sealer submitted to, in submission order.
    pub calendars: Vec<OtsCalendarSubmission>,
    /// The upgrade group, once a poll found a Bitcoin attestation: attested
    /// height, the 80-byte header, and the fetch date, together or not at all
    /// (D79). Reuses F's [`OtsUpgrade`] — the bundle carries exactly this.
    pub upgrade: Option<OtsUpgrade>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_state_verdict() -> Vec<AnchorVerdict> {
        vec![
            AnchorVerdict::proven(AnchorKind::Tsa, 1_785_000_000, Some("freetsa".into()), None),
            AnchorVerdict::valid_at_stamping_cert_since_expired(
                AnchorKind::Tsa,
                1_785_000_600,
                Some("digicert".into()),
                None,
            ),
            AnchorVerdict::attested(AnchorKind::Ots, Some("calendar.example".into()), None),
            AnchorVerdict::pending(AnchorKind::Ots, None, None),
            AnchorVerdict::internally_consistent_only(AnchorKind::Tsa, None, None),
            AnchorVerdict::invalid(
                AnchorKind::Ots,
                AnchorDiagnostic::new("anchor-model-test-code"),
                None,
                None,
            ),
            AnchorVerdict::absent(AnchorKind::Tsa),
        ]
    }

    /// A2 Accept row 1: all seven states are representable, and each has
    /// exactly one constructor.
    ///
    /// Would fail if a constructor were deleted, mis-wired to a neighbouring
    /// state, or if an eighth state appeared with no way to build it.
    #[test]
    fn every_one_of_the_seven_states_is_constructible() {
        let built: Vec<AnchorState> = every_state_verdict().iter().map(|v| v.state()).collect();
        assert_eq!(built.len(), AnchorState::ALL.len());
        for state in AnchorState::ALL {
            assert!(
                built.contains(&state),
                "{state:?} has no constructor in this model"
            );
        }
    }

    /// A2 Accept row 1, second half: the eligibility flag is on the verdict and
    /// agrees with A1's single predicate — there is no second table.
    #[test]
    fn eligibility_flags_are_a1s_predicate_and_no_other() {
        for verdict in every_state_verdict() {
            assert_eq!(
                verdict.is_headline_eligible(),
                headline_eligible(verdict.state()),
                "{:?}",
                verdict.state()
            );
        }
        let eligible: Vec<AnchorState> = every_state_verdict()
            .iter()
            .filter(|v| v.is_headline_eligible())
            .map(AnchorVerdict::state)
            .collect();
        assert_eq!(
            eligible,
            vec![
                AnchorState::Proven,
                AnchorState::ValidAtStampingCertSinceExpired
            ],
            "exactly the spec's two [H] states"
        );
    }

    /// D53 §4 / D56 §5: no ineligible state carries a verified time.
    ///
    /// `aggregate_anchors` ignores times on ineligible slots, so a wrongly
    /// populated time is invisible to every other test. Here it is
    /// unrepresentable — the constructors take no such parameter — and this
    /// asserts the equality in both directions, so an ineligible state that
    /// *gained* a time parameter would go red.
    #[test]
    fn no_ineligible_state_carries_a_verified_time() {
        for verdict in every_state_verdict() {
            assert_eq!(
                verdict.verified_time_unix().is_some(),
                verdict.is_headline_eligible(),
                "{:?} time/eligibility disagree",
                verdict.state()
            );
        }
    }

    /// D56 §5, called out on its own because it is the one A12's `Do` omits:
    /// an `attested` anchor's `verified_time_unix` is `None`, always.
    #[test]
    fn an_attested_verdict_never_carries_a_verified_time() {
        let attested = AnchorVerdict::attested(AnchorKind::Ots, None, Some("1785000100".into()));
        assert_eq!(attested.state(), AnchorState::Attested);
        assert_eq!(attested.verified_time_unix(), None);
        assert!(!attested.is_headline_eligible());
        let slot = attested.to_anchor_result().expect("attested emits a slot");
        assert_eq!(slot.verified_time_unix, None);
    }

    /// D53 §4a — the ruling, and the test the empty-anchor vector cannot be.
    ///
    /// `absent` is what the evaluator returns for a **kind** with no artifact,
    /// and R12 emits no slot for it. A18's Accept says "`absent` covered by the
    /// empty-anchor vector"; that vector produces **zero** anchor slots, so it
    /// witnesses nothing and would keep passing if the variant were deleted.
    /// This one names the variant, the constructor, and the no-slot rule, so
    /// deleting `Absent` breaks compilation and changing the projection breaks
    /// the assertion.
    #[test]
    fn absent_is_returned_for_a_kind_with_no_artifact_and_emits_no_slot() {
        let empty = AnchorArtifacts::from_parts(&[], &[], None);
        for kind in [AnchorKind::Ots, AnchorKind::Tsa] {
            assert_eq!(empty.count_for(kind), 0);
            let verdict = empty
                .absent_verdict(kind)
                .expect("a kind with no artifact has an absent verdict");
            assert_eq!(verdict.state(), AnchorState::Absent);
            assert_eq!(verdict.kind(), kind);
            assert!(!verdict.is_headline_eligible());
            assert_eq!(verdict.verified_time_unix(), None);
            assert_eq!(
                verdict.to_anchor_result(),
                None,
                "R12 emits no slot for an absent kind"
            );
        }
        assert!(
            project_anchor_results(&[
                AnchorVerdict::absent(AnchorKind::Ots),
                AnchorVerdict::absent(AnchorKind::Tsa),
            ])
            .is_empty(),
            "all-absent projects to the empty array that serializes \"anchors\":[]"
        );
        assert_eq!(
            serde_json::to_string(&Vec::<AnchorResult>::new()).expect("empty array serializes"),
            "[]"
        );
    }

    /// The other half of D53 §4a: once a bundle *does* carry artifacts of a
    /// kind, that kind has no `absent` verdict — every artifact lands in one of
    /// the other six states (rule F3 included: "not `absent`, the artifact is
    /// present").
    #[test]
    fn a_kind_with_artifacts_has_no_absent_verdict() {
        use crate::bundle::AnchorStatus;

        let ots = [OtsAnchor::new(
            AnchorStatus::Pending,
            OpaqueBytes::from_vec(b"fixture .ots".to_vec()),
            None,
        )
        .expect("under the D10 caps")];
        let artifacts = AnchorArtifacts::from_parts(&ots, &[], None);
        assert_eq!(artifacts.count_for(AnchorKind::Ots), 1);
        assert_eq!(artifacts.absent_verdict(AnchorKind::Ots), None);
        // …and the other kind is still absent in the same bundle.
        assert_eq!(artifacts.count_for(AnchorKind::Tsa), 0);
        assert!(artifacts.absent_verdict(AnchorKind::Tsa).is_some());
    }

    /// D53 §6, the constraint that keeps M2 off the format-event path: the
    /// diagnostic code is dropped by the projection and appears nowhere in the
    /// serialized report slot.
    #[test]
    fn the_diagnostic_code_never_reaches_the_report() {
        const CODE: &str = "anchor-model-diagnostic-probe";
        let verdict = AnchorVerdict::invalid(
            AnchorKind::Tsa,
            AnchorDiagnostic::new(CODE),
            Some("claimed-tsa".into()),
            // Decimal POSIX seconds — the ONLY shape the emitter produces
            // (`verdicts.rs` renders the wire `uint` through `to_string()`).
            // This literal read `"2026-08-02"` until 2026-08-06, so the tree's
            // one byte-exact example of a rendered fetch date disagreed with
            // its one real producer about the field's format (D95 / R73).
            Some("1785000100".into()),
        );
        assert_eq!(
            verdict.diagnostic().map(AnchorDiagnostic::code),
            Some(CODE),
            "the CLI holds the code"
        );
        let slot = verdict.to_anchor_result().expect("invalid emits a slot");
        let json = serde_json::to_string(&slot).expect("slot serializes");
        assert!(
            !json.contains(CODE),
            "the diagnostic leaked into the report: {json}"
        );
        assert!(json.contains("\"state\":\"invalid\""), "{json}");
        // Exactly the five frozen fields, no sixth. This pin is deliberate
        // and it is a **coupled edit**: `AnchorResult` gaining a field is a
        // `REPORT_VERSION` event by D53 §6, so this line going red is the
        // intended signal, not a chore. It does not pin `report_version`
        // itself, so a bump that leaves `AnchorResult` alone passes here and
        // is caught by the three edits `REPORT_VERSION`'s doc comment lists.
        assert_eq!(
            json,
            r#"{"kind":"tsa","state":"invalid","verified_time_unix":null,"source":"claimed-tsa","fetch_date":"1785000100"}"#
        );
    }

    /// D53 §4: a source is *verified* for the two `[H]` states and *claimed*
    /// for the rest, and the caller does not get to choose.
    #[test]
    fn source_verification_kind_is_chosen_by_the_state() {
        for verdict in every_state_verdict() {
            let Some(source) = verdict.source() else {
                continue;
            };
            assert_eq!(
                source.is_verified(),
                verdict.is_headline_eligible(),
                "{:?} source kind disagrees with its state",
                verdict.state()
            );
        }
        let claimed = AnchorVerdict::internally_consistent_only(
            AnchorKind::Tsa,
            Some("cn=liar".into()),
            None,
        );
        assert_eq!(
            claimed.source(),
            Some(&AnchorSource::Claimed("cn=liar".to_owned()))
        );
        assert_eq!(
            claimed.source().map(AnchorSource::identity),
            Some("cn=liar")
        );
    }

    /// D56 §3: a probe that resolved nothing is **only** representable as the
    /// absence of the entry, at every height.
    ///
    /// # What this test is, and what it is not
    ///
    /// D56 §9's table has a row — the unreachable-and-disagreeing-endpoints
    /// differential, its name spelled out there — that "constructs both
    /// `antseal-anchor` outcomes and asserts they produce the identical core
    /// input", under a section heading placing every row of that table in
    /// `antseal-core`. **That one row cannot live here**: the A16 outcome type
    /// is in `antseal-anchor`, and `antseal-core` must never depend on it. The
    /// obligation is still owed, on the anchor side (task A47); giving this
    /// test D56's name for that row would have discharged it on paper. The
    /// name is deliberately not quoted here — a rustdoc pointer at a test that
    /// does not exist reads as evidence and is not, which is the whole subject
    /// of `tests/doc_pointer_liveness.rs`.
    ///
    /// What is checkable here is the property that makes the differential
    /// trivially true once it is written: the observable is
    /// `Option<OnlineBlockResult>`, whose `Some` payload is agreement and
    /// whose `None` is everything else. The type has no third thing to be, so
    /// there is nothing for a state machine to branch on.
    #[test]
    fn absence_of_evidence_is_the_only_shape_a_failed_probe_can_take() {
        let resolved_nothing = OnlineEvidence::new();
        assert!(resolved_nothing.blocks().is_empty());
        for height in [0, 1, 900_000, u64::MAX] {
            assert_eq!(
                resolved_nothing.blocks().block(height),
                None,
                "height {height} must be silent, not failed"
            );
        }

        // An agreed result is a *positive* record, at one height only: it
        // never implies anything about a neighbouring height.
        let agreed = OnlineEvidence::new().with_block(900_000, OnlineBlockResult::NoSuchBlock);
        assert_eq!(
            agreed.blocks().block(900_000),
            Some(OnlineBlockResult::NoSuchBlock)
        );
        assert_eq!(agreed.blocks().block(900_001), None);
        assert_eq!(agreed.blocks().len(), 1);
    }

    /// D56 §3/O7: agreed absence of the block is evidence — a distinct value,
    /// never collapsed into "no evidence". Collapsing them would let an `.ots`
    /// claiming a height beyond the chain tip render `attested` for ever.
    #[test]
    fn agreed_absence_of_a_block_is_not_the_same_as_no_evidence() {
        let embedded = [0x11u8; BLOCK_HEADER_LEN as usize];
        let no_such = OnlineEvidence::new().with_block(700_000, OnlineBlockResult::NoSuchBlock);
        let none = OnlineEvidence::new();
        assert_ne!(no_such, none);
        assert_eq!(
            no_such
                .blocks()
                .block(700_000)
                .map(|r| r.agreement_with(&embedded)),
            Some(HeaderAgreement::NoSuchBlock)
        );
        assert_eq!(
            none.blocks()
                .block(700_000)
                .map(|r| r.agreement_with(&embedded)),
            None
        );
    }

    /// The online half of D56's O3/O6/O7 discriminator, over all three
    /// outcomes. The header comparison is byte-exact, so a single flipped bit
    /// is `Differs`, not `Matches`.
    #[test]
    fn header_agreement_covers_match_mismatch_and_absence() {
        let embedded = [0x22u8; BLOCK_HEADER_LEN as usize];
        let mut other = embedded;
        other[BLOCK_HEADER_LEN as usize - 1] ^= 0x01;

        assert_eq!(
            OnlineBlockResult::Header(embedded).agreement_with(&embedded),
            HeaderAgreement::Matches
        );
        assert_eq!(
            OnlineBlockResult::Header(other).agreement_with(&embedded),
            HeaderAgreement::Differs
        );
        assert_eq!(
            OnlineBlockResult::NoSuchBlock.agreement_with(&embedded),
            HeaderAgreement::NoSuchBlock
        );

        // D56 §3, structurally: the wildcard-free arms below enumerate the
        // whole type. An "attempted and failed" variant — the shape the
        // ruling forbids — could not be added without failing to compile
        // here and in `agreement_with`.
        for result in [
            OnlineBlockResult::Header(embedded),
            OnlineBlockResult::NoSuchBlock,
        ] {
            match result {
                OnlineBlockResult::Header(_) | OnlineBlockResult::NoSuchBlock => {}
            }
        }
    }

    /// A2 Accept row 2: online evidence is constructible with no network
    /// access — every field is written from literals here — and it is pure
    /// data, so this test runs identically on wasm32.
    #[test]
    fn online_evidence_is_constructible_from_literals() {
        let evidence = OnlineEvidence::new()
            .with_block(900_000, OnlineBlockResult::Header([0x33; 80]))
            .with_block(900_001, OnlineBlockResult::NoSuchBlock)
            .with_receipt(ReceiptConfirmation::Agreed(ReceiptFacts {
                status: 1,
                block_number: 400_000_000,
                block_hash: [0x44; 32],
            }));
        assert_eq!(evidence.blocks().len(), 2);
        assert!(matches!(
            evidence.receipt(),
            Some(ReceiptConfirmation::Agreed(_))
        ));
    }

    /// D55: the receipt evidence reaches core in a field no `AnchorState` rule
    /// reads. Structurally, A18's rules take `&BlockEvidence`, which cannot
    /// name the receipt — asserted here as the value-level consequence:
    /// changing the receipt arm changes no block evidence whatsoever.
    #[test]
    fn receipt_evidence_cannot_reach_the_block_evidence_anchor_rules_read() {
        let base = OnlineEvidence::new().with_block(900_000, OnlineBlockResult::NoSuchBlock);
        let with_receipt = base.clone().with_receipt(ReceiptConfirmation::NotOnChain);
        let with_other = base
            .clone()
            .with_receipt(ReceiptConfirmation::Agreed(ReceiptFacts {
                status: 0,
                block_number: 1,
                block_hash: [0xAB; 32],
            }));
        assert_eq!(base.blocks(), with_receipt.blocks());
        assert_eq!(base.blocks(), with_other.blocks());
        assert_ne!(with_receipt.receipt(), with_other.receipt());
    }

    /// MVP-SPEC.md line 110 / A19, at the type level: a receipt's class is
    /// fixed and carries no time. `AnchorKind` has no receipt variant, so a
    /// receipt cannot even be *counted* as an anchor.
    #[test]
    fn the_receipt_is_classification_only_and_never_an_anchor() {
        use crate::bundle::ReceiptRecord;

        let record = ReceiptRecord::new(
            vec![[0xE1; 32]],
            400_000_000,
            OpaqueBytes::from_vec(b"opaque capture".to_vec()),
        )
        .expect("receipt has a transaction hash");
        let artifacts = AnchorArtifacts::from_parts(&[], &[], Some(&record));
        let receipt = artifacts.receipt().expect("receipt present");
        assert_eq!(
            receipt.class(),
            ReceiptClass::SupportingEvidenceNoProvenTime
        );
        assert_eq!(receipt.transaction_hashes().len(), 1);
        assert_eq!(receipt.block_number(), 400_000_000);
        assert_eq!(receipt.payload_len(), 14);
        // The receipt is invisible to both anchor kinds.
        assert_eq!(artifacts.count_for(AnchorKind::Ots), 0);
        assert_eq!(artifacts.count_for(AnchorKind::Tsa), 0);
    }

    /// The artifact views drop the sealer-recorded `status` (registry
    /// §7.8/§7.9; MVP-SPEC.md line 121). Two artifacts differing **only** in
    /// their recorded status must present identically to the verifier — which
    /// is the property "never trusted" actually means.
    #[test]
    fn the_sealer_recorded_status_is_not_visible_to_the_verifier() {
        use crate::bundle::AnchorStatus;

        let honest = OtsAnchor::new(
            AnchorStatus::Pending,
            OpaqueBytes::from_vec(b"same bytes".to_vec()),
            None,
        )
        .expect("under the D10 caps");
        let lying = OtsAnchor::new(
            AnchorStatus::Proven,
            OpaqueBytes::from_vec(b"same bytes".to_vec()),
            None,
        )
        .expect("under the D10 caps");
        assert_ne!(honest.status(), lying.status());
        assert_eq!(
            OtsArtifactView::from_anchor(&honest),
            OtsArtifactView::from_anchor(&lying),
            "a sealer's claimed status must not reach the evaluation input"
        );

        let honest_tsa = TsaAnchor::new(
            AnchorStatus::Invalid,
            OpaqueBytes::from_vec(b"token".to_vec()),
            vec![OpaqueBytes::from_vec(b"cert".to_vec())],
            1_785_000_000,
        )
        .expect("under the D10 caps");
        let lying_tsa = TsaAnchor::new(
            AnchorStatus::Proven,
            OpaqueBytes::from_vec(b"token".to_vec()),
            vec![OpaqueBytes::from_vec(b"cert".to_vec())],
            1_785_000_000,
        )
        .expect("under the D10 caps");
        assert_eq!(
            TsaArtifactView::from_anchor(&honest_tsa),
            TsaArtifactView::from_anchor(&lying_tsa)
        );
    }

    /// The views expose every field the bundle carries, and the D79 upgrade
    /// group survives as a group.
    #[test]
    fn views_expose_every_bundle_carried_artifact_field() {
        use crate::bundle::AnchorStatus;

        let upgrade = OtsUpgrade::new(900_000, [0x55; BLOCK_HEADER_LEN as usize], 1_785_000_900);
        let ots = OtsAnchor::new(
            AnchorStatus::Attested,
            OpaqueBytes::from_vec(b"upgraded .ots".to_vec()),
            Some(upgrade.clone()),
        )
        .expect("under the D10 caps");
        let view = OtsArtifactView::from_anchor(&ots);
        assert_eq!(view.ots(), b"upgraded .ots");
        let carried = view.upgrade().expect("upgrade group present");
        assert_eq!(carried.block_height(), 900_000);
        assert_eq!(carried.block_header(), &[0x55; BLOCK_HEADER_LEN as usize]);
        assert_eq!(carried.fetch_date(), 1_785_000_900);
        assert_eq!(&upgrade, carried);

        let tsa = TsaAnchor::new(
            AnchorStatus::Proven,
            OpaqueBytes::from_vec(b"DER token".to_vec()),
            vec![
                OpaqueBytes::from_vec(b"cert-1".to_vec()),
                OpaqueBytes::from_vec(b"cert-2".to_vec()),
            ],
            1_785_000_000,
        )
        .expect("under the D10 caps");
        let view = TsaArtifactView::from_anchor(&tsa);
        assert_eq!(view.token(), b"DER token");
        assert_eq!(view.intermediate_count(), 2);
        assert_eq!(
            view.intermediates().collect::<Vec<_>>(),
            vec![b"cert-1".as_slice(), b"cert-2".as_slice()]
        );
        assert_eq!(view.fetch_date(), 1_785_000_000);

        // A not-yet-upgraded artifact has no group at all (D79: all or none).
        let pending = OtsAnchor::new(
            AnchorStatus::Pending,
            OpaqueBytes::from_vec(b"pending .ots".to_vec()),
            None,
        )
        .expect("under the D10 caps");
        assert_eq!(OtsArtifactView::from_anchor(&pending).upgrade(), None);
    }

    /// The capture records carry exactly what D59 §3 fixed and what A2's `Do`
    /// names: request nonce, fetch dates, calendar URLs.
    #[test]
    fn capture_records_carry_the_fields_u_persists() {
        let tsa = TsaCaptureRecord {
            anchor_digest: [0x77; 32],
            endpoint: "https://freetsa.org/tsr".to_owned(),
            request_nonce: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            fetch_date: 1_785_000_000,
        };
        assert_eq!(tsa.request_nonce.len(), 8, "D59 §4: exactly 8 bytes");

        let ots = OtsCaptureRecord {
            anchor_digest: [0x77; 32],
            calendars: vec![
                OtsCalendarSubmission {
                    calendar_url: "https://alice.btc.calendar.opentimestamps.org".to_owned(),
                    submitted_date: 1_785_000_000,
                },
                OtsCalendarSubmission {
                    calendar_url: "https://bob.btc.calendar.opentimestamps.org".to_owned(),
                    submitted_date: 1_785_000_002,
                },
            ],
            upgrade: None,
        };
        assert_eq!(
            ots.calendars.len(),
            2,
            "≥2 calendars (MVP-SPEC.md line 108)"
        );
        assert_eq!(ots.anchor_digest, tsa.anchor_digest);
    }

    /// No secret material in any capture record's `Debug`.
    ///
    /// The nonce is deliberately *not* secret (D59 §3: public by construction,
    /// it ships inside the signed `TSTInfo`), so this guards the fields that
    /// would be — none of these types has a key, salt or seed field, and this
    /// is the tripwire against one being added.
    #[test]
    fn capture_records_expose_no_secret_material() {
        let record = TsaCaptureRecord {
            anchor_digest: [0xA5; 32],
            endpoint: "https://freetsa.org/tsr".to_owned(),
            request_nonce: [0xB6; 8],
            fetch_date: 1,
        };
        let rendered = format!("{record:?}");
        for forbidden in ["salt", "seed", "k_u", "k_m", "secret", "passphrase"] {
            assert!(
                !rendered.to_ascii_lowercase().contains(forbidden),
                "capture record names {forbidden:?}"
            );
        }
    }

    /// Every state's [`spec_line`] is distinct and inside the taxonomy block
    /// (MVP-SPEC.md lines 129–135, introduced at 127).
    #[test]
    fn spec_lines_are_distinct_and_inside_the_taxonomy_block() {
        let mut seen = Vec::new();
        for state in AnchorState::ALL {
            let line = spec_line(state);
            assert!((129..=135).contains(&line), "{state:?} cites line {line}");
            assert!(!seen.contains(&line), "line {line} cited twice");
            seen.push(line);
        }
        assert_eq!(seen.len(), 7);
    }

    /// A2 Accept row 3, the checkable half: each state's cited line is the line
    /// that **defines** it.
    ///
    /// Reads the spec, so native-only — the codes and line numbers are
    /// target-independent (the `error_universe` precedent). Goes red if the
    /// taxonomy block moves, which is exactly when the citations in
    /// [`spec_line`] and in every constructor's doc comment need re-cutting.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn spec_line_points_at_the_states_own_definition() {
        const SPEC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../MVP-SPEC.md");
        let text = std::fs::read_to_string(SPEC).expect("MVP-SPEC.md is in the tree");
        let lines: Vec<&str> = text.lines().collect();
        for state in AnchorState::ALL {
            let line_no = spec_line(state) as usize;
            let line = lines
                .get(line_no - 1)
                .unwrap_or_else(|| panic!("MVP-SPEC.md has no line {line_no}"));
            let expected = format!("- `{}`", state.wire_name());
            assert!(
                line.starts_with(&expected),
                "MVP-SPEC.md:{line_no} should define {expected:?}, found: {line}"
            );
        }
    }
}
