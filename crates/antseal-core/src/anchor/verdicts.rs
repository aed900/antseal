//! The per-anchor verdict state machine (**A18**), the receipt's
//! supporting-evidence class (**A19**), the suppressed-anomaly list
//! (**A39**) and anchor identity (**A40**).
//!
//! Everything below D53's stages and D56's rules already exists: A5/A8 own
//! T1/T2, A9 owns T3's `C1–C6`, A11 owns `.ots` parsing and the O1/O2 digest
//! check, A12 owns the embedded-header question. This module is the one place
//! that puts an artifact into exactly one of the seven frozen states, and it
//! implements **D53's `T0–T3`** and **D56's `O0–O9`** in their stated order
//! rather than a summary of either.
//!
//! # Pure
//!
//! No clock, no socket, no file. `verify_at_unix` is a parameter and online
//! results arrive as data ([`OnlineEvidence`]), so the same bytes render the
//! same verdict on every host, in every runtime, at every wall-clock instant
//! — which is what A22's native-vs-wasm32 bit-match will assert.
//!
//! # The rules cannot name the receipt
//!
//! A2 deviated deliberately: the agreed block results arrive behind
//! [`BlockEvidence`] rather than a public map, so that D55's *"in a field
//! that no `AnchorState` arm reads"* is a fact about the types instead of a
//! rule someone must remember. A2's own doc records that the obligation lands
//! **here**: an evaluator taking `&OnlineEvidence` and reaching through it
//! compiles fine and gives the property up silently.
//!
//! So [`evaluate_ots_artifact`] takes `&BlockEvidence` and
//! [`evaluate_tsa_artifact`] takes no online input at all. Widening either is
//! a compile error in
//! [`tests::the_per_anchor_rules_cannot_be_handed_the_receipt`], which passes
//! `&BlockEvidence` positionally — `&OnlineEvidence` does not coerce to it.
//!
//! # What is deliberately **not** here
//!
//! Aggregation. Earliest-headline selection, the >48 h divergence flag and
//! the UNANCHORED outcome are R17's (M3); A1's zero-headline-eligible flag
//! covers M1/M2 library use and is reachable through
//! [`AnchorVerdicts::aggregate`]. Wording is R18's: every datum here is
//! wording-free.
//!
//! And no report byte. The diagnostic codes and the A39 anomaly list **must
//! not** enter [`crate::verify::report::VerificationReport`] (D53 §6,
//! D56 §6): `AnchorResult` has exactly five fields and report v1 is frozen
//! (D29/R32; Q14). [`AnchorVerdicts::project_anchor_results`] is the R12
//! projection that drops them, and
//! [`tests::the_projection_drops_every_diagnostic_and_anomaly`] asserts the
//! boundary rather than commenting on it.

use std::collections::BTreeSet;

use der::{Decode as _, Encode as _};
use x509_cert::Certificate;

use crate::verify::aggregate::{AnchorAggregate, aggregate_anchors};
use crate::verify::report::AnchorResult;

use super::chain::{ChainFault, validate_token_chain};
use super::error::{DerSite, der_error};
use super::model::{
    AnchorArtifacts, AnchorDiagnostic, AnchorKind, AnchorState, AnchorVerdict, BlockEvidence,
    OnlineBlockResult, OnlineEvidence, OtsArtifactView, ReceiptArtifact, ReceiptClass,
    ReceiptConfirmation, TsaArtifactView,
};
use super::ots::{
    EmbeddedHeader, OtsArtifact, OtsAttestation, check_embedded_header, header_time_unix,
    merkle_root_of, parse_ots,
};
use super::roots::TsaRootStore;
use super::tsa::{VerifiedToken, verify_token};

// ---------------------------------------------------------------------------
// D56's two online refutation codes
// ---------------------------------------------------------------------------

/// **D56 rule O6.** The agreed fetched header for the attested height differs
/// from the one the bundle embeds.
///
/// Minted by D56 §7 and spelled by D91 §6.1's single `anchor-` prefix. It is
/// a `const` rather than an error arm for the same reason A12's
/// [`EmbeddedHeader::UNCOMMITTED_CODE`] is: nothing here fails, an artifact is
/// *classified*, and the code travels as a diagnostic on the verdict.
pub const OTS_ONLINE_HEADER_MISMATCH_CODE: &str = "anchor-ots-online-header-mismatch";

/// **D56 rule O7.** Both endpoints agreed there is no block at the attested
/// height.
///
/// Agreed absence is evidence, not the lack of it (D56 §3): without this code
/// an `.ots` claiming a height beyond the chain tip would render `attested`
/// for ever.
pub const OTS_ONLINE_BLOCK_ABSENT_CODE: &str = "anchor-ots-online-block-absent";

/// The two codes this module mints, for the Q52 error-code universe and
/// A38's reverse-coverage accounting.
///
/// D56 §7's other two are owned elsewhere and enumerated there:
/// `anchor-ots-digest-mismatch` is an `OtsError` arm (A11, D91 §6.4 —
/// the check lives inside `parse_ots`, so O2 names an outcome rather than
/// adding a second check), and `anchor-ots-header-uncommitted` is A12's
/// [`EmbeddedHeader::UNCOMMITTED_CODE`].
#[must_use]
pub const fn all_code_exemplars() -> [&'static str; 2] {
    [
        OTS_ONLINE_HEADER_MISMATCH_CODE,
        OTS_ONLINE_BLOCK_ABSENT_CODE,
    ]
}

// ---------------------------------------------------------------------------
// A39 — the suppressed-anomaly list
// ---------------------------------------------------------------------------

/// Where in an artifact a suppressed refutation was found.
///
/// # Why the chain half has no index
///
/// A39's `Do` asks for *"the path or branch index it came from"*. For an
/// `.ots` the branches are a document-ordered list and an index is a real
/// reference. For a certificate chain there is **no path list to index**:
/// D53 §3 forbids a permutation-style enumerator (16 mutually name-chaining
/// intermediates are cheap to build and enumerating simple paths over them is
/// factorial), so A9 searches a memoised DP over `(node, depth)` and never
/// materialises a path. A chain refutation is therefore reported against the
/// artifact. Recorded here rather than papered over with a fabricated index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnomalyLocus {
    /// The refutation is a property of the whole artifact — every chain
    /// anomaly, and every `.ots` anomaly about the upgrade group as a whole.
    Artifact,
    /// One `.ots` attestation, by index in **document order**.
    ///
    /// Document order is part of the artifact, so this is deterministic and
    /// identical on native and wasm32; it is not, and does not claim to be,
    /// invariant under a permutation of the branches. The *state*, the
    /// diagnostic and the anomaly **codes** are (D56 §5), and
    /// [`tests::the_state_and_anomaly_codes_are_invariant_under_branch_order`]
    /// is what pins that.
    Branch {
        /// Position of the attestation in the parsed artifact.
        index: u32,
    },
}

/// One refutation that best-evidence-wins discarded — **task A39**.
///
/// Both M2 decisions rule best-evidence-wins (D53's `C1/C2` over `C3–C5`,
/// D56's `O3–O5` over `O6–O8`) because the `.sealproof` bundle is
/// **unsigned**: under refutation-wins any relay could append one garbage
/// branch or certificate and turn an honest anchor `invalid`, which is a
/// downgrade-to-forgery-accusation primitive exercisable by anyone who
/// forwards a bundle. The price is that the discarded refutation vanishes
/// from the state; this is the record that it did not vanish from the datum.
///
/// **Wording-free.** [`Self::code`] is the stable code the suppressed rule
/// *would* have produced, and R18/R61 own every user-facing string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnchorAnomaly {
    code: &'static str,
    locus: AnomalyLocus,
}

impl AnchorAnomaly {
    /// A refutation about the artifact as a whole.
    #[must_use]
    pub const fn artifact(code: &'static str) -> Self {
        Self {
            code,
            locus: AnomalyLocus::Artifact,
        }
    }

    /// A refutation localised to one `.ots` attestation.
    #[must_use]
    pub const fn branch(code: &'static str, index: u32) -> Self {
        Self {
            code,
            locus: AnomalyLocus::Branch { index },
        }
    }

    /// The stable code the suppressed rule would have produced.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Where it was found.
    #[must_use]
    pub const fn locus(&self) -> AnomalyLocus {
        self.locus
    }
}

// ---------------------------------------------------------------------------
// A40 — anchor identity
// ---------------------------------------------------------------------------

/// A **verified** anchor identity — `docs/format/registry-v1.md` §8's
/// *"anchor independence must be evaluated from verified identities, never
/// from array length"*, given a type.
///
/// §8 makes duplicate anchor artifacts legal v1 **by decision**: *"a sealer
/// wanting two 'independent' TSA anchors from one TSA simply requests two
/// tokens — different bytes, same TSA, passes any byte-distinctness check"*.
/// Counting artifacts therefore over-states independence by construction, and
/// §8 records this is the irreversible direction — permissive now cannot be
/// tightened after the freeze — so the check has to live in the verdict layer
/// or nowhere.
///
/// # An identity exists exactly where the source is verified
///
/// A2 already ties [`super::model::AnchorSource::Verified`] to the two
/// headline-eligible states and `Claimed` to the rest. This type inherits that
/// rule instead of restating it: [`AnchorOutcome::identity`] is `Some` iff the
/// verdict is headline-eligible, so `internally-consistent-only` and `invalid`
/// contribute **zero** identities however different their claimed source
/// strings are (A40 Accept row 3), and so do `attested` and `pending`, whose
/// calendar names are equally unbound.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnchorIdentity {
    /// The TSA whose signer certificate the validated path closed under, by
    /// the DER of that certificate's `subject` distinguished name.
    ///
    /// DN rather than public key, deliberately: a TSA that rotates its
    /// signing key issues two tokens under two keys and one name, and
    /// counting keys would report a **rotation** as two independent
    /// anchors. Under-counting independence is the safe direction; the
    /// dangerous one is the direction registry §8 exists to close.
    ///
    /// The identity is only ever built from a certificate a validated path to
    /// a pinned root closed under, never from a bundle-recorded string — the
    /// wire carries no source string for either kind (D8 §1).
    TsaSigner {
        /// DER of the signer certificate's `subject` `Name`.
        subject_dn_der: Vec<u8>,
    },
    /// The calendars an `.ots` names, sorted and de-duplicated
    /// (A40 `Do`; `verify::report::AnchorResult::source` — *"OTS — the `.ots`
    /// attestations, which name their calendars"*).
    OtsCalendars(Vec<String>),
}

// ---------------------------------------------------------------------------
// A19 — the receipt's class
// ---------------------------------------------------------------------------

/// The Arbitrum payment receipt as it appears in a verdict — **task A19**.
///
/// MVP-SPEC.md line 110: the receipt renders as *"supporting evidence — no
/// independently proven time"*, because **no on-chain datum contains
/// `anchor_digest`**. This type is the enforcement, not a label on one:
///
/// - it has no [`AnchorState`] and no conversion to one;
/// - it has no verified time and no field one could be read from;
/// - its [`ReceiptClass`] has a single variant, so there is no other value to
///   return;
/// - it is not in [`AnchorVerdicts::outcomes`], so nothing that iterates
///   anchors can reach it, and [`AnchorKind`] has no receipt variant for it to
///   be one of.
///
/// [`Self::confirmation`] is the agreed two-RPC result (A17/D55) and is
/// **advisory overlay only**: it moves no state, contributes no headline, and
/// changes no byte of the projection. That is asserted as a differential in
/// [`tests::a_confirmed_receipt_changes_no_anchor_datum`], because a
/// classification that merely *happens* to be unused is one refactor away
/// from being used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptEvidence {
    block_number: u64,
    transaction_count: usize,
    confirmation: Option<ReceiptConfirmation>,
}

impl ReceiptEvidence {
    /// The fixed class. One variant; nothing this type carries can change it.
    #[must_use]
    pub const fn class(&self) -> ReceiptClass {
        ReceiptClass::SupportingEvidenceNoProvenTime
    }

    /// The recorded Arbitrum block number — display-only, unverified in v1,
    /// never verdict-bearing (registry §7.10 key 1).
    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }

    /// How many transactions the receipt records.
    #[must_use]
    pub const fn transaction_count(&self) -> usize {
        self.transaction_count
    }

    /// The agreed two-RPC confirmation, when the host performed one.
    ///
    /// Advisory overlay only (MVP-SPEC.md line 137: *"distinct from the
    /// offline cryptographic verdict"*). A19: a successful confirmation
    /// leaves the class, every anchor state and the headline untouched.
    #[must_use]
    pub const fn confirmation(&self) -> Option<ReceiptConfirmation> {
        self.confirmation
    }

    /// Never headline-eligible, and not because anyone remembered to check.
    ///
    /// The method exists so the claim is greppable and testable; there is no
    /// code path that could make it return `true`.
    #[must_use]
    pub const fn is_headline_eligible(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// one artifact's outcome
// ---------------------------------------------------------------------------

/// What A18 concluded about **one** anchor artifact.
///
/// The verdict is the report-facing datum; the other two fields are the ones
/// D53 §6 keeps out of report v1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorOutcome {
    verdict: AnchorVerdict,
    suppressed: Vec<AnchorAnomaly>,
    identity: Option<AnchorIdentity>,
}

impl AnchorOutcome {
    fn new(
        verdict: AnchorVerdict,
        suppressed: Vec<AnchorAnomaly>,
        identity: Option<AnchorIdentity>,
    ) -> Self {
        // A40's rule, applied once here rather than at every construction
        // site: an identity exists exactly where the source is verified, and
        // A2 ties that to headline eligibility. A claimed identity is not an
        // identity.
        let identity = identity.filter(|_| verdict.is_headline_eligible());
        Self {
            verdict,
            suppressed,
            identity,
        }
    }

    /// The verdict — state, verified time, source, fetch date, diagnostic.
    #[must_use]
    pub const fn verdict(&self) -> &AnchorVerdict {
        &self.verdict
    }

    /// Every refutation the precedence rule discarded (**A39**).
    ///
    /// **Empty, never absent**, when nothing was suppressed: "no anomalies"
    /// and "not computed" must never be the same value (A39 Accept row 3).
    #[must_use]
    pub fn suppressed(&self) -> &[AnchorAnomaly] {
        &self.suppressed
    }

    /// The verified identity (**A40**), or `None` where the artifact carries
    /// only a claimed one.
    #[must_use]
    pub const fn identity(&self) -> Option<&AnchorIdentity> {
        self.identity.as_ref()
    }
}

// ---------------------------------------------------------------------------
// the whole evaluation
// ---------------------------------------------------------------------------

/// Every anchor verdict for one bundle, plus the receipt's separate class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorVerdicts {
    outcomes: Vec<AnchorOutcome>,
    receipt: Option<ReceiptEvidence>,
    ots_present: bool,
    tsa_present: bool,
}

impl AnchorVerdicts {
    /// One outcome per artifact the bundle carries — `.ots` artifacts first,
    /// then TSA, each in wire order.
    ///
    /// That order is `verify::pipeline`'s (`bundle.ots_anchors()` chained with
    /// `bundle.tsa_anchors()`), matched so R12's projection lands the slots
    /// where the report already puts them.
    #[must_use]
    pub fn outcomes(&self) -> &[AnchorOutcome] {
        &self.outcomes
    }

    /// The `absent` verdict for a **kind** — `Some` iff the bundle carries no
    /// artifact of that kind (**D53 §4a**).
    ///
    /// This is the whole of [`AnchorState::Absent`]'s reachability from M2
    /// onward, and it is a ruling rather than a convenience:
    ///
    /// > `AnchorState::Absent` is what `evaluate_anchors` returns for a query
    /// > about an anchor **kind** the bundle does not carry — not for an
    /// > artifact — and R12 emits no `AnchorResult` slot for it.
    ///
    /// Every *artifact* lands in one of the other six states, F3 included
    /// (*"not `absent` — the artifact is present"*). A18's Accept originally
    /// said `absent` was *"covered by the empty-anchor vector"*; that vector
    /// produces **zero** slots, so it witnesses nothing and would keep passing
    /// if the variant were deleted.
    #[must_use]
    pub fn absent_verdict(&self, kind: AnchorKind) -> Option<AnchorVerdict> {
        let present = match kind {
            AnchorKind::Ots => self.ots_present,
            AnchorKind::Tsa => self.tsa_present,
        };
        (!present).then(|| AnchorVerdict::absent(kind))
    }

    /// The receipt's supporting-evidence datum (**A19**), when the bundle
    /// opted one in. Never an anchor.
    #[must_use]
    pub const fn receipt(&self) -> Option<&ReceiptEvidence> {
        self.receipt.as_ref()
    }

    /// Project into the report's `anchors` array — the **R12** primitive.
    ///
    /// Drops the diagnostic codes and the A39 anomaly list, because
    /// `AnchorResult` has exactly five fields and report v1 is frozen
    /// (D53 §6, D56 §6). An `absent` kind contributes no slot, so a bundle
    /// with no anchors still serializes the pinned `"anchors":[]`.
    #[must_use]
    pub fn project_anchor_results(&self) -> Vec<AnchorResult> {
        self.outcomes
            .iter()
            .filter_map(|outcome| outcome.verdict.to_anchor_result())
            .collect()
    }

    /// A1's minimal aggregate over the projected slots — the
    /// zero-headline-eligible (UNANCHORED) flag and the earliest headline
    /// time.
    ///
    /// Full aggregation is **R17's** (M3): earliest-headline selection across
    /// sources, the >48 h divergence flag and the UNANCHORED *outcome*. This
    /// is the M1/M2 library datum and nothing more.
    #[must_use]
    pub fn aggregate(&self) -> AnchorAggregate {
        aggregate_anchors(&self.project_anchor_results())
    }

    /// Every verified identity among headline-eligible anchors, de-duplicated
    /// and ordered (**A40**).
    #[must_use]
    pub fn verified_identities(&self) -> BTreeSet<&AnchorIdentity> {
        self.outcomes
            .iter()
            .filter_map(AnchorOutcome::identity)
            .collect()
    }

    /// How many **distinct** verified identities the headline-eligible anchors
    /// establish — the number A20's minimum-anchor gate and R17's divergence
    /// rule must read instead of `ots_anchors.len()` or `tsa_anchors.len()`
    /// (registry §8; **A40**).
    ///
    /// Two `proven` tokens from one TSA are **one**. A byte-identical
    /// duplicate `.ots` is **one**. Neither is a malformed bundle: §8 makes
    /// duplicates legal v1 by decision, and this is where that legality stops
    /// being mistakable for independence.
    #[must_use]
    pub fn distinct_verified_identities(&self) -> usize {
        self.verified_identities().len()
    }
}

/// Evaluate every anchor artifact in a bundle — **A18**.
///
/// Pure: no clock, no socket, no file. `verify_at_unix` is the caller's
/// verification time and `online` is data a host gathered (CLI via
/// `antseal-anchor`, or the page's JS); core never fetches.
///
/// # The signature is wider than A18's `Do` states, and it has to be
///
/// A18 writes `evaluate_anchors(artifacts, online_evidence, verify_at)`. Two
/// further inputs are load-bearing and cannot be defaulted away:
///
/// - **`anchor_digest`** — every per-artifact rule is *about this seal*. It is
///   `TSTInfo.messageImprint` at T2 and a required parameter of `parse_ots` at
///   O1 (D58 §10.2, D91 §6.4). Without it the strongest reachable defect in
///   D56 §9 is live: an `.ots` for *someone else's* seal carrying a genuine
///   online-confirmable Bitcoin attestation would render `proven`.
/// - **`roots`** — T3 validates against a pinned store. It is a parameter
///   rather than `TsaRootStore::pinned()` because A7's injection API is what
///   makes the untrusted-root row (`MATRIX.json`
///   `anchor-untrusted-root`) and A21's positive twin buildable at all.
#[must_use]
pub fn evaluate_anchors(
    artifacts: &AnchorArtifacts<'_>,
    anchor_digest: &[u8; 32],
    online: &OnlineEvidence,
    verify_at_unix: u64,
    roots: &TsaRootStore,
) -> AnchorVerdicts {
    let mut outcomes = Vec::with_capacity(
        artifacts.count_for(AnchorKind::Ots) + artifacts.count_for(AnchorKind::Tsa),
    );

    // The `.ots` rules see the block evidence and nothing else; the TSA rules
    // see no online input at all. Both are the D55/A2 obligation discharged
    // in the type rather than by discipline.
    for view in artifacts.ots() {
        outcomes.push(evaluate_ots_artifact(&view, anchor_digest, online.blocks()));
    }
    for view in artifacts.tsa() {
        outcomes.push(evaluate_tsa_artifact(
            &view,
            anchor_digest,
            roots,
            verify_at_unix,
        ));
    }

    AnchorVerdicts {
        outcomes,
        receipt: artifacts
            .receipt()
            .map(|receipt| receipt_evidence(&receipt, online.receipt())),
        ots_present: artifacts.count_for(AnchorKind::Ots) > 0,
        tsa_present: artifacts.count_for(AnchorKind::Tsa) > 0,
    }
}

/// A19 — classify the receipt. It reads no anchor and no anchor reads it.
fn receipt_evidence(
    receipt: &ReceiptArtifact<'_>,
    confirmation: Option<ReceiptConfirmation>,
) -> ReceiptEvidence {
    ReceiptEvidence {
        block_number: receipt.block_number(),
        transaction_count: receipt.transaction_hashes().len(),
        confirmation,
    }
}

// ---------------------------------------------------------------------------
// D56's O0–O9 — one `.ots` artifact
// ---------------------------------------------------------------------------

/// Classify one `.ots` artifact — **D56 rules O1–O9**, in that order.
///
/// O0 (*"artifact absent for this slot"*) is a kind-level answer and lives on
/// [`AnchorVerdicts::absent_verdict`]; by the time this is called an artifact
/// exists.
///
/// # `blocks`, not `online`
///
/// D55 §4 requires the Arbitrum receipt evidence to reach core *"in a field
/// that no `AnchorState` arm reads"*, and A2 made that structural by handing
/// the anchor rules a [`BlockEvidence`] that **cannot name** the receipt. This
/// signature is the other half of it.
#[must_use]
pub fn evaluate_ots_artifact(
    view: &OtsArtifactView<'_>,
    anchor_digest: &[u8; 32],
    blocks: &BlockEvidence,
) -> AnchorOutcome {
    let upgrade = view.upgrade();
    let fetch_date = upgrade.map(|u| u.fetch_date().to_string());

    // ── O1 (and O2) ────────────────────────────────────────────────────
    //
    // The `.ots` codec rejects the bytes. **O2 is the same rule**, not a
    // second check: D58 §10.2 makes `anchor_digest` a required parameter of
    // `parse_ots`, so the digest comparison happens at §10.3 step 5 inside
    // the parser — deliberately, since a post-parse check would let a
    // wrong-digest `.ots` amplify work — and `OtsArtifact` has no
    // `stamped_digest` field to read (D91 §6.4: *"Do not add a
    // `stamped_digest` field to make O2 literally executable"*). O1 claims
    // this input and its code for it is `anchor-ots-digest-mismatch`, which
    // is exactly what O2 says.
    let artifact = match parse_ots(view.ots(), anchor_digest) {
        Ok(artifact) => artifact,
        Err(error) => {
            return AnchorOutcome::new(
                AnchorVerdict::invalid(
                    AnchorKind::Ots,
                    AnchorDiagnostic::new(error.code()),
                    None,
                    fetch_date,
                ),
                Vec::new(),
                None,
            );
        }
    };

    let calendars = calendars_of(&artifact);
    let calendar_source = (!calendars.is_empty()).then(|| calendars.join(" "));
    let identity = AnchorIdentity::OtsCalendars(calendars);

    // A12's offline question, existential over the branch set so the answer
    // is invariant under branch order.
    let committed =
        upgrade.is_some_and(|u| check_embedded_header(&artifact, u) == EmbeddedHeader::Committed);
    // D56 §5's branch model: a branch whose path crossed a
    // registered-but-unimplemented op has an **indeterminate** value and is
    // `Unevaluable`. It is not evidence, so it neither promotes nor demotes —
    // which is what keeps an unknown attestation from demoting an honest
    // pending `.ots`.
    let has_evaluable_pending = artifact.attestations.iter().any(|attestation| {
        matches!(
            attestation,
            OtsAttestation::Pending {
                commitment: Some(_),
                ..
            }
        )
    });
    let agreed = upgrade.and_then(|u| blocks.block(u.block_height()));

    // The refutation O6/O7/O8 **would** have produced, computed once. When a
    // better rule wins it becomes the A39 suppressed entry; when none does it
    // becomes the verdict.
    let refutation = ots_refutation(&artifact, view, committed, agreed);

    // ── O3 ─────────────────────────────────────────────────────────────
    //
    // Both conjuncts are required. An online-agreed header alone proves
    // nothing about *this* seal — an attacker can embed a real, fetchable
    // header whose merkle root has no relation to the ops — and it is the
    // conjunction that makes `merkle_root_of(fetched) == branch commitment`
    // true transitively.
    if let (Some(u), Some(OnlineBlockResult::Header(agreed_header))) = (upgrade, agreed)
        && committed
        && agreed_header == *u.block_header()
    {
        // The time is the **agreed** header's `nTime`, never the embedded
        // one (D56 §5).
        //
        // **Measured, so that nobody re-derives it the hard way:** under the
        // guard above the two headers are byte-identical, so swapping this
        // for `header_time_unix(u.block_header())` is a *semantically
        // equivalent* mutation — planted, it survives the whole suite,
        // because it is the same computation. D56 §5 calls this rule "the
        // invariant no existing test can see"; the sharper statement is that
        // **no test can see it, existing or not**, because O3's byte equality
        // makes the distinction unobservable (D56 §9's row for it is
        // unsatisfiable — see `the_proven_time_is_read_from_the_agreed_header`).
        //
        // What *is* observable is a weakened guard — comparing merkle roots
        // instead of the whole header, which is the natural way to "fix" the
        // untestable rule — and that mutation is caught by two rows. So the
        // line below is written the safe way on principle, and the guard
        // above is where the defence actually lives.
        let time = i64::from(header_time_unix(&agreed_header));
        return AnchorOutcome::new(
            AnchorVerdict::proven(
                AnchorKind::Ots,
                time,
                Some(bitcoin_source(u.block_height())),
                fetch_date,
            ),
            refutation.into_iter().collect(),
            Some(identity),
        );
    }

    // ── O4 ─────────────────────────────────────────────────────────────
    //
    // Upgraded, header embedded, committed by the ops — and **never**
    // headline-eligible offline, carrying no time. A lone header's
    // proof-of-work is self-referential (MVP-SPEC.md line 108), and A2 made
    // the time unrepresentable rather than merely unset.
    //
    // The `let Some(u)` is structural rather than defensive: `committed` is
    // `upgrade.is_some_and(…)`, so the two conditions cannot disagree — and
    // writing it this way means there is no `unwrap_or(0)` here that would
    // silently render `bitcoin-block-0` if they ever did.
    if let Some(u) = upgrade
        && committed
    {
        return AnchorOutcome::new(
            AnchorVerdict::attested(
                AnchorKind::Ots,
                Some(bitcoin_source(u.block_height())),
                fetch_date,
            ),
            refutation.into_iter().collect(),
            Some(identity),
        );
    }

    // ── O5 ─────────────────────────────────────────────────────────────
    //
    // Best-evidence-wins puts `pending` above every refutation. The cheapest
    // laundering append is a pending attestation, so this is the pair an
    // attacker actually reaches — and it gains nothing, since `pending`
    // proves no time either.
    if has_evaluable_pending {
        return AnchorOutcome::new(
            AnchorVerdict::pending(AnchorKind::Ots, calendar_source, fetch_date),
            refutation.into_iter().collect(),
            Some(identity),
        );
    }

    // ── O6 / O7 / O8 ───────────────────────────────────────────────────
    if let Some(anomaly) = refutation {
        return AnchorOutcome::new(
            AnchorVerdict::invalid(
                AnchorKind::Ots,
                AnchorDiagnostic::new(anomaly.code()),
                calendar_source,
                fetch_date,
            ),
            Vec::new(),
            None,
        );
    }

    // ── O9 ─────────────────────────────────────────────────────────────
    //
    // Well-formed, committing `anchor_digest`, and pointing at nothing this
    // verifier holds: every branch ends in an op or attestation type it
    // cannot evaluate, or the artifact carries a Bitcoin branch with no
    // embedded header to be `attested` about. Line 133's definition,
    // unedited.
    AnchorOutcome::new(
        AnchorVerdict::internally_consistent_only(AnchorKind::Ots, calendar_source, fetch_date),
        Vec::new(),
        None,
    )
}

/// D56's refutation rules **O6 → O7 → O8**, first match wins.
///
/// Every one is guarded on `upgrade.is_some()`, which is why the converse
/// shape — a Bitcoin-attested branch with **no** upgrade group — falls
/// through to O9 rather than being refuted. That is correct rather than an
/// oversight: MVP-SPEC.md line 108 defines `attested` as *"ops commit
/// `anchor_digest` to the merkle root of Bitcoin block H (**header
/// embedded**)"*, so without the header there is nothing to be `attested`
/// about, and verifying such a branch from online evidence alone would be a
/// second promotion route the spec does not define.
fn ots_refutation(
    artifact: &OtsArtifact,
    view: &OtsArtifactView<'_>,
    committed: bool,
    agreed: Option<OnlineBlockResult>,
) -> Option<AnchorAnomaly> {
    let upgrade = view.upgrade()?;
    match agreed {
        // O6 — an agreed header that is not the embedded one refutes it.
        Some(OnlineBlockResult::Header(fetched)) if fetched != *upgrade.block_header() => {
            Some(AnchorAnomaly::artifact(OTS_ONLINE_HEADER_MISMATCH_CODE))
        }
        // O7 — agreed absence of the block. Collapsing this into "no
        // evidence" would let an `.ots` claiming a height beyond the chain
        // tip render `attested` for ever.
        Some(OnlineBlockResult::NoSuchBlock) => {
            Some(AnchorAnomaly::artifact(OTS_ONLINE_BLOCK_ABSENT_CODE))
        }
        // O8 — the embedded header is not committed by the ops. One code for
        // three shapes, because the predicate is one (D56 §5).
        _ if !committed => {
            let root = merkle_root_of(upgrade.block_header());
            // Where a branch *does* claim the recorded height and derives a
            // different root, name it — that is A12's own case and the only
            // shape of O8 that has a branch to point at. The lowest index
            // wins, so the locus is a total function of the artifact. The
            // other two shapes (no Bitcoin branch at that height at all; a
            // branch whose value is indeterminate) have no branch to blame
            // and stay at the artifact.
            let culprit = artifact
                .attestations
                .iter()
                .position(|attestation| match attestation {
                    OtsAttestation::Bitcoin {
                        height,
                        merkle_root: Some(derived),
                    } => *height == upgrade.block_height() && derived.as_slice() != root,
                    _ => false,
                })
                .and_then(|index| u32::try_from(index).ok());
            Some(match culprit {
                Some(index) => AnchorAnomaly::branch(EmbeddedHeader::UNCOMMITTED_CODE, index),
                None => AnchorAnomaly::artifact(EmbeddedHeader::UNCOMMITTED_CODE),
            })
        }
        _ => None,
    }
}

/// The calendars an artifact's pending attestations name — sorted and
/// de-duplicated, so the value is invariant under branch order.
///
/// **Indeterminate branches are included.** A calendar URI is read out of the
/// attestation payload, not derived through the ops, so a branch that crossed
/// an unimplemented op still names its calendar truthfully. That matters for
/// A40: the identity is about *who* the artifact points at, not about what the
/// verifier could compute.
fn calendars_of(artifact: &OtsArtifact) -> Vec<String> {
    let mut calendars: Vec<String> = artifact
        .attestations
        .iter()
        .filter_map(|attestation| match attestation {
            OtsAttestation::Pending { uri, .. } => Some(uri.clone()),
            _ => None,
        })
        .collect();
    calendars.sort_unstable();
    calendars.dedup();
    calendars
}

/// The source string for an upgraded `.ots`: the Bitcoin block its evidence
/// is about.
///
/// Not the calendar list, for the two upgraded states. `AnchorResult::source`
/// is documented as *"OTS — the `.ots` attestations, which name their
/// calendars"*, which is right for `pending`, `internally-consistent-only`
/// and `invalid`; for `attested` and `proven` the calendars are not what the
/// evidence is about, and for `proven` A2 would render them as **verified**,
/// which they are not — a pending attestation is unsigned. The block is.
fn bitcoin_source(height: u64) -> String {
    format!("bitcoin-block-{height}")
}

// ---------------------------------------------------------------------------
// D53's T0–T3 — one TSA artifact
// ---------------------------------------------------------------------------

/// Classify one RFC 3161 artifact — **D53 stages T1, T2, T3**, in that order.
///
/// T0 (*"no TSA artifact in the bundle"*) is a kind-level answer and lives on
/// [`AnchorVerdicts::absent_verdict`].
///
/// # T2 strictly before T3, and it is load-bearing
///
/// It is what makes `internally-consistent-only` mean what F3 says it means:
/// the state is **unreachable** unless the token's own bytes have already
/// been fully checked. A token whose CMS signature does not verify never
/// reaches C6 and never acquires the *"cryptographically well-formed"* label.
/// The natural wrong implementation builds the chain first and reports
/// "untrusted root" for something that was never a token.
///
/// # No online input, at all
///
/// Not merely `&BlockEvidence` — nothing. No TSA rule reads online evidence
/// in any D53 sub-case, and a parameter that exists is a parameter someone
/// can start branching on.
#[must_use]
pub fn evaluate_tsa_artifact(
    view: &TsaArtifactView<'_>,
    anchor_digest: &[u8; 32],
    roots: &TsaRootStore,
    verify_at_unix: u64,
) -> AnchorOutcome {
    let fetch_date = Some(view.fetch_date().to_string());

    // ── T1 / T2 ────────────────────────────────────────────────────────
    //
    // Strict-DER and the anchor-stage limits (A5) and the token-intrinsic
    // checks (A8) are one call and one code space. A failure renders **this
    // anchor** `invalid` (F2/F3) and no source at all: nothing was parsed far
    // enough to claim one.
    let token = match verify_token(view.token(), anchor_digest, None) {
        Ok(token) => token,
        Err(error) => {
            return AnchorOutcome::new(
                AnchorVerdict::invalid(
                    AnchorKind::Tsa,
                    AnchorDiagnostic::new(error.code()),
                    None,
                    fetch_date,
                ),
                Vec::new(),
                None,
            );
        }
    };

    // The bundle's own `intermediates` (registry §7.9 key 2), strict-DER like
    // everything else in the anchor stage. A certificate that does not decode
    // is an artifact we refused to finish reading, which F3 puts at `invalid`
    // and explicitly **not** at `internally-consistent-only`.
    let mut bundle_intermediates = Vec::with_capacity(view.intermediate_count());
    for der in view.intermediates() {
        match Certificate::from_der(der) {
            Ok(cert) => bundle_intermediates.push(cert),
            Err(error) => {
                // A5's own classification, minted by A5 and consumed here —
                // `anchor-der-not-strict` for a BER construct,
                // `anchor-der-nesting-depth` for an over-deep one,
                // `anchor-der-malformed` otherwise. No new code: the
                // rejection class is the same one whether the certificate
                // arrived in the token's bag or in the bundle's field.
                return AnchorOutcome::new(
                    AnchorVerdict::invalid(
                        AnchorKind::Tsa,
                        AnchorDiagnostic::new(der_error(DerSite::Certificate, error).code()),
                        claimed_signer(&token),
                        fetch_date,
                    ),
                    Vec::new(),
                    None,
                );
            }
        }
    }

    // ── T3 ─────────────────────────────────────────────────────────────
    let chain = validate_token_chain(&token, &bundle_intermediates, roots, verify_at_unix);
    let suppressed: Vec<AnchorAnomaly> = chain
        .suppressed_faults()
        .iter()
        .map(|fault| AnchorAnomaly::artifact(fault.code()))
        .collect();
    let identity =
        signer_dn_der(&token).map(|subject_dn_der| AnchorIdentity::TsaSigner { subject_dn_der });
    // `genTime` is a `GeneralizedTime`, so it cannot reach `i64::MAX`; the
    // saturation is here because `expect` in library code is not this
    // project's answer to an impossible branch.
    let gen_time = i64::try_from(token.gen_time_unix()).unwrap_or(i64::MAX);

    let verdict = match chain.state() {
        AnchorState::Proven => AnchorVerdict::proven(
            AnchorKind::Tsa,
            gen_time,
            verified_signer(&token),
            fetch_date,
        ),
        AnchorState::ValidAtStampingCertSinceExpired => {
            AnchorVerdict::valid_at_stamping_cert_since_expired(
                AnchorKind::Tsa,
                gen_time,
                verified_signer(&token),
                fetch_date,
            )
        }
        AnchorState::Invalid => {
            // A9 populates `fault` exactly when the state is `Invalid`. The
            // fallback names the most severe class rather than minting a
            // code for an unreachable branch, and
            // `tests::every_invalid_tsa_verdict_carries_one_of_a9s_three_codes`
            // is what says it is never taken.
            let fault = chain.fault().unwrap_or(ChainFault::ChainSignatureInvalid);
            AnchorVerdict::invalid(
                AnchorKind::Tsa,
                AnchorDiagnostic::new(fault.code()),
                claimed_signer(&token),
                fetch_date,
            )
        }
        // C6, and everything A9 cannot return: `Attested`, `Pending` and
        // `Absent` belong to other kinds and to T0, so the fallthrough is
        // the one state a chain that reaches no pinned root can carry.
        AnchorState::InternallyConsistentOnly
        | AnchorState::Attested
        | AnchorState::Pending
        | AnchorState::Absent => AnchorVerdict::internally_consistent_only(
            AnchorKind::Tsa,
            claimed_signer(&token),
            fetch_date,
        ),
    };

    AnchorOutcome::new(verdict, suppressed, identity)
}

/// The signer certificate's `subject`, rendered — the identity string the
/// report carries.
///
/// Read out of the certificate the ESS attribute bound and the path validated,
/// never from a bundle field: the wire carries no source string for either
/// kind (D8 §1 removed the TSA one — a sealer's claim, bound by nothing in an
/// unsigned bundle).
fn verified_signer(token: &VerifiedToken) -> Option<String> {
    Some(token.signer().tbs_certificate().subject().to_string())
}

/// The same string, for the states where it is only *claimed*.
///
/// One function and not two by design: A2 chooses the `Verified`/`Claimed`
/// arm from the **state**, so a claimed identity presented as verified is not
/// a mistake this module can make.
fn claimed_signer(token: &VerifiedToken) -> Option<String> {
    verified_signer(token)
}

/// DER of the signer certificate's `subject` `Name` — A40's TSA identity.
fn signer_dn_der(token: &VerifiedToken) -> Option<Vec<u8>> {
    token.signer().tbs_certificate().subject().to_der().ok()
}

#[cfg(test)]
mod tests;
