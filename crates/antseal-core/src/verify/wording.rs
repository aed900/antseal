//! **The single authoritative verdict-wording set** — R17 landed the
//! mechanism, **R18 froze it**.
//!
//! Every verdict sentence the product prints lives here. Renderers — the CLI
//! (R19/R21/U30), the page (R22/R23) and the overlay builder
//! ([`super::overlay::build_online_overlay`]) — receive **final strings** and
//! do layout only; none composes a verdict sentence of its own. The
//! enforcement is `tests/verdict_wording.rs`'s source scan, and the
//! consequence of the freeze is that **changing a string below is a
//! wording-snapshot event**: the committed document
//! `crates/antseal-core/tests/snapshots/verdict-wording.txt` moves with it,
//! deliberately and in review.
//!
//! # Where the words are not mine
//!
//! MVP-SPEC.md dictates several strings outright, and they appear here
//! verbatim rather than paraphrased:
//!
//! - line 137 — the headline template *"Existed no later than \<time\>
//!   (source)"*, the claimed-time label *"asserted by sealer — NOT
//!   verified"*, the UNANCHORED banner, the >48 h divergence rule;
//! - lines 110/137 — the receipt class *"supporting evidence — no
//!   independently proven time"*;
//! - line 132 — the `pending` guidance *"not yet independently provable —
//!   ask the sealer to run `status --upgrade`"*;
//! - line 108 — the `attested` guidance (*"ops commit `anchor_digest` to the
//!   merkle root of Bitcoin block H (header embedded); a provable time
//!   requires `--online` confirmation"*), with the height filled in;
//! - line 97 — the signature labels *"hybrid (PQ)"* and *"Ed25519-only"*;
//! - line 118 — *"storage is the product's bonus, not its proof"*, and
//!   *"this alone carries the evidentiary verdict"*.
//!
//! D64 (`docs/decisions/D64-online-overlay-headline-presentation.md` §8)
//! freezes the overlay's **structure** — block order, the heading's
//! "online"/"advisory"/non-replacement/strengthen-or-refute tokens, the
//! one-of-three headline impact, always-on slot-named probe lines with a
//! state word only on refutation, the overlay-only receipt line, the
//! endpoints disclosure, change-only deltas — and rules that *"every sentence
//! spelling inside that structure is R18's to author"*. Everything not listed
//! above is authored here under MVP-SPEC.md line 28's possession discipline;
//! the review checklist and its sweep live in the test file's header.
//!
//! # Declared divergences (CLI ↔ page)
//!
//! One table, one spelling — with exactly these declared exceptions, each
//! carrying a reason. A divergence that is not declared here is a defect.
//!
//! 1. **The `pending` guidance has two audiences.**
//!    [`PENDING_GUIDANCE`] is MVP-SPEC.md line 132's verifier-page copy,
//!    whose reader is a *third party* ("ask the sealer to…").
//!    [`PENDING_GUIDANCE_SELF`] is the same fact addressed to the sealer,
//!    who is `antseal status`'s own reader (D98 rider 5). Two audiences,
//!    two second persons, one table.
//! 2. **Page chrome is not wording.** D64 §5 declares the overlay's
//!    non-string surfaces — the activation affordance (CLI flag vs page
//!    button and its pre-activation placeholder), the page's visual
//!    distinction (CSS), R23's busy affordance — as page chrome, carrying no
//!    verdict wording at all. Nothing here spells them.
//! 3. **R61 extends this list**, with the suppressed-anomaly rows and the
//!    report-v1 carriage asymmetry (the CLI holds `AnchorVerdicts`; the page
//!    holds report bytes, which carry no anomaly field). The list is shaped
//!    to be added to.
//!
//! # WASM-safe
//!
//! Pure string assembly over already-computed data. No clock, no I/O, no
//! locale: times render as decimal POSIX seconds (the same spelling
//! `claimed_time_informational_only` and `fetch_date` froze at Q14), so the
//! output is byte-identical on native and wasm32.

use super::aggregate::headline_eligible;
use super::overlay::{EndpointProbeFailure, ProbeFailureClass};
use super::report::{AnchorKind, AnchorState, SignatureScheme};
use super::verdict::Headline;

// ---------------------------------------------------------------------------
// shared slots and tokens
// ---------------------------------------------------------------------------

/// The spec's headline-eligibility marker (MVP-SPEC.md line 127: *"**headline
/// eligible** states are tagged \[H\]"*).
pub const HEADLINE_TAG: &str = "[H]";

/// The slot text rendered when a headline-eligible anchor carries no source
/// identity.
pub const SOURCE_NOT_RECORDED: &str = "source not recorded";

/// The mandatory online-attribution marker (D64 §3.1: the Supplies headline
/// reuses the one template *"with a mandatory online-attribution marker in or
/// beside the source slot"*).
pub const ONLINE_ATTRIBUTION_MARKER: &str = "online-confirmed";

/// The anchor-kind label used inside sentences.
///
/// Byte-identical to [`AnchorKind::wire_name`] today — kept as its own
/// wildcard-free match so the two surfaces can be respelled apart without
/// touching the report's frozen wire names, and so a third kind fails
/// compilation here as well.
#[must_use]
pub const fn kind_label(kind: AnchorKind) -> &'static str {
    match kind {
        AnchorKind::Ots => "ots",
        AnchorKind::Tsa => "tsa",
    }
}

/// The slot name for one per-anchor row: the kind plus its 1-based ordinal
/// **within that kind**, in report order (OTS artifacts first, then TSA, each
/// in wire order — [`crate::anchor::verdicts::AnchorVerdicts::outcomes`]).
///
/// This is the U23 slot convention D64 §6.2 requires the overlay's rows to
/// align with; the offline per-anchor rows draw their names from this same
/// function so the two blocks name one anchor one way.
#[must_use]
pub fn slot_name(kind: AnchorKind, ordinal_within_kind: usize) -> String {
    format!("{}-{}", kind_label(kind), ordinal_within_kind)
}

/// The undecorated source-slot text for the offline headline sentence.
#[must_use]
pub fn source_slot(source: Option<&str>) -> String {
    source.unwrap_or(SOURCE_NOT_RECORDED).to_owned()
}

/// The online-attributed source-slot text (D64 §3.1: the marker lives in or
/// beside the source slot, never as a second sentence shape).
#[must_use]
pub fn online_source_slot(source: Option<&str>) -> String {
    format!(
        "{} — {ONLINE_ATTRIBUTION_MARKER}",
        source.unwrap_or(SOURCE_NOT_RECORDED)
    )
}

// ---------------------------------------------------------------------------
// the offline verdict block — headline and its absence
// ---------------------------------------------------------------------------

/// **The one headline template** (MVP-SPEC.md line 137's *"Existed no later
/// than \<time\> (source)"*; D64 §3: *"Template unity is frozen"*).
///
/// Both headline-shaped sentences the product can print — the offline block's
/// and the overlay's Supplies line ([`supplies_line`]) — come from this
/// function, differing only in the `source_slot` text they pass. A second
/// "existed no later than"-class shape anywhere is the defect Q89 names.
///
/// **Two authored departures from the spec's rendering, both deliberate:**
/// the sentence is lower-case because it never starts a sentence (it renders
/// indented inside a block, and the loud upper-case banner in this product is
/// [`UNANCHORED_BANNER`] alone); and the parenthesis carries the anchor
/// **kind** beside the source, which is the shipped U23 house convention D64
/// §1c measured, and is Q89's divergent-datum-naming rule applied to a slot
/// that would otherwise print two independent evidence families under one
/// name. Both keep the spec's own words, and both keep this string
/// byte-identical to what `antseal status` already prints — so the one-table
/// rule became true at adoption instead of after a U23 wording event.
#[must_use]
pub fn headline_sentence(time_unix: i64, kind: AnchorKind, source_slot: &str) -> String {
    format!(
        "existed no later than {time_unix} ({}, {source_slot})",
        kind_label(kind)
    )
}

/// The loud zero-headline-eligible banner (MVP-SPEC.md line 137, verbatim).
pub const UNANCHORED_BANNER: &str = "UNANCHORED — integrity and signature only, no provable time";

/// What a seal proves and what it does not (MVP-SPEC.md line 28's possession
/// discipline, in the verdict's own words).
///
/// The two limits the spec requires every rendering to state. The
/// compelled-disclosure note line 28 also mandates is documentation copy, not
/// verdict copy, and is deliberately not a row here.
pub const SEAL_MEANING_NOTE: &str = "a seal proves the holder of the sealing key possessed this \
                                     content by the proven time — not authorship, and not \
                                     exclusive possession";

/// How the >48 h rule is spelled, once (MVP-SPEC.md line 137: *"Divergence
/// \>48 h between headline-eligible anchors is flagged"*; the exact boundary
/// is [`super::verdict::HEADLINE_DIVERGENCE_THRESHOLD_SECS`]'s).
const DIVERGENCE_PHRASE: &str = "disagree by more than 48 h";

/// The offline block's divergence flag.
#[must_use]
pub fn divergence_flag_line(earliest_unix: i64, latest_unix: i64) -> String {
    format!(
        "flagged: headline-eligible anchors {DIVERGENCE_PHRASE} \
         (earliest {earliest_unix}, latest {latest_unix})"
    )
}

/// Change-only aggregate line: the online-augmented computation flags a
/// headline divergence where the offline one did not (D64 §3's example, and
/// the only aggregate delta the machinery can produce today — online evidence
/// adds eligible times and removes none, so a flag can appear and never
/// disappear).
#[must_use]
pub fn divergence_newly_flagged_line(earliest_unix: i64, latest_unix: i64) -> String {
    format!(
        "newly flagged: headline-eligible anchors now {DIVERGENCE_PHRASE} \
         (earliest {earliest_unix}, latest {latest_unix})"
    )
}

// ---------------------------------------------------------------------------
// the offline verdict block — per-anchor state rows
// ---------------------------------------------------------------------------

/// The `[H]` tag for one state, or the empty string.
///
/// Delegates to A1's **single** eligibility predicate
/// ([`headline_eligible`]) — there is deliberately no second match on
/// [`AnchorState`] here, so an eighth state breaks compilation at the
/// predicate and this tag follows it automatically (U23's "no second
/// eligibility table", made a ruling by D64 §6.1).
#[must_use]
pub const fn headline_tag(state: AnchorState) -> &'static str {
    if headline_eligible(state) {
        HEADLINE_TAG
    } else {
        ""
    }
}

/// What one anchor state means, in one sentence (MVP-SPEC.md lines 129–135).
///
/// Wildcard-free, so an eighth state cannot ship unspelled. This *is* a match
/// on [`AnchorState`] — a wording table, never an eligibility one: the `[H]`
/// tag beside it comes from [`headline_tag`] and nothing here decides it.
#[must_use]
pub const fn state_meaning(state: AnchorState) -> &'static str {
    match state {
        AnchorState::Proven => {
            "a TSA token valid against the pinned root store, or an OTS anchor confirmed online \
             against its Bitcoin block — it carries an independently proven time"
        }
        AnchorState::ValidAtStampingCertSinceExpired => {
            "valid at stamping; certificate since expired — the chain closed at the token's own \
             stamping time, which stays independently proven"
        }
        AnchorState::Attested => {
            "an upgraded OTS with the block header embedded — not headline-eligible offline, \
             because an embedded header proves no time on its own"
        }
        AnchorState::Pending => "an OTS submitted but not yet upgraded to a Bitcoin attestation",
        AnchorState::InternallyConsistentOnly => {
            "cryptographically well-formed but not independently anchored — it chains to no \
             pinned root (TSA) and matched nothing online (OTS)"
        }
        AnchorState::Invalid => "the signature or op check failed — this anchor proves nothing",
        AnchorState::Absent => "no anchor of this kind is present",
    }
}

/// One anchor state's row: the state word, its `[H]` tag when it has one, and
/// its meaning.
#[must_use]
pub fn anchor_state_line(state: AnchorState) -> String {
    let tag = headline_tag(state);
    if tag.is_empty() {
        format!("{} — {}", state.wire_name(), state_meaning(state))
    } else {
        format!("{} {tag} — {}", state.wire_name(), state_meaning(state))
    }
}

/// The `pending` guidance as MVP-SPEC.md line 132 mandates it, verbatim.
///
/// Third-person by design: the verifier page's reader is a counterparty, not
/// the sealer. The sealer-facing form is [`PENDING_GUIDANCE_SELF`] (declared
/// divergence 1, module docs).
pub const PENDING_GUIDANCE: &str =
    "not yet independently provable — ask the sealer to run `status --upgrade`";

/// The `pending` guidance addressed to the sealer (D98 rider 5): `antseal
/// status`'s reader **is** the sealer, so the page's "ask the sealer to…"
/// would be nonsense there.
///
/// The upgrade command is the caller's datum (it embeds a work id), so this
/// row is the sentence up to it; [`pending_guidance_self_line`] renders the
/// whole line.
pub const PENDING_GUIDANCE_SELF: &str = "not yet independently provable — run";

/// The sealer-facing `pending` line, command included.
#[must_use]
pub fn pending_guidance_self_line(upgrade_command: &str) -> String {
    format!("{PENDING_GUIDANCE_SELF} {upgrade_command}")
}

/// The `attested` guidance as MVP-SPEC.md line 108 mandates it, with the
/// attested height filled into the spec's `H`.
///
/// The height reaches a renderer only as an embedded display string: it lives
/// in `AnchorVerdicts`/the artifact, and **no `AnchorResult` field carries
/// it** (D64 §1c) — which is why this row exists rather than a page-side
/// composition.
#[must_use]
pub fn attested_block_line(height: u64) -> String {
    format!(
        "ops commit `anchor_digest` to the merkle root of Bitcoin block {height} (header \
         embedded); a provable time requires `--online` confirmation"
    )
}

/// The independently verified time carried by a time-proving state.
#[must_use]
pub fn verified_time_line(time_unix: i64) -> String {
    format!("independently proven time: {time_unix}")
}

/// A source identity that **this run verified** (D95 rider (b)/R74: one table
/// answers "was this identity verified?", so the CLI and the page cannot give
/// two differently-worded answers).
pub const SOURCE_VERIFIED_LABEL: &str = "verified by this run";

/// A source identity read out of the artifact and **not** verified — the
/// `internally-consistent-only` / `invalid` case, where the state already
/// says the chain did not close.
pub const SOURCE_CLAIMED_LABEL: &str = "claimed by the artifact — this run did not verify it";

/// One anchor's source line, labelled claimed or verified.
#[must_use]
pub fn source_line(identity: &str, verified: bool) -> String {
    let label = if verified {
        SOURCE_VERIFIED_LABEL
    } else {
        SOURCE_CLAIMED_LABEL
    };
    format!("source: {identity} ({label})")
}

// ---------------------------------------------------------------------------
// subordinate, sealer-written metadata — the `claimed_time` register
// ---------------------------------------------------------------------------

/// The claimed-time label (MVP-SPEC.md line 137, verbatim).
pub const CLAIMED_TIME_LABEL: &str = "asserted by sealer — NOT verified";

/// The sealer's claimed time, rendered subordinate and never headline-bound
/// (MVP-SPEC.md line 137). The value is
/// [`WorkMetadata::claimed_time_informational_only`]'s verbatim string.
///
/// [`WorkMetadata::claimed_time_informational_only`]:
///     super::report::WorkMetadata::claimed_time_informational_only
#[must_use]
pub fn claimed_time_line(claimed_time: &str) -> String {
    format!("claimed time: {claimed_time} ({CLAIMED_TIME_LABEL})")
}

/// The fetch-date label — the second, distinctly-named resident of the
/// `claimed_time` register (**D95 rider (a)**).
///
/// Named apart from [`CLAIMED_TIME_LABEL`] on purpose: two sealer-written
/// times in one output read as one datum unless their names diverge (Q89).
pub const FETCH_DATE_LABEL: &str = "sealer-recorded — NOT verified";

/// The sealer's recorded capture instant for one anchor artifact
/// (**D95 rider (a)**, format-permanent for report v1).
///
/// Three obligations, all discharged by this one row:
///
/// - **Subordinate to the state.** It renders beneath its anchor's state row
///   and never beside the headline; nothing here is a verdict.
/// - **Labelled sealer-recorded and not verified.** The bundle is unsigned
///   and `anchor_digest` covers the manifest envelope, not the anchor
///   sections; D59 §6(a) forbids comparing this value to anything, in any
///   direction.
/// - **No state gate.** It renders in *every* state that emits a slot,
///   `invalid` included — this function takes no [`AnchorState`], so there is
///   no branch to get wrong. That is exactly where the label has to hold:
///   beside a refuted anchor, an unlabelled date is read as corroboration,
///   which is why the sentence says outright that it is not evidence for the
///   state above.
#[must_use]
pub fn fetch_date_line(fetch_date: &str) -> String {
    format!("fetch date: {fetch_date} ({FETCH_DATE_LABEL}; it is not evidence for the state above)")
}

// ---------------------------------------------------------------------------
// the receipt's separate supporting-evidence class
// ---------------------------------------------------------------------------

/// The class the Arbitrum receipt renders in (MVP-SPEC.md lines 110 and 137,
/// verbatim) — never an anchor, never headline-eligible.
pub const RECEIPT_CLASS: &str = "supporting evidence — no independently proven time";

/// The receipt's class line: no state word, no time (D98 rider 4; D64 §5).
#[must_use]
pub fn receipt_class_line() -> String {
    format!("receipt: {RECEIPT_CLASS}")
}

/// The receipt's recorded detail — display-only figures (registry §7.10),
/// with the reason they prove no time attached to them.
#[must_use]
pub fn receipt_detail_line(block_number: u64, transaction_count: u64) -> String {
    format!(
        "recorded on Arbitrum block {block_number} across {transaction_count} transaction(s) — \
         this proves payment and existence-by-block, never this work's time"
    )
}

// ---------------------------------------------------------------------------
// the signature-scheme label
// ---------------------------------------------------------------------------

/// The signature-scheme label (MVP-SPEC.md line 97: verdicts label *"hybrid
/// (PQ)"* vs *"Ed25519-only"*).
///
/// Wildcard-free, so a fifth scheme cannot ship unspelled.
/// [`SignatureScheme::NotEvaluated`]'s spelling is dictated by its own field
/// doc — the stage has not run, so the label must not read as "unsigned" or
/// as "signatures failed" — and [`SignatureScheme::Other`]'s says only what
/// the report can support: report v1 carries the scheme and **no algorithm
/// list**, so no row here may name algorithms it cannot read.
#[must_use]
pub const fn signature_scheme_label(scheme: SignatureScheme) -> &'static str {
    match scheme {
        SignatureScheme::NotEvaluated => {
            "not evaluated by this build — this says nothing about the bundle's signatures in \
             either direction"
        }
        SignatureScheme::HybridPq => "hybrid (PQ)",
        SignatureScheme::Ed25519Only => "Ed25519-only",
        SignatureScheme::Other => {
            "a registered signature policy that is neither of the two named schemes — its \
             signatures were checked and passed"
        }
    }
}

/// The signature-scheme row.
#[must_use]
pub fn signature_scheme_line(scheme: SignatureScheme) -> String {
    format!("signature scheme: {}", signature_scheme_label(scheme))
}

// ---------------------------------------------------------------------------
// the raw mirror — R53's policy, as wording
// ---------------------------------------------------------------------------

/// The phrase reserved for a **full** reveal's mirror, and for nothing else.
pub const MIRROR_ORIGINAL_FILE_PHRASE: &str = "the original file";

/// A full reveal's raw mirror: the one state in which the mirror's bytes are
/// proven to be the file's original bytes (rows 9–10 — the `raw_commit`
/// opening and the `canonicalize_v(raw) == canonical` binding).
#[must_use]
pub fn mirror_full_reveal_line(size: u64) -> String {
    format!(
        "raw mirror: {MIRROR_ORIGINAL_FILE_PHRASE}, byte-for-byte ({size} bytes) — its bytes open \
         the raw commitment and canonicalize to the sealed canonical form"
    )
}

/// **The R53 policy**, stated as a row so no renderer has to re-derive it.
///
/// A mirror revealed beside a *partial* reveal is verified as an ordinary
/// unit and deliberately **not** reported as the file's mirror
/// ([`FileReveal::raw_mirror`] is `Some` only when `fully_revealed`): rows
/// 9–10 do not run, so those bytes are bound to the file by nothing.
/// Presenting them as [`MIRROR_ORIGINAL_FILE_PHRASE`] would promote unbound,
/// attacker-choosable bytes (2026-07-31 review, finding 8) — the exact defect
/// R53 closed on the producer side, kept closed here on the wording side.
///
/// [`FileReveal::raw_mirror`]: super::report::FileReveal::raw_mirror
pub const MIRROR_PARTIAL_REVEAL_POLICY: &str = "a raw mirror revealed beside a partial reveal is an ordinary revealed unit — verified as a \
     unit, and never presented as the original file: the raw-commitment opening and the \
     canonicalization binding run only on a full reveal";

// ---------------------------------------------------------------------------
// the two proof layers, and the advisory live check
// ---------------------------------------------------------------------------

/// The evidence layer's label (MVP-SPEC.md line 118, verbatim clause) — the
/// one layer that carries a verdict.
pub const EVIDENCE_LAYER_LABEL: &str = "evidence — this alone carries the evidentiary verdict";

/// The storage-linkage layer's label (MVP-SPEC.md lines 118–119) — rendered
/// distinctly from the evidence layer, and gating nothing in it.
pub const STORAGE_LINKAGE_LAYER_LABEL: &str = "storage linkage — offline address recomputation; \
                                               storage is the product's bonus, not its proof";

/// Storage linkage: the stage has not run (report v1's only arm today,
/// [`StorageLinkageResult::NotEvaluated`]).
///
/// Says nothing in either direction about where the work is stored — the same
/// discipline [`SignatureScheme::NotEvaluated`] carries.
///
/// [`StorageLinkageResult::NotEvaluated`]:
///     super::report::StorageLinkageResult::NotEvaluated
#[must_use]
pub const fn storage_linkage_not_evaluated_line() -> &'static str {
    "storage linkage: not evaluated by this build — this says nothing about where the work is \
     stored"
}

/// Storage linkage passed: every embedded ciphertext, and the re-encrypted
/// manifest, recompute to the addresses the manifest records (R20).
#[must_use]
pub fn storage_linkage_pass_line(unit_count: u64) -> String {
    format!(
        "storage linkage: {unit_count} embedded ciphertext(s) and the encrypted manifest \
         recompute to the addresses the manifest records"
    )
}

/// Storage linkage failed (R20) — and the evidence verdict is untouched,
/// because storage never gates it.
#[must_use]
pub fn storage_linkage_fail_line(mismatch_count: u64, checked_count: u64) -> String {
    format!(
        "storage linkage: {mismatch_count} of {checked_count} recorded address(es) do not match \
         the bytes in this bundle — the evidence verdict above is unchanged"
    )
}

/// The `--live` layer's label (MVP-SPEC.md line 119) — advisory, CLI-only
/// (D64 §6: the live section is a third sibling document), and never a gate
/// on the evidence verdict.
pub const LIVE_LAYER_LABEL: &str = "live network check (`--live`) — advisory: whether Autonomi \
                                    still serves these bytes today; it gates no verdict above";

/// `--live` verdict: every record came back byte-identical.
#[must_use]
pub fn live_all_persisted_line(checked_count: u64) -> String {
    format!("live check: all {checked_count} blob(s) are still served, byte-identical")
}

/// `--live` verdict: at least one address served bytes that are not the
/// expected ones — under content addressing that should be impossible, which
/// is why it outranks every other outcome.
#[must_use]
pub fn live_divergent_line(different_count: u64) -> String {
    format!(
        "live check: {different_count} address(es) served different bytes — under content \
         addressing that should be impossible"
    )
}

/// `--live` verdict: no divergence, but at least one record is not on the
/// network.
#[must_use]
pub fn live_some_missing_line(missing_count: u64) -> String {
    format!("live check: {missing_count} blob(s) are no longer on the network")
}

/// `--live` verdict: nothing negative was established, but the check could
/// not be completed.
#[must_use]
pub fn live_inconclusive_line(failed_count: u64) -> String {
    format!(
        "live check: inconclusive — {failed_count} fetch(es) failed and nothing negative was \
         established"
    )
}

/// One `--live` row: the record is still served, byte-identical.
#[must_use]
pub fn live_blob_identical_line(subject: &str) -> String {
    format!("{subject}: still served, byte-identical")
}

/// One `--live` row: the network served different bytes.
#[must_use]
pub fn live_blob_different_line(subject: &str) -> String {
    format!("{subject}: the network served different bytes")
}

/// One `--live` row: the network had nothing at this address.
#[must_use]
pub fn live_blob_not_found_line(subject: &str) -> String {
    format!("{subject}: not found on the network")
}

/// One `--live` row: the fetch failed, so nothing was established either way.
#[must_use]
pub fn live_blob_fetch_error_line(subject: &str, reason: &str) -> String {
    format!("{subject}: fetch failed ({reason}) — nothing established either way")
}

// ---------------------------------------------------------------------------
// the online advisory overlay (D64 §3's fixed structure)
// ---------------------------------------------------------------------------

/// The overlay's framing sentence (D64 §3/§5/§8): names "online" and
/// "advisory", refers to the offline verdict **above**, does not replace it,
/// and discloses that online results can strengthen **or refute**.
#[must_use]
pub const fn overlay_framing_line() -> &'static str {
    "online advisory — must-agree endpoint pairs; does not replace the offline verdict above; \
     online results can strengthen or refute individual anchors"
}

/// The Supplies-form headline-impact line (D64 §3.1 case 1): the one template
/// with the online-attribution marker in the source slot.
#[must_use]
pub fn supplies_line(headline: &Headline) -> String {
    headline_sentence(
        headline.time_unix(),
        headline.kind(),
        &online_source_slot(headline.source()),
    )
}

/// The Stands-form headline-impact line (D64 §3.1 case 2): points at the
/// offline headline, deliberately **not** restating the sentence.
#[must_use]
pub const fn stands_line() -> &'static str {
    "online result agrees: the offline headline above stands (time and source unchanged)"
}

/// The still-unanchored headline-impact line (D64 §3.1 case 3).
#[must_use]
pub const fn still_unanchored_line() -> &'static str {
    "still no independently provable time after the online check — the offline verdict above \
     stands"
}

/// Per-anchor line: promotion (D64 §5). Carries the promoted verdict's own
/// verified datum — block height, agreed time, attributed source — and **no
/// state word** (D64 §8: state words appear only on refutation).
#[must_use]
pub fn promoted_line(slot: &str, height: u64, time_unix: i64, source: Option<&str>) -> String {
    format!(
        "{slot}: Bitcoin block {height} agreed by both endpoints — time {time_unix} \
         ({})",
        online_source_slot(source)
    )
}

/// Per-anchor line: agreed refutation (D64 §5). The one line class that
/// carries the **state word `invalid`** and the error code (the
/// `anchor-forged-header` tamper family).
#[must_use]
pub fn refuted_line(slot: &str, code: &str) -> String {
    format!("{slot}: invalid — agreed online evidence refutes this anchor ({code})")
}

/// Per-anchor line: agreed refutation out-voted by a pending branch
/// (D56 §4's best-evidence-wins, D93 §5: the refutation is recorded as a
/// suppressed anomaly and the anchor's state does not move to `invalid`).
#[must_use]
pub fn refutation_suppressed_line(slot: &str, code: &str) -> String {
    format!(
        "{slot}: agreed online evidence contradicts the embedded header ({code}), but a pending \
         attestation out-votes the refutation; recorded, not promoted"
    )
}

/// Per-anchor line: the endpoint pair disagreed (D64 §5: advisory register,
/// no state word — nothing changed state; the offline state stands and
/// promotion is suppressed for this anchor alone).
#[must_use]
pub fn disagreed_line(slot: &str, height: u64) -> String {
    format!(
        "{slot}: the two endpoints disagreed about block {height} — no promotion; the offline \
         state stands"
    )
}

/// Per-anchor line: per-endpoint probe failures (D64 §5/§6.3; R24's
/// "per-endpoint fetch-failure states").
#[must_use]
pub fn endpoint_failures_line(
    slot: &str,
    height: u64,
    failures: &[EndpointProbeFailure],
) -> String {
    format!(
        "{slot}: online check for block {height} failed ({}) — no promotion; the offline \
         state stands",
        endpoint_failure_detail(failures)
    )
}

/// Per-anchor line: no agreed online evidence reached the verdict path for
/// this anchor's height (not attempted, or nothing usable arrived).
#[must_use]
pub fn no_evidence_line(slot: &str, height: u64) -> String {
    format!(
        "{slot}: no agreed online evidence for block {height} — no promotion; the offline state \
         stands"
    )
}

/// The failure-class word for one endpoint's probe failure. Wildcard-free so
/// a new class cannot ship unspelled (the L2 discipline at the class level).
#[must_use]
pub const fn probe_failure_class_label(class: ProbeFailureClass) -> &'static str {
    match class {
        ProbeFailureClass::Transport => "transport failure",
        ProbeFailureClass::Payload => "unusable reply",
        ProbeFailureClass::WrongChain => "wrong chain",
    }
}

/// The per-endpoint failure detail shared by the anchor and receipt failure
/// lines — one spelling of "endpoint: class", and one spelling of the empty
/// case.
fn endpoint_failure_detail(failures: &[EndpointProbeFailure]) -> String {
    if failures.is_empty() {
        return "no endpoint detail recorded".to_owned();
    }
    let parts: Vec<String> = failures
        .iter()
        .map(|failure| {
            format!(
                "{}: {}",
                failure.endpoint,
                probe_failure_class_label(failure.class)
            )
        })
        .collect();
    parts.join("; ")
}

/// Receipt echo: both RPCs confirmed the recorded transaction (supporting-
/// evidence register — **no time, no state word**; D64 §5, D98 rider 4).
#[must_use]
pub fn receipt_confirmed_line(block_number: u64, status_success: bool) -> String {
    let status = if status_success {
        ""
    } else {
        "; the transaction reverted"
    };
    format!(
        "receipt: both RPC endpoints confirm the recorded transaction on Arbitrum \
         (block {block_number}{status}) — supporting evidence only"
    )
}

/// Receipt echo: both RPCs agreed the transaction is not on chain.
#[must_use]
pub const fn receipt_not_on_chain_line() -> &'static str {
    "receipt: both RPC endpoints agree the recorded transaction is not on chain — supporting \
     evidence only"
}

/// Receipt echo: the RPC pair disagreed — no confirmation either way.
#[must_use]
pub const fn receipt_disagreed_line() -> &'static str {
    "receipt: the two RPC endpoints disagreed — no confirmation; supporting evidence only"
}

/// Receipt echo: the confirmation probe failed per endpoint.
#[must_use]
pub fn receipt_failed_line(failures: &[EndpointProbeFailure]) -> String {
    format!(
        "receipt: online confirmation failed ({}) — supporting evidence only",
        endpoint_failure_detail(failures)
    )
}

/// The endpoints-disclosure line (D64 §3/§8 edit 5): pinned defaults, or a
/// clearly-labeled departure from them.
#[must_use]
pub fn endpoints_line(identities: &[String], overridden: bool) -> String {
    let label = if overridden {
        "override — departing from pinned defaults"
    } else {
        "pinned defaults"
    };
    if identities.is_empty() {
        format!("endpoints: none recorded ({label})")
    } else {
        format!("endpoints: {} ({label})", identities.join(", "))
    }
}

#[cfg(test)]
mod tests;
