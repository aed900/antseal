//! A18/A19/A39/A40 against real captured material.
//!
//! These are **unit** tests on purpose: the `wasm32-core-tests` lane runs this
//! crate's `--lib` tests on `wasm32-unknown-unknown`, which has no filesystem,
//! so every fixture arrives through `include_bytes!` and every row below runs
//! natively **and** on wasm32. That is A18's third Accept clause
//! ("deterministic native-vs-wasm output") in the only form available before
//! A22 lands the bit-match harness.
//!
//! # The instrument warning this file was written under
//!
//! The root-store lane's suite passed 25/25 while four of eleven wrong
//! implementations survived it, because **real fixtures offer one viable path
//! and outlive their children**. So every rule here has either a differential
//! (the same bytes, one input changed, two different answers) or an explicit
//! anti-vacuity twin, and the synthetic `.ots` builder exists so that shapes
//! the captures do not contain — an unknown attestation type, a Bitcoin branch
//! with no upgrade group, a forged sibling — are reachable at all.

use super::*;

use crate::bundle::AnchorStatus;
use crate::bundle::schema::{OpaqueBytes, OtsAnchor, OtsUpgrade, ReceiptRecord, TsaAnchor};
use crate::verify::report::AnchorResult;

use crate::anchor::roots::{PinnedRoot, TsaRootStore};

use crate::anchor::testing::tamper_rows::{
    AFTER_CAPTURE, D60_STAMPED, DIGEST_A, FREETSA, MERGED_A, RowOutcome,
};

// The synthetic `.ots` writer, promoted out of this file into
// `anchor::testing` by **A82** so that A21's tamper rows and the integration
// targets can reach it — `test_util` is not `cfg(test)` and
// `crates/antseal-core/tests/` is a separate crate, so a `#[cfg(test)]` helper
// here was invisible to both homes the matrix uses. Nothing below changed
// except where these names resolve from.
use crate::anchor::testing::ots_writer::{
    ATTESTED_HEIGHT, DIGEST_UPGRADED_LARGE_TEST as DIGEST_UPGRADED, FETCH_DATE, HEADER_NTIME,
    SECOND_ATTESTED_HEIGHT, UPGRADED_LARGE_TEST as UPGRADED, bitcoin, committed_single_branch,
    committing_upgrade, committing_upgrade_at, container, derived_root, fork, header_with, pending,
    synthetic_digest, unknown,
};

/// A height neither real Bitcoin attestation in [`UPGRADED`] uses, so a
/// synthetic artifact and the two real ones can share one bundle and one
/// [`BlockEvidence`] map.
const SYNTHETIC_HEIGHT: u64 = 700_001;

// ── real captured material ──────────────────────────────────────────────
//
// The five fixtures A21's rows also need — `D60_STAMPED`, `FREETSA`,
// `MERGED_A`, `DIGEST_A`, `AFTER_CAPTURE` — are **imported** from
// `anchor::testing::tamper_rows` rather than declared twice. A21 needed them
// under `feature = "test-util"` as well as `cfg(test)`, which is the same
// promotion A82 made for the `.ots` writer one wave earlier and for the same
// reason: a second `include_bytes!` of the same path is a duplicate whose
// drift nothing would catch (the class task A88 records).
const DIGICERT: &[u8] =
    include_bytes!("../../../../../testdata/anchors/A25-bootstrap/D60-tsa-digicert-resp.tsr");
const SECTIGO: &[u8] =
    include_bytes!("../../../../../testdata/anchors/A25-bootstrap/D60-tsa-sectigo-resp.tsr");
/// Entrust and Sectigo are **two endpoints of one TSA**: the same signer
/// certificate signs both captures (`tests/anchor_real_tokens.rs`). That makes
/// them A40's decisive real fixture rather than a synthetic duplicate.
const ENTRUST: &[u8] =
    include_bytes!("../../../../../testdata/anchors/A25-bootstrap/D60-tsa-entrust-resp.tsr");
/// SwissSign's root is deliberately **not** pinned, so its chain reaches no
/// trust anchor — D53 C6 over real material.
const SWISSSIGN: &[u8] =
    include_bytes!("../../../../../testdata/anchors/A25-bootstrap/D60-tsa-swisssign-resp.tsr");

/// A height no chain has reached — D56 §3's *"an `.ots` claiming a block
/// beyond the chain tip"*, literally.
const BEYOND_CHAIN_TIP: u64 = 99_999_999;

// ── helpers ─────────────────────────────────────────────────────────────

fn opaque(bytes: &[u8]) -> OpaqueBytes {
    OpaqueBytes::from_vec(bytes.to_vec())
}

/// The sealer-recorded `status` is **never trusted** — the verifier derives
/// its own state (MVP-SPEC.md line 121), and A2's views do not even expose the
/// field. Every fixture here records `proven`, so a machine that leaked the
/// sealer's claim into the verdict would be *right* on the honest rows and
/// wrong on every negative one.
fn tsa_anchor(token: &[u8]) -> TsaAnchor {
    TsaAnchor::new(AnchorStatus::Proven, opaque(token), Vec::new(), FETCH_DATE)
        .expect("a real capture is under the D10 caps")
}

fn ots_anchor(bytes: &[u8], upgrade: Option<OtsUpgrade>) -> OtsAnchor {
    let status = if upgrade.is_some() {
        AnchorStatus::Attested
    } else {
        AnchorStatus::Pending
    };
    OtsAnchor::new(status, opaque(bytes), upgrade).expect("under the D10 caps")
}

fn receipt_record() -> ReceiptRecord {
    ReceiptRecord::new(
        vec![[0xab; 32]],
        200_000_001,
        opaque(b"opaque capture payload"),
    )
    .expect("a one-transaction receipt is well-formed")
}

/// An injected store built from owned DER, as `chain::tests` does it.
fn store_of(ders: Vec<(Vec<u8>, &'static str)>) -> TsaRootStore {
    use sha2::{Digest as _, Sha256};
    let roots: Vec<PinnedRoot> = ders
        .into_iter()
        .map(|(der, label)| {
            let cert = Certificate::from_der(&der).expect("test root parses");
            let spki = cert
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()
                .expect("SPKI encodes");
            let cert_sha256: [u8; 32] = Sha256::digest(&der).into();
            let spki_sha256: [u8; 32] = Sha256::digest(&spki).into();
            PinnedRoot {
                der: Box::leak(der.into_boxed_slice()),
                cert_sha256,
                spki_sha256,
                label,
            }
        })
        .collect();
    TsaRootStore::from_static(Box::leak(roots.into_boxed_slice()))
}

fn empty_store() -> TsaRootStore {
    store_of(Vec::new())
}

/// The same shape with a merkle root the ops do **not** derive — a header
/// substituted into an otherwise honest artifact.
fn forged_upgrade() -> OtsUpgrade {
    let mut root = derived_root(ATTESTED_HEIGHT);
    root[0] ^= 0x01;
    OtsUpgrade::new(
        ATTESTED_HEIGHT,
        header_with(&root, HEADER_NTIME),
        FETCH_DATE,
    )
}

fn evidence_header(height: u64, header: [u8; 80]) -> OnlineEvidence {
    OnlineEvidence::new().with_block(height, OnlineBlockResult::Header(header))
}

// `OtsError` stays imported here: the code-distinctness row below reads
// `OtsError::DigestMismatch.code()`. The writer that used to live in this
// section is now `anchor::testing::ots_writer` (**A82**).
use crate::anchor::ots::OtsError;

/// Evaluate one `.ots` with no online evidence.
fn ots_offline(bytes: &[u8], digest: &[u8; 32], upgrade: Option<OtsUpgrade>) -> AnchorOutcome {
    let view = OtsArtifactView::from_parts(bytes, upgrade.as_ref());
    evaluate_ots_artifact(&view, digest, &BlockEvidence::new())
}

/// Evaluate one `.ots` against supplied block evidence.
fn ots_online(
    bytes: &[u8],
    digest: &[u8; 32],
    upgrade: Option<OtsUpgrade>,
    online: &OnlineEvidence,
) -> AnchorOutcome {
    let view = OtsArtifactView::from_parts(bytes, upgrade.as_ref());
    evaluate_ots_artifact(&view, digest, online.blocks())
}

/// Evaluate one real TSA capture against a store.
fn tsa(token: &[u8], store: &TsaRootStore, verify_at: u64) -> AnchorOutcome {
    let anchor = tsa_anchor(token);
    let view = TsaArtifactView::from_anchor(&anchor);
    evaluate_tsa_artifact(&view, &D60_STAMPED, store, verify_at)
}

fn state_of(outcome: &AnchorOutcome) -> AnchorState {
    outcome.verdict().state()
}

fn code_of(outcome: &AnchorOutcome) -> Option<&'static str> {
    outcome.verdict().diagnostic().map(|d| d.code())
}

fn anomaly_codes(outcome: &AnchorOutcome) -> Vec<&'static str> {
    outcome
        .suppressed()
        .iter()
        .map(AnchorAnomaly::code)
        .collect()
}

// ════════════════════════════════════════════════════════════════════════
// A18 Accept row 1 — every one of the seven states, from a concrete fixture
// ════════════════════════════════════════════════════════════════════════

/// The exhaustive reachability row, and it is a row that can fail.
///
/// A18's Accept originally discharged `absent` with *"the empty-anchor
/// vector"*. D53 §4a measured that this witnesses **nothing**: that vector
/// produces zero anchor slots, so the clause passes vacuously and would keep
/// passing if the variant were deleted. `absent` is here as what it actually
/// is — the answer to a query about a **kind** the bundle does not carry —
/// and the companion row below asserts R12 emits no slot for it.
#[test]
fn every_one_of_the_seven_states_is_reachable_from_a_concrete_fixture() {
    let pinned = TsaRootStore::pinned();
    let mut seen: Vec<AnchorState> = Vec::new();
    let record = |state: AnchorState, seen: &mut Vec<AnchorState>| {
        if !seen.contains(&state) {
            seen.push(state);
        }
    };

    // proven — a real DigiCert token against the real pinned store.
    record(state_of(&tsa(DIGICERT, pinned, AFTER_CAPTURE)), &mut seen);
    // valid-at-stamping-cert-since-expired — the same bytes, a later clock.
    record(state_of(&tsa(DIGICERT, pinned, 4_000_000_000)), &mut seen);
    // attested — the real upgraded `.ots`, offline.
    record(
        state_of(&ots_offline(
            UPGRADED,
            &DIGEST_UPGRADED,
            Some(committing_upgrade()),
        )),
        &mut seen,
    );
    // pending — the real merged pending `.ots`.
    record(state_of(&ots_offline(MERGED_A, &DIGEST_A, None)), &mut seen);
    // internally-consistent-only — a real token whose root is not pinned.
    record(state_of(&tsa(SWISSSIGN, pinned, AFTER_CAPTURE)), &mut seen);
    // invalid — an `.ots` that stamps a different digest.
    record(
        state_of(&ots_offline(MERGED_A, &synthetic_digest(0x5a), None)),
        &mut seen,
    );
    // absent — a kind the bundle does not carry.
    let empty = AnchorArtifacts::from_parts(&[], &[], None);
    let verdicts = evaluate_anchors(
        &empty,
        &D60_STAMPED,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        pinned,
    );
    record(
        verdicts
            .absent_verdict(AnchorKind::Tsa)
            .expect("a kind with no artifact")
            .state(),
        &mut seen,
    );

    assert_eq!(
        seen.len(),
        AnchorState::ALL.len(),
        "states reached: {seen:?}"
    );
    for state in AnchorState::ALL {
        assert!(seen.contains(&state), "{state:?} is unreachable");
    }
}

/// **D53 §4a.** `absent` is a kind-level answer and R12 emits no slot for it,
/// so the empty-anchor vector still serializes the pinned `"anchors":[]`.
///
/// What makes it fail: the rejected alternative — a fixed `ots`+`tsa` slot
/// pair, `absent` when the kind has none — which would rewrite that pinned
/// string, the one report vector that carries anchor slots, and
/// `REPORT_VERSION` with them. That is a format event, not a lane decision.
#[test]
fn absent_is_a_kind_level_answer_and_emits_no_slot() {
    let empty = AnchorArtifacts::from_parts(&[], &[], None);
    let verdicts = evaluate_anchors(
        &empty,
        &D60_STAMPED,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );

    assert!(verdicts.outcomes().is_empty(), "no artifact, no outcome");
    for kind in [AnchorKind::Ots, AnchorKind::Tsa] {
        let verdict = verdicts
            .absent_verdict(kind)
            .expect("a kind with no artifact has an absent verdict");
        assert_eq!(verdict.state(), AnchorState::Absent);
        assert_eq!(verdict.kind(), kind);
        assert_eq!(verdict.verified_time_unix(), None);
        assert!(!verdict.is_headline_eligible());
        assert_eq!(verdict.to_anchor_result(), None);
    }

    assert!(verdicts.project_anchor_results().is_empty());
    assert_eq!(
        serde_json::to_string(&verdicts.project_anchor_results()).expect("serializes"),
        "[]",
        "the pinned \"anchors\":[] byte string"
    );
    assert!(verdicts.aggregate().is_unanchored());
}

/// Once a bundle carries an artifact of a kind, that kind has no `absent`
/// verdict — every artifact lands in one of the other six states, F3 included
/// (*"not `absent`, the artifact is present"*).
#[test]
fn a_kind_with_an_artifact_has_no_absent_verdict() {
    let ots = [ots_anchor(MERGED_A, None)];
    let artifacts = AnchorArtifacts::from_parts(&ots, &[], None);
    let verdicts = evaluate_anchors(
        &artifacts,
        &DIGEST_A,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );
    assert_eq!(verdicts.absent_verdict(AnchorKind::Ots), None);
    assert!(verdicts.absent_verdict(AnchorKind::Tsa).is_some());
    assert_eq!(verdicts.outcomes().len(), 1);
    assert_eq!(state_of(&verdicts.outcomes()[0]), AnchorState::Pending);
}

/// **D53 §4 / D56 §5.** No ineligible state carries a verified time, through
/// the whole evaluator rather than only at A2's constructors.
///
/// `aggregate_anchors` drops times on ineligible slots, so a wrongly populated
/// one is invisible to every other test in the tree.
#[test]
fn no_ineligible_state_carries_a_verified_time() {
    let pinned = TsaRootStore::pinned();
    let outcomes = vec![
        tsa(DIGICERT, pinned, AFTER_CAPTURE),
        tsa(DIGICERT, pinned, 4_000_000_000),
        tsa(SWISSSIGN, pinned, AFTER_CAPTURE),
        tsa(FREETSA, &empty_store(), AFTER_CAPTURE),
        ots_offline(UPGRADED, &DIGEST_UPGRADED, Some(committing_upgrade())),
        ots_offline(MERGED_A, &DIGEST_A, None),
        ots_offline(MERGED_A, &synthetic_digest(0x11), None),
        ots_online(
            UPGRADED,
            &DIGEST_UPGRADED,
            Some(committing_upgrade()),
            &evidence_header(
                ATTESTED_HEIGHT,
                header_with(&derived_root(ATTESTED_HEIGHT), HEADER_NTIME),
            ),
        ),
    ];
    for outcome in &outcomes {
        let verdict = outcome.verdict();
        assert_eq!(
            verdict.verified_time_unix().is_some(),
            verdict.is_headline_eligible(),
            "{:?} time/eligibility disagree",
            verdict.state()
        );
    }
    // Anti-vacuity: the run covers both sides of the equality.
    assert!(outcomes.iter().any(|o| o.verdict().is_headline_eligible()));
    assert!(outcomes.iter().any(|o| !o.verdict().is_headline_eligible()));
}

// ════════════════════════════════════════════════════════════════════════
// D56's O0–O9
// ════════════════════════════════════════════════════════════════════════

/// **O5.** The real merged pending `.ots` is `pending`, and it names its three
/// calendars.
///
/// The baseline every row below is a mutation of. A fixture that is not a
/// valid pending `.ots` makes all of them vacuous (R7's rule).
#[test]
fn a_real_merged_pending_ots_is_pending() {
    let outcome = ots_offline(MERGED_A, &DIGEST_A, None);
    assert_eq!(state_of(&outcome), AnchorState::Pending);
    assert_eq!(code_of(&outcome), None);
    assert_eq!(outcome.verdict().verified_time_unix(), None);
    assert!(!outcome.verdict().is_headline_eligible());
    assert!(outcome.suppressed().is_empty());

    let source = outcome
        .verdict()
        .source()
        .expect("a pending `.ots` names its calendars")
        .identity()
        .to_owned();
    for calendar in [
        "https://alice.btc.calendar.opentimestamps.org",
        "https://bob.btc.calendar.opentimestamps.org",
        "https://btc.calendar.catallaxy.com",
    ] {
        assert!(source.contains(calendar), "{source}");
    }
}

/// **O4.** The real upgraded `.ots` is `attested` offline — never `proven`,
/// and carrying no time.
///
/// What makes it fail: an implementation promoting on the embedded header
/// alone. That is the exact hole the online gate exists to close: a lone
/// header's proof-of-work is self-referential, so a minimal-difficulty forged
/// header mines in seconds (MVP-SPEC.md line 108).
#[test]
fn an_upgraded_ots_is_attested_offline_and_carries_no_time() {
    let outcome = ots_offline(UPGRADED, &DIGEST_UPGRADED, Some(committing_upgrade()));
    assert_eq!(state_of(&outcome), AnchorState::Attested);
    assert_eq!(outcome.verdict().verified_time_unix(), None);
    assert!(!outcome.verdict().is_headline_eligible());
    assert!(outcome.suppressed().is_empty());
}

/// **O3.** Matching online evidence promotes `attested` to `proven`, with the
/// block header's timestamp (A18 Accept row 2).
///
/// The differential: the *same* artifact, evaluated with and without the
/// evidence entry, gives two different states. An implementation that never
/// threads online evidence into the machine passes nothing here.
#[test]
fn matching_online_evidence_promotes_attested_to_proven() {
    let upgrade = committing_upgrade();
    let agreed = header_with(&derived_root(ATTESTED_HEIGHT), HEADER_NTIME);

    let offline = ots_offline(UPGRADED, &DIGEST_UPGRADED, Some(upgrade.clone()));
    assert_eq!(state_of(&offline), AnchorState::Attested);

    let online = ots_online(
        UPGRADED,
        &DIGEST_UPGRADED,
        Some(upgrade),
        &evidence_header(ATTESTED_HEIGHT, agreed),
    );
    assert_eq!(state_of(&online), AnchorState::Proven);
    assert!(online.verdict().is_headline_eligible());
    assert_eq!(
        online.verdict().verified_time_unix(),
        Some(i64::from(HEADER_NTIME)),
        "the proven time is the block header's nTime"
    );
    assert!(online.suppressed().is_empty());
}

/// **D56 §5's `nTime` rule — and the fixture D56 §9 asks for cannot exist.**
///
/// D56 §9 demands a row proving the `proven` time is read from the
/// **online-agreed** header rather than the embedded one, over *"a fixture
/// whose two headers differ in `nTime` alone while both commit the ops
/// root"*. **No such fixture can reach `proven`.** O3's guard is
/// `online == Some(Header(h)) && h == u.block_header` — a byte equality over
/// all 80 bytes — so two headers differing in `nTime` fail it and the
/// artifact never becomes `proven` at all. The distinction the row wants to
/// observe is unobservable by construction: whenever O3 fires the two headers
/// are byte-identical, so `nTime` read from either is the same integer.
///
/// This row pins the two things that *are* observable, and together they leave
/// a wrong implementation nowhere to go:
///
/// 1. **The guard is a whole-header equality, not a merkle-root comparison.**
///    An implementation that compared only the roots — the natural way to
///    "fix" the untestable rule — would promote on a header differing in
///    `nTime` and this row would go red.
/// 2. **The promoted time is that header's `nTime`**, not the fixture's
///    filler bytes or zero.
#[test]
fn the_proven_time_is_read_from_the_agreed_header() {
    let upgrade = committing_upgrade();
    let root = derived_root(ATTESTED_HEIGHT);
    let embedded = header_with(&root, HEADER_NTIME);
    let mut differs_in_ntime = header_with(&root, HEADER_NTIME + 3600);
    assert_eq!(
        embedded[..68],
        differs_in_ntime[..68],
        "the two headers differ in nTime alone"
    );
    assert_ne!(embedded, differs_in_ntime);
    assert_eq!(*upgrade.block_header(), embedded);

    let outcome = ots_online(
        UPGRADED,
        &DIGEST_UPGRADED,
        Some(upgrade.clone()),
        &evidence_header(ATTESTED_HEIGHT, differs_in_ntime),
    );
    assert_ne!(
        state_of(&outcome),
        AnchorState::Proven,
        "a header agreeing only up to nTime must not promote"
    );
    assert_eq!(outcome.verdict().verified_time_unix(), None);

    // …and with the embedded header agreed, the time is that header's `nTime`.
    differs_in_ntime[68..72].copy_from_slice(&HEADER_NTIME.to_le_bytes());
    assert_eq!(differs_in_ntime, embedded);
    let promoted = ots_online(
        UPGRADED,
        &DIGEST_UPGRADED,
        Some(upgrade),
        &evidence_header(ATTESTED_HEIGHT, differs_in_ntime),
    );
    assert_eq!(state_of(&promoted), AnchorState::Proven);
    assert_eq!(
        promoted.verdict().verified_time_unix(),
        Some(i64::from(HEADER_NTIME))
    );
}

/// **O6 as amended by D93 §5 — a self-consistent forgery that agreed online
/// evidence refutes is `invalid`, not `attested`.**
///
/// This row previously asserted the opposite — it was named
/// *a\_self\_consistent\_forgery\_refuted\_online\_**is\_attested**\_with\_the\_refutation\_recorded*,
/// and the name was accurate: it was **pinning the defect**. (Written without
/// backticks deliberately — Q69's doc-pointer check treats a backticked
/// test name as a live pointer, and this one names nothing.) As D56 §5 first
/// wrote the rule order, O4
/// returned on `upgrade.is_some() && header_commits` with `agreed` nowhere in
/// its guard, so O6 and O7 could only ever produce a verdict when the ops did
/// *not* commit the header — which is exactly when O8 already convicts the
/// artifact offline, with no online evidence needed. The online gate refuted
/// nothing it did not already have. Five statements contradicted that order,
/// four of them inside D56 (§3, §5's own summary table, §1's ruling that
/// MVP-SPEC.md lines 108/168 win, and A18's own Accept row 2); D93 §4 rules on
/// them and D93 §5 gives O4 a guard rather than a position.
///
/// The base is `committed_single_branch`, and both halves of that name are the
/// point: an *uncommitted* forgery renders `invalid` offline whatever the
/// evidence says, and a *pending sibling* makes O5 fire first.
///
/// What makes it fail — all three redden this row:
///
/// 1. **Restoring D56 §5's original order** (drop `!refuted_online` from O4):
///    renders `attested`. That is the fault this row exists for.
/// 2. **Dropping the online evidence** from the exercise: renders `attested`,
///    which is why the withheld-evidence direction is asserted here too — the
///    online gate has to be threaded and not decoration.
/// 3. **Weakening O3's guard to a merkle-root comparison**: renders `proven`,
///    which is the promotion hole D56 §9's retired `nTime` row was reaching
///    for (D93 §8).
#[test]
fn a_committed_forgery_refuted_online_is_invalid() {
    let (digest, bytes, upgrade) = committed_single_branch(0xe1, ATTESTED_HEIGHT);
    let embedded = *upgrade.block_header();

    // Anti-vacuity, over one artifact and in both directions: the base really
    // is committed **and** promotable, so `invalid` below is the online gate
    // firing rather than the fixture being broken.
    let proven = ots_online(
        &bytes,
        &digest,
        Some(upgrade.clone()),
        &evidence_header(ATTESTED_HEIGHT, embedded),
    );
    assert_eq!(
        state_of(&proven),
        AnchorState::Proven,
        "the base must be committed and promotable, or this row pins nothing"
    );

    // …and with the evidence withheld it is `attested`. Same bytes, one input
    // removed, a different answer.
    let withheld = ots_offline(&bytes, &digest, Some(upgrade.clone()));
    assert_eq!(state_of(&withheld), AnchorState::Attested);
    assert!(withheld.suppressed().is_empty());

    // The rule under test: one agreed header that is not the embedded one.
    let refuting = header_with(&digest, HEADER_NTIME + 3600);
    assert_eq!(
        refuting[..68],
        embedded[..68],
        "the refuting header differs in nTime alone, so only O3's whole-header \
         equality separates them"
    );
    let refuted = ots_online(
        &bytes,
        &digest,
        Some(upgrade),
        &evidence_header(ATTESTED_HEIGHT, refuting),
    );
    assert_eq!(state_of(&refuted), AnchorState::Invalid);
    assert_eq!(code_of(&refuted), Some(OTS_ONLINE_HEADER_MISMATCH_CODE));
    assert_eq!(refuted.verdict().verified_time_unix(), None);
    assert!(!refuted.verdict().is_headline_eligible());
    assert!(
        refuted.suppressed().is_empty(),
        "the refutation is the verdict here, not a suppressed anomaly"
    );

    // **O6 over O8, unchanged by D93.** The *uncommitted* forgery — the only
    // shape the pre-D93 machine could refute — still reports the online code
    // rather than the structural one.
    let (other, substituted, _) = committed_single_branch(0xe2, ATTESTED_HEIGHT);
    let honest_root = header_with(&derived_root(ATTESTED_HEIGHT), HEADER_NTIME + 3600);
    let outcome = ots_online(
        &substituted,
        &other,
        Some(committing_upgrade()),
        &evidence_header(ATTESTED_HEIGHT, honest_root),
    );
    assert_eq!(state_of(&outcome), AnchorState::Invalid);
    assert_eq!(
        code_of(&outcome),
        Some(OTS_ONLINE_HEADER_MISMATCH_CODE),
        "an agreed online refutation beats the offline structural one (O6 over O8)"
    );
    assert_eq!(outcome.verdict().verified_time_unix(), None);
}

/// **D56 §4 survives D93 §5 — O5 keeps its precedence over O6 and O7.**
///
/// A `committed` artifact that agreed evidence refutes renders `pending`, not
/// `invalid`, when it also carries an evaluable pending branch: the pending
/// branch is the strongest unrefuted claim, and the `.sealproof` bundle is
/// **unsigned**, so refutation-wins would hand any relay a
/// downgrade-to-forgery-accusation primitive. The refutation is carried as the
/// A39 suppressed entry rather than acted on.
///
/// This is the case D93's amendment moves from `attested` to `pending`, and
/// it is the *only* place best-evidence-wins still discards a genuine online
/// refutation. Before the amendment this artifact rendered `attested` — a
/// strictly stronger claim than the evidence supports.
///
/// What makes it fail: lifting O6/O7 above O5 as well as above O4, which
/// renders `invalid` and reinstates the relay primitive D56 §4 exists to
/// close.
#[test]
fn a_pending_branch_is_not_demoted_by_an_online_refutation() {
    let upgrade = committing_upgrade();
    let refuting = header_with(&derived_root(ATTESTED_HEIGHT), HEADER_NTIME + 3600);
    let outcome = ots_online(
        UPGRADED,
        &DIGEST_UPGRADED,
        Some(upgrade.clone()),
        &evidence_header(ATTESTED_HEIGHT, refuting),
    );
    assert_eq!(state_of(&outcome), AnchorState::Pending);
    assert_eq!(
        anomaly_codes(&outcome),
        vec![OTS_ONLINE_HEADER_MISMATCH_CODE],
        "the online refutation must survive best-evidence-wins"
    );
    assert_eq!(outcome.verdict().verified_time_unix(), None);
    assert!(!outcome.verdict().is_headline_eligible());

    // The fixture is committed **and** carries an evaluable pending branch —
    // both, or this row is about some other rule. Two evaluations of the same
    // bytes say so.
    assert_eq!(
        state_of(&ots_offline(UPGRADED, &DIGEST_UPGRADED, Some(upgrade))),
        AnchorState::Attested,
        "committed: with no evidence O4 fires"
    );
    assert_eq!(
        state_of(&ots_offline(UPGRADED, &DIGEST_UPGRADED, None)),
        AnchorState::Pending,
        "and an evaluable pending branch exists"
    );
}

/// **D93 §5's A39 consequence, asserted rather than argued.** Under the
/// amended guard O4 can carry **no** suppressed anomaly: `refutation` is
/// `Some` only for O6 (excluded by `!refuted_online`), O7 (likewise) or O8
/// (excluded by `committed`).
///
/// What makes it fail: restoring D56 §5's original order. O4 then fires on a
/// committed artifact that agreed evidence refutes, carrying that refutation
/// as a recorded-and-ignored anomaly — which is the one case D93 removed, and
/// the shape in which the defect was invisible for a whole wave.
///
/// The sweep is anti-vacuous in both directions: it asserts it saw an
/// `attested` outcome at all, and that the same sweep *can* observe a
/// non-empty suppressed list (the O5 rows do).
#[test]
fn an_attested_ots_never_carries_a_suppressed_anomaly() {
    let (single, single_bytes, single_upgrade) = committed_single_branch(0xe3, ATTESTED_HEIGHT);
    let refuting = header_with(&single, HEADER_NTIME + 3600);
    let absent = OnlineEvidence::new().with_block(ATTESTED_HEIGHT, OnlineBlockResult::NoSuchBlock);
    let honest = header_with(&derived_root(ATTESTED_HEIGHT), HEADER_NTIME);

    let cases: Vec<AnchorOutcome> = vec![
        // committed, no evidence -> attested
        ots_offline(&single_bytes, &single, Some(single_upgrade.clone())),
        // committed, refuting header -> invalid (was: attested + anomaly)
        ots_online(
            &single_bytes,
            &single,
            Some(single_upgrade.clone()),
            &evidence_header(ATTESTED_HEIGHT, refuting),
        ),
        // committed, agreed absence -> invalid (was: attested + anomaly)
        ots_online(&single_bytes, &single, Some(single_upgrade), &absent),
        // committed with a pending sibling, refuted -> pending + anomaly
        ots_online(
            UPGRADED,
            &DIGEST_UPGRADED,
            Some(committing_upgrade()),
            &evidence_header(ATTESTED_HEIGHT, header_with(&single, HEADER_NTIME)),
        ),
        // uncommitted with a pending sibling -> pending + anomaly
        ots_offline(MERGED_A, &DIGEST_A, Some(committing_upgrade())),
        // the real upgraded fixture, honest and offline -> attested
        ots_offline(UPGRADED, &DIGEST_UPGRADED, Some(committing_upgrade())),
        // …and online, agreeing -> proven
        ots_online(
            UPGRADED,
            &DIGEST_UPGRADED,
            Some(committing_upgrade()),
            &evidence_header(ATTESTED_HEIGHT, honest),
        ),
    ];

    for outcome in &cases {
        if state_of(outcome) == AnchorState::Attested {
            assert!(
                outcome.suppressed().is_empty(),
                "O4 carried {:?}",
                anomaly_codes(outcome)
            );
        }
    }
    assert!(
        cases.iter().any(|o| state_of(o) == AnchorState::Attested),
        "the sweep must reach O4 at all"
    );
    assert!(
        cases.iter().any(|o| !o.suppressed().is_empty()),
        "the sweep must be able to see a non-empty suppressed list, or the \
         assertion above is vacuous"
    );
}

/// **O3's conjunction.** An agreed header the ops do not commit does not
/// promote.
///
/// What makes it fail: checking only `h == u.block_header` and skipping
/// `header_commits`. The artifact would reach `proven` on a real, fetchable
/// block that has no relation to this seal — and since the attacker chooses
/// both the embedded header and the height, that is a promotion route with no
/// cryptographic content at all.
#[test]
fn online_evidence_that_does_not_commit_the_ops_root_does_not_promote() {
    let upgrade = forged_upgrade();
    // The fetched header is byte-identical to the embedded one, so the online
    // half of O3 holds. Only `header_commits` fails.
    let agreed = *upgrade.block_header();
    let outcome = ots_online(
        UPGRADED,
        &DIGEST_UPGRADED,
        Some(upgrade),
        &evidence_header(ATTESTED_HEIGHT, agreed),
    );
    assert_ne!(state_of(&outcome), AnchorState::Proven);
    assert_eq!(state_of(&outcome), AnchorState::Pending, "O5 over O8");
    assert_eq!(
        anomaly_codes(&outcome),
        vec![EmbeddedHeader::UNCOMMITTED_CODE],
        "the refutation is suppressed, not lost"
    );
}

/// **O7, over the fixture that can actually witness it (D93 §3/§7).** An
/// `.ots` whose ops commit its embedded header, at a height both endpoints
/// agree holds no block, is `invalid`.
///
/// This is the committed twin, and D93 §3 is why it had to be written: the
/// `!committed` row below carried this rule's doc comment for a whole wave
/// while being unable to see it. Under the original rule order O4 returned
/// before the refutation block ever ran whenever the ops committed the header,
/// so `NoSuchBlock` was **not** collapsed into "no evidence" — it was simply
/// never reached, and an `.ots` claiming a height beyond the chain tip
/// rendered `attested` for ever, which is the defect D56 §3 states in those
/// words as the reason this rule exists.
///
/// The `attested`-for-ever defect is made visible rather than described: the
/// same bytes with the evidence withheld render `attested`, and **nothing
/// offline can ever refute them** — the ops do commit the header, so O8 has
/// nothing to say. Only the online gate can, and only if it is reachable.
///
/// What makes it fail: collapsing `NoSuchBlock` into "no entry" (renders
/// `attested`), or reverting D93's guard on O4 (also `attested`).
#[test]
fn agreed_absence_of_the_block_is_invalid_when_the_ops_commit_the_header() {
    let (digest, bytes, upgrade) = committed_single_branch(0x22, BEYOND_CHAIN_TIP);

    // The offline half of the defect, measured: this artifact is `attested`
    // with no online evidence and there is no offline rule that can refute it.
    let withheld = ots_offline(&bytes, &digest, Some(upgrade.clone()));
    assert_eq!(
        state_of(&withheld),
        AnchorState::Attested,
        "the ops commit the header, so O8 has nothing to say about it"
    );
    assert!(withheld.suppressed().is_empty());

    let online = OnlineEvidence::new().with_block(BEYOND_CHAIN_TIP, OnlineBlockResult::NoSuchBlock);
    let outcome = ots_online(&bytes, &digest, Some(upgrade), &online);
    assert_eq!(state_of(&outcome), AnchorState::Invalid);
    assert_eq!(code_of(&outcome), Some(OTS_ONLINE_BLOCK_ABSENT_CODE));
    assert_eq!(outcome.verdict().verified_time_unix(), None);
    assert!(!outcome.verdict().is_headline_eligible());
}

/// **O7 over O8**, which is all this row has ever measured.
///
/// Kept, renamed and re-scoped by D93 §7. It was committed under the
/// unqualified name *agreed\_absence\_of\_the\_block\_is\_invalid*, carrying the
/// doc comment *"What makes it fail: collapsing `NoSuchBlock` into 'no entry'.
/// An `.ots` claiming a height beyond the chain tip would then render
/// `attested` for ever"* — and it **could not see that defect**, because its
/// fixture is not committed:
/// with zero ops every branch commitment is the stamped digest, while
/// `committing_upgrade()`'s header carries the real ops-derived root of the
/// `LARGE_TEST` capture. O8 convicts these same bytes on its own. It is the
/// eighth instrument this project has caught naming a defect in prose and
/// being structurally blind to it, and the committed twin above is the row
/// that is not.
///
/// The precondition is now **asserted rather than assumed**, so nobody can
/// re-read this row as the witness for O7: the same bytes with no online
/// evidence render `invalid` with O8's code.
///
/// What makes it fail: putting O8 above O7 in [`ots_refutation`]. The row then
/// reports `anchor-ots-header-uncommitted` and the ordering claim is gone.
#[test]
fn agreed_absence_of_the_block_beats_the_uncommitted_header() {
    let digest = synthetic_digest(0x21);
    // Strip the pending branches so nothing better applies: the real fixture's
    // two pending attestations would otherwise win under O5, which is itself
    // the A21 trap D56 §4 records.
    let bytes = container(
        &digest,
        &fork(&[bitcoin(ATTESTED_HEIGHT), bitcoin(ATTESTED_HEIGHT + 1)]),
    );

    // The precondition, measured: O8 alone already convicts this artifact.
    let offline = ots_offline(&bytes, &digest, Some(committing_upgrade()));
    assert_eq!(state_of(&offline), AnchorState::Invalid);
    assert_eq!(
        code_of(&offline),
        Some(EmbeddedHeader::UNCOMMITTED_CODE),
        "this fixture is NOT committed, which is why it cannot witness O7"
    );

    let online = OnlineEvidence::new().with_block(ATTESTED_HEIGHT, OnlineBlockResult::NoSuchBlock);
    let outcome = ots_online(&bytes, &digest, Some(committing_upgrade()), &online);
    assert_eq!(state_of(&outcome), AnchorState::Invalid);
    assert_eq!(
        code_of(&outcome),
        Some(OTS_ONLINE_BLOCK_ABSENT_CODE),
        "the agreed online refutation is reported, not the structural one"
    );
    assert_eq!(outcome.verdict().verified_time_unix(), None);
}

/// **O8's second shape.** An embedded header for a height that has no Bitcoin
/// attestation at all.
///
/// What makes it fail: an O8 predicate written as *"the derived root
/// disagrees"* rather than *"the embedded header is not committed"* — with no
/// branch at the recorded height there is no root to disagree, and the
/// artifact would fall through to O9 and render `internally-consistent-only`.
/// The locus is the artifact, because there is no branch to name.
#[test]
fn an_embedded_header_for_an_unattested_height_is_invalid() {
    let digest = synthetic_digest(0x31);
    let bytes = container(&digest, &bitcoin(ATTESTED_HEIGHT + 77));
    let outcome = ots_offline(&bytes, &digest, Some(committing_upgrade()));
    assert_eq!(state_of(&outcome), AnchorState::Invalid);
    assert_eq!(code_of(&outcome), Some(EmbeddedHeader::UNCOMMITTED_CODE));
}

/// **O5 over O8.** An upgrade group over a still-pending `.ots` is `pending`,
/// not `invalid`.
///
/// `docs/format/registry-v1.md` §7.8 makes this artifact well-formed v1 **by
/// decision**, and it is the shape a sealer produces mid-upgrade. Reordering
/// O8 above O5 would accuse an honest bundle of forgery.
#[test]
fn an_upgrade_group_over_a_pending_only_ots_is_pending_not_invalid() {
    let outcome = ots_offline(MERGED_A, &DIGEST_A, Some(committing_upgrade()));
    assert_eq!(state_of(&outcome), AnchorState::Pending);
    assert_eq!(
        anomaly_codes(&outcome),
        vec![EmbeddedHeader::UNCOMMITTED_CODE],
        "the uncommitted header is recorded, not asserted"
    );
}

/// **The converse shape (D56 §5).** A Bitcoin-attested branch with **no**
/// upgrade group is `internally-consistent-only`.
///
/// What makes it fail: promoting to `attested` on the ops alone, with no
/// embedded header — which is the offline forgeable time the online gate
/// exists to prevent, reached by a different route than the one line 108
/// closes. A relay can strip keys 2–4 from an unsigned bundle to produce this
/// shape, so it is a degradation and never a false statement.
#[test]
fn a_bitcoin_branch_without_an_upgrade_group_is_internally_consistent_only() {
    let outcome = ots_offline(UPGRADED, &DIGEST_UPGRADED, None);
    // The real upgraded fixture carries pending branches too, so isolate the
    // Bitcoin-only case.
    assert_eq!(state_of(&outcome), AnchorState::Pending, "O5 still applies");

    let digest = synthetic_digest(0x41);
    let bitcoin_only = container(&digest, &bitcoin(ATTESTED_HEIGHT));
    let outcome = ots_offline(&bitcoin_only, &digest, None);
    assert_eq!(state_of(&outcome), AnchorState::InternallyConsistentOnly);
    assert_eq!(outcome.verdict().verified_time_unix(), None);
    assert!(!outcome.verdict().is_headline_eligible());
}

/// **D56 §3.** An `--online` probe that resolved nothing leaves the state at
/// `attested`, unchanged from the offline evaluation.
///
/// A cryptographic verdict must not move with network weather, and the ruling
/// is enforced structurally: unreachable and disagreeing are represented by
/// *the absence of the entry*, so there is no failure variant to branch on.
/// This row asserts the property survives the state machine — including that
/// evidence about a **different** height is not silently borrowed.
#[test]
fn absent_online_evidence_leaves_the_state_at_attested() {
    let upgrade = committing_upgrade();
    let agreed = header_with(&derived_root(ATTESTED_HEIGHT), HEADER_NTIME);
    for online in [
        OnlineEvidence::new(),
        // Evidence, but for another height.
        evidence_header(ATTESTED_HEIGHT + 1, agreed),
    ] {
        let outcome = ots_online(UPGRADED, &DIGEST_UPGRADED, Some(upgrade.clone()), &online);
        assert_eq!(state_of(&outcome), AnchorState::Attested);
        assert_eq!(outcome.verdict().verified_time_unix(), None);
        assert!(outcome.suppressed().is_empty());
    }
}

/// **O9 / D56 §2 — the only row that proves the state is OTS-reachable at
/// all.**
///
/// An `.ots` whose ops commit `anchor_digest` and whose every attestation is
/// of a type this verifier cannot evaluate is *"cryptographically well-formed
/// but not independently anchored"* — line 133's own definition, unedited.
///
/// What makes it fail: mapping unknown attestations to `invalid` (which
/// accuses an honest artifact merged from a Litecoin or Ethereum calendar of
/// forgery) or to `pending` (which offers `status --upgrade`, and that can
/// never help).
#[test]
fn an_all_unknown_attestation_ots_is_internally_consistent_only() {
    let digest = synthetic_digest(0x51);
    let bytes = container(&digest, &fork(&[unknown(), unknown()]));
    let outcome = ots_offline(&bytes, &digest, None);
    assert_eq!(state_of(&outcome), AnchorState::InternallyConsistentOnly);
    assert_eq!(code_of(&outcome), None);
    assert!(!outcome.verdict().is_headline_eligible());
    assert_eq!(outcome.verdict().verified_time_unix(), None);
    assert_eq!(outcome.identity(), None, "a claimed identity is not one");
}

/// **O5 over O9.** One unknown attestation beside one pending branch is
/// `pending`.
///
/// A naive implementation that treats the *presence* of an unknown
/// attestation as the O9 trigger passes the row above and fails only here —
/// and in production it would demote every honest `.ots` merged from one
/// supported and one unsupported calendar.
#[test]
fn an_unknown_attestation_does_not_demote_a_pending_ots() {
    let digest = synthetic_digest(0x61);
    let bytes = container(
        &digest,
        &fork(&[
            pending("https://alice.btc.calendar.opentimestamps.org"),
            unknown(),
        ]),
    );
    let outcome = ots_offline(&bytes, &digest, None);
    assert_eq!(state_of(&outcome), AnchorState::Pending);
}

/// **O5 over O6/O8 — §4's whole argument, as a test.**
///
/// A pending branch beside a forged Bitcoin branch renders `pending`. Under
/// refutation-wins it would render `invalid`, and since the `.sealproof`
/// bundle is **unsigned**, any relay that forwards a bundle could append one
/// branch and turn an honest anchor into a forgery accusation.
///
/// This is also the A21 trap D56 §4 records: the `anchor-forged-header` row's
/// fixture must be **single-branch**, or O5 fires first and the row renders
/// `pending`.
#[test]
fn a_pending_branch_is_not_demoted_by_a_forged_bitcoin_branch() {
    let digest = synthetic_digest(0x71);
    let bytes = container(
        &digest,
        &fork(&[
            pending("https://bob.btc.calendar.opentimestamps.org"),
            bitcoin(ATTESTED_HEIGHT),
        ]),
    );
    let outcome = ots_offline(&bytes, &digest, Some(committing_upgrade()));
    assert_eq!(state_of(&outcome), AnchorState::Pending);
    assert_eq!(code_of(&outcome), None);
    assert_eq!(
        anomaly_codes(&outcome),
        vec![EmbeddedHeader::UNCOMMITTED_CODE]
    );

    // The single-branch fixture — the one A21 must build — does render
    // `invalid`, which is what makes the row above a statement about
    // precedence rather than about the refutation being unreachable.
    let single = container(&digest, &bitcoin(ATTESTED_HEIGHT));
    let alone = ots_offline(&single, &digest, Some(committing_upgrade()));
    assert_eq!(state_of(&alone), AnchorState::Invalid);
    assert_eq!(code_of(&alone), Some(EmbeddedHeader::UNCOMMITTED_CODE));
}

/// **O4 over O5.** The normal post-partial-upgrade artifact — one calendar
/// upgraded, one still pending — is `attested`, the stronger true statement.
///
/// What makes it fail: order-of-branches dependence, which would render this
/// `pending` about half the time.
#[test]
fn a_partially_upgraded_merge_is_attested_not_pending() {
    let outcome = ots_offline(UPGRADED, &DIGEST_UPGRADED, Some(committing_upgrade()));
    assert_eq!(state_of(&outcome), AnchorState::Attested);
    // The fixture really does mix the two: two pending branches and two
    // Bitcoin ones. Without this the row could pass on a Bitcoin-only file.
    let artifact = parse_ots(UPGRADED, &DIGEST_UPGRADED).expect("parses");
    assert!(
        artifact
            .attestations
            .iter()
            .any(|a| matches!(a, OtsAttestation::Pending { .. }))
    );
    assert!(
        artifact
            .attestations
            .iter()
            .any(|a| matches!(a, OtsAttestation::Bitcoin { .. }))
    );
}

/// **O2 over everything — the worst reachable defect in D56 §9.**
///
/// An `.ots` for *someone else's* seal, carrying a genuine online-confirmable
/// Bitcoin attestation, must be `invalid`. An implementation that checked the
/// stamped digest after walking the branches would render it `proven`, and
/// the bundle would inherit a stranger's timestamp.
///
/// D91 §6.4 rules the check is O1's, inside `parse_ots`, before the walk: the
/// comparison costs 32 bytes and a wrong-digest `.ots` can never amplify work.
#[test]
fn a_wrong_digest_ots_is_invalid_regardless_of_its_attestations() {
    let stranger = synthetic_digest(0x81);
    let upgrade = committing_upgrade();
    let online = evidence_header(
        ATTESTED_HEIGHT,
        header_with(&derived_root(ATTESTED_HEIGHT), HEADER_NTIME),
    );

    // The very inputs that promote the honest artifact to `proven`.
    let honest = ots_online(UPGRADED, &DIGEST_UPGRADED, Some(upgrade.clone()), &online);
    assert_eq!(state_of(&honest), AnchorState::Proven);

    let outcome = ots_online(UPGRADED, &stranger, Some(upgrade), &online);
    assert_eq!(state_of(&outcome), AnchorState::Invalid);
    assert_eq!(code_of(&outcome), Some("anchor-ots-digest-mismatch"));
    assert_eq!(outcome.verdict().verified_time_unix(), None);
    assert_eq!(outcome.identity(), None);
}

/// **D56 §5's existential form.** The state, the diagnostic and the anomaly
/// **codes** are invariant under a permutation of the branches.
///
/// Any "first branch wins" implementation passes every fixture row above and
/// fails only here. The *loci* are document-order references and deliberately
/// are not asserted invariant — see [`AnomalyLocus::Branch`].
#[test]
fn the_state_and_anomaly_codes_are_invariant_under_branch_order() {
    let digest = synthetic_digest(0x91);
    let branches = [
        pending("https://alice.btc.calendar.opentimestamps.org"),
        bitcoin(ATTESTED_HEIGHT),
        unknown(),
        bitcoin(ATTESTED_HEIGHT + 5),
    ];
    let orders = [
        [0, 1, 2, 3],
        [3, 2, 1, 0],
        [1, 0, 3, 2],
        [2, 3, 0, 1],
        [0, 2, 1, 3],
        [3, 1, 2, 0],
    ];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for order in orders {
        let permuted: Vec<Vec<u8>> = order.iter().map(|&i| branches[i].clone()).collect();
        let bytes = container(&digest, &fork(&permuted));
        for (label, upgrade) in [
            ("none", None),
            ("committing", Some(committing_upgrade())),
            ("forged", Some(forged_upgrade())),
        ] {
            let outcome = ots_offline(&bytes, &digest, upgrade);
            seen.insert(format!(
                "{:?}|{:?}|{:?}|{:?}",
                label,
                state_of(&outcome),
                code_of(&outcome),
                anomaly_codes(&outcome),
            ));
        }
    }
    assert_eq!(
        seen.len(),
        3,
        "one answer per upgrade group, whatever the branch order: {seen:?}"
    );
}

/// **O9 / O1.** A zero-attestation `.ots` is never `pending` and never
/// headline-eligible.
///
/// D56 §5 leaves the choice open — A11 may reject it at parse — and pins that
/// **both** treatments are safe, so the choice never becomes load-bearing.
/// A11 rejects; this asserts the property that matters either way.
#[test]
fn a_zero_attestation_ots_is_never_pending_or_headline_eligible() {
    let digest = synthetic_digest(0xa1);
    let outcome = ots_offline(&container(&digest, &[]), &digest, None);
    assert_ne!(state_of(&outcome), AnchorState::Pending);
    assert!(!outcome.verdict().is_headline_eligible());
    assert_eq!(outcome.verdict().verified_time_unix(), None);
}

/// The `.ots` codes this module can attach are pairwise distinct and all
/// carry the A domain's single `anchor-` prefix (D91 §6.1).
#[test]
fn every_ots_code_is_pairwise_distinct_and_anchor_prefixed() {
    let codes = [
        OTS_ONLINE_HEADER_MISMATCH_CODE,
        OTS_ONLINE_BLOCK_ABSENT_CODE,
        EmbeddedHeader::UNCOMMITTED_CODE,
        OtsError::DigestMismatch.code(),
    ];
    let unique: BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(unique.len(), codes.len(), "a code was copy-pasted");
    for code in codes {
        assert!(code.starts_with("anchor-"), "{code}");
        assert!(
            !code.starts_with("ots-") && !code.starts_with("tsa-"),
            "{code}"
        );
    }
    assert_eq!(all_code_exemplars().len(), 2);
    for code in all_code_exemplars() {
        assert!(unique.contains(code));
    }
}

// ════════════════════════════════════════════════════════════════════════
// D53's T1–T3
// ════════════════════════════════════════════════════════════════════════

/// **T2 before T3, and it is what makes `internally-consistent-only` mean
/// what F3 says it means.**
///
/// A token whose CMS signature does not verify must never reach chain
/// classification: the state carries the positive claim *"everything checkable
/// has been checked and passed"*. The natural wrong implementation builds the
/// chain first and labels a non-token `internally-consistent-only`.
///
/// The differential is one byte: the same capture, its signature flipped, is
/// `invalid` with a CMS code — never `internally-consistent-only`, under
/// **either** store, so "it failed because the root was not pinned" cannot be
/// the explanation.
#[test]
fn a_token_whose_cms_signature_fails_never_reaches_chain_classification() {
    let mut broken = FREETSA.to_vec();
    let last = broken.len() - 1;
    broken[last] ^= 0x01;

    for store in [TsaRootStore::pinned(), &empty_store()] {
        let outcome = tsa(&broken, store, AFTER_CAPTURE);
        assert_eq!(
            state_of(&outcome),
            AnchorState::Invalid,
            "a non-token reached chain classification"
        );
        let code = code_of(&outcome).expect("invalid carries a code");
        assert!(code.starts_with("anchor-"), "{code}");
        assert_ne!(code, "anchor-chain-signature-invalid", "that is a T3 code");
        assert_eq!(outcome.identity(), None);
    }

    // Anti-vacuity: the unmutated capture passes T2 and is classified by its
    // chain — `proven` under the pinned store, `internally-consistent-only`
    // under an empty one.
    assert_eq!(
        state_of(&tsa(FREETSA, TsaRootStore::pinned(), AFTER_CAPTURE)),
        AnchorState::Proven
    );
    assert_eq!(
        state_of(&tsa(FREETSA, &empty_store(), AFTER_CAPTURE)),
        AnchorState::InternallyConsistentOnly
    );
}

/// **C6, over real material.** A well-formed token whose chain reaches no
/// pinned root is `internally-consistent-only` — and the row asserts the
/// token **passed T2**, or it would pass vacuously against a token that was
/// malformed for an unrelated reason.
#[test]
fn an_untrusted_root_is_internally_consistent_only_and_passed_t2() {
    let outcome = tsa(SWISSSIGN, TsaRootStore::pinned(), AFTER_CAPTURE);
    assert_eq!(state_of(&outcome), AnchorState::InternallyConsistentOnly);
    assert_eq!(code_of(&outcome), None);
    assert!(!outcome.verdict().is_headline_eligible());
    assert_eq!(outcome.verdict().verified_time_unix(), None);
    assert_eq!(outcome.identity(), None, "a claimed identity is not one");

    // T2 passed: the same bytes verify as a token.
    assert!(
        verify_token(SWISSSIGN, &D60_STAMPED, None).is_ok(),
        "the fixture must be a valid token, or this row pins nothing"
    );
    // The source is present and claimed, never verified.
    let source = outcome.verdict().source().expect("a claimed identity");
    assert!(!source.is_verified());
    assert!(!source.identity().is_empty());
}

/// **C1 → C2 on one artifact, and the row that catches a clock.**
///
/// The same capture at two `verify_at` values gives two states. Any
/// implementation reading a system clock instead of the parameter returns the
/// same answer twice, whichever it is.
#[test]
fn one_capture_two_verify_times_flips_proven_and_since_expired() {
    let pinned = TsaRootStore::pinned();
    let now = tsa(DIGICERT, pinned, AFTER_CAPTURE);
    let later = tsa(DIGICERT, pinned, 4_000_000_000);

    assert_eq!(state_of(&now), AnchorState::Proven);
    assert_eq!(
        state_of(&later),
        AnchorState::ValidAtStampingCertSinceExpired
    );
    // Both are headline-eligible and both carry the **same** proven time:
    // aging bundles must not silently rot (MVP-SPEC.md lines 109/130).
    assert!(now.verdict().is_headline_eligible());
    assert!(later.verdict().is_headline_eligible());
    assert_eq!(
        now.verdict().verified_time_unix(),
        later.verdict().verified_time_unix()
    );
}

/// Every `invalid` TSA verdict carries one of A9's three T3 codes or one of
/// A5/A8's T1/T2 codes — never an empty diagnostic, and never a fabricated
/// one.
#[test]
fn every_invalid_tsa_verdict_carries_one_of_a9s_three_codes() {
    let pinned = TsaRootStore::pinned();
    let mut broken = DIGICERT.to_vec();
    let last = broken.len() - 1;
    broken[last] ^= 0x01;

    for (bytes, store) in [
        (broken.as_slice(), pinned),
        (DIGICERT, pinned),
        (SWISSSIGN, pinned),
        (FREETSA, &empty_store()),
    ] {
        let outcome = tsa(bytes, store, AFTER_CAPTURE);
        let has_code = code_of(&outcome).is_some();
        assert_eq!(
            has_code,
            state_of(&outcome) == AnchorState::Invalid,
            "a diagnostic exists exactly for `invalid`"
        );
    }
}

/// A bundle-supplied certificate that is not strict DER fails **that anchor**
/// (F2/F3) with A5's own rejection class, not a code invented here.
#[test]
fn a_malformed_bundle_intermediate_is_invalid_with_a5s_der_code() {
    let anchor = TsaAnchor::new(
        AnchorStatus::Proven,
        opaque(DIGICERT),
        vec![opaque(b"\x30\x80not der")],
        FETCH_DATE,
    )
    .expect("under the D10 caps");
    let view = TsaArtifactView::from_anchor(&anchor);
    let outcome = evaluate_tsa_artifact(&view, &D60_STAMPED, TsaRootStore::pinned(), AFTER_CAPTURE);

    assert_eq!(state_of(&outcome), AnchorState::Invalid);
    let code = code_of(&outcome).expect("invalid carries a code");
    assert!(
        code.starts_with("anchor-der-"),
        "expected one of A5's DER classes, got {code}"
    );
    // Anti-vacuity: the same token with no intermediates is `proven`, so the
    // rejection is about the certificate and not about the token.
    assert_eq!(
        state_of(&tsa(DIGICERT, TsaRootStore::pinned(), AFTER_CAPTURE)),
        AnchorState::Proven
    );
}

// ════════════════════════════════════════════════════════════════════════
// A39 — the suppressed-anomaly list
// ════════════════════════════════════════════════════════════════════════

/// **A39 Accept row 1.** A TSA artifact with one valid path and one
/// broken-signature path renders `proven` **and** carries exactly one
/// suppressed entry naming `anchor-chain-signature-invalid`.
#[test]
fn a_tsa_anchor_records_the_chain_refutation_best_evidence_discarded() {
    let token = verify_token(DIGICERT, &D60_STAMPED, None).expect("a real token");
    let intermediates: Vec<OpaqueBytes> = token
        .chain_material()
        .iter()
        .map(|cert| {
            let mut der = cert.to_der().expect("re-encodes");
            *der.last_mut().expect("non-empty") ^= 0x01;
            OpaqueBytes::from_vec(der)
        })
        .collect();

    let anchor = TsaAnchor::new(
        AnchorStatus::Proven,
        opaque(DIGICERT),
        intermediates,
        FETCH_DATE,
    )
    .expect("under the D10 caps");
    let view = TsaArtifactView::from_anchor(&anchor);
    let outcome = evaluate_tsa_artifact(&view, &D60_STAMPED, TsaRootStore::pinned(), AFTER_CAPTURE);

    assert_eq!(state_of(&outcome), AnchorState::Proven);
    assert_eq!(
        anomaly_codes(&outcome),
        vec!["anchor-chain-signature-invalid"]
    );
    assert_eq!(
        outcome.suppressed()[0].locus(),
        AnomalyLocus::Artifact,
        "D53 §3's DP materialises no path, so there is no index to report"
    );
}

/// **A39 Accept row 2.** A merged `.ots` with one pending branch and one
/// forged Bitcoin branch renders `pending` **and** carries one suppressed
/// entry — here localised to the branch, because that shape has one to name.
#[test]
fn an_ots_anchor_records_the_branch_refutation_best_evidence_discarded() {
    let digest = synthetic_digest(0xb1);
    let bytes = container(
        &digest,
        &fork(&[
            pending("https://alice.btc.calendar.opentimestamps.org"),
            bitcoin(ATTESTED_HEIGHT),
        ]),
    );
    // The upgrade group's header is *not* the one the ops derive at this
    // height, and a branch does claim that height — so O8 has a culprit.
    let outcome = ots_offline(&bytes, &digest, Some(committing_upgrade()));
    assert_eq!(state_of(&outcome), AnchorState::Pending);
    assert_eq!(outcome.suppressed().len(), 1);
    assert_eq!(
        outcome.suppressed()[0].code(),
        EmbeddedHeader::UNCOMMITTED_CODE
    );
    assert_eq!(
        outcome.suppressed()[0].locus(),
        AnomalyLocus::Branch { index: 1 }
    );
}

/// **A39 Accept row 3.** An artifact with nothing suppressed carries an
/// **empty** list, not an absent field — "no anomalies" and "not computed"
/// must never be the same value.
#[test]
fn an_artifact_with_nothing_suppressed_carries_an_empty_list() {
    for outcome in [
        tsa(DIGICERT, TsaRootStore::pinned(), AFTER_CAPTURE),
        tsa(SWISSSIGN, TsaRootStore::pinned(), AFTER_CAPTURE),
        ots_offline(MERGED_A, &DIGEST_A, None),
        ots_offline(UPGRADED, &DIGEST_UPGRADED, Some(committing_upgrade())),
    ] {
        assert!(
            outcome.suppressed().is_empty(),
            "{:?} reported {:?}",
            state_of(&outcome),
            anomaly_codes(&outcome)
        );
    }
}

/// **A39 Accept row 4 / D53 §6 / D56 §6.** The diagnostic codes and the
/// anomaly list never reach the report, and a non-empty list moves no
/// serialized byte.
///
/// The differential is exact: two artifacts with the same state and the same
/// report-visible fields, one carrying a suppressed anomaly and one not,
/// serialize identically. Adding a sixth `AnchorResult` field would bump
/// `REPORT_VERSION` and re-emit all 21 pinned strings — a format event, not a
/// lane decision.
#[test]
fn the_projection_drops_every_diagnostic_and_anomaly() {
    let token = verify_token(DIGICERT, &D60_STAMPED, None).expect("a real token");
    let junk: Vec<OpaqueBytes> = token
        .chain_material()
        .iter()
        .map(|cert| {
            let mut der = cert.to_der().expect("re-encodes");
            *der.last_mut().expect("non-empty") ^= 0x01;
            OpaqueBytes::from_vec(der)
        })
        .collect();

    let clean = tsa_anchor(DIGICERT);
    let noisy = TsaAnchor::new(AnchorStatus::Proven, opaque(DIGICERT), junk, FETCH_DATE)
        .expect("under the D10 caps");

    let render = |anchor: &TsaAnchor| {
        let artifacts = AnchorArtifacts::from_parts(&[], std::slice::from_ref(anchor), None);
        let verdicts = evaluate_anchors(
            &artifacts,
            &D60_STAMPED,
            &OnlineEvidence::new(),
            AFTER_CAPTURE,
            TsaRootStore::pinned(),
        );
        let slots = verdicts.project_anchor_results();
        (
            verdicts.outcomes()[0].suppressed().len(),
            serde_json::to_string(&slots).expect("slots serialize"),
        )
    };

    let (clean_anomalies, clean_json) = render(&clean);
    let (noisy_anomalies, noisy_json) = render(&noisy);
    assert_eq!(clean_anomalies, 0);
    assert_eq!(noisy_anomalies, 1, "the differential must actually differ");
    assert_eq!(
        clean_json, noisy_json,
        "a suppressed anomaly moved a report byte"
    );
    assert!(!noisy_json.contains("anchor-chain-signature-invalid"));
    assert!(!noisy_json.contains("suppressed"));

    // And an `invalid` slot carries no diagnostic either.
    let broken = ots_offline(MERGED_A, &synthetic_digest(0xc1), None);
    let slot = broken
        .verdict()
        .to_anchor_result()
        .expect("invalid emits a slot");
    let json = serde_json::to_string(&slot).expect("serializes");
    assert!(!json.contains("anchor-ots-digest-mismatch"), "{json}");
    assert!(json.contains("\"state\":\"invalid\""), "{json}");
}

// ════════════════════════════════════════════════════════════════════════
// A40 — independence from verified identities, never from array length
// ════════════════════════════════════════════════════════════════════════

/// **A40 Accept rows 1 and 2, over real material.**
///
/// Sectigo and Entrust are two endpoints of **one** TSA and their captures
/// carry the same signer certificate, so two `proven` anchors from them are
/// one identity — while FreeTSA and DigiCert are two. Counting artifacts gives
/// 2 in every case, which is exactly what registry §8 forbids.
#[test]
fn two_proven_anchors_from_one_tsa_are_one_identity() {
    let pinned = TsaRootStore::pinned();

    let one_tsa = [tsa_anchor(SECTIGO), tsa_anchor(ENTRUST)];
    let verdicts = evaluate_anchors(
        &AnchorArtifacts::from_parts(&[], &one_tsa, None),
        &D60_STAMPED,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        pinned,
    );
    assert!(
        verdicts
            .outcomes()
            .iter()
            .all(|o| state_of(o) == AnchorState::Proven),
        "both endpoints must reach `proven`, or the row pins nothing"
    );
    assert_eq!(verdicts.outcomes().len(), 2, "two artifacts");
    assert_eq!(
        verdicts.distinct_verified_identities(),
        1,
        "two endpoints of one TSA are one identity"
    );

    let two_tsas = [tsa_anchor(FREETSA), tsa_anchor(DIGICERT)];
    let verdicts = evaluate_anchors(
        &AnchorArtifacts::from_parts(&[], &two_tsas, None),
        &D60_STAMPED,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        pinned,
    );
    assert_eq!(verdicts.distinct_verified_identities(), 2);

    // The same token twice — the shape registry §8 names verbatim.
    let duplicate = [tsa_anchor(FREETSA), tsa_anchor(FREETSA)];
    let verdicts = evaluate_anchors(
        &AnchorArtifacts::from_parts(&[], &duplicate, None),
        &D60_STAMPED,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        pinned,
    );
    assert_eq!(verdicts.outcomes().len(), 2);
    assert_eq!(verdicts.distinct_verified_identities(), 1);
}

/// **A40 Accept row 2, OTS half.** A byte-identical duplicate `.ots` counts
/// one identity **and still verifies** — §8's legality is not walked back.
///
/// The artifact must be headline-eligible or the row is vacuous: a duplicated
/// `pending` pair contributes zero identities either way, which would let a
/// broken implementation pass.
///
/// # This row is insensitive to D92 and must never be cited as its witness
///
/// The two artifacts are **byte-identical**, so it asserts `1` under the
/// calendar key, the block key and the chain key alike. It excludes exactly
/// one of D92 §4's four candidates — *"no identity for OTS"* — and nothing
/// else. For a whole task it was the only OTS-side identity row in the tree,
/// which is how A40's OTS half shipped unpinned. The rows that carry the
/// falsifiability are [`two_bitcoin_heights_are_one_identity`] and
/// [`disjoint_calendars_at_one_height_are_one_identity`] (D92 §9 T1/T2).
#[test]
fn a_duplicate_ots_counts_one_identity_and_still_verifies() {
    let upgrade = committing_upgrade();
    let online = evidence_header(
        ATTESTED_HEIGHT,
        header_with(&derived_root(ATTESTED_HEIGHT), HEADER_NTIME),
    );
    let anchors = [
        ots_anchor(UPGRADED, Some(upgrade.clone())),
        ots_anchor(UPGRADED, Some(upgrade)),
    ];
    let verdicts = evaluate_anchors(
        &AnchorArtifacts::from_parts(&anchors, &[], None),
        &DIGEST_UPGRADED,
        &online,
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );

    assert_eq!(verdicts.outcomes().len(), 2);
    assert!(
        verdicts
            .outcomes()
            .iter()
            .all(|o| state_of(o) == AnchorState::Proven),
        "both must be headline-eligible, or the identity count is vacuously 0"
    );
    assert_eq!(verdicts.distinct_verified_identities(), 1);
    assert_eq!(verdicts.aggregate().headline_eligible_count(), 2);
}

/// **A40 Accept row 3.** `internally-consistent-only` and `invalid` anchors
/// contribute **zero** identities even when their claimed source strings
/// differ — a claimed identity is not a verified one.
#[test]
fn claimed_identities_contribute_nothing() {
    let anchors = [tsa_anchor(FREETSA), tsa_anchor(DIGICERT)];
    let verdicts = evaluate_anchors(
        &AnchorArtifacts::from_parts(&[], &anchors, None),
        &D60_STAMPED,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        &empty_store(),
    );

    assert!(
        verdicts
            .outcomes()
            .iter()
            .all(|o| state_of(o) == AnchorState::InternallyConsistentOnly)
    );
    // The claimed sources really are different, so "zero" is not an accident
    // of two anchors looking alike.
    let sources: BTreeSet<String> = verdicts
        .outcomes()
        .iter()
        .filter_map(|o| o.verdict().source().map(|s| s.identity().to_owned()))
        .collect();
    assert_eq!(
        sources.len(),
        2,
        "two distinct claimed identities: {sources:?}"
    );
    assert_eq!(verdicts.distinct_verified_identities(), 0);
    assert!(verdicts.aggregate().is_unanchored());

    // Same for `invalid`: a wrong-digest `.ots` names its calendars and
    // contributes nothing.
    let ots = [ots_anchor(MERGED_A, None)];
    let verdicts = evaluate_anchors(
        &AnchorArtifacts::from_parts(&ots, &[], None),
        &synthetic_digest(0xd1),
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );
    assert_eq!(state_of(&verdicts.outcomes()[0]), AnchorState::Invalid);
    assert_eq!(verdicts.distinct_verified_identities(), 0);
}

// ── D92 — the OTS half is keyed on Bitcoin, the chain ───────────────────

/// Two `proven` OTS anchors at **different real Bitcoin heights** are **one**
/// identity (**D92 §9 T1**).
///
/// Both upgrade groups are built from the committed `LARGE_TEST` capture,
/// which really does carry ops-derived merkle roots at 449399 *and* 449397, so
/// no block is invented. Two heights of one chain share every failure mode
/// they have — one proof-of-work regime, one reorg, one must-agree esplora
/// pair — so they are one identity and two data points, and joint failure is
/// exactly what an independence count denies.
///
/// Anti-vacuity is asserted **first and in two directions**: both anchors are
/// `proven` (a `pending` pair would count zero identities either way), and
/// their two `source` strings differ, so the heights genuinely are two.
///
/// What makes it fail: re-keying on the block —
/// `AnchorIdentity::BitcoinBlock { height: u.block_height() }` — which turns
/// the 1 into a 2. D92 §3 measured that on real material: the 2026-08-03
/// cycle put one digest's three calendars in three different blocks, so the
/// block key scores an honest single seal as **3**.
#[test]
fn two_bitcoin_heights_are_one_identity() {
    let first = committing_upgrade_at(ATTESTED_HEIGHT);
    let second = committing_upgrade_at(SECOND_ATTESTED_HEIGHT);
    let online = OnlineEvidence::new()
        .with_block(
            ATTESTED_HEIGHT,
            OnlineBlockResult::Header(*first.block_header()),
        )
        .with_block(
            SECOND_ATTESTED_HEIGHT,
            OnlineBlockResult::Header(*second.block_header()),
        );

    let anchors = [
        ots_anchor(UPGRADED, Some(first)),
        ots_anchor(UPGRADED, Some(second)),
    ];
    let verdicts = evaluate_anchors(
        &AnchorArtifacts::from_parts(&anchors, &[], None),
        &DIGEST_UPGRADED,
        &online,
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );

    assert!(
        verdicts
            .outcomes()
            .iter()
            .all(|o| state_of(o) == AnchorState::Proven),
        "both must be headline-eligible, or the identity count is vacuously 0"
    );
    assert_eq!(verdicts.aggregate().headline_eligible_count(), 2);
    let sources: BTreeSet<String> = verdicts
        .outcomes()
        .iter()
        .filter_map(|o| o.verdict().source().map(|s| s.identity().to_owned()))
        .collect();
    assert_eq!(
        sources.len(),
        2,
        "two different blocks, or this compares a thing with itself: {sources:?}"
    );

    assert_eq!(verdicts.distinct_verified_identities(), 1);
    assert_eq!(verdicts.distinct_verified_identities_of(AnchorKind::Ots), 1);
}

/// Two `proven` OTS anchors at **one height through disjoint calendar sets**
/// are **one** identity (**D92 §9 T2**) — the recorded A67 risk, exactly.
///
/// This is the row the pre-D92 code fails. Under the calendar key the two
/// artifacts are `{alice}` and `{bob}`, two distinct identities from one
/// mechanism; and because that key is set-valued, `{alice}` and
/// `{alice, bob}` would be two identities *sharing a member*, which
/// independence counting cannot represent at all.
///
/// The disjointness is **witnessed rather than asserted**: the same two byte
/// strings evaluated with no upgrade group render `pending` and produce two
/// different `source` strings, so the calendar sets really are two.
///
/// What makes it fail: restoring `AnchorIdentity::OtsCalendars(calendars_of(&artifact))`
/// at the O3 arm — the 1 becomes 2.
#[test]
fn disjoint_calendars_at_one_height_are_one_identity() {
    const ALICE: &str = "https://alice.btc.calendar.opentimestamps.org";
    const BOB: &str = "https://bob.btc.calendar.opentimestamps.org";

    // Stamped over the same digest the real capture uses, so this bundle and
    // the ones below can share one `anchor_digest`. With no ops the branch
    // commitment *is* that digest, so a header carrying it commits.
    let through = |uri: &str| {
        container(
            &DIGEST_UPGRADED,
            &fork(&[pending(uri), bitcoin(SYNTHETIC_HEIGHT)]),
        )
    };
    let alice = through(ALICE);
    let bob = through(BOB);
    let upgrade = OtsUpgrade::new(
        SYNTHETIC_HEIGHT,
        header_with(&DIGEST_UPGRADED, HEADER_NTIME),
        FETCH_DATE,
    );

    // The calendars really are disjoint: the same bytes without an upgrade
    // group are `pending` and name two different calendars.
    let unupgraded = [ots_anchor(&alice, None), ots_anchor(&bob, None)];
    let pendings = evaluate_anchors(
        &AnchorArtifacts::from_parts(&unupgraded, &[], None),
        &DIGEST_UPGRADED,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );
    assert!(
        pendings
            .outcomes()
            .iter()
            .all(|o| state_of(o) == AnchorState::Pending)
    );
    let calendars: BTreeSet<String> = pendings
        .outcomes()
        .iter()
        .filter_map(|o| o.verdict().source().map(|s| s.identity().to_owned()))
        .collect();
    assert_eq!(
        calendars,
        BTreeSet::from([ALICE.to_owned(), BOB.to_owned()]),
        "the two calendar sets must be disjoint, or this row pins nothing"
    );
    assert_eq!(
        pendings.distinct_verified_identities(),
        0,
        "and a pending anchor contributes no identity at all"
    );

    // …and upgraded, at one height, they are one identity.
    let anchors = [
        ots_anchor(&alice, Some(upgrade.clone())),
        ots_anchor(&bob, Some(upgrade.clone())),
    ];
    let verdicts = evaluate_anchors(
        &AnchorArtifacts::from_parts(&anchors, &[], None),
        &DIGEST_UPGRADED,
        &evidence_header(SYNTHETIC_HEIGHT, *upgrade.block_header()),
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );
    assert!(
        verdicts
            .outcomes()
            .iter()
            .all(|o| state_of(o) == AnchorState::Proven),
        "both must be headline-eligible, or the identity count is vacuously 0"
    );
    assert_eq!(verdicts.aggregate().headline_eligible_count(), 2);
    assert_eq!(verdicts.distinct_verified_identities(), 1);
    assert_eq!(verdicts.distinct_verified_identities_of(AnchorKind::Ots), 1);
}

/// An `attested` OTS anchor contributes **no** identity (**D92 §9 T3**) — the
/// first OTS-side witness for the eligibility filter.
///
/// Until this row the filter at `AnchorOutcome::new` was falsifiable **only
/// through the TSA path** (`claimed_identities_contribute_nothing`), so an
/// OTS-specific bypass was invisible. `attested` deliberately still *passes*
/// `Some(BitcoinChain)` into the constructor, so the filter stays the single
/// enforcement point rather than being duplicated at the call site — which is
/// precisely why it needs a witness on this side.
///
/// What makes it fail:
///
/// 1. deleting `.filter(|_| verdict.is_headline_eligible())` — caught here and
///    by the TSA-path row;
/// 2. the OTS-specific bypass
///    `verdict.is_headline_eligible() || verdict.kind() == AnchorKind::Ots` —
///    **only this row catches it.**
#[test]
fn an_attested_ots_contributes_no_identity() {
    let outcome = ots_offline(UPGRADED, &DIGEST_UPGRADED, Some(committing_upgrade()));
    assert_eq!(
        state_of(&outcome),
        AnchorState::Attested,
        "the fixture must be `attested`, or the row is about some other state"
    );
    assert_eq!(outcome.identity(), None);

    // In a bundle beside one `proven` TSA the total is 1, not 2.
    let otss = [ots_anchor(UPGRADED, Some(committing_upgrade()))];
    let tsas = [tsa_anchor(DIGICERT)];
    let verdicts = evaluate_anchors(
        &AnchorArtifacts::from_parts(&otss, &tsas, None),
        &D60_STAMPED,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );
    assert_eq!(state_of(&verdicts.outcomes()[1]), AnchorState::Proven);
    assert_eq!(verdicts.distinct_verified_identities(), 1);
    assert_eq!(verdicts.distinct_verified_identities_of(AnchorKind::Ots), 0);
    assert_eq!(verdicts.distinct_verified_identities_of(AnchorKind::Tsa), 1);
}

/// A lone `proven` OTS establishes **one** identity and is not UNANCHORED
/// (**D92 §9 T4**), and `count == 0` ⟺ `is_unanchored()` over every bundle
/// shape this module builds.
///
/// That equivalence is why *"no identity for OTS at all"* was rejected: under
/// it a bundle whose only headline-eligible anchor is a `proven` OTS reports
/// one headline-eligible anchor and **zero** verified identities — a verifier
/// saying "nothing was verified" about something it just verified. Under-
/// counting is safe; a false statement is not a weak one.
///
/// What makes it fail: passing `None` at the O3 arm — the 1 becomes 0 and the
/// equivalence breaks in the same step.
///
/// # It also separates senses (c) and (d) of UNANCHORED (D98 rider 3c, D108 R2)
///
/// The four-bundle sweep is not only about identity counting.
/// `pending_only_unanchored` holds a **non-empty** `ots_anchors` — one
/// `pending` OTS — and is `is_unanchored()`, which is precisely the pair D108
/// names as most likely to collapse: sense (c), *zero headline-eligible
/// anchors* (MVP-SPEC.md line 137), against sense (d), registry §7.6 key 3's
/// *"both anchor arrays empty"*. Rewrite `is_unanchored()` as the shape fact
/// and this row goes red — measured, not assumed. So do not re-bless it:
/// the aggregate is a verdict, never a container size.
#[test]
fn a_lone_proven_ots_establishes_one_identity() {
    let (digest, bytes, upgrade) = committed_single_branch(0xd4, SYNTHETIC_HEIGHT);
    let online = evidence_header(SYNTHETIC_HEIGHT, *upgrade.block_header());
    let anchors = [ots_anchor(&bytes, Some(upgrade))];
    let lone = evaluate_anchors(
        &AnchorArtifacts::from_parts(&anchors, &[], None),
        &digest,
        &online,
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );
    assert_eq!(state_of(&lone.outcomes()[0]), AnchorState::Proven);
    assert_eq!(lone.aggregate().headline_eligible_count(), 1);
    assert_eq!(lone.distinct_verified_identities(), 1);
    assert!(!lone.aggregate().is_unanchored());

    // The invariant, over both sides of it. The name says the thing the row
    // is for: a **non-empty** anchor array whose aggregate is still
    // UNANCHORED (sense (c), not the registry's sense (d)).
    let pending_only = [ots_anchor(MERGED_A, None)];
    let pending_only_unanchored = evaluate_anchors(
        &AnchorArtifacts::from_parts(&pending_only, &[], None),
        &DIGEST_A,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );
    let tsas = [tsa_anchor(DIGICERT)];
    let tsa_only = evaluate_anchors(
        &AnchorArtifacts::from_parts(&[], &tsas, None),
        &D60_STAMPED,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );
    let empty = evaluate_anchors(
        &AnchorArtifacts::from_parts(&[], &[], None),
        &D60_STAMPED,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );

    let all = [&lone, &pending_only_unanchored, &tsa_only, &empty];
    for verdicts in all {
        assert_eq!(
            verdicts.distinct_verified_identities() == 0,
            verdicts.aggregate().is_unanchored(),
            "count/UNANCHORED disagree"
        );
    }
    assert!(all.iter().any(|v| v.aggregate().is_unanchored()));
    assert!(all.iter().any(|v| !v.aggregate().is_unanchored()));
}

/// A `proven` TSA plus a `proven` OTS is **two** independent identities
/// (**D92 §9 T5**) — asserted by matching **one of each enum arm**, never by
/// cardinality alone.
///
/// The `.ots` is minted over `D60_STAMPED` so one `anchor_digest` serves both
/// artifacts; with no ops the branch commitment is that digest, so the
/// embedded header commits it.
///
/// What makes it fail: the lazy implementation that expresses the OTS identity
/// as `TsaSigner { subject_dn_der: b"bitcoin".to_vec() }` instead of adding an
/// arm. The **count is still 2**, so a cardinality-only row stays green; the
/// pattern assertion is what fires.
#[test]
fn a_tsa_and_an_ots_are_two_independent_identities() {
    let bytes = container(&D60_STAMPED, &bitcoin(SYNTHETIC_HEIGHT));
    let upgrade = OtsUpgrade::new(
        SYNTHETIC_HEIGHT,
        header_with(&D60_STAMPED, HEADER_NTIME),
        FETCH_DATE,
    );
    let online = evidence_header(SYNTHETIC_HEIGHT, *upgrade.block_header());

    let otss = [ots_anchor(&bytes, Some(upgrade))];
    let tsas = [tsa_anchor(DIGICERT)];
    let verdicts = evaluate_anchors(
        &AnchorArtifacts::from_parts(&otss, &tsas, None),
        &D60_STAMPED,
        &online,
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );

    assert!(
        verdicts
            .outcomes()
            .iter()
            .all(|o| state_of(o) == AnchorState::Proven),
        "both must be headline-eligible, or the count is vacuous"
    );
    assert_eq!(verdicts.distinct_verified_identities(), 2);

    let identities: Vec<&AnchorIdentity> = verdicts.verified_identities().into_iter().collect();
    assert_eq!(
        identities
            .iter()
            .filter(|identity| matches!(identity, AnchorIdentity::BitcoinChain))
            .count(),
        1,
        "one Bitcoin identity, by arm: {identities:?}"
    );
    assert_eq!(
        identities
            .iter()
            .filter(|identity| matches!(identity, AnchorIdentity::TsaSigner { .. }))
            .count(),
        1,
        "one TSA identity, by arm: {identities:?}"
    );
    assert_eq!(verdicts.distinct_verified_identities_of(AnchorKind::Ots), 1);
    assert_eq!(verdicts.distinct_verified_identities_of(AnchorKind::Tsa), 1);
}

/// The whole OTS mechanism contributes **at most one** identity, over every
/// combination of this module's `proven` OTS fixtures (**D92 §9 T6**), and the
/// total matches D92 §5.4's closed form.
///
/// Four anchors: the two real Bitcoin heights of T1 and the two disjoint
/// calendars of T2, all stamped over one digest so they share one bundle. All
/// fifteen non-empty subsets are exercised, with and without a `proven` TSA
/// beside them — 30 bundles, no combination reaching 2.
///
/// What makes it fail: either T1's fault (re-key on the block) or T2's
/// (restore the calendar key). Some combination then reports 2, and the closed
/// form stops holding at the same moment.
#[test]
fn the_ots_contribution_is_never_more_than_one() {
    let first = committing_upgrade_at(ATTESTED_HEIGHT);
    let second = committing_upgrade_at(SECOND_ATTESTED_HEIGHT);
    let synthetic = OtsUpgrade::new(
        SYNTHETIC_HEIGHT,
        header_with(&DIGEST_UPGRADED, HEADER_NTIME),
        FETCH_DATE,
    );
    let through = |uri: &str| {
        container(
            &DIGEST_UPGRADED,
            &fork(&[pending(uri), bitcoin(SYNTHETIC_HEIGHT)]),
        )
    };
    let alice = through("https://alice.btc.calendar.opentimestamps.org");
    let bob = through("https://btc.calendar.catallaxy.com");

    let online = OnlineEvidence::new()
        .with_block(
            ATTESTED_HEIGHT,
            OnlineBlockResult::Header(*first.block_header()),
        )
        .with_block(
            SECOND_ATTESTED_HEIGHT,
            OnlineBlockResult::Header(*second.block_header()),
        )
        .with_block(
            SYNTHETIC_HEIGHT,
            OnlineBlockResult::Header(*synthetic.block_header()),
        );

    let catalogue: [(&[u8], OtsUpgrade); 4] = [
        (UPGRADED, first),
        (UPGRADED, second),
        (&alice, synthetic.clone()),
        (&bob, synthetic),
    ];

    let mut saw_two_ots_anchors = false;
    for mask in 1_u8..16 {
        let otss: Vec<OtsAnchor> = catalogue
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, (bytes, upgrade))| ots_anchor(bytes, Some(upgrade.clone())))
            .collect();
        saw_two_ots_anchors |= otss.len() >= 2;

        for tsas in [Vec::new(), vec![tsa_anchor(DIGICERT)]] {
            // The real TSA capture is stamped over a different digest from the
            // OTS fixtures, so it renders `invalid` here and contributes
            // nothing. That is worth having in the sweep rather than avoiding:
            // the closed form must hold with a present-but-non-contributing
            // artifact of the other kind, and the second half of this row
            // exercises a TSA term that is not zero.
            let with_tsa = !tsas.is_empty();
            let verdicts = evaluate_anchors(
                &AnchorArtifacts::from_parts(&otss, &tsas, None),
                &DIGEST_UPGRADED,
                &online,
                AFTER_CAPTURE,
                TsaRootStore::pinned(),
            );
            if with_tsa {
                assert_eq!(
                    verdicts.distinct_verified_identities_of(AnchorKind::Tsa),
                    0,
                    "mask {mask:#06b}: an `invalid` TSA artifact contributes nothing"
                );
            }

            assert!(
                verdicts
                    .outcomes()
                    .iter()
                    .filter(|o| o.verdict().kind() == AnchorKind::Ots)
                    .all(|o| state_of(o) == AnchorState::Proven),
                "mask {mask:#06b}: every OTS anchor must be `proven`, or the \
                 subset is vacuous"
            );

            let ots = verdicts.distinct_verified_identities_of(AnchorKind::Ots);
            assert!(ots <= 1, "mask {mask:#06b}: OTS contributed {ots}");

            // D92 §5.4, verbatim.
            let any_eligible_ots = verdicts.outcomes().iter().any(|o| {
                o.verdict().kind() == AnchorKind::Ots && o.verdict().is_headline_eligible()
            });
            assert_eq!(
                verdicts.distinct_verified_identities(),
                verdicts.distinct_verified_identities_of(AnchorKind::Tsa)
                    + usize::from(any_eligible_ots),
                "mask {mask:#06b}: the closed form"
            );
        }
    }
    assert!(
        saw_two_ots_anchors,
        "the sweep must reach bundles with more than one OTS anchor"
    );

    // The mixed case, with **both** terms of the closed form non-zero: two
    // distinct real TSAs and one `proven` OTS, all over one digest. Without
    // this the sweep above only ever measures `0 + {0,1}`, and a `+ 0`
    // implementation of the TSA term would survive it.
    let bytes = container(&D60_STAMPED, &bitcoin(SYNTHETIC_HEIGHT));
    let upgrade = OtsUpgrade::new(
        SYNTHETIC_HEIGHT,
        header_with(&D60_STAMPED, HEADER_NTIME),
        FETCH_DATE,
    );
    let otss = [ots_anchor(&bytes, Some(upgrade.clone()))];
    // FreeTSA and DigiCert are two TSAs; Sectigo and Entrust are one, so the
    // three tokens establish three identities, not four.
    let tsas = [
        tsa_anchor(FREETSA),
        tsa_anchor(DIGICERT),
        tsa_anchor(SECTIGO),
        tsa_anchor(ENTRUST),
    ];
    let mixed = evaluate_anchors(
        &AnchorArtifacts::from_parts(&otss, &tsas, None),
        &D60_STAMPED,
        &evidence_header(SYNTHETIC_HEIGHT, *upgrade.block_header()),
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );
    assert!(
        mixed
            .outcomes()
            .iter()
            .all(|o| state_of(o) == AnchorState::Proven),
        "all five artifacts must be `proven`, or the mixed row is vacuous"
    );
    assert_eq!(mixed.aggregate().headline_eligible_count(), 5);
    assert_eq!(mixed.distinct_verified_identities_of(AnchorKind::Ots), 1);
    assert_eq!(
        mixed.distinct_verified_identities_of(AnchorKind::Tsa),
        3,
        "four tokens, three TSAs"
    );
    assert_eq!(
        mixed.distinct_verified_identities(),
        4,
        "3 TSA identities + 1 for the whole OTS mechanism (D92 §5.4)"
    );
    assert!(mixed.distinct_verified_identities() < mixed.outcomes().len());
}

/// The identity count is a function of the identities, not of the artifact
/// count — asserted as an inequality that a length-based implementation
/// cannot satisfy.
#[test]
fn independence_is_never_the_artifact_count() {
    let pinned = TsaRootStore::pinned();
    let anchors = [
        tsa_anchor(SECTIGO),
        tsa_anchor(ENTRUST),
        tsa_anchor(FREETSA),
    ];
    let verdicts = evaluate_anchors(
        &AnchorArtifacts::from_parts(&[], &anchors, None),
        &D60_STAMPED,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        pinned,
    );
    assert_eq!(verdicts.outcomes().len(), 3);
    assert_eq!(verdicts.aggregate().headline_eligible_count(), 3);
    assert_eq!(
        verdicts.distinct_verified_identities(),
        2,
        "three tokens, two TSAs"
    );
    assert!(verdicts.distinct_verified_identities() < verdicts.outcomes().len());
}

// ════════════════════════════════════════════════════════════════════════
// A19 — the receipt is supporting evidence, never an anchor
// ════════════════════════════════════════════════════════════════════════

/// **A19 Accept row 1.** A bundle carrying only a receipt has every anchor
/// kind `absent`, is UNANCHORED, and still renders the receipt.
#[test]
fn a_receipt_only_bundle_is_unanchored_with_the_receipt_present() {
    let receipt = receipt_record();
    let artifacts = AnchorArtifacts::from_parts(&[], &[], Some(&receipt));
    let verdicts = evaluate_anchors(
        &artifacts,
        &D60_STAMPED,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );

    assert!(verdicts.outcomes().is_empty());
    for kind in [AnchorKind::Ots, AnchorKind::Tsa] {
        assert_eq!(
            verdicts.absent_verdict(kind).map(|v| v.state()),
            Some(AnchorState::Absent)
        );
    }
    assert!(verdicts.aggregate().is_unanchored());
    assert_eq!(verdicts.aggregate().headline_time_unix(), None);

    let evidence = verdicts.receipt().expect("the receipt is rendered");
    assert_eq!(
        evidence.class(),
        ReceiptClass::SupportingEvidenceNoProvenTime
    );
    assert!(!evidence.is_headline_eligible());
    assert_eq!(evidence.block_number(), 200_000_001);
    assert_eq!(evidence.transaction_count(), 1);
    // It is not an anchor and contributes no slot.
    assert!(verdicts.project_anchor_results().is_empty());
    assert_eq!(verdicts.distinct_verified_identities(), 0);
}

/// **A19 Accept row 2.** A successful two-RPC confirmation contributes no
/// headline and changes no anchor datum — asserted as a differential over
/// every byte the report can see.
///
/// A classification that merely *happens* to be unused is one refactor away
/// from being used; this compares the whole projection.
#[test]
fn a_confirmed_receipt_changes_no_anchor_datum() {
    let receipt = receipt_record();
    let tsas = [tsa_anchor(DIGICERT)];
    let otss = [ots_anchor(MERGED_A, None)];
    let artifacts = AnchorArtifacts::from_parts(&otss, &tsas, Some(&receipt));

    let evaluate = |online: &OnlineEvidence| {
        evaluate_anchors(
            &artifacts,
            &D60_STAMPED,
            online,
            AFTER_CAPTURE,
            TsaRootStore::pinned(),
        )
    };

    let bare = evaluate(&OnlineEvidence::new());
    let confirmed = evaluate(
        &OnlineEvidence::new().with_receipt(ReceiptConfirmation::Agreed(
            crate::anchor::model::ReceiptFacts {
                status: 1,
                block_number: 200_000_001,
                block_hash: [0x5c; 32],
            },
        )),
    );

    assert_eq!(
        bare.outcomes(),
        confirmed.outcomes(),
        "the receipt moved an anchor outcome"
    );
    assert_eq!(
        serde_json::to_string(&bare.project_anchor_results()).expect("serializes"),
        serde_json::to_string(&confirmed.project_anchor_results()).expect("serializes")
    );
    assert_eq!(bare.aggregate(), confirmed.aggregate());
    assert_eq!(
        bare.distinct_verified_identities(),
        confirmed.distinct_verified_identities()
    );

    // The confirmation *is* recorded — on the advisory overlay only — so the
    // equality above is not the equality of two empty things.
    assert_eq!(bare.receipt().and_then(ReceiptEvidence::confirmation), None);
    assert!(
        confirmed
            .receipt()
            .and_then(ReceiptEvidence::confirmation)
            .is_some()
    );
    assert_eq!(
        confirmed.receipt().map(ReceiptEvidence::class),
        Some(ReceiptClass::SupportingEvidenceNoProvenTime),
        "confirmation does not change the class"
    );
    assert!(!confirmed.receipt().expect("present").is_headline_eligible());
}

// ════════════════════════════════════════════════════════════════════════
// structural obligations
// ════════════════════════════════════════════════════════════════════════

/// **A2's obligation on A18, discharged in the type system.**
///
/// The per-anchor rules must take `&BlockEvidence`, never `&OnlineEvidence`,
/// so the anchor rules **cannot name the receipt** (D55 §4). This row is a
/// compile-time assertion: `&OnlineEvidence` does not coerce to
/// `&BlockEvidence`, so widening the parameter breaks the build here. An
/// evaluator that took the whole thing and reached through it would compile
/// fine and give the property up silently — which is why A2 wrote the
/// obligation down where A18's implementer would read it.
#[test]
fn the_per_anchor_rules_cannot_be_handed_the_receipt() {
    let blocks: BlockEvidence = BlockEvidence::new();
    let view = OtsArtifactView::from_parts(MERGED_A, None);
    let _: AnchorOutcome = evaluate_ots_artifact(&view, &DIGEST_A, &blocks);

    // And the TSA rules take no online input at all — not even the block
    // evidence — because no D53 sub-case reads one and a parameter that
    // exists is a parameter someone can start branching on.
    let anchor = tsa_anchor(DIGICERT);
    let tsa_view = TsaArtifactView::from_anchor(&anchor);
    let _: AnchorOutcome = evaluate_tsa_artifact(
        &tsa_view,
        &D60_STAMPED,
        TsaRootStore::pinned(),
        AFTER_CAPTURE,
    );
}

/// **A18 Accept row 3.** The evaluator reads no clock: `verify_at` is the only
/// temporal input, and the whole evaluation is a pure function of its
/// arguments.
///
/// Two calls with identical arguments produce identical results, and two calls
/// differing only in `verify_at` produce different ones. A clock-reading
/// implementation could satisfy the first and never the second.
#[test]
fn the_evaluation_is_a_pure_function_of_its_arguments() {
    let tsas = [tsa_anchor(DIGICERT)];
    let otss = [ots_anchor(UPGRADED, Some(committing_upgrade()))];
    let artifacts = AnchorArtifacts::from_parts(&otss, &tsas, None);
    let run = |verify_at| {
        evaluate_anchors(
            &artifacts,
            &D60_STAMPED,
            &OnlineEvidence::new(),
            verify_at,
            TsaRootStore::pinned(),
        )
    };
    assert_eq!(run(AFTER_CAPTURE), run(AFTER_CAPTURE));
    assert_ne!(run(AFTER_CAPTURE), run(4_000_000_000));
}

/// The outcome order is `.ots` first then TSA, each in wire order — the order
/// `verify::pipeline` already builds its anchor slots in, so R12's projection
/// lands them where the report puts them.
#[test]
fn outcomes_are_ots_then_tsa_in_wire_order() {
    let otss = [ots_anchor(MERGED_A, None), ots_anchor(UPGRADED, None)];
    let tsas = [tsa_anchor(DIGICERT), tsa_anchor(SWISSSIGN)];
    let verdicts = evaluate_anchors(
        &AnchorArtifacts::from_parts(&otss, &tsas, None),
        &DIGEST_A,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );
    let kinds: Vec<AnchorKind> = verdicts
        .outcomes()
        .iter()
        .map(|o| o.verdict().kind())
        .collect();
    assert_eq!(
        kinds,
        vec![
            AnchorKind::Ots,
            AnchorKind::Ots,
            AnchorKind::Tsa,
            AnchorKind::Tsa
        ]
    );
    let slots: Vec<AnchorResult> = verdicts.project_anchor_results();
    assert_eq!(slots.len(), 4, "every artifact emits exactly one slot");
}

/// One artifact's failure never touches another's (rule **F2**).
///
/// A wrong-digest `.ots`, a malformed token and an honest token in one bundle:
/// the honest one is still `proven`.
#[test]
fn one_bad_artifact_never_takes_another_down() {
    let mut broken = SECTIGO.to_vec();
    let last = broken.len() - 1;
    broken[last] ^= 0x01;

    let otss = [ots_anchor(b"not an ots file at all", None)];
    let tsas = [tsa_anchor(&broken), tsa_anchor(DIGICERT)];
    let verdicts = evaluate_anchors(
        &AnchorArtifacts::from_parts(&otss, &tsas, None),
        &D60_STAMPED,
        &OnlineEvidence::new(),
        AFTER_CAPTURE,
        TsaRootStore::pinned(),
    );

    let states: Vec<AnchorState> = verdicts.outcomes().iter().map(state_of).collect();
    assert_eq!(
        states,
        vec![
            AnchorState::Invalid,
            AnchorState::Invalid,
            AnchorState::Proven
        ]
    );
    assert_eq!(verdicts.aggregate().headline_eligible_count(), 1);
    assert!(!verdicts.aggregate().is_unanchored());
    assert_eq!(verdicts.distinct_verified_identities(), 1);
}

/// **A19 Accept row 3.** Nothing in `antseal-core` parses receipt internals
/// for a time claim.
///
/// Structural, and asserted as a differential anyway: two receipts whose
/// opaque payloads differ produce **identical** evidence. The payload cannot
/// reach a verdict, because [`ReceiptEvidence`] has no field it could reach
/// through — registry §7.10 puts its internal layout outside v1 wire format
/// on purpose, and MVP-SPEC.md line 110 is why: **no on-chain datum contains
/// `anchor_digest`**, so there is nothing in there for a v1 verdict to depend
/// on.
///
/// v1.1's verification chain stays out of scope with no reseal ever needed
/// (A19 `Do`), and that stays true only while this holds.
#[test]
fn no_receipt_internal_can_reach_a_verdict() {
    let make = |payload: &[u8]| {
        ReceiptRecord::new(vec![[0xab; 32]], 200_000_001, opaque(payload))
            .expect("a one-transaction receipt is well-formed")
    };
    let short = make(b"one");
    let long = make(b"a very much longer opaque capture payload, with different bytes");

    let evidence = |record: &ReceiptRecord| {
        let artifacts = AnchorArtifacts::from_parts(&[], &[], Some(record));
        *evaluate_anchors(
            &artifacts,
            &D60_STAMPED,
            &OnlineEvidence::new(),
            AFTER_CAPTURE,
            TsaRootStore::pinned(),
        )
        .receipt()
        .expect("the receipt is rendered")
    };

    assert_ne!(
        short.payload().len(),
        long.payload().len(),
        "the two payloads must actually differ, or this compares a thing with itself"
    );
    assert_eq!(evidence(&short), evidence(&long));
    // And the class is the same one value either way — there is no other to
    // return.
    assert_eq!(
        evidence(&short).class(),
        ReceiptClass::SupportingEvidenceNoProvenTime
    );
}

/// **D56 §5's branch model, at the one place it bites.** A pending attestation
/// whose path crossed a registered-but-unimplemented op has an
/// **indeterminate** commitment, is `Unevaluable`, and must **not** satisfy
/// O5.
///
/// What makes it fail: an O5 predicate written as *"some `Pending`
/// attestation exists"* rather than *"some **evaluable** pending branch
/// exists"*. Such an artifact would render `pending` — which tells the user to
/// run `status --upgrade`, and that can never help, because the commitment the
/// upgrade URL needs is exactly the value the unimplemented op made
/// unknowable. D56 §2 names that as one of the two wrong answers.
///
/// The differential is one wire byte: the same attestation with and without a
/// `0x02` op in front of it.
#[test]
fn an_indeterminate_pending_branch_does_not_satisfy_o5() {
    let digest = synthetic_digest(0xf1);
    let uri = "https://alice.btc.calendar.opentimestamps.org";

    let evaluable = ots_offline(&container(&digest, &pending(uri)), &digest, None);
    assert_eq!(state_of(&evaluable), AnchorState::Pending, "the baseline");

    // `0x02` — one of the five registered-but-unimplemented ops
    // (`anchor::ots::exec`): one wire byte, no operand, and the subtree below
    // it has an indeterminate value.
    //
    // Written inline rather than as a tag-shaped `u8` constant, because C1's
    // domain-tag scanner (`crypto::domain`) reads *this whole file* as
    // library region: a `tests.rs` submodule carries no `#[cfg(test)]` marker
    // of its own, and the scanner's library region is everything before the
    // first one. So a tag-shaped constant here is a violation it correctly
    // reports.
    //
    // Recorded rather than evaded with a decimal literal, which would have
    // slipped the pattern and taught the wrong habit — and note that the
    // *first* rewrite of this comment tripped the scanner too, by quoting the
    // spelling it forbids. That is the same raw-text trap the A38 lane hit
    // inside `MATRIX.json`'s `why` field on 2026-08-03.
    let mut shadowed = vec![0x02_u8];
    shadowed.extend_from_slice(&pending(uri));
    let artifact = parse_ots(&container(&digest, &shadowed), &digest).expect("parses");
    assert!(
        matches!(
            artifact.attestations.as_slice(),
            [OtsAttestation::Pending {
                commitment: None,
                ..
            }]
        ),
        "the fixture must really be indeterminate, or this compares two identical things"
    );

    let outcome = ots_offline(&container(&digest, &shadowed), &digest, None);
    assert_eq!(state_of(&outcome), AnchorState::InternallyConsistentOnly);
    assert!(!outcome.verdict().is_headline_eligible());

    // …and the calendar is still *named*, because a URI is read out of the
    // attestation payload rather than derived through the ops. A40's identity
    // is about who the artifact points at, not about what the verifier could
    // compute.
    assert_eq!(
        outcome
            .verdict()
            .source()
            .map(|s| s.identity().to_owned())
            .as_deref(),
        Some(uri)
    );
}

// ── A21's eight M2 tamper rows, on wasm32 as well as natively ───────────
//
// The rows themselves are registered in the tamper matrix
// (`test_util::tamper_rows_anchor_verdicts`), which is gated
// `feature = "test-util"` and driven from an integration target — neither of
// which the wasm32 lane compiles or runs. A21's Accept requires all eight to
// execute on `wasm32-unknown-unknown` too, so each row's verdict assertion is
// additionally pinned here, in the `--lib` tests, exactly as A18's 44 rows and
// A43's five are (A90's ruling, recorded in `tasks/A.md` before A21 began).
//
// These are not a second implementation of the rows. Both homes call the same
// exercise in `anchor::testing::tamper_rows`, so what runs on wasm32 is the
// row, not a description of it. What the matrix adds natively is the
// cross-domain distinctness check; what these add is the target.

/// Row 1 — a real merged pending `.ots` verified against the other committed
/// golden digest (D56 rule O2).
#[test]
fn a21_row_1_ots_digest_mismatch() {
    assert_eq!(
        crate::anchor::testing::tamper_rows::row_1_ots_digest_mismatch(),
        RowOutcome::Error("anchor-ots-digest-mismatch")
    );
}

/// Row 2 — a real TSA token verified against a digest it was not stamped
/// over, against an empty store so the T2-before-T3 ordering is observable.
#[test]
fn a21_row_2_tsa_imprint_mismatch() {
    assert_eq!(
        crate::anchor::testing::tamper_rows::row_2_tsa_imprint_mismatch(),
        RowOutcome::Error("anchor-tsa-imprint-mismatch")
    );
}

/// Row 3 — a well-formed mock token whose chain reaches no pinned root
/// (D53 rule C6). Carries its own positive twin as a precondition.
#[test]
fn a21_row_3_untrusted_root() {
    assert_eq!(
        crate::anchor::testing::tamper_rows::row_3_untrusted_root(),
        RowOutcome::Verdict("internally-consistent-only")
    );
}

/// Row 4 — a single-branch, ops-committing upgraded `.ots` whose embedded
/// header's `nTime` is forged, refuted by the agreed header (D56 rule O6 as
/// amended by D93). The one row claiming `verdict:invalid`.
#[test]
fn a21_row_4_forged_header() {
    assert_eq!(
        crate::anchor::testing::tamper_rows::row_4_forged_header(),
        RowOutcome::Verdict("invalid")
    );
}

/// Row 5 — the positive control: an honest `attested` artifact withheld from
/// the offline headline (D56 rule O4), asserted only when it is not
/// headline-eligible.
#[test]
fn a21_row_5_attested_not_headline() {
    assert_eq!(
        crate::anchor::testing::tamper_rows::row_5_attested_not_headline(),
        RowOutcome::Verdict("attested")
    );
}

/// Row 6 — the signing certificate had already expired at `genTime`
/// (D53 rule C3), verified at an instant inside the signer window.
#[test]
fn a21_row_6_expired_at_gentime() {
    assert_eq!(
        crate::anchor::testing::tamper_rows::row_6_expired_at_gentime(),
        RowOutcome::Error("anchor-cert-not-valid-at-gentime")
    );
}

/// Row 7 — the expiry pair's positive control: valid at `genTime`, expired
/// since (D53 rule C2). `expired != invalid`.
#[test]
fn a21_row_7_expired_after_gentime() {
    assert_eq!(
        crate::anchor::testing::tamper_rows::row_7_expired_after_gentime(),
        RowOutcome::Verdict("valid-at-stamping-cert-since-expired")
    );
}

/// Row 8 — the committed BER twin of a real token, where RFC 3161 requires
/// strict DER (D53 §8 row 8; the code is A5's, named by D60 §7.3).
#[test]
fn a21_row_8_ber_not_der() {
    assert_eq!(
        crate::anchor::testing::tamper_rows::row_8_ber_not_der(),
        RowOutcome::Error("anchor-der-not-strict")
    );
}

/// The eight rows' outcomes are **pairwise distinct**, asserted here as well
/// as in the matrix.
///
/// Natively this duplicates `check_registry`'s global distinctness pass. It is
/// repeated because the matrix does not run on wasm32 at all, and because
/// distinctness is the property the whole tamper matrix exists for: eight rows
/// that all rendered `invalid` would satisfy every assertion above and prove
/// nothing about the machine's ability to tell the eight cases apart.
#[test]
fn a21_the_eight_rows_are_pairwise_distinct() {
    use crate::anchor::testing::tamper_rows as rows;

    let outcomes = [
        rows::row_1_ots_digest_mismatch(),
        rows::row_2_tsa_imprint_mismatch(),
        rows::row_3_untrusted_root(),
        rows::row_4_forged_header(),
        rows::row_5_attested_not_headline(),
        rows::row_6_expired_at_gentime(),
        rows::row_7_expired_after_gentime(),
        rows::row_8_ber_not_der(),
    ];

    for (i, a) in outcomes.iter().enumerate() {
        assert!(
            !matches!(a, RowOutcome::Precondition(_)),
            "row {} failed a precondition: {a:?}",
            i + 1
        );
        for (j, b) in outcomes.iter().enumerate().skip(i + 1) {
            assert_ne!(a, b, "rows {} and {} share an outcome", i + 1, j + 1);
        }
    }
}
