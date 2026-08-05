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

// ── real captured material ──────────────────────────────────────────────

/// The nine D60 captures were all taken over this digest.
const D60_STAMPED: [u8; 32] = [
    0x08, 0x3f, 0x87, 0xdf, 0x00, 0xfd, 0x5c, 0x70, 0x3d, 0x35, 0xb8, 0x83, 0xd8, 0x35, 0x35, 0x64,
    0x4c, 0x68, 0x6f, 0x9e, 0x53, 0xf1, 0x58, 0x4d, 0x7d, 0xf1, 0x26, 0xab, 0xda, 0xbd, 0x69, 0xdf,
];

const FREETSA: &[u8] =
    include_bytes!("../../../../../testdata/anchors/A25-bootstrap/D60-tsa-freetsa-resp.tsr");
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

/// A real merged **pending** `.ots` over three calendars (A25, 2026-08-02).
const MERGED_A: &[u8] =
    include_bytes!("../../../../../testdata/anchors/A25-bootstrap/merged-A.ots");
const DIGEST_A: [u8; 32] =
    *include_bytes!("../../../../../testdata/anchors/A25-bootstrap/digest-A.bin");

/// A real **upgraded** mainnet proof: two pending branches and two Bitcoin
/// attestations, at heights 449397 and 449399.
const UPGRADED: &[u8] = include_bytes!(
    "../../../../../testdata/anchors/A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots"
);
const DIGEST_UPGRADED: [u8; 32] = [
    0x6f, 0xd9, 0xc1, 0xc4, 0xf0, 0x96, 0xb7, 0x7e, 0x6d, 0x44, 0x57, 0xba, 0xc1, 0xc7, 0xf5, 0x10,
    0x10, 0xd3, 0x18, 0xdb, 0x48, 0x3f, 0x28, 0x68, 0xd3, 0x79, 0x58, 0x43, 0xf0, 0x98, 0xd3, 0x78,
];

/// The height whose Bitcoin attestation the upgrade fixtures below pin to.
const ATTESTED_HEIGHT: u64 = 449_399;
/// A recognisable `nTime` for the synthetic headers. Never read from an
/// embedded header to produce a verdict (D56 §5); see
/// `the_proven_time_is_read_from_the_agreed_header`.
const HEADER_NTIME: u32 = 1_483_398_000;
const FETCH_DATE: u64 = 1_785_000_100;

/// A verification instant comfortably inside every captured certificate's
/// validity window.
const AFTER_CAPTURE: u64 = 1_785_000_000;

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

/// The 80-byte header shape: `root` at bytes 36..68, `ntime` little-endian at
/// 68..72, everything else a recognisable filler.
fn header_with(root: &[u8], ntime: u32) -> [u8; 80] {
    let mut header = [0xaa_u8; 80];
    header[36..68].copy_from_slice(root);
    header[68..72].copy_from_slice(&ntime.to_le_bytes());
    header
}

/// The merkle root the real upgraded fixture's ops derive at `height`.
///
/// Read out of the parsed artifact rather than transcribed, so the synthetic
/// header below commits what the real ops actually produce and cannot drift
/// from them.
fn derived_root(height: u64) -> Vec<u8> {
    let artifact = parse_ots(UPGRADED, &DIGEST_UPGRADED).expect("the real fixture parses");
    artifact
        .attestations
        .iter()
        .find_map(|attestation| match attestation {
            OtsAttestation::Bitcoin {
                height: h,
                merkle_root: Some(root),
            } if *h == height => Some(root.clone()),
            _ => None,
        })
        .expect("the fixture attests this height")
}

/// The upgrade group the real upgraded fixture's ops **do** commit.
///
/// The merkle-root field is the real ops-derived value; the surrounding 48
/// bytes are filler, because no fetched mainnet header for block 449399 is in
/// the tree (A25/A48 owe that, `anchor::ots::header`'s module docs). Nothing
/// below reads a filler byte: the only fields any rule touches are the merkle
/// root and `nTime`.
fn committing_upgrade() -> OtsUpgrade {
    OtsUpgrade::new(
        ATTESTED_HEIGHT,
        header_with(&derived_root(ATTESTED_HEIGHT), HEADER_NTIME),
        FETCH_DATE,
    )
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

// ── a minimal `.ots` writer, for shapes no capture contains ─────────────
//
// The container format is A11's (`anchor::ots::parse`); this mirrors the
// builder in `anchor::ots::tests` rather than importing it, because that one
// is private to its own module. Every constant below is imported by name from
// the parser, so a format change breaks the build here instead of silently
// producing bytes the parser rejects for the wrong reason.

use crate::anchor::ots::{
    OTS_DIGEST_TYPE_SHA256, OTS_MAGIC, OTS_PENDING_TAG, OTS_VERSION, OtsError,
};

const BITCOIN_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
/// An attestation type this verifier does not implement — the shape D56 §2
/// says keeps `internally-consistent-only` reachable for OTS. Litecoin and
/// Ethereum calendars really do exist.
const UNKNOWN_TAG: [u8; 8] = [0x0f, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee];

fn varuint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = u8::try_from(value % 128).expect("masked to 7 bits");
        value /= 128;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn container(digest: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&OTS_MAGIC);
    out.extend_from_slice(&varuint(OTS_VERSION));
    out.push(OTS_DIGEST_TYPE_SHA256);
    out.extend_from_slice(digest);
    out.extend_from_slice(body);
    out
}

fn attestation(tag: [u8; 8], payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00];
    out.extend_from_slice(&tag);
    out.extend_from_slice(&varuint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

fn pending(uri: &str) -> Vec<u8> {
    let mut payload = varuint(uri.len() as u64);
    payload.extend_from_slice(uri.as_bytes());
    attestation(OTS_PENDING_TAG, &payload)
}

fn bitcoin(height: u64) -> Vec<u8> {
    attestation(BITCOIN_TAG, &varuint(height))
}

fn unknown() -> Vec<u8> {
    attestation(
        UNKNOWN_TAG,
        b"opaque payload from a calendar we do not implement",
    )
}

/// `N` children under one node: a fork marker before every child but the last
/// (D58 §7.2).
fn fork(children: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, child) in children.iter().enumerate() {
        if i + 1 < children.len() {
            out.push(0xff);
        }
        out.extend_from_slice(child);
    }
    out
}

/// A synthetic digest, distinct from every committed one.
fn synthetic_digest(seed: u8) -> [u8; 32] {
    [seed; 32]
}

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

/// **O6, and the precondition D56 does not state: it is reachable only when
/// the ops do *not* commit the embedded header.**
///
/// Found by writing the row above and watching it fail. O4 precedes O6, and
/// O4's guard is `header_commits` — so an artifact whose ops **do** commit an
/// embedded header that agreed online evidence then refutes never reaches O6.
/// It renders `attested`, with the refutation carried as an A39 anomaly.
///
/// That is D56 §4 working exactly as argued rather than a hole: *"the ceiling
/// an attacker can reach on its own is `attested`, which requires only mining
/// a minimal-difficulty header with the right merkle root — and `attested` is
/// **already** designed to be forgeable-but-not-headline-eligible offline"*.
/// A self-consistent forgery is not headline-eligible, proves no time, and now
/// carries the online refutation in its record.
///
/// **This is a trap for A21 beyond the single-branch one D56 §4 records**: the
/// `anchor-forged-header` row pins `verdict:invalid`, so its fixture must be
/// one whose ops do **not** commit the substituted header — which is what
/// substituting a header into an honest artifact naturally produces, and what
/// forging the whole artifact naturally does not.
#[test]
fn a_self_consistent_forgery_refuted_online_is_attested_with_the_refutation_recorded() {
    let upgrade = committing_upgrade();
    let root = derived_root(ATTESTED_HEIGHT);
    let refuting = header_with(&root, HEADER_NTIME + 3600);

    let self_consistent = ots_online(
        UPGRADED,
        &DIGEST_UPGRADED,
        Some(upgrade.clone()),
        &evidence_header(ATTESTED_HEIGHT, refuting),
    );
    assert_eq!(state_of(&self_consistent), AnchorState::Attested);
    assert!(!self_consistent.verdict().is_headline_eligible());
    assert_eq!(self_consistent.verdict().verified_time_unix(), None);
    assert_eq!(
        anomaly_codes(&self_consistent),
        vec![OTS_ONLINE_HEADER_MISMATCH_CODE],
        "the online refutation must survive best-evidence-wins"
    );

    // The reachable O6 shape: the ops do not commit the embedded header, and
    // there is no pending branch to win under O5.
    let digest = synthetic_digest(0xe1);
    let substituted = container(&digest, &bitcoin(ATTESTED_HEIGHT));
    let outcome = ots_online(
        &substituted,
        &digest,
        Some(upgrade),
        &evidence_header(ATTESTED_HEIGHT, refuting),
    );
    assert_eq!(state_of(&outcome), AnchorState::Invalid);
    assert_eq!(
        code_of(&outcome),
        Some(OTS_ONLINE_HEADER_MISMATCH_CODE),
        "an agreed online refutation beats the offline structural one (O6 over O8)"
    );
    assert_eq!(outcome.verdict().verified_time_unix(), None);
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

/// **O7.** Two endpoints agreeing that the height holds no block is agreed
/// evidence refuting the artifact, not the absence of evidence.
///
/// What makes it fail: collapsing `NoSuchBlock` into "no entry". An `.ots`
/// claiming a height beyond the chain tip would then render `attested` for
/// ever.
#[test]
fn agreed_absence_of_the_block_is_invalid() {
    let upgrade = committing_upgrade();
    let online = OnlineEvidence::new().with_block(ATTESTED_HEIGHT, OnlineBlockResult::NoSuchBlock);
    // Strip the pending branches so nothing better than O7 applies: the real
    // fixture's two pending attestations would otherwise win under O5, which
    // is itself the A21 trap D56 §4 records.
    let bytes = container(
        &synthetic_digest(0x21),
        &fork(&[bitcoin(ATTESTED_HEIGHT), bitcoin(ATTESTED_HEIGHT + 1)]),
    );
    let outcome = ots_online(&bytes, &synthetic_digest(0x21), Some(upgrade), &online);
    assert_eq!(state_of(&outcome), AnchorState::Invalid);
    assert_eq!(code_of(&outcome), Some(OTS_ONLINE_BLOCK_ABSENT_CODE));
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
    const UNIMPLEMENTED_OP: u8 = 0x02;
    let digest = synthetic_digest(0xf1);
    let uri = "https://alice.btc.calendar.opentimestamps.org";

    let evaluable = ots_offline(&container(&digest, &pending(uri)), &digest, None);
    assert_eq!(state_of(&evaluable), AnchorState::Pending, "the baseline");

    let mut shadowed = vec![UNIMPLEMENTED_OP];
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
