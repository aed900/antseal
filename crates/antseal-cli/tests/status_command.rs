//! U23 acceptance suite: `status` over a five-class fixture vault, and
//! `--upgrade` driving a pending OpenTimestamps attestation to `attested`
//! against a mock calendar.
//!
//! The works are built through the real journal API (S10's state machine and
//! U9's store) and the anchor slots through the real record codec
//! (`AnchorArtifact::encode` → `WorkStore::put_anchor`), so what is rendered
//! is what a real vault would hold. Nothing here decodes a manifest: `status`
//! only *hashes* the journaled envelope to recover `anchor_digest`, which is
//! why one shared fixture manifest serves every work.
//!
//! # No test here can reach a real endpoint (Q16)
//!
//! Two independent reasons, both structural. The calendar URI baked into the
//! synthetic `.ots` fixtures is `calendar.example` — RFC 2606 reserved, so it
//! can never resolve — and the upgrade run goes through
//! `upgrade_pending_with`, whose resolver is supplied by this file and maps
//! every URI onto a `127.0.0.1:0` stub. The production resolver would refuse
//! that stub (A42 requires https, a bare host and no port), which is exactly
//! why D99 R5 opened the seam: without it the transition below is
//! unexecutable by any means.
//!
//! NON-SECRET: every digest, seal id, passphrase and artifact here is a
//! documented fixture (project rule 6).

mod common;

use std::time::Duration;

use antseal_anchor::agree::EndpointPair;
use antseal_anchor::http::{Endpoint, HttpClient, HttpPolicy, TlsPolicy};
// `upgrade_pending_with` is reached through its own module rather than
// through `ots`'s re-export list, because it deliberately has none: it is
// `test-util`-gated (D99 R5) and a re-export beside `upgrade_pending` would
// read like a second production entry point.
use antseal_anchor::ots::engine::upgrade_pending_with;
use antseal_anchor::ots::upgrade_uri::UpgradeUriRefusal;
use antseal_anchor::ots::{UpgradeBudget, UpgradeReport, UpgradeTarget};
use antseal_anchor::testing::replay::{CalendarBehaviour, calendar};
use antseal_anchor::testing::stub::{StubMatch, StubReply, StubScript, StubServer};
use antseal_cli::pipeline::journal::{SealJournal, SealPlan, SealState, WorkIdentity};
use antseal_cli::pipeline::{
    AnchorArtifact, ArtifactKind, OTS_SLOT, PLAN_ENTRY, StoredAnchors, VaultJournal, tsa_slot,
};
use antseal_cli::status::{
    RECEIPT_CLASS, StatusContext, UNANCHORED_NOTE, WorkStatus, pending_work, persist_upgrades,
};
use antseal_cli::vault::store::{ConsentChannel, ConsentRecord, SealShapingFlags, WorkStore};
use antseal_core::anchor::roots::TsaRootStore;
use antseal_core::anchor::testing::{MockTsa, MockTsaConfig, ots_writer};
use antseal_core::bundle::schema::OtsUpgrade;
use antseal_core::crypto::secrets::{MasterSecret, SealId};
use antseal_core::manifest::anchor_digest;
use antseal_core::verify::report::{AnchorKind, AnchorState};
use common::IsolatedVault;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// The one clock this suite pins, standing in for `commands.rs`'s single
/// `now_unix_secs()` read (D98 rider 2a). Inside `MockTsaConfig`'s default
/// certificate window, and the same literal the rest of this crate's suites
/// use — so `proven` here is a statement about the chain and not about
/// whichever day the test ran.
const VERIFY_AT: u64 = 1_800_000_000;

/// A calendar host that can never resolve (RFC 2606 `.example`).
const CALENDAR: &str = "https://calendar.example/alice";

/// The `fetch_date` recorded on every synthetic capture (A32: recorded,
/// never compared).
const FETCH_DATE: u64 = 1_785_600_000;

/// The `fetch_date` the upgraded header group carries — deliberately a
/// different literal from [`FETCH_DATE`], because D97 R4 makes them different
/// facts: key 2 is when the *capture* arrived and key 6 is when the *block
/// header* was fetched.
const HEADER_FETCH_DATE: u64 = 1_790_000_000;

/// The Bitcoin height the synthetic attestations name.
const HEIGHT: u64 = 700_113;

// ─────────────────────────────────────────────────────────────────────
// Fixture material
// ─────────────────────────────────────────────────────────────────────

fn seal_id(tag: u8) -> SealId {
    let mut bytes = [tag; 16];
    bytes[0] = 0x23;
    SealId::from_bytes(bytes)
}

fn work_id(tag: u8) -> [u8; 32] {
    [tag; 32]
}

/// The manifest every fixture work journals, and the digest its anchors
/// commit. `status` recovers the second from the first exactly as
/// `pipeline/resume.rs` does — SHA-256 over the envelope bytes, never a field
/// on the work record, which is not there (D98 gap 3).
fn manifest() -> Vec<u8> {
    common::fixture_manifest_envelope()
}

fn digest() -> [u8; 32] {
    anchor_digest(&manifest()).into_bytes()
}

/// A pending `.ots`: one calendar attestation, zero ops, no upgrade group.
fn pending_ots() -> Vec<u8> {
    ots_writer::container(&digest(), &ots_writer::pending(CALENDAR))
}

/// An upgraded `.ots` and the group D97 stores beside it in keys 4/5/6.
///
/// With zero ops the branch's commitment **is** the stamped digest, so a
/// header carrying that digest at bytes 36..68 is committed by the ops —
/// which is what `check_embedded_header` asks and therefore what makes this
/// render `attested` rather than `invalid`.
fn attested_ots() -> (Vec<u8>, OtsUpgrade) {
    let digest = digest();
    (
        ots_writer::container(&digest, &ots_writer::bitcoin(HEIGHT)),
        OtsUpgrade::new(
            HEIGHT,
            ots_writer::header_with(&digest, ots_writer::HEADER_NTIME),
            HEADER_FETCH_DATE,
        ),
    )
}

/// The two mock TSAs the fixture signs with: one whose signer certificate is
/// still valid at [`VERIFY_AT`], and one whose certificate expired after it
/// stamped.
///
/// Both carry the **same** `ca_validity`, so both mint a byte-identical CA
/// certificate and one injected root store trusts both — which is what lets
/// `proven` and `valid-at-stamping-cert-since-expired` sit in one work and
/// therefore in one snapshot.
fn signers() -> (MockTsa, MockTsa) {
    let current = MockTsa::granted().expect("the mock CA mints");
    let expired = MockTsa::new(MockTsaConfig {
        gen_time_unix: 1_780_000_000,
        signer_validity: (1_700_000_000, 1_790_000_000),
        ..MockTsaConfig::default()
    })
    .expect("the mock CA mints");
    (current, expired)
}

fn tsa_artifact(signer: &MockTsa, endpoint: &str) -> AnchorArtifact {
    AnchorArtifact {
        kind: ArtifactKind::TsaToken,
        endpoint: endpoint.to_owned(),
        fetch_date: FETCH_DATE,
        bytes: signer.issue(&digest(), None).expect("the mock signs"),
        upgrade: None,
    }
}

fn ots_artifact(bytes: Vec<u8>, upgrade: Option<OtsUpgrade>) -> AnchorArtifact {
    AnchorArtifact {
        kind: ArtifactKind::OtsPending,
        endpoint: String::new(),
        fetch_date: FETCH_DATE,
        bytes,
        upgrade,
    }
}

fn fixture_receipt() -> antseal_net::PaymentReceipt {
    use antseal_net::{GasSummary, PaymentReceipt, QuoteHash, TxHash, TxRecord, TxStatus};

    let quote = QuoteHash::from_bytes([0xB1; 32]);
    let tx = TxHash::from_bytes([0xB2; 32]);
    PaymentReceipt {
        blobs: Vec::new(),
        tx_map: [(quote, tx)].into_iter().collect(),
        txs: vec![TxRecord {
            tx_hash: tx,
            block_number: Some(377_262_147),
            status: TxStatus::Confirmed,
            quote_hashes: vec![quote],
        }],
        storage_cost_atto: 4_200_000_000_000_000_000,
        gas: GasSummary {
            gas_cost_wei: 21_000,
        },
    }
}

/// One fixture work: what it was sealed as, and which anchor slots it holds.
struct Fixture {
    tag: u8,
    title: &'static str,
    unanchored: bool,
    degraded: bool,
    receipt: bool,
    anchors: Vec<(String, AnchorArtifact)>,
}

/// The five classes U23's Accept row names, plus the two states that ride
/// along for free.
///
/// | work | what it demonstrates |
/// | --- | --- |
/// | 1 | `pending` beside a `proven` TSA — the ordinary same-day seal |
/// | 2 | `attested` — D97's keys 4/5/6, read back |
/// | 3 | degraded: `invalid` TSA + `internally-consistent-only` OTS |
/// | 4 | UNANCHORED by `--no-anchor`: both kinds `absent` |
/// | 5 | two headline-eligible TSAs, one of them since-expired |
fn fixtures() -> Vec<Fixture> {
    let (current, expired) = signers();
    let (attested_bytes, attested_group) = attested_ots();
    vec![
        Fixture {
            tag: 0x01,
            title: "thesis draft",
            unanchored: false,
            degraded: false,
            receipt: true,
            anchors: vec![
                (OTS_SLOT.to_owned(), ots_artifact(pending_ots(), None)),
                (
                    tsa_slot(0),
                    tsa_artifact(&current, "https://tsa.example/tsr"),
                ),
            ],
        },
        Fixture {
            tag: 0x02,
            title: "upgraded overnight",
            unanchored: false,
            degraded: false,
            receipt: false,
            anchors: vec![
                (
                    OTS_SLOT.to_owned(),
                    ots_artifact(attested_bytes, Some(attested_group)),
                ),
                (
                    tsa_slot(0),
                    tsa_artifact(&current, "https://tsa.example/tsr"),
                ),
            ],
        },
        Fixture {
            tag: 0x03,
            title: "degraded anchors",
            unanchored: false,
            degraded: true,
            receipt: false,
            anchors: vec![
                (
                    OTS_SLOT.to_owned(),
                    // An attestation type this verifier does not implement:
                    // well-formed, and anchored to nothing it can check.
                    ots_artifact(
                        ots_writer::container(&digest(), &ots_writer::unknown()),
                        None,
                    ),
                ),
                (
                    tsa_slot(0),
                    AnchorArtifact {
                        kind: ArtifactKind::TsaToken,
                        endpoint: "https://tsa.example/tsr".to_owned(),
                        fetch_date: FETCH_DATE,
                        bytes: b"not a TimeStampResp".to_vec(),
                        upgrade: None,
                    },
                ),
            ],
        },
        Fixture {
            tag: 0x04,
            title: "dev smoke",
            unanchored: true,
            degraded: false,
            receipt: false,
            anchors: Vec::new(),
        },
        Fixture {
            tag: 0x05,
            title: "aging bundle",
            unanchored: false,
            degraded: false,
            receipt: false,
            anchors: vec![
                (
                    tsa_slot(0),
                    tsa_artifact(&current, "https://tsa.example/tsr"),
                ),
                (
                    tsa_slot(1),
                    tsa_artifact(&expired, "https://tsa-two.example/tsr"),
                ),
            ],
        },
    ]
}

/// The injected root store both mocks close against (A6/A7's injection API;
/// `TsaRootStore::from_static` is `test-util`-gated, so no shipped build can
/// reach it).
fn roots() -> TsaRootStore {
    signers().0.root_store()
}

fn ctx() -> StatusContext {
    StatusContext {
        verify_at_unix: VERIFY_AT,
        roots: roots(),
    }
}

/// Build the fixture vault: one work per row, driven through the real state
/// machine, with its anchor slots written through the real record codec.
fn fixture_vault() -> IsolatedVault {
    let vault = IsolatedVault::create("status");
    let unlocked = vault.unlock();
    let mut rng = ChaCha20Rng::from_seed([0x23; 32]);
    let store = WorkStore::new(&unlocked);
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);
    let mut slot_rng = ChaCha20Rng::from_seed([0x24; 32]);

    for f in fixtures() {
        let w = MasterSecret::from_bytes([f.tag; 32]);
        let id = seal_id(f.tag);
        journal
            .begin(&WorkIdentity {
                w: w.secret_ref(),
                seal_id: id,
                network: "arbitrum-one".to_owned(),
                unanchored: f.unanchored,
                degraded: f.degraded,
                input_paths_as_given: vec!["notes.txt".to_owned()],
                input_paths_absolute: vec!["/w/notes.txt".to_owned()],
                shaping: SealShapingFlags {
                    title: Some(f.title.to_owned()),
                    split_blank_lines: false,
                    force_text: false,
                    no_fine_tree: Vec::new(),
                    no_anchor: f.unanchored,
                    force_degraded: f.degraded,
                },
            })
            .expect("begin");
        journal
            .put_plan(
                &id,
                &SealPlan {
                    unit_count: 1,
                    manifest_bytes: Some(manifest()),
                },
            )
            .expect("plan");
        for step in [
            SealState::Anchored,
            SealState::Paid,
            SealState::Finalizing,
            SealState::Complete,
        ] {
            journal.set_state(&id, step).expect("advance");
        }
        journal
            .put_consent(
                &id,
                ConsentRecord {
                    total_ant_atto: 4_200_000_000_000_000_000,
                    gas_estimate_wei: 21_000,
                    consent_time_unix_secs: 1_798_761_600,
                    channel: ConsentChannel::YesFlag,
                },
            )
            .expect("consent");
        if f.receipt {
            journal
                .put_receipt(&id, &fixture_receipt())
                .expect("receipt");
        }
        for (slot, artifact) in &f.anchors {
            store
                .put_anchor(
                    &id,
                    slot,
                    &artifact.encode().expect("encode"),
                    &mut slot_rng,
                )
                .expect("put anchor");
        }
        journal
            .record_outcome(&id, Some(work_id(f.tag)), Some(4_200_000_000_000_000_000))
            .expect("outcome");
    }
    vault
}

/// **D100 R6**'s vault: one work whose journaled manifest is gone, and one
/// holding an anchor record the codec refuses.
///
/// Deliberately its own vault rather than two more `fixtures()` rows: those
/// five are the committed `status-report.txt` snapshot, and D100 changes what
/// `status` does with damage rather than what it says about healthy anchors.
///
/// Tag `0x11` is the state D100 §1.2 found `list` and `status` **contradicting
/// each other** on, in production, each documenting its own answer as
/// obviously correct: a work holding anchor artifacts with no journaled
/// manifest listed as a soft *"anchors: unclassified"* row at exit 0 and
/// exited **12** accusing the passphrase under `status`.
fn damaged_vault() -> IsolatedVault {
    let vault = IsolatedVault::create("status-d100");
    let unlocked = vault.unlock();
    let mut rng = ChaCha20Rng::from_seed([0x33; 32]);
    let store = WorkStore::new(&unlocked);
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);
    let mut slot_rng = ChaCha20Rng::from_seed([0x34; 32]);
    let (current, _) = signers();

    for (tag, title, keep_plan) in [
        (0x11u8, "artifacts, journaled manifest gone", false),
        (0x12u8, "one anchor record that will not decode", true),
    ] {
        let w = MasterSecret::from_bytes([tag; 32]);
        let id = seal_id(tag);
        journal
            .begin(&WorkIdentity {
                w: w.secret_ref(),
                seal_id: id,
                network: "arbitrum-one".to_owned(),
                unanchored: false,
                degraded: false,
                input_paths_as_given: vec!["notes.txt".to_owned()],
                input_paths_absolute: vec!["/w/notes.txt".to_owned()],
                shaping: SealShapingFlags {
                    title: Some(title.to_owned()),
                    split_blank_lines: false,
                    force_text: false,
                    no_fine_tree: Vec::new(),
                    no_anchor: false,
                    force_degraded: false,
                },
            })
            .expect("begin");
        journal
            .put_plan(
                &id,
                &SealPlan {
                    unit_count: 1,
                    manifest_bytes: Some(manifest()),
                },
            )
            .expect("plan");
        for step in [
            SealState::Anchored,
            SealState::Paid,
            SealState::Finalizing,
            SealState::Complete,
        ] {
            journal.set_state(&id, step).expect("advance");
        }
        store
            .put_anchor(
                &id,
                &tsa_slot(0),
                &tsa_artifact(&current, "https://tsa.example/tsr")
                    .encode()
                    .expect("encode"),
                &mut slot_rng,
            )
            .expect("put anchor");
        if !keep_plan {
            assert!(
                store
                    .delete_journal_entry(&id, PLAN_ENTRY)
                    .expect("delete plan"),
                "the plan record was there to delete"
            );
        } else {
            // Sealed by the real record cipher, so the AEAD opens and it is
            // the *record codec* that refuses the plaintext — the population
            // D100 §1.5 puts above the AEAD boundary.
            store
                .put_anchor(
                    &id,
                    OTS_SLOT,
                    b"not an anchor-artifact record",
                    &mut slot_rng,
                )
                .expect("put damaged anchor");
        }
        journal
            .record_outcome(&id, Some(work_id(tag)), Some(4_200_000_000_000_000_000))
            .expect("outcome");
    }
    vault
}

/// Read one work's status through an already-unlocked vault.
///
/// Taking the store rather than the vault is not tidiness: `IsolatedVault::unlock`
/// pays an Argon2id derivation, and a suite that unlocked per assertion would
/// spend minutes on a 2-core machine deriving the same key.
fn status_of(store: &WorkStore<'_>, tag: u8) -> WorkStatus {
    WorkStatus::gather(store, &seal_id(tag), ctx()).expect("gather")
}

// ─────────────────────────────────────────────────────────────────────
// U23 Accept row 1: five classes, distinct, snapshot-tested
// ─────────────────────────────────────────────────────────────────────

/// **U23 accept**: `pending`, `attested`, `proven` (TSA), degraded and
/// UNANCHORED render distinctly, against a committed snapshot.
///
/// The snapshot is deterministic because rider 2a pins the verification time
/// and because every anchor record here is written with a literal
/// `fetch_date`. It deliberately carries **no** OTS capture date: the only
/// fetch date any OTS row renders is the *upgrade group's* (key 6), which
/// D97 R5 pins from the engine's parameter — key 2 is still written from
/// `SystemTime::now()` in the seal pipeline and is unpinnable until U48.
#[test]
fn every_anchor_class_renders_distinctly() {
    let vault = fixture_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let mut rendered = String::new();
    for f in fixtures() {
        let status = status_of(&store, f.tag);
        rendered.push_str(&status.render().join("\n"));
        rendered.push('\n');
    }

    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/status-report.txt");
    if std::env::var_os("ANTSEAL_BLESS").is_some() {
        std::fs::write(&path, &rendered).expect("bless");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing committed status snapshot at {}: {e} (generate with ANTSEAL_BLESS=1)",
            path.display()
        )
    });
    assert!(
        committed == rendered,
        "the `status` report drifted from {} — regenerate with ANTSEAL_BLESS=1 and justify \
         the diff\n--- rendered ---\n{rendered}",
        path.display()
    );
}

/// The five classes are distinct **as data**, not merely as text — and the
/// states they carry are the ones D98's reachability table predicts.
///
/// Written beside the snapshot rather than folded into it because a snapshot
/// says "this changed", and this says "this is wrong": a future edit that
/// made two classes agree would produce a reviewable diff and no explanation.
#[test]
fn the_five_classes_carry_the_states_the_ruling_predicts() {
    let vault = fixture_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let state_of = |tag: u8, slot: &str| {
        status_of(&store, tag)
            .anchors
            .iter()
            .find(|row| row.slot == slot)
            .map(|row| row.verdict.state())
    };

    assert_eq!(state_of(0x01, OTS_SLOT), Some(AnchorState::Pending));
    assert_eq!(state_of(0x01, &tsa_slot(0)), Some(AnchorState::Proven));
    assert_eq!(state_of(0x02, OTS_SLOT), Some(AnchorState::Attested));
    assert_eq!(
        state_of(0x03, OTS_SLOT),
        Some(AnchorState::InternallyConsistentOnly)
    );
    assert_eq!(state_of(0x03, &tsa_slot(0)), Some(AnchorState::Invalid));
    assert_eq!(state_of(0x05, &tsa_slot(0)), Some(AnchorState::Proven));
    assert_eq!(
        state_of(0x05, &tsa_slot(1)),
        Some(AnchorState::ValidAtStampingCertSinceExpired),
        "an aging bundle must not silently rot into `invalid`"
    );

    // Six of the seven frozen names, from one fixture vault — every state
    // D98's reachability table says `status` can emit. The seventh,
    // `absent`, is reachable only from the kind-level question and is
    // asserted below.
    let mut seen: Vec<AnchorState> = fixtures()
        .iter()
        .flat_map(|f| status_of(&store, f.tag).anchors)
        .map(|row| row.verdict.state())
        .collect();
    seen.sort_by_key(|state| state.wire_name());
    seen.dedup();
    assert_eq!(seen.len(), 6, "{seen:?}");
    assert!(
        !seen.contains(&AnchorState::Absent),
        "R70: never an outcome"
    );

    let unanchored = status_of(&store, 0x04);
    assert!(unanchored.anchors.is_empty());
    assert_eq!(unanchored.absent.len(), 2, "both kinds, asked for by name");
    assert!(unanchored.is_unanchored());
    assert!(unanchored.render().join("\n").contains(UNANCHORED_NOTE));
}

/// **U23 accept**: the receipt is never rendered as an anchor.
///
/// D98 rider 4 is why this is a test and not a type: on the bundle path
/// `ReceiptEvidence` is a separate field with a `const fn -> false`
/// eligibility, but `receipt_evidence` is private and `AnchorVerdicts` has no
/// public constructor, so `status` inherits none of it.
#[test]
fn the_receipt_is_supporting_evidence_and_never_an_anchor_row() {
    let vault = fixture_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let status = status_of(&store, 0x01);

    assert!(status.receipt.is_some(), "the fixture journals one");
    assert_eq!(status.anchors.len(), 2, "the receipt is not among them");
    assert!(
        status
            .anchors
            .iter()
            .all(|row| row.slot == OTS_SLOT || row.slot == tsa_slot(0)),
        "no anchor row may come from the receipt"
    );

    let rendered = status.render();
    let receipt_at = rendered
        .iter()
        .position(|line| line.contains(RECEIPT_CLASS))
        .expect("rendered under the spec's own sentence");
    let last_anchor = rendered
        .iter()
        .rposition(|line| line.contains(&tsa_slot(0)))
        .expect("the fixture has a TSA row");
    assert!(receipt_at > last_anchor, "outside the per-anchor section");

    // Rider 4d: the block number, and no time of any kind.
    assert!(rendered[receipt_at + 1].contains("377262147"));
    let json = status.json();
    assert_eq!(json["receipt"]["class"], serde_json::json!(RECEIPT_CLASS));
    assert_eq!(
        json["receipt"]["block_numbers"],
        serde_json::json!([377_262_147])
    );

    // A work with no journaled receipt renders no receipt block at all —
    // "not paid yet" is a state, not an empty row.
    let unpaid = status_of(&store, 0x02);
    assert!(unpaid.receipt.is_none());
    assert!(!unpaid.render().join("\n").contains(RECEIPT_CLASS));
}

/// The headline is the **earliest** headline-eligible time, and a
/// since-expired anchor still supplies one.
///
/// The fixture is built so the earliest time belongs to the *expired* signer:
/// if eligibility were read from certificate validity at status time rather
/// than from the state, this row would name the later token.
#[test]
fn the_headline_is_the_earliest_independently_proven_time() {
    let vault = fixture_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let status = status_of(&store, 0x05);
    assert_eq!(status.headline_eligible(), 2);
    let headline = status.headline().expect("two eligible anchors");
    assert_eq!(
        headline.time_unix, 1_780_000_000,
        "the earliest, which is the since-expired token's genTime"
    );
    assert!(!status.is_unanchored());
    assert!(
        status
            .render()
            .join("\n")
            .contains("existed no later than 1780000000")
    );
}

// ─────────────────────────────────────────────────────────────────────
// U23 Accept row 3: the `--json` document
// ─────────────────────────────────────────────────────────────────────

/// **U23 accept**: the machine document carries a per-anchor state for every
/// artifact, and the U3 envelope makes it one document.
///
/// The envelope's own registration lives in `machine_mode.rs`'s committed
/// fixture; this asserts the shape the envelope wraps.
#[test]
fn the_json_document_carries_a_machine_readable_state_per_anchor() {
    let vault = fixture_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let json = status_of(&store, 0x01).json();

    assert_eq!(json["state"], serde_json::json!("complete"));
    assert_eq!(json["unanchored"], serde_json::json!(false));
    let anchors = json["anchors"].as_array().expect("an array");
    assert_eq!(anchors.len(), 2);
    assert_eq!(anchors[0]["slot"], serde_json::json!(OTS_SLOT));
    assert_eq!(anchors[0]["kind"], serde_json::json!("ots"));
    assert_eq!(anchors[0]["state"], serde_json::json!("pending"));
    assert_eq!(anchors[0]["headline_eligible"], serde_json::json!(false));
    assert_eq!(anchors[0]["source"]["verified"], serde_json::json!(false));
    assert_eq!(anchors[1]["slot"], serde_json::json!(tsa_slot(0)));
    assert_eq!(anchors[1]["state"], serde_json::json!("proven"));
    assert_eq!(anchors[1]["headline_eligible"], serde_json::json!(true));
    assert_eq!(anchors[1]["source"]["verified"], serde_json::json!(true));
    assert_eq!(
        anchors[1]["fetch_date"],
        serde_json::json!(FETCH_DATE.to_string())
    );

    // The whole document survives a round trip through `serde_json` as one
    // value — the U3 one-document contract's local half.
    let text = serde_json::to_string(&json).expect("serializes");
    let reparsed: serde_json::Value = serde_json::from_str(&text).expect("one document");
    assert_eq!(reparsed, json);

    // …and the `--no-anchor` work's `absent` rows are machine-visible too,
    // in their own field rather than smuggled into `anchors`.
    let unanchored = status_of(&store, 0x04).json();
    assert_eq!(unanchored["anchors"], serde_json::json!([]));
    assert_eq!(unanchored["unanchored"], serde_json::json!(true));
    let absent = unanchored["absent"].as_array().expect("an array");
    assert_eq!(absent.len(), 2);
    assert!(
        absent
            .iter()
            .all(|value| value["state"] == serde_json::json!("absent"))
    );
}

// ─────────────────────────────────────────────────────────────────────
// U23 Accept row 2: `--upgrade` against a mock calendar
// ─────────────────────────────────────────────────────────────────────

/// Resolve every pending URI onto one loopback stub — **D99 R5's seam**.
///
/// A42's allowlist requires https, a bare host and no port, so a stub can
/// never be admitted through the production constructor. That is correct, and
/// it is also why this row was unexecutable from this crate until R5 widened
/// `upgrade_pending_with` and `UpgradeTarget::loopback_for_tests` from
/// `cfg(test)` to `test-util`. The production resolver is untouched:
/// `upgrade_pending` still closes over `UpgradeTarget::from_pending_uri`.
fn to_stub(server: &StubServer) -> impl Fn(&str) -> Result<UpgradeTarget, UpgradeUriRefusal> {
    let base = server.base_url();
    move |_uri: &str| Ok(UpgradeTarget::loopback_for_tests(&base))
}

/// A stub esplora pair answering for one height with one header hex.
fn esplora_at(height: u64, header_hex: &str) -> StubScript {
    // A block hash is only ever echoed back into the next path, so any
    // 64-character lowercase hex string serves; the pair must agree on it,
    // which they do because both stubs are built from this one function.
    let hash: String = "00000000000000000000".to_owned() + &"ab".repeat(22);
    StubScript::new()
        .route(
            StubMatch::target(format!("/block-height/{height}")),
            StubReply::Body {
                status: 200,
                content_type: "text/plain",
                bytes: hash.as_bytes()[..64].to_vec(),
            },
        )
        .route(
            StubMatch::target("/header"),
            StubReply::Body {
                status: 200,
                content_type: "text/plain",
                bytes: header_hex.as_bytes().to_vec(),
            },
        )
}

fn esplora_pair(first: &StubServer, second: &StubServer) -> EndpointPair {
    EndpointPair::new(
        Endpoint::parse(&first.base_url(), TlsPolicy::RequiredExceptLoopback).expect("first"),
        Endpoint::parse(&second.base_url(), TlsPolicy::RequiredExceptLoopback).expect("second"),
    )
    .expect("distinct loopback origins")
}

/// Drive the engine over one work's stored anchors, through the R5 seam.
///
/// Everything except the resolver is the production path: the same
/// [`pending_work`] reader, the same engine, the same budget `status
/// --upgrade` uses.
fn poll_through_the_seam(store: &WorkStore<'_>, id: &SealId) -> (StoredAnchors, UpgradeReport) {
    let (stored, work) = pending_work(store, id).expect("read the anchors");
    let work = work.expect("the fixture holds a pending OTS anchor");

    // The calendar answers the poll with a timestamp rooted at the polled
    // commitment. With zero ops that commitment is the stamped digest, so the
    // body is a bare Bitcoin attestation — which is exactly what the merge
    // must splice in beside the pending branch.
    let upgrade_body = ots_writer::bitcoin(HEIGHT);
    let header = ots_writer::header_with(&digest(), ots_writer::HEADER_NTIME);
    let header_hex: String = header.iter().map(|byte| format!("{byte:02x}")).collect();

    let calendar_stub = StubServer::spawn(calendar(&CalendarBehaviour::Upgraded {
        pending: Vec::new(),
        upgrade: upgrade_body,
    }));
    let first = StubServer::spawn(esplora_at(HEIGHT, &header_hex));
    let second = StubServer::spawn(esplora_at(HEIGHT, &header_hex));

    let report = upgrade_pending_with(
        &HttpClient::new(HttpPolicy::opportunistic()),
        &esplora_pair(&first, &second),
        std::slice::from_ref(&work),
        UpgradeBudget {
            // The interactive budget's shape, with a bound small enough that
            // a broken stub fails fast rather than sitting for two minutes.
            total: Duration::from_secs(30),
            max_polls: usize::MAX,
        },
        HEADER_FETCH_DATE,
        &to_stub(&calendar_stub),
    );
    (stored, report)
}

/// **U23 accept**: `--upgrade` against a mock calendar transitions
/// `pending` → `attested`, persists the upgraded `.ots` **with** its header
/// group, and a re-run shows the new state.
///
/// The re-run is a fresh unlock over a closed vault, so "shows the new state"
/// is a claim about bytes on disk rather than about a live cache.
#[test]
fn upgrade_transitions_a_pending_anchor_to_attested_and_persists_it() {
    let vault = fixture_vault();
    let id = seal_id(0x01);
    {
        let unlocked = vault.unlock();
        assert_eq!(
            status_of(&WorkStore::new(&unlocked), 0x01)
                .anchors
                .iter()
                .find(|row| row.slot == OTS_SLOT)
                .map(|row| row.verdict.state()),
            Some(AnchorState::Pending),
            "the fixture starts pending, or this proves nothing"
        );
    }

    let outcome = {
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        let (stored, report) = poll_through_the_seam(&store, &id);
        assert_eq!(report.upgraded.len(), 1, "notes: {:?}", report.notes);
        assert!(
            report.upgraded[0].upgrade.is_some(),
            "D97 R6: the artifact and its group are recorded together or not at all"
        );
        let mut rng = ChaCha20Rng::from_seed([0x25; 32]);
        persist_upgrades(&store, &id, &stored, &report, &mut rng).expect("persist")
    };
    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.declined, 0);
    assert!(outcome.polls >= 1);

    // The re-run: a fresh unlock, a fresh read, no state carried over.
    let reread = vault.unlock();
    let store = WorkStore::new(&reread);
    let after = status_of(&store, 0x01);
    let row = after
        .anchors
        .iter()
        .find(|row| row.slot == OTS_SLOT)
        .expect("the slot survives");
    assert_eq!(
        row.verdict.state(),
        AnchorState::Attested,
        "a persisted upgrade group is what makes `attested` reachable at all (D97)"
    );
    assert_eq!(
        row.verdict.fetch_date(),
        Some(HEADER_FETCH_DATE.to_string().as_str()),
        "key 6 carries the engine's pinned header fetch date (D97 R5), never a clock read"
    );

    // D97 R4: the read-modify-write kept the *submission's* capture date in
    // key 2, which is a different fact from the header's.
    let stored_stored = StoredAnchors::read(&store, &id).expect("read");
    let stored = stored_stored.require_intact().expect("read");
    let (_, artifact) = stored.ots_entry(0).expect("the OTS slot");
    assert_eq!(artifact.fetch_date, FETCH_DATE, "key 2 is carried across");
    assert_eq!(
        artifact.upgrade.as_ref().map(OtsUpgrade::block_height),
        Some(HEIGHT)
    );
    assert_ne!(
        artifact.bytes,
        pending_ots(),
        "the merged artifact replaced the pending bytes"
    );
}

/// A repeated `--upgrade` over an already-upgraded anchor is a **no-op**, and
/// the stored artifact is byte-stable across arbitrarily many runs.
///
/// # The defect this row used to characterise
///
/// It was a red-in-spirit test asserting growth, and this is that measurement
/// turned into the fixed behaviour. The merge is a *pure insertion* —
/// `splice_sibling_before` keeps the pending branch, which is correct and is
/// why a real merged `.ots` still names its calendars — so `pending_refs`
/// finds the same attestation again on the next run and the calendar answers
/// with the same body. `added_bitcoin` is a **multiset** difference, so the
/// second identical attestation counted as *added*, `changed` went true, and a
/// transition was produced; and because `upgrade.is_some()` by then,
/// `confirm_header` was skipped, so the pre-existing group was re-recorded
/// beside a grown artifact. The evidence never degraded — the state stayed
/// `attested` — but the file grew one spliced attestation per run, bounded
/// only by `MAX_OTS_BYTES` (1 MiB).
///
/// That was one `--upgrade`'s worth of waste. **U24's hook runs on every CLI
/// invocation, for every completed work**, which would have made it
/// per-invocation and unbounded for the life of the vault — so the fix landed
/// with the hook rather than after it. `already_merged` refuses a body already
/// spliced at this insertion point; a body that *differs* still merges, so
/// this refuses repetition and never new evidence.
#[test]
fn a_repeated_upgrade_run_is_a_no_op_and_the_stored_artifact_is_byte_stable() {
    let vault = fixture_vault();
    let id = seal_id(0x01);
    {
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        let (stored, report) = poll_through_the_seam(&store, &id);
        let mut rng = ChaCha20Rng::from_seed([0x26; 32]);
        persist_upgrades(&store, &id, &stored, &report, &mut rng).expect("persist");
    }
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let stored_before = StoredAnchors::read(&store, &id).expect("read");
    let before = stored_before.require_intact().expect("read");
    let (_, before_artifact) = before.ots_entry(0).expect("the OTS slot");
    let pinned = before_artifact.clone();

    // Two further runs, because "stable" is a claim about repetition and one
    // repeat could be an accident of the first merge's shape.
    for round in 0..2 {
        let (stored, report) = poll_through_the_seam(&store, &id);
        assert_eq!(
            report.polls, 1,
            "round {round}: the pending branch survives the merge by design, so it is still \
             polled — the fix refuses the re-splice, it does not stop asking"
        );
        assert!(
            report.upgraded.is_empty(),
            "round {round}: an attestation already in the artifact must produce NO transition; \
             notes: {:?}",
            report.notes
        );
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.to_string().contains("already merged")),
            "round {round}: and the refusal must say which calendar and why; notes: {:?}",
            report.notes
        );
        let mut rng = ChaCha20Rng::from_seed([0x27; 32]);
        let outcome = persist_upgrades(&store, &id, &stored, &report, &mut rng).expect("persist");
        assert_eq!(outcome.applied, 0, "round {round}: nothing was written");
        assert_eq!(
            outcome.declined, 0,
            "round {round}: and nothing was discarded"
        );

        // The row the fix is *for*: the record on disk is unchanged, byte for
        // byte, across repeated runs.
        let stored_after = StoredAnchors::read(&store, &id).expect("read");
        let after = stored_after.require_intact().expect("read");
        let (_, after_artifact) = after.ots_entry(0).expect("the OTS slot");
        assert_eq!(
            after_artifact.bytes.len(),
            pinned.bytes.len(),
            "round {round}: the artifact grew from {} to {} bytes — one spliced attestation per \
             invocation is exactly the unbounded growth U24's hook would have amplified",
            pinned.bytes.len(),
            after_artifact.bytes.len()
        );
        assert_eq!(
            *after_artifact, pinned,
            "round {round}: the whole record is byte-stable — bytes, the D79 upgrade group, and \
             D97 R4's key-2 capture date alike"
        );
    }

    // …and the evidence is still there: refusing the re-splice must not have
    // cost the attestation the first run earned.
    assert_eq!(
        status_of(&store, 0x01)
            .anchors
            .iter()
            .find(|row| row.slot == OTS_SLOT)
            .map(|row| row.verdict.state()),
        Some(AnchorState::Attested)
    );
}

/// D99 R3's compare-and-set, from the caller's side: a transition computed
/// against a record another writer has since replaced is **discarded and
/// counted**, never written.
///
/// The engine polls unlocked, so the window is real — its most ordinary
/// occupant is the resume path, which rewrites `ots-pending` from a *fresh*
/// submission. Writing anyway would pair a genuinely upgraded `.ots` with a
/// previous submission's bytes, which renders `invalid` /
/// `anchor-ots-header-uncommitted` on an honest work (D97 §2 K2).
#[test]
fn a_transition_whose_slot_moved_is_declined_rather_than_written() {
    let vault = fixture_vault();
    let id = seal_id(0x01);
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);

    let (stored, report) = poll_through_the_seam(&store, &id);
    assert_eq!(report.upgraded.len(), 1);

    // Another writer replaces the slot between the poll and the write — a
    // fresh submission of the same work, with a later capture date.
    let mut interloper = ChaCha20Rng::from_seed([0x28; 32]);
    let replacement = AnchorArtifact {
        fetch_date: FETCH_DATE + 1,
        ..ots_artifact(pending_ots(), None)
    };
    store
        .put_anchor(
            &id,
            OTS_SLOT,
            &replacement.encode().expect("encode"),
            &mut interloper,
        )
        .expect("the interloping write");

    let mut rng = ChaCha20Rng::from_seed([0x29; 32]);
    let outcome = persist_upgrades(&store, &id, &stored, &report, &mut rng).expect("persist");
    assert_eq!(outcome.applied, 0, "nothing was written");
    assert_eq!(
        outcome.declined, 1,
        "and the discard is counted, not silent"
    );

    let stored_after = StoredAnchors::read(&store, &id).expect("read");

    let after = stored_after.require_intact().expect("read");
    let (_, artifact) = after.ots_entry(0).expect("the OTS slot");
    assert_eq!(
        *artifact, replacement,
        "the interloper's record survives untouched"
    );
    assert_eq!(
        status_of(&store, 0x01)
            .anchors
            .iter()
            .find(|row| row.slot == OTS_SLOT)
            .map(|row| row.verdict.state()),
        Some(AnchorState::Pending),
        "and the work is still honestly pending rather than falsely invalid"
    );
}

/// A `--no-anchor` work has nothing to poll, and asking is not an error.
#[test]
fn an_unanchored_work_has_no_pending_work_to_poll() {
    let vault = fixture_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let (stored, work) = pending_work(&store, &seal_id(0x04)).expect("read");
    assert!(stored.is_empty());
    assert!(work.is_none(), "no OTS artifact means nothing to upgrade");
}

// ─────────────────────────────────────────────────────────────────────
// D100 R6: damage is data here too, and at exit 0
// ─────────────────────────────────────────────────────────────────────

/// **D100 §1.2, closed**: a work holding anchor artifacts with no journaled
/// manifest is rendered, not refused.
///
/// Before this, `status` answered exit **12** and *"wrong passphrase, or the
/// vault store or header has been modified or corrupted"* — on a vault whose
/// passphrase it had already proven, a work the user had named by id, and a
/// meta record it had already read — while `list` rendered the *identical*
/// state as a soft row at exit 0. Two committed authorities, days apart,
/// each documenting itself as obviously right and neither citing the other.
/// The divergence is closed in `list`'s favour and both now say the same
/// sentence.
#[test]
fn a_work_with_anchors_and_no_manifest_is_rendered_rather_than_refused() {
    let vault = damaged_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);

    // 1. It does not error at all — which is the whole change.
    let status = WorkStatus::gather(&store, &seal_id(0x11), ctx())
        .expect("a work with no manifest is reported, not refused");

    // 2. No verdict is stated, because none can be: every A18 evaluator takes
    //    an `anchor_digest` and there is none to give it.
    assert!(status.anchors.is_empty());
    assert_eq!(status.unclassifiable.len(), 1);
    assert_eq!(status.unclassifiable[0].slot, tsa_slot(0));
    assert_eq!(status.unclassifiable[0].kind, AnchorKind::Tsa);
    assert!(status.damaged.is_empty(), "no *record* here is damaged");

    // 3. …and it must not claim the TSA kind is `absent`, which would make a
    //    work holding a token look like a `--no-anchor` seal.
    assert!(
        !status.absent.iter().any(|v| v.kind() == AnchorKind::Tsa),
        "a slot that exists is never absent, whatever can be said about it"
    );

    let rendered = status.render().join("\n");
    assert!(rendered.contains("(unclassified)"));
    assert!(
        rendered.contains(antseal_cli::status::UNCLASSIFIED_NOTE),
        "the sentence is `list`'s own, verbatim; rendered:\n{rendered}"
    );

    let doc = status.json();
    assert_eq!(
        doc["unclassifiable"],
        serde_json::json!([{ "slot": tsa_slot(0), "kind": "tsa" }])
    );
    assert_eq!(doc["damaged_anchors"], serde_json::json!([]));
}

/// **D100 R6**: an anchor record the codec refuses is a per-slot row, outside
/// the frozen seven, at exit 0.
///
/// D99 R6 assigned `status <work-id>` the **loud** report of a corrupt or
/// future-versioned anchor record — *"that is a command the user ran about
/// that work"* — and that assignment had never been executable, because the
/// command answered it by accusing the passphrase. It is executable now.
#[test]
fn a_damaged_anchor_record_is_a_row_not_a_refusal() {
    let vault = damaged_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);

    let status = WorkStatus::gather(&store, &seal_id(0x12), ctx())
        .expect("a damaged record is reported, not refused");

    // The good slot still produces a verdict — the survivors and the damage,
    // together, which is what the reporting door is for.
    assert_eq!(status.anchors.len(), 1);
    assert_eq!(status.anchors[0].slot, tsa_slot(0));
    assert!(status.unclassifiable.is_empty());

    assert_eq!(status.damaged.len(), 1);
    assert_eq!(status.damaged[0].slot, OTS_SLOT);
    assert_eq!(status.damaged[0].reason.name(), "undecodable");
    assert_eq!(
        status.damaged[0].reason.detail(),
        "journal record is not canonical CBOR",
        "the decoder's own message, verbatim (R10.5)"
    );

    // **The honesty rule**: the record's `kind` is at key 0 *inside* the
    // record that will not open, so the kind is unknowable — but the slot
    // *name* gives a family, and `status` must not answer `absent` for it.
    // Claiming `ots absent` here would make this work look cleaner than a
    // healthy one, which is the exact failure D100 removes.
    assert!(
        !status.absent.iter().any(|v| v.kind() == AnchorKind::Ots),
        "the damaged slot is an `ots-pending` slot; `absent` would be a lie"
    );

    let rendered = status.render().join("\n");
    assert!(rendered.contains("(record unreadable)"));
    assert!(rendered.contains("undecodable"));
    assert!(rendered.contains("this record is malformed"));
    assert!(
        rendered.contains("2 anchor artifact(s)"),
        "the count includes the damaged slot, or the damage disappears into a smaller \
         number; rendered:\n{rendered}"
    );

    // The four keys of R3, spelled exactly as `list` spells them.
    let doc = status.json();
    assert_eq!(
        doc["damaged_anchors"],
        serde_json::json!([{
            "slot": OTS_SLOT,
            "reason": "undecodable",
            "detail": "journal record is not canonical CBOR",
            "format_version": null,
        }])
    );
    assert_eq!(doc["unclassifiable"], serde_json::json!([]));
}

/// **D100 §1.3, the measurement that killed the error class**: the same damage
/// one layer down already rendered at exit 0, and now both layers do.
///
/// `.ots` **bytes** that do not parse render `invalid` (D98's cross-walk); the
/// CBOR **record** wrapping them used to render exit 12 and *"wrong
/// passphrase"*. One layer of wrapping apart, with no severity difference
/// between them and no way for a user to perceive where the boundary fell.
#[test]
fn the_record_and_the_bytes_it_wraps_are_reported_at_the_same_severity() {
    let unreadable_bytes = {
        let vault = fixture_vault();
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        // Work 3's TSA slot holds `b"not a TimeStampResp"`: the record opens,
        // the artifact does not parse.
        let status = status_of(&store, 0x03);
        status
            .anchors
            .iter()
            .find(|row| row.slot == tsa_slot(0))
            .expect("the TSA row")
            .verdict
            .state()
            .wire_name()
    };
    assert_eq!(unreadable_bytes, "invalid");

    // …and the record wrapping such bytes is now reported, rather than
    // refusing the command that was asked about the work.
    let vault = damaged_vault();
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    assert!(
        WorkStatus::gather(&store, &seal_id(0x12), ctx()).is_ok(),
        "both sides of one wrapper must be reportable, or the user sees a boundary that \
         carries no difference in severity"
    );
}
