//! U19 acceptance suite: `list` over a five-state fixture vault.
//!
//! The fixture is built through the real journal API (S10's state machine
//! and U9's store), never by hand-writing records, so what is rendered is
//! what a real vault would hold at each barrier.
//!
//! NON-SECRET: every `W`, path and title here is a documented fixture.

mod common;

use antseal_anchor::ots::NagState;
use antseal_cli::listing::{ResumeClock, WorkListing, WorkRow};
use antseal_cli::pipeline::journal::{SealJournal, SealState, WorkIdentity};
use antseal_cli::pipeline::{
    AnchorArtifact, ArtifactKind, OTS_SLOT, PLAN_ENTRY, SealPlan, VaultJournal, tsa_slot,
};
use antseal_cli::vault::store::{
    ConsentChannel, ConsentRecord, SealShapingFlags, WorkState, WorkStore,
};
use antseal_core::crypto::secrets::{MasterSecret, SealId};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::IsolatedVault;

/// A base moment for the fixture clocks (2027-01-01T00:00:00Z), so the
/// rendered dates are stable and obviously synthetic.
const BASE_TIME: u64 = 1_798_761_600;

/// One fixture work: how far it got, and what it looks like.
struct Fixture {
    tag: u8,
    state: SealState,
    title: Option<&'static str>,
    paths: &'static [&'static str],
    unanchored: bool,
    consent_offset: Option<u64>,
    cost_atto: Option<u128>,
    work_id: Option<u8>,
}

fn fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            tag: 0x01,
            state: SealState::Complete,
            title: Some("thesis draft"),
            paths: &["chapter one.txt", "notes.md"],
            unanchored: false,
            consent_offset: Some(400),
            cost_atto: Some(4_200_000_000_000_000_000),
            work_id: Some(0xA1),
        },
        Fixture {
            tag: 0x02,
            state: SealState::Complete,
            title: Some("dev smoke"),
            paths: &["scratch.txt"],
            unanchored: true,
            consent_offset: Some(300),
            cost_atto: Some(7),
            work_id: Some(0xA2),
        },
        Fixture {
            tag: 0x03,
            state: SealState::Staged,
            title: None,
            paths: &["half-done.txt"],
            unanchored: false,
            consent_offset: None,
            cost_atto: None,
            work_id: None,
        },
        Fixture {
            tag: 0x04,
            state: SealState::Paid,
            title: Some("paid but unfinished"),
            paths: &["big.bin"],
            unanchored: false,
            consent_offset: Some(200),
            cost_atto: Some(1_000_000_000_000_000_000),
            work_id: Some(0xA4),
        },
        Fixture {
            tag: 0x05,
            state: SealState::Abandoned,
            title: Some("gave up"),
            paths: &["lost.txt"],
            unanchored: false,
            consent_offset: Some(100),
            cost_atto: Some(5),
            work_id: Some(0xA5),
        },
    ]
}

fn seal_id(tag: u8) -> SealId {
    let mut bytes = [tag; 16];
    bytes[0] = 0xE1;
    SealId::from_bytes(bytes)
}

/// Build the fixture vault: one work per row, driven through the real
/// state machine to the state it should be in.
fn fixture_vault() -> IsolatedVault {
    let vault = IsolatedVault::create("list");
    let unlocked = vault.unlock();
    let mut rng = ChaCha20Rng::from_seed([0x19; 32]);
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);

    for f in fixtures() {
        let w = MasterSecret::from_bytes([f.tag; 32]);
        let id = seal_id(f.tag);
        journal
            .begin(&WorkIdentity {
                w: w.secret_ref(),
                seal_id: id,
                network: if f.unanchored {
                    "devnet"
                } else {
                    "arbitrum-one"
                }
                .to_owned(),
                unanchored: f.unanchored,
                degraded: false,
                input_paths_as_given: f.paths.iter().map(|p| (*p).to_owned()).collect(),
                input_paths_absolute: f.paths.iter().map(|p| format!("/w/{p}")).collect(),
                shaping: SealShapingFlags {
                    title: f.title.map(str::to_owned),
                    split_blank_lines: f.tag == 0x01,
                    force_text: false,
                    no_fine_tree: if f.tag == 0x01 {
                        vec!["*.png".to_owned()]
                    } else {
                        Vec::new()
                    },
                    no_anchor: f.unanchored,
                    force_degraded: false,
                },
            })
            .expect("begin");

        // Walk the machine to the target state, one legal step at a time.
        let path: &[SealState] = match f.state {
            SealState::Staged => &[],
            SealState::Anchored => &[SealState::Anchored],
            SealState::Paid => &[SealState::Anchored, SealState::Paid],
            SealState::Finalizing => &[SealState::Anchored, SealState::Paid, SealState::Finalizing],
            SealState::Complete => &[
                SealState::Anchored,
                SealState::Paid,
                SealState::Finalizing,
                SealState::Complete,
            ],
            SealState::Abandoned => &[SealState::Abandoned],
        };
        for step in path {
            journal.set_state(&id, *step).expect("advance");
        }
        if let Some(offset) = f.consent_offset {
            journal
                .put_consent(
                    &id,
                    ConsentRecord {
                        total_ant_atto: f.cost_atto.unwrap_or(0),
                        gas_estimate_wei: 21_000,
                        consent_time_unix_secs: BASE_TIME + offset,
                        channel: ConsentChannel::YesFlag,
                    },
                )
                .expect("consent");
        }
        journal
            .record_outcome(&id, f.work_id.map(|b| [b; 32]), f.cost_atto)
            .expect("outcome");
    }
    vault
}

fn listing(vault: &IsolatedVault) -> WorkListing {
    let unlocked = vault.unlock();
    WorkListing::gather(&WorkStore::new(&unlocked)).expect("gather")
}

// ─────────────────────────────────────────────────────────────────────
// U19 Accept row 1: every state renders distinctly
// ─────────────────────────────────────────────────────────────────────

/// **U19 accept**: a vault holding complete, incomplete-pre-pay,
/// incomplete-post-receipt, abandoned and `--no-anchor` works renders all
/// five distinctly, against a committed snapshot.
#[test]
fn every_state_renders_distinctly() {
    let vault = fixture_vault();
    let listing = listing(&vault);
    assert_eq!(listing.works.len(), 5);

    let counts = listing.counts();
    assert_eq!(counts.total, 5);
    assert_eq!(counts.complete, 2);
    assert_eq!(counts.incomplete, 2);
    assert_eq!(counts.abandoned, 1);
    assert_eq!(counts.unanchored, 1);

    let rendered = format!("{}\n", listing.render().join("\n"));
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/list-report.txt");
    if std::env::var_os("ANTSEAL_BLESS").is_some() {
        std::fs::write(&path, &rendered).expect("bless");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing committed listing snapshot at {}: {e} (generate with ANTSEAL_BLESS=1)",
            path.display()
        )
    });
    assert!(
        committed == rendered,
        "the `list` report drifted from {} — regenerate with ANTSEAL_BLESS=1 and justify \
         the diff\n--- rendered ---\n{rendered}",
        path.display()
    );
}

/// **U19 accept**: the post-receipt row carries the time-boxed-resume nag
/// and the pre-pay row the re-quote note — the two clocks, saying
/// opposite things to the two classes of unfinished seal.
#[test]
fn the_two_clocks_land_on_the_right_rows() {
    let vault = fixture_vault();
    let listing = listing(&vault);

    let pre_pay = listing
        .works
        .iter()
        .find(|r| r.state == WorkState::IncompletePrePay)
        .expect("a pre-pay work");
    let post_pay = listing
        .works
        .iter()
        .find(|r| r.state == WorkState::IncompletePostPay)
        .expect("a post-receipt work");

    assert_eq!(
        pre_pay.resume.as_ref().expect("hint").clock,
        ResumeClock::ReQuote
    );
    assert_eq!(
        post_pay.resume.as_ref().expect("hint").clock,
        ResumeClock::TimeBoxed
    );
    assert!(
        post_pay
            .resume
            .as_ref()
            .expect("hint")
            .clock
            .note()
            .contains("RESUME PROMPTLY")
    );
    assert!(
        pre_pay
            .resume
            .as_ref()
            .expect("hint")
            .clock
            .note()
            .contains("nothing was paid")
    );

    // Finished works carry no hint at all: there is nothing to resume.
    for row in &listing.works {
        if matches!(row.state, WorkState::Complete | WorkState::Abandoned) {
            assert!(row.resume.is_none(), "{}", row.badge());
        }
    }

    // The fine tag distinguishes the two pre-pay barriers, which the
    // coarse mirror cannot.
    assert_eq!(pre_pay.detail_state_name(), "staged");
    assert_eq!(post_pay.detail_state_name(), "paid");
}

/// **U19 accept**: the resume hint reproduces the recorded invocation
/// identity — paths and seal-shaping flags — verbatim, so running it
/// finishes this seal instead of starting a second one.
#[test]
fn the_resume_hint_reproduces_the_recorded_invocation() {
    let vault = fixture_vault();
    let listing = listing(&vault);
    let row = listing
        .works
        .iter()
        .find(|r| r.state == WorkState::IncompletePostPay)
        .expect("a post-receipt work");
    assert_eq!(
        row.resume.as_ref().expect("hint").invocation,
        "antseal seal big.bin --title 'paid but unfinished'",
        "recorded paths and flags, and nothing invented"
    );

    // And a work with the full flag set round-trips every one of them.
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let record = store.load_meta(&seal_id(0x01)).expect("meta");
    let hint = antseal_cli::listing::seal_invocation(
        &record.input_paths_as_given,
        &record.shaping,
        &record.network,
    );
    assert_eq!(
        hint,
        "antseal seal 'chapter one.txt' notes.md --title 'thesis draft' --split blank-lines \
         --no-fine-tree '*.png'"
    );
}

/// **U19 accept**: per-work cost is the value journaled at seal, exact at
/// atto scale.
#[test]
fn per_work_cost_matches_the_journaled_value() {
    let vault = fixture_vault();
    let listing = listing(&vault);
    let complete = listing
        .works
        .iter()
        .find(|r| r.title.as_deref() == Some("thesis draft"))
        .expect("the complete work");
    assert_eq!(complete.cost_atto, Some(4_200_000_000_000_000_000));

    let staged = listing
        .works
        .iter()
        .find(|r| r.state == WorkState::IncompletePrePay)
        .expect("the pre-pay work");
    assert_eq!(staged.cost_atto, None, "nothing paid, nothing recorded");
}

// ─────────────────────────────────────────────────────────────────────
// The `--json` fixture shape
// ─────────────────────────────────────────────────────────────────────

/// The machine document carries every row with the full record set, the
/// counts, and U25's two anchor fields — and amounts ride as exact decimal
/// strings, because atto-ANT does not survive a JSON number in most
/// consumers.
#[test]
fn the_json_document_carries_the_full_record_set() {
    let vault = fixture_vault();
    let listing = listing(&vault);
    let doc = listing.json();

    let works = doc["works"].as_array().expect("works array");
    assert_eq!(works.len(), 5);
    assert_eq!(doc["counts"]["total"], serde_json::json!(5));
    assert_eq!(doc["counts"]["unanchored"], serde_json::json!(1));

    for row in works {
        for key in [
            "work_id",
            "seal_id",
            "title",
            "sealed_at",
            "network",
            "state",
            "detail_state",
            "unanchored",
            "degraded",
            "cost_atto",
            "resume",
            "pending_anchors",
            "nag",
        ] {
            assert!(row.get(key).is_some(), "row is missing {key}: {row}");
        }
        // No work in this vault ever reached the anchor stage, so every
        // row is a *counted* zero rather than the `null` that means "could
        // not tell" — and the class says which of the three "no nag"
        // meanings it is.
        assert_eq!(row["pending_anchors"], serde_json::json!(0), "{row}");
        assert_eq!(row["nag"], serde_json::json!("unanchored"), "{row}");
    }
    assert_eq!(doc["counts"]["pending_anchor_nags"], serde_json::json!(0));

    let complete = works
        .iter()
        .find(|r| r["title"] == serde_json::json!("thesis draft"))
        .expect("the complete row");
    assert_eq!(complete["state"], serde_json::json!("complete"));
    assert_eq!(
        complete["cost_atto"],
        serde_json::json!("4200000000000000000"),
        "exact at atto scale, as a string"
    );
    assert!(complete["resume"].is_null());

    let unanchored = works
        .iter()
        .find(|r| r["unanchored"] == serde_json::json!(true))
        .expect("the UNANCHORED row");
    assert_eq!(unanchored["network"], serde_json::json!("devnet"));

    let post_pay = works
        .iter()
        .find(|r| r["detail_state"] == serde_json::json!("paid"))
        .expect("the post-receipt row");
    assert_eq!(post_pay["resume"]["clock"], serde_json::json!("time-boxed"));
    assert!(
        post_pay["resume"]["note"]
            .as_str()
            .expect("note")
            .contains("RESUME PROMPTLY")
    );
}

// ─────────────────────────────────────────────────────────────────────
// Robustness
// ─────────────────────────────────────────────────────────────────────

/// Order is total and deterministic: newest first, undated last, seal id
/// as the tie-break — so a snapshot and a script both see a stable
/// sequence.
#[test]
fn the_order_is_deterministic_newest_first() {
    let vault = fixture_vault();
    let first = listing(&vault);
    let second = listing(&vault);
    assert_eq!(first, second, "two reads, one order");

    let dates: Vec<Option<u64>> = first.works.iter().map(|r| r.sealed_at_unix_secs).collect();
    assert_eq!(
        dates,
        vec![
            Some(BASE_TIME + 400),
            Some(BASE_TIME + 300),
            Some(BASE_TIME + 200),
            Some(BASE_TIME + 100),
            None,
        ]
    );
}

/// A work whose journal state record is gone — the shape a `vault
/// import`ed complete work has, since U12 exports no journal entries for
/// one — still lists, from U9's coarse mirror. `list` is the command you
/// reach for on exactly that machine.
#[test]
fn a_work_without_its_fine_state_record_still_lists() {
    let vault = fixture_vault();
    {
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        // Journal entry 0 is the fine state record (S10's namespace).
        assert!(
            store
                .delete_journal_entry(&seal_id(0x01), 0)
                .expect("delete"),
            "the fine tag was there to delete"
        );
    }

    let listing = listing(&vault);
    let row = listing
        .works
        .iter()
        .find(|r| r.title.as_deref() == Some("thesis draft"))
        .expect("still listed");
    assert!(row.fine_state.is_none());
    assert_eq!(
        row.state,
        WorkState::Complete,
        "the coarse mirror carries it"
    );
    assert_eq!(row.detail_state_name(), "complete");
    assert_eq!(row.state_name(), "complete");
}

/// An empty vault says so, rather than printing nothing at all.
#[test]
fn an_empty_vault_renders_a_sentence_not_a_blank() {
    let vault = IsolatedVault::create("list-empty");
    let unlocked = vault.unlock();
    let listing = WorkListing::gather(&WorkStore::new(&unlocked)).expect("gather");
    assert!(listing.works.is_empty());
    assert_eq!(listing.render(), vec!["No sealed works in this vault yet."]);
    assert_eq!(listing.json()["counts"]["total"], serde_json::json!(0));
}

// ─────────────────────────────────────────────────────────────────────
// U25 — the pending-anchor nag, over a vault holding real artifacts
// ─────────────────────────────────────────────────────────────────────
//
// A second vault rather than more rows in `fixture_vault`: U19's suite and
// its committed snapshot are an accepted acceptance surface, and growing
// them would have made every U25 assertion a diff against U19's.
//
// NON-SECRET: the three artifacts below are committed public cryptographic
// material — two real RFC 3161 responses and one real merged `.ots` — and
// the plan record carries the F12 golden manifest envelope. They agree on
// one `anchor_digest`, `083f87df…69df`, which is what makes a vault holding
// *verifiable* anchors buildable at all: `D60-CAPTURE.log` records the nine
// `D60-*` tokens as stamped over it, `CAPTURE.log` records it as the
// `digest_A` of the three calendar submissions merged into `merged-A.ots`,
// and `anchor_digest` is bare SHA-256 of the manifest envelope — so the
// golden envelope bytes are a preimage the fixture can journal.

/// A real DigiCert `TimeStampResp` over the fixture digest, chaining to a
/// root pinned in store v1.
const TSA_PINNED: &[u8] =
    include_bytes!("../../../testdata/anchors/A25-bootstrap/D60-tsa-digicert-resp.tsr");

/// A real GlobalSign `TimeStampResp` over the same digest, whose root is
/// deliberately **outside** store v1.
const TSA_UNPINNED: &[u8] =
    include_bytes!("../../../testdata/anchors/A25-bootstrap/D60-tsa-globalsign-resp.tsr");

/// A real merged `.ots` over the same digest: three calendars, none buried.
const OTS_PENDING: &[u8] = include_bytes!("../../../testdata/anchors/A25-bootstrap/merged-A.ots");

/// The F12 golden manifest envelope the fixture journals as its plan.
fn fixture_manifest_bytes() -> Vec<u8> {
    let doc: serde_json::Value = serde_json::from_str(include_str!(
        "../../../testdata/vectors/v1/manifest/manifest.json"
    ))
    .expect("the F12 manifest vectors parse");
    let hex = doc["expect"]["cases"][1]["manifest_bytes"]
        .as_str()
        .expect("case 1 carries its envelope bytes");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("vector hex"))
        .collect()
}

/// One work of U25's matrix.
struct AnchorFixture {
    tag: u8,
    title: &'static str,
    state: SealState,
    /// `--no-anchor`, and therefore no artifacts at all.
    unanchored: bool,
    /// `--force-degraded`.
    degraded: bool,
    /// A `tsa-0` slot holding these bytes, when there is one.
    tsa: Option<&'static [u8]>,
    /// An `ots-pending` slot holding the merged pending artifact.
    ots: bool,
    /// Whether `record_outcome` recorded a work id — `false` is a seal
    /// killed between the anchor stage and `finalize`.
    work_id: Option<u8>,
    /// Whether the journaled plan record survives, i.e. whether
    /// `anchor_digest` is recoverable at all.
    keep_plan: bool,
    consent_offset: u64,
}

fn anchor_fixtures() -> Vec<AnchorFixture> {
    vec![
        AnchorFixture {
            tag: 0x11,
            title: "tsa token, verified",
            state: SealState::Complete,
            unanchored: false,
            degraded: false,
            tsa: Some(TSA_PINNED),
            ots: true,
            work_id: Some(0xB1),
            keep_plan: true,
            consent_offset: 600,
        },
        AnchorFixture {
            tag: 0x12,
            title: "degraded, only pending ots",
            state: SealState::Complete,
            unanchored: false,
            degraded: true,
            tsa: None,
            ots: true,
            work_id: Some(0xB2),
            keep_plan: true,
            consent_offset: 500,
        },
        AnchorFixture {
            tag: 0x13,
            title: "sealed with --no-anchor",
            state: SealState::Complete,
            unanchored: true,
            degraded: false,
            tsa: None,
            ots: false,
            work_id: Some(0xB3),
            keep_plan: true,
            consent_offset: 400,
        },
        AnchorFixture {
            tag: 0x14,
            title: "token whose root left the store",
            state: SealState::Complete,
            unanchored: false,
            degraded: false,
            tsa: Some(TSA_UNPINNED),
            ots: true,
            work_id: Some(0xB4),
            keep_plan: true,
            consent_offset: 300,
        },
        AnchorFixture {
            tag: 0x15,
            title: "anchored, killed before finalize",
            state: SealState::Anchored,
            unanchored: false,
            degraded: false,
            tsa: None,
            ots: true,
            work_id: None,
            keep_plan: true,
            consent_offset: 200,
        },
        AnchorFixture {
            tag: 0x16,
            title: "artifacts, journaled manifest gone",
            state: SealState::Complete,
            unanchored: false,
            degraded: false,
            tsa: None,
            ots: true,
            work_id: Some(0xB6),
            keep_plan: false,
            consent_offset: 100,
        },
    ]
}

/// Build U25's vault: the works through the real state machine, then the
/// artifacts through `WorkStore::put_anchor` in the same record shape the
/// anchor stage writes.
fn anchor_fixture_vault() -> IsolatedVault {
    let vault = IsolatedVault::create("list-anchors");
    let manifest_bytes = fixture_manifest_bytes();
    {
        let unlocked = vault.unlock();
        let mut rng = ChaCha20Rng::from_seed([0x25; 32]);
        let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);
        for f in anchor_fixtures() {
            let w = MasterSecret::from_bytes([f.tag; 32]);
            let id = seal_id(f.tag);
            journal
                .begin(&WorkIdentity {
                    w: w.secret_ref(),
                    seal_id: id,
                    network: "arbitrum-one".to_owned(),
                    unanchored: f.unanchored,
                    degraded: f.degraded,
                    input_paths_as_given: vec!["work.txt".to_owned()],
                    input_paths_absolute: vec!["/w/work.txt".to_owned()],
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
                        manifest_bytes: Some(manifest_bytes.clone()),
                    },
                )
                .expect("plan");
            let path: &[SealState] = match f.state {
                SealState::Anchored => &[SealState::Anchored],
                _ => &[
                    SealState::Anchored,
                    SealState::Paid,
                    SealState::Finalizing,
                    SealState::Complete,
                ],
            };
            for step in path {
                journal.set_state(&id, *step).expect("advance");
            }
            journal
                .put_consent(
                    &id,
                    ConsentRecord {
                        total_ant_atto: 11,
                        gas_estimate_wei: 21_000,
                        consent_time_unix_secs: BASE_TIME + f.consent_offset,
                        channel: ConsentChannel::YesFlag,
                    },
                )
                .expect("consent");
            journal
                .record_outcome(&id, f.work_id.map(|b| [b; 32]), Some(11))
                .expect("outcome");
        }
    }

    // The artifacts, and the one deletion, over the finished works.
    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);
    let mut rng = ChaCha20Rng::from_seed([0x26; 32]);
    for f in anchor_fixtures() {
        let id = seal_id(f.tag);
        if f.ots {
            put_artifact(
                &store,
                &mut rng,
                &id,
                OTS_SLOT,
                ArtifactKind::OtsPending,
                "",
                OTS_PENDING,
            );
        }
        if let Some(token) = f.tsa {
            put_artifact(
                &store,
                &mut rng,
                &id,
                &tsa_slot(0),
                ArtifactKind::TsaToken,
                "tsa-fixture:committed-capture",
                token,
            );
        }
        if !f.keep_plan {
            assert!(
                store
                    .delete_journal_entry(&id, PLAN_ENTRY)
                    .expect("delete plan"),
                "the plan record was there to delete"
            );
        }
    }
    vault
}

fn put_artifact(
    store: &WorkStore<'_>,
    rng: &mut ChaCha20Rng,
    seal_id: &SealId,
    slot: &str,
    kind: ArtifactKind,
    endpoint: &str,
    bytes: &'static [u8],
) {
    let record = AnchorArtifact {
        kind,
        endpoint: endpoint.to_owned(),
        // A32 provenance: recorded, compared against nothing.
        fetch_date: BASE_TIME,
        bytes: bytes.to_vec(),
        upgrade: None,
    };
    store
        .put_anchor(seal_id, slot, &record.encode().expect("encode"), rng)
        .expect("put anchor");
}

fn row_titled<'a>(listing: &'a WorkListing, title: &str) -> &'a WorkRow {
    listing
        .works
        .iter()
        .find(|r| r.title.as_deref() == Some(title))
        .unwrap_or_else(|| panic!("no row titled {title}"))
}

/// **U25 accept row 1**: the fixture matrix, over a real vault.
///
/// A work with a valid TSA token does not nag; a `--force-degraded` work
/// whose only anchor is a pending `.ots` does; a `--no-anchor` work is
/// UNANCHORED and never "pending". The fourth row is the one D98 left
/// under-determined — a stored token whose root is not in the pinned store
/// is not headline-eligible, so it does not silence the nag.
#[test]
fn the_anchor_fixture_matrix_renders_three_classes_distinctly() {
    let vault = anchor_fixture_vault();
    let listing = listing(&vault);
    assert_eq!(listing.works.len(), 6);

    let verified = row_titled(&listing, "tsa token, verified");
    assert_eq!(verified.nag, Some(NagState::Anchored));
    assert!(!verified.nags(), "a headline anchor already exists");
    assert_eq!(
        verified.pending_anchors,
        Some(3),
        "the pending count is still a fact about the .ots"
    );

    let pending = row_titled(&listing, "degraded, only pending ots");
    assert_eq!(pending.nag, Some(NagState::OnlyPendingOts));
    assert!(pending.nags());
    assert_eq!(pending.pending_anchors, Some(3));
    assert_eq!(
        pending.badge(),
        "complete (degraded anchors)",
        "degraded is the seal's shape and stays in the state column"
    );

    let unanchored = row_titled(&listing, "sealed with --no-anchor");
    assert_eq!(unanchored.nag, Some(NagState::Unanchored));
    assert!(!unanchored.nags(), "UNANCHORED is labelled, never nagged");
    assert_eq!(unanchored.pending_anchors, Some(0));
    assert_eq!(unanchored.badge(), "complete UNANCHORED");
    assert_ne!(
        unanchored.nag, pending.nag,
        "UNANCHORED and pending are different classes and must not collapse"
    );

    let stale = row_titled(&listing, "token whose root left the store");
    assert_eq!(
        stale.nag,
        Some(NagState::OnlyPendingOts),
        "a token that no longer chains to a pinned root is evidence of nothing"
    );
    assert!(stale.nags());

    // Three predicates, three answers, on one row: the `--no-anchor` flag
    // is false, A15's class is `only-pending-ots`, and the spec's
    // zero-headline-eligible sense is satisfied — which is exactly why
    // `list` prints none of the spec's UNANCHORED sentence off the flag.
    assert!(!stale.unanchored);

    assert_eq!(listing.counts().pending_anchor_nags, 3);
    assert_eq!(listing.counts().unanchored, 1);
}

/// A work whose journaled manifest is gone cannot have its artifacts
/// classified at all, and says so rather than guessing a class — both
/// U25 fields go `null` together, and the listing still runs.
#[test]
fn a_work_whose_manifest_record_is_gone_lists_as_unclassified() {
    let vault = anchor_fixture_vault();
    let listing = listing(&vault);
    let row = row_titled(&listing, "artifacts, journaled manifest gone");
    assert_eq!(row.nag, None);
    assert_eq!(row.pending_anchors, None);
    assert!(!row.nags());
    assert_eq!(row.nag_name(), None);
}

/// **U25 accept row 2, the human half**: the nag is a marked block on the
/// row, carrying the count and the exact command that changes the state —
/// against a committed snapshot of the whole report.
#[test]
fn the_nag_appears_in_the_human_report() {
    let vault = anchor_fixture_vault();
    let listing = listing(&vault);
    let rendered = format!("{}\n", listing.render().join("\n"));

    assert!(rendered.contains("ANCHORS PENDING: 3 calendar attestation(s)"));
    assert!(rendered.contains(&format!("run antseal status {} --upgrade", "b2".repeat(32))));
    // The seal killed before `finalize` has no work id for `status` to
    // take, so the hint names the step that comes first instead of
    // printing a command with a hole in it.
    assert!(rendered.contains("no work id yet — finish this seal first"));
    // The UNANCHORED row is labelled and not nagged.
    assert!(rendered.contains("complete UNANCHORED"));

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/list-anchor-nags.txt");
    if std::env::var_os("ANTSEAL_BLESS").is_some() {
        std::fs::write(&path, &rendered).expect("bless");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing committed nag snapshot at {}: {e} (generate with ANTSEAL_BLESS=1)",
            path.display()
        )
    });
    assert!(
        committed == rendered,
        "the `list` nag report drifted from {} — regenerate with ANTSEAL_BLESS=1 and justify \
         the diff\n--- rendered ---\n{rendered}",
        path.display()
    );
}

/// **U25 accept row 2, the machine half**: the class is a structured field
/// on every row, the count rides beside it, and the summary counts the
/// nags separately from the `--no-anchor` works.
#[test]
fn the_nag_is_a_structured_field_in_the_json_document() {
    let vault = anchor_fixture_vault();
    let doc = listing(&vault).json();
    let works = doc["works"].as_array().expect("works array");

    let by_title = |title: &str| -> serde_json::Value {
        works
            .iter()
            .find(|r| r["title"] == serde_json::json!(title))
            .unwrap_or_else(|| panic!("no row titled {title}"))
            .clone()
    };

    let verified = by_title("tsa token, verified");
    assert_eq!(verified["nag"], serde_json::json!("anchored"));
    assert_eq!(verified["pending_anchors"], serde_json::json!(3));

    let pending = by_title("degraded, only pending ots");
    assert_eq!(pending["nag"], serde_json::json!("only-pending-ots"));
    assert_eq!(pending["pending_anchors"], serde_json::json!(3));
    assert_eq!(pending["degraded"], serde_json::json!(true));
    assert_eq!(pending["unanchored"], serde_json::json!(false));

    let unanchored = by_title("sealed with --no-anchor");
    assert_eq!(unanchored["nag"], serde_json::json!("unanchored"));
    assert_eq!(unanchored["pending_anchors"], serde_json::json!(0));
    assert_eq!(unanchored["unanchored"], serde_json::json!(true));

    let stale = by_title("token whose root left the store");
    assert_eq!(stale["nag"], serde_json::json!("only-pending-ots"));

    let unclassified = by_title("artifacts, journaled manifest gone");
    assert!(unclassified["nag"].is_null());
    assert!(unclassified["pending_anchors"].is_null());

    assert_eq!(doc["counts"]["pending_anchor_nags"], serde_json::json!(3));
    assert_eq!(
        doc["counts"]["unanchored"],
        serde_json::json!(1),
        "the nag count and the --no-anchor count are different questions"
    );
}
