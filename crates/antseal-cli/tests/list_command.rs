//! U19 acceptance suite: `list` over a five-state fixture vault.
//!
//! The fixture is built through the real journal API (S10's state machine
//! and U9's store), never by hand-writing records, so what is rendered is
//! what a real vault would hold at each barrier.
//!
//! NON-SECRET: every `W`, path and title here is a documented fixture.

mod common;

use antseal_cli::listing::{ResumeClock, WorkListing};
use antseal_cli::pipeline::VaultJournal;
use antseal_cli::pipeline::journal::{SealJournal, SealState, WorkIdentity};
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
/// counts, and U25's reserved `pending_anchors` slot — and amounts ride
/// as exact decimal strings, because atto-ANT does not survive a JSON
/// number in most consumers.
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
        ] {
            assert!(row.get(key).is_some(), "row is missing {key}: {row}");
        }
        assert!(
            row["pending_anchors"].is_null(),
            "U25's slot stays reserved at M1"
        );
    }

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
