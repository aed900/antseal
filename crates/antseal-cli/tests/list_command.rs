//! U19 acceptance suite: `list` over a five-state fixture vault.
//!
//! The fixture is built through the real journal API (S10's state machine
//! and U9's store), never by hand-writing records, so what is rendered is
//! what a real vault would hold at each barrier.
//!
//! NON-SECRET: every `W`, path and title here is a documented fixture.

mod common;

use antseal_anchor::ots::NagState;
use antseal_cli::listing::{NAG_VERIFY_AT_UNIX, ResumeClock, ResumeRefusal, WorkListing, WorkRow};
use antseal_cli::pipeline::journal::{SealJournal, SealState, WorkIdentity};
use antseal_cli::pipeline::{
    AnchorArtifact, ArtifactKind, Barrier, OTS_SLOT, PLAN_ENTRY, Pipeline, SealError, SealFile,
    SealPlan, SealRequest, VaultJournal, tsa_slot,
};
use antseal_cli::status::{StatusContext, WorkStatus};
use antseal_cli::vault::store::{
    ConsentChannel, ConsentRecord, SealShapingFlags, WorkState, WorkStore,
};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::secrets::{MasterSecret, SealId};
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_net::NetworkId;
use antseal_net::test_util::{MockBackend, block_on};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::{IsolatedVault, RecordingGate, ScriptedConsent};

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
                    // **The glob must MATCH one of `paths`, and that is not
                    // cosmetic** (D152 §1.8; U85). It was `*.png` over
                    // `chapter one.txt` / `notes.md` until 2026-08-18 — a
                    // shaping `build_plan` has refused as a zero-match glob
                    // since `442165e` (2026-08-02), so it described no work
                    // that could ever have existed, and it pinned **the one
                    // shape in which `--split` and `--no-fine-tree` cannot
                    // interact**. That is why nothing here went red when
                    // U82/D149 made the pair a hard refusal and `list` began
                    // printing a command `seal` aborts on. Do not change it
                    // back to a glob that matches nothing.
                    no_fine_tree: if f.tag == 0x01 {
                        vec!["*.txt".to_owned()]
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
         --no-fine-tree '*.txt'"
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

/// **D106**: a second antseal is inside `begin()` — its work directory
/// exists, its `meta` record has not landed yet — and `antseal list` still
/// renders this vault.
///
/// Before D106 it did not: `list_works` enumerated the bare directory,
/// `load_meta` refused it, and `gather` returned `CliError::Usage` *"no work
/// with this id exists in the vault (see `antseal list`)"* — the whole vault
/// refused at exit 2, with `--json` emitting an error envelope carrying no
/// `works` array at all, and `list` telling the user to run `list`. Since
/// nothing sweeps the directory, one killed `seal` made the vault
/// permanently unlistable.
///
/// The state is **constructed on disk**, not raced for: `list` is
/// deliberately lock-free (`commands.rs:316-323`), so this is exactly the
/// shape a concurrent `begin` presents, and constructing it is the only way
/// to assert on it deterministically.
#[test]
fn a_work_being_created_right_now_does_not_break_the_listing() {
    let vault = fixture_vault();
    let unlocked = vault.unlock();

    // All-zero, so it sorts first under `list_works`' ascending seal-id
    // order: whatever the fix is, it is met before any fixture work.
    let planted_name = "0".repeat(32);
    std::fs::create_dir_all(unlocked.layout().works_dir().join(&planted_name))
        .expect("plant a mid-`begin` work directory");

    let listing = WorkListing::gather(&WorkStore::new(&unlocked)).expect("gather");
    assert_eq!(listing.works.len(), 5, "every fixture work still lists");
    assert!(
        !listing
            .works
            .iter()
            .any(|row| *row.seal_id.as_bytes() == [0u8; 16]),
        "and the directory that is not yet a work is not a row"
    );

    // Neither surface mentions it — a work under construction is rendered
    // as nothing, not as a row with no work id, title, state or date
    // (D106 R1.4: every column would have to be invented).
    let rendered = listing.render().join("\n");
    assert!(!rendered.contains(&planted_name), "{rendered}");
    assert!(
        !listing.json().to_string().contains(&planted_name),
        "the --json document names it nowhere"
    );
    assert_eq!(listing.json()["counts"]["total"], serde_json::json!(5));
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
    /// A `tsa-1` slot holding bytes the **record codec** refuses (U65).
    ///
    /// Sealed by the real record cipher, so the AEAD opens and the refusal is
    /// a CBOR schema refusal on plaintext — the population D100 §1.5 puts on
    /// the far side of the AEAD boundary. A corrupt-ciphertext fixture would
    /// exercise the other population, which still exits 12 and must.
    damaged: bool,
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
            damaged: false,
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
            damaged: false,
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
            damaged: false,
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
            damaged: false,
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
            damaged: false,
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
            damaged: false,
            consent_offset: 100,
        },
        // **U65**, the defect this fixture exists for: one slot whose record
        // will not decode. Before D100 this one work made `list` refuse the
        // **entire vault** at exit 12 with the passphrase sentence, so the
        // five rows above it could not be rendered at all.
        //
        // It keeps a verified TSA token beside the damaged slot deliberately:
        // the nag class stays `anchored` (R4 — the damage is orthogonal and
        // does not suppress a true statement), so this row also proves the
        // damage is visible on a work that `nag` alone would call clean.
        AnchorFixture {
            tag: 0x17,
            title: "one anchor record that will not decode",
            state: SealState::Complete,
            unanchored: false,
            degraded: false,
            tsa: Some(TSA_PINNED),
            ots: true,
            work_id: Some(0xB7),
            keep_plan: true,
            damaged: true,
            consent_offset: 50,
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
        if f.damaged {
            // Through the store's own writer, so the AEAD is genuine and it
            // is the *record codec* that refuses the plaintext — the arm a
            // corrupt-ciphertext fixture would never reach.
            store
                .put_anchor(
                    &id,
                    &tsa_slot(1),
                    b"not an anchor-artifact record",
                    &mut rng,
                )
                .expect("put damaged anchor");
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
    assert_eq!(listing.works.len(), 7);

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
    //
    // **Q120**: the third answer used to be prose only. The class is
    // asserted above this comment and the flag on the line below it; the
    // clause claiming a third was checked by nothing, so a collapse of the
    // spec's predicate into either of the other two left this comment
    // reading true and the suite green. It is now computed, at the same
    // clock and against the same root store `list` itself used, so the two
    // columns are comparable. The cross-surface *disagreement* matrix lives
    // in `status_command.rs`, the one suite whose vault both surfaces read.
    assert!(!stale.unanchored);
    let spec_unanchored = {
        let unlocked = vault.unlock();
        WorkStatus::gather(
            &WorkStore::new(&unlocked),
            &stale.seal_id,
            StatusContext::new(NAG_VERIFY_AT_UNIX),
        )
        .expect("gather")
        .is_unanchored()
    };
    assert!(
        spec_unanchored,
        "a token that chains to nothing pinned and an un-upgraded .ots are zero \
         headline-eligible anchors between them — MVP-SPEC.md line 137's UNANCHORED, on a \
         row whose `--no-anchor` flag is false"
    );

    assert_eq!(listing.counts().pending_anchor_nags, 3);
    assert_eq!(listing.counts().unanchored, 1);
    assert_eq!(
        listing.counts().damaged_anchors,
        1,
        "a fourth orthogonal predicate, counted in works like the two above it"
    );
}

/// **U65, the defect, closed** (D100 R3): one anchor record that will not
/// decode is a datum on its own row, and the rest of the vault still lists.
///
/// The before is what makes this row worth reading: this exact vault used to
/// produce **no rows at all** and `error: vault authentication failed: wrong
/// passphrase, or the vault store or header has been modified or corrupted`
/// at exit 12 — for a CBOR schema refusal on plaintext the AEAD had already
/// accepted, on a work whose other anchors were fine.
#[test]
fn one_undecodable_anchor_record_is_a_row_and_not_a_refusal() {
    let vault = anchor_fixture_vault();
    let listing = listing(&vault);

    // 1. The whole vault still lists. This is the clause of U65's Accept that
    //    option (a) — a better sentence on the same total refusal — would not
    //    have satisfied, and it is the one the register calls the defect.
    assert_eq!(listing.works.len(), 7);
    assert!(
        listing
            .works
            .iter()
            .any(|row| row.title.as_deref() == Some("tsa token, verified")),
        "the works behind the damaged one are the point"
    );

    let row = row_titled(&listing, "one anchor record that will not decode");

    // 2. The damage is on the row, per slot, with a machine-branchable
    //    reason and the decoder's own message verbatim (R1, R10.5).
    assert_eq!(row.damaged_anchors.slots.len(), 1);
    let damaged = &row.damaged_anchors.slots[0];
    assert_eq!(damaged.slot, tsa_slot(1));
    assert_eq!(damaged.reason.name(), "undecodable");
    assert_eq!(
        damaged.reason.detail(),
        "journal record is not canonical CBOR"
    );
    assert_eq!(damaged.reason.format_version(), None);

    // 3. …and it says *how much*, which is the whole reason per-record
    //    isolation beat a per-work badge (D100 §2(b)): three slots, one bad.
    assert_eq!(row.damaged_anchors.total_slots, 3);

    // 4. The nag class is **orthogonal** and is not suppressed (R4). This
    //    work does hold a headline-eligible anchor, so `anchored` is true —
    //    and a consumer branching on `nag` alone would call it clean, which
    //    is exactly why the damage is its own column and not a fourth
    //    meaning of `null`.
    assert_eq!(row.nag, Some(NagState::Anchored));
    assert!(!row.nags());
    assert_eq!(row.nag_name(), Some("anchored"));

    // 5. Every healthy row carries an **empty** array rather than an absent
    //    one — the honesty guarantee, because a key that only appeared on
    //    damage would leave a damaged work looking exactly like a clean one.
    let clean = row_titled(&listing, "degraded, only pending ots");
    assert!(clean.damaged_anchors.is_intact());
    assert_eq!(clean.damaged_anchors.total_slots, 1);
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
    // **U65/D100 R3**: the damage block, and the summary's third clause.
    assert!(rendered.contains(&format!(
        "  anchors: 1 of 3 slot(s) unreadable — {}: journal record is not canonical CBOR",
        tsa_slot(1)
    )));
    assert!(rendered.contains("1 with unreadable anchors"));

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
    assert_eq!(
        unclassified["damaged_anchors"],
        serde_json::json!([]),
        "unclassifiable and damaged are two facts; this row has the first and not the second"
    );

    // **U65/D100 R3/R9**: the four keys, all present, and the count a CI job
    // tests instead of an exit code.
    let damaged = by_title("one anchor record that will not decode");
    assert_eq!(
        damaged["damaged_anchors"],
        serde_json::json!([{
            "slot": tsa_slot(1),
            "reason": "undecodable",
            "detail": "journal record is not canonical CBOR",
            "format_version": null,
        }])
    );
    assert_eq!(
        damaged["nag"],
        serde_json::json!("anchored"),
        "the nag is orthogonal and is not suppressed by the damage (R4)"
    );
    assert_eq!(doc["counts"]["damaged_anchors"], serde_json::json!(1));

    assert_eq!(doc["counts"]["pending_anchor_nags"], serde_json::json!(3));
    assert_eq!(
        doc["counts"]["unanchored"],
        serde_json::json!(1),
        "the nag count and the --no-anchor count are different questions"
    );
}

// ─────────────────────────────────────────────────────────────────────
// U85 (ruled by D152): `list` must not print a command `seal` refuses
//
// U82/D149 made `--split blank-lines` × a matching `--no-fine-tree` glob a
// hard refusal in `build_plan` (`invalid-seal-argument`, exit 27) for any
// non-empty **text** file. D45 makes the recorded flag set a work's identity
// and there is no `--resume` subcommand — re-running `seal` *is* the resume
// — so a work sealed before that change with such a file cannot be finished
// through the documented route, and `list` was printing the failing command
// as an instruction.
//
// Every work below is built through the **pipeline**, killed at
// `PostStagingJournal`, because that barrier's contract is *"every staged
// blob and the plan record are durable"* — which is the production shape of
// a stranded work, manifest and all. Such a work can no longer be created
// through `seal` at all, which is the whole premise of the row.
//
// NON-SECRET: every byte string and path below is a documented fixture.
// ─────────────────────────────────────────────────────────────────────

/// One file in a constructed legacy work: its bytes, and whether the work's
/// recorded glob matched it.
struct Shaped {
    name: &'static str,
    bytes: &'static [u8],
    /// Whether a recorded `--no-fine-tree` glob caught this file — i.e.
    /// what `build_plan:220-228` would have set on its `PlannedFile`.
    matched: bool,
    force_text: bool,
}

/// Text whose raw and canonical renditions are equal: no raw mirror.
const PROSE: &[u8] = b"alpha one\n\nbeta two\n";
/// Binary — D24 §1's G6 exemption, and the flag pair's *designed* use.
const OPAQUE: &[u8] = &[0xFF; 40];
/// The lone-BOM class: valid UTF-8, raw 3 bytes, **canonical 0** — so its
/// descriptor carries `fine_tree_present = false` with no glob involved.
const LONE_BOM: &[u8] = "\u{FEFF}".as_bytes();

/// Seal `files` into a fresh vault and kill the seal after the plan record
/// is journaled, leaving the work `Staged` with a real manifest.
fn staged_vault(tag: &str, glob: &str, files: &[Shaped]) -> IsolatedVault {
    let vault = IsolatedVault::create(tag);
    seal_into(&vault, 0, "legacy work", glob, "/w", files);
    vault
}

/// One staged work, into an existing vault.
///
/// `nth` seeds both RNGs: a fixed journal seed would draw the **same**
/// `seal_id` for every work and the second `begin` would collide, so the
/// index is load-bearing rather than tidy.
fn seal_into(
    vault: &IsolatedVault,
    nth: u8,
    title: &str,
    glob: &str,
    root: &str,
    files: &[Shaped],
) {
    {
        let unlocked = vault.unlock();
        let mock = MockBackend::new();
        let gate = RecordingGate::new();
        let consent = ScriptedConsent::always_yes();
        let kill = common::KillAt::new(Barrier::PostStagingJournal);
        let mut journal_rng = ChaCha20Rng::from_seed([0x85 ^ nth; 32]);
        let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut journal_rng);

        let absolutes: Vec<String> = files.iter().map(|f| format!("{root}/{}", f.name)).collect();
        let seal_files: Vec<SealFile<'_>> = files
            .iter()
            .enumerate()
            .map(|(i, f)| SealFile {
                path_as_given: f.name,
                path_absolute: &absolutes[i],
                bytes: f.bytes,
                // Exactly what `base_flags` + the glob pass would have
                // produced: `--split` on every file unconditionally, the
                // opt-out on the ones the glob caught.
                flags: {
                    let mut flags = FileFlags::new().with_split(SplitMode::BlankLines);
                    if f.matched {
                        flags = flags.with_no_fine_tree();
                    }
                    if f.force_text {
                        flags = flags.with_force_text();
                    }
                    flags
                },
            })
            .collect();
        let request = SealRequest {
            files: &seal_files,
            title: title.to_owned(),
            claimed_time_unix_secs: BASE_TIME,
            app_version: "antseal-test/1".to_owned(),
            network: NetworkId::Devnet,
            no_anchor: false,
            degraded: false,
            dry_run: false,
            sig_policy: SigPolicy::hybrid(),
            shaping: SealShapingFlags {
                title: Some(title.to_owned()),
                split_blank_lines: true,
                force_text: files.iter().any(|f| f.force_text),
                no_fine_tree: vec![glob.to_owned()],
                no_anchor: false,
                force_degraded: false,
            },
        };
        let pipeline = Pipeline::new(&mock, &gate, &journal, &consent, &kill);
        match block_on(pipeline.seal(&request, &mut ChaCha20Rng::from_seed([0x86 ^ nth; 32]))) {
            Err(SealError::KilledAtBarrier(Barrier::PostStagingJournal)) => {}
            other => panic!("the fixture must land staged, not {other:?}"),
        }
        assert_eq!(mock.call_log().len(), 0, "no backend call before the kill");
    }
}

/// The one work in a fixture vault built by [`staged_vault`].
fn only_row(listing: &WorkListing) -> &WorkRow {
    assert_eq!(listing.works.len(), 1, "these fixtures hold one work");
    &listing.works[0]
}

/// The `resume` object of a row, as `--json` renders it, selected by title.
fn resume_json(listing: &WorkListing, title: Option<&str>) -> serde_json::Value {
    let doc = listing.json();
    let works = doc["works"].as_array().expect("works array").clone();
    let row = match title {
        None => {
            assert_eq!(works.len(), 1, "expected a single-work vault");
            works[0].clone()
        }
        Some(title) => works
            .into_iter()
            .find(|w| w["title"] == serde_json::json!(title))
            .expect("that work is in the document"),
    };
    row["resume"].clone()
}

/// The rendered lines belonging to the single work in a listing.
fn rendered(listing: &WorkListing) -> String {
    listing.render().join("\n")
}

// ── T1 ───────────────────────────────────────────────────────────────

/// **U85 accept 1 (D152 §2 R9 T1).** A stored shaping `build_plan` would
/// refuse does not yield a bare hint: the row names the refusal, the money,
/// the one route that works, and demotes the recorded command to a record.
#[test]
fn a_blocked_work_names_the_refusal_and_a_workaround_that_runs() {
    let vault = staged_vault(
        "u85-blocked",
        "*.txt",
        &[Shaped {
            name: "chapter one.txt",
            bytes: PROSE,
            matched: true,
            force_text: false,
        }],
    );
    let listing = listing(&vault);
    let row = only_row(&listing);
    assert_eq!(row.state, WorkState::IncompletePrePay);
    assert!(
        matches!(
            row.resume_refusal,
            Some(ResumeRefusal::SplitOnNoFineTree { .. })
        ),
        "the recorded shaping is one `build_plan` refuses: {:?}",
        row.resume_refusal
    );

    let text = rendered(&listing);
    for needle in [
        "  CANNOT BE FINISHED: chapter one.txt was selected for splitting by --split blank-lines \
         and is also matched by --no-fine-tree '*.txt', and antseal refuses that pair (D24). D45 \
         makes the recorded flags this work's identity, so no re-run can change them.",
        "  nothing was paid, so only the local staged copy is lost. To seal this material, move \
         or copy the file(s) to a different path and seal them there with either --split or \
         --no-fine-tree dropped: re-running the recorded command is refused, and re-running the \
         same paths with different flags is refused too. This build has no command that discards \
         a staged work.",
        "  recorded invocation, refused — do not re-run: antseal seal 'chapter one.txt' --title \
         'legacy work' --split blank-lines --no-fine-tree '*.txt' --network devnet",
    ] {
        assert!(
            text.contains(needle),
            "the blocked row must carry, verbatim:\n{needle}\n--- rendered ---\n{text}"
        );
    }

    // The two things it must NOT say: the hint as an instruction, and the
    // clock note that tells a paid user to hurry up and do the impossible.
    assert!(
        !text.contains("resume with:"),
        "a command that aborts must not be printed as an instruction:\n{text}"
    );
    assert!(
        !text.contains("the recorded quote is stale by design"),
        "the clock note is replaced, not merely preceded (D152 §3.2):\n{text}"
    );

    // And the machine document says the same thing in its own vocabulary.
    assert_eq!(
        resume_json(&listing, None)["refusal"],
        serde_json::json!({
            "rule": "split-x-no-fine-tree",
            "files": ["chapter one.txt"],
            "patterns": ["*.txt"],
        })
    );
}

/// **U85 (D152 §2 R5).** The money clause takes `ResumeClock`'s own two-way
/// split, and the post-pay half is the one that matters: `RESUME PROMPTLY …
/// finishing it costs a second payment` is an instruction to do the
/// impossible, on a deadline, about money that is already gone.
#[test]
fn a_blocked_post_pay_work_says_the_payment_cannot_be_recovered() {
    let vault = staged_vault(
        "u85-blocked-paid",
        "*.txt",
        &[Shaped {
            name: "chapter one.txt",
            bytes: PROSE,
            matched: true,
            force_text: false,
        }],
    );
    // Walk the same work forward to PAID, exactly as `fixture_vault` does.
    {
        let unlocked = vault.unlock();
        let store = WorkStore::new(&unlocked);
        let id = store.list_works().expect("list")[0];
        let mut rng = ChaCha20Rng::from_seed([0x87; 32]);
        let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);
        for step in [SealState::Anchored, SealState::Paid] {
            journal.set_state(&id, step).expect("advance");
        }
        journal
            .put_consent(
                &id,
                ConsentRecord {
                    total_ant_atto: 9,
                    gas_estimate_wei: 21_000,
                    consent_time_unix_secs: BASE_TIME,
                    channel: ConsentChannel::YesFlag,
                },
            )
            .expect("consent");
    }
    let listing = listing(&vault);
    let row = only_row(&listing);
    assert_eq!(row.state, WorkState::IncompletePostPay);

    let text = rendered(&listing);
    assert!(
        text.contains(
            "  this seal is paid for and the payment cannot be recovered. To seal this \
                       material, move or copy the file(s) to a different path"
        ),
        "the post-pay money clause, verbatim:\n{text}"
    );
    assert!(
        !text.contains("RESUME PROMPTLY"),
        "a work that cannot be finished must not be told to hurry:\n{text}"
    );
}

// ── T2: the false-positive control ───────────────────────────────────

/// **U85 accept (D152 §2 R9 T2).** A work carrying **both flags
/// legitimately** — a binary opted out beside split prose — still prints
/// `resume with:` and its clock note, and its `refusal` is `null`.
///
/// This is the test that kills the cheap `split && !no_fine_tree.is_empty()`
/// trigger. That trigger's false positives are not exotic: they are the flag
/// pair's *designed* use (D24 §1's G6 exemption), they are creatable at HEAD
/// today, and firing on one would tell the owner of a **recoverable**
/// payment that it is lost — inside the one-day window in which it still is.
#[test]
fn the_flag_pair_alone_does_not_block_a_work() {
    let vault = staged_vault(
        "u85-ordinary",
        "*.dat",
        &[
            Shaped {
                name: "chapter one.txt",
                bytes: PROSE,
                matched: false,
                force_text: false,
            },
            Shaped {
                name: "photo.dat",
                bytes: OPAQUE,
                matched: true,
                force_text: false,
            },
        ],
    );
    let listing = listing(&vault);
    let row = only_row(&listing);
    assert!(
        row.resume_refusal.is_none(),
        "the pair over a BINARY file is legal, seals today and resumes today: {:?}",
        row.resume_refusal
    );

    let text = rendered(&listing);
    assert!(
        text.contains(
            "  resume with: antseal seal 'chapter one.txt' photo.dat --title 'legacy work' \
             --split blank-lines --no-fine-tree '*.dat' --network devnet"
        ),
        "the ordinary path is untouched:\n{text}"
    );
    assert!(text.contains("nothing was paid; the recorded quote is stale by design"));
    assert!(!text.contains("CANNOT BE FINISHED"), "{text}");
    assert_eq!(
        resume_json(&listing, None)["refusal"],
        serde_json::Value::Null
    );
}

// ── T8: multi-file, one offender ─────────────────────────────────────

/// **U85 (D152 §2 R9 T8).** Every offending file is named and only the
/// offending files are — D46's *"every offending argument named"*, the rule
/// `refuse_split_on_no_fine_tree` follows for the same refusal.
#[test]
fn only_the_refused_file_is_named_not_every_matched_one() {
    let vault = staged_vault(
        "u85-three",
        "*.dat",
        &[
            // Text, NOT matched: keeps its fine tree, so the pair never
            // touches it.
            Shaped {
                name: "unmatched.txt",
                bytes: PROSE,
                matched: false,
                force_text: false,
            },
            // Binary, matched: matched but not refused (G6).
            Shaped {
                name: "opaque.dat",
                bytes: OPAQUE,
                matched: true,
                force_text: false,
            },
            // Text, matched: the only offender.
            Shaped {
                name: "prose.dat",
                bytes: PROSE,
                matched: true,
                force_text: false,
            },
        ],
    );
    let listing = listing(&vault);
    let row = only_row(&listing);
    let Some(ResumeRefusal::SplitOnNoFineTree { files, patterns }) = &row.resume_refusal else {
        panic!("expected a refusal, got {:?}", row.resume_refusal);
    };
    assert_eq!(files, &vec!["prose.dat".to_owned()], "one offender, named");
    assert_eq!(patterns, &vec!["*.dat".to_owned()]);

    let text = rendered(&listing);
    assert!(
        text.contains("CANNOT BE FINISHED: prose.dat was selected"),
        "{text}"
    );
    assert!(
        !text.contains("CANNOT BE FINISHED: unmatched.txt")
            && !text.contains("opaque.dat was selected")
            && !text.contains("unmatched.txt, ")
            && !text.contains(", opaque.dat"),
        "a file that is not refused must not appear in the refusal:\n{text}"
    );
}

// ── T3 and T7: the third value, and the gate that keeps it cheap ──────

/// A vault of works that never reached `put_plan` — `journal.begin` and
/// nothing else, which is `SealState::Staged` with **no manifest**.
///
/// Work `0xB1` carries the flag pair, `0xB2` and `0xB3` do not. That is the
/// whole population T7 counts over, and it is the same fixture T3 reads.
fn no_manifest_vault() -> IsolatedVault {
    let vault = IsolatedVault::create("u85-no-manifest");
    let unlocked = vault.unlock();
    let mut rng = ChaCha20Rng::from_seed([0x88; 32]);
    let journal = VaultJournal::new(WorkStore::new(&unlocked), &mut rng);
    for (tag, paired) in [(0xB1_u8, true), (0xB2, false), (0xB3, false)] {
        let w = MasterSecret::from_bytes([tag; 32]);
        journal
            .begin(&WorkIdentity {
                w: w.secret_ref(),
                seal_id: seal_id(tag),
                network: "devnet".to_owned(),
                unanchored: false,
                degraded: false,
                input_paths_as_given: vec!["draft.txt".to_owned()],
                input_paths_absolute: vec!["/w/draft.txt".to_owned()],
                shaping: SealShapingFlags {
                    title: Some(format!("work {tag:#04x}")),
                    split_blank_lines: paired,
                    force_text: false,
                    no_fine_tree: if paired {
                        vec!["*.txt".to_owned()]
                    } else {
                        Vec::new()
                    },
                    no_anchor: false,
                    force_degraded: false,
                },
            })
            .expect("begin");
    }
    vault
}

/// **U85 (D152 §2 R9 T3).** A work that was killed before `put_plan` has no
/// manifest, so there is **no verdict** — the third value. Its human row is
/// byte-identical to what it rendered before this row, because the branch
/// carries no money: `put_plan` (`pipeline/seal.rs:351`) runs before
/// `quote_batch` (`:372`), so a work with no journaled manifest was never
/// quoted, consented to or paid for.
#[test]
fn a_work_with_no_manifest_gets_no_verdict_and_renders_as_before() {
    let vault = no_manifest_vault();
    let listing = listing(&vault);
    let row = listing
        .works
        .iter()
        .find(|r| r.seal_id == seal_id(0xB1))
        .expect("the flag-pair work");
    assert_eq!(row.resume_refusal, Some(ResumeRefusal::Undetermined));

    let text = rendered(&listing);
    assert!(
        !text.contains("CANNOT BE FINISHED"),
        "no verdict is not a verdict:\n{text}"
    );
    assert!(
        text.contains(
            "  resume with: antseal seal draft.txt --title 'work 0xb1' --split blank-lines \
             --no-fine-tree '*.txt' --network devnet"
        ),
        "the ordinary hint, unchanged:\n{text}"
    );
    assert!(
        text.contains("nothing was paid; the recorded quote is stale by design"),
        "{text}"
    );

    assert_eq!(
        resume_json(&listing, Some("work 0xb1"))["refusal"],
        serde_json::json!({ "rule": "undetermined" })
    );
}

/// **U85 accept (D152 §2 R9 T7).** The cheap gate is load-bearing, and this
/// counts rather than argues it.
///
/// `Undetermined` is *only* reachable through the plan read, so a work whose
/// shaping lacks the flag pair and whose row reads `null` is a work whose
/// plan record was **not** read. The count is over the whole population, and
/// the anti-vacuity arm is built in: the same vault holds one work that
/// *does* carry the pair, so `Undetermined` is demonstrably reachable and
/// `0 of 2` is not a value the fixture could not produce.
#[test]
fn only_the_flag_pair_pays_for_a_plan_read() {
    let vault = no_manifest_vault();
    let listing = listing(&vault);

    let read: Vec<&WorkRow> = listing
        .works
        .iter()
        .filter(|r| r.resume_refusal.is_some())
        .collect();
    let unread: Vec<&WorkRow> = listing
        .works
        .iter()
        .filter(|r| r.resume.is_some() && r.resume_refusal.is_none())
        .collect();

    assert_eq!(listing.works.len(), 3, "the whole population");
    assert_eq!(
        unread.len(),
        2,
        "two ordinary incomplete works, and neither may cost a plan read"
    );
    assert_eq!(read.len(), 1, "exactly the work carrying both flags");
    assert_eq!(read[0].seal_id, seal_id(0xB1));
    // Anti-vacuity: the value the two `None`s are being distinguished from
    // is one this very fixture produces, so `None` here means "not read"
    // rather than "unreachable".
    assert_eq!(read[0].resume_refusal, Some(ResumeRefusal::Undetermined));
}

// ── T5 and T6: the doors, and the differential ───────────────────────

/// A scratch directory holding the real files `build_plan` opens, removed
/// when the test ends.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "antseal-u85-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("mk scratch");
        Self(path)
    }

    /// Plant `files` on disk and return the directory as a `str`.
    fn plant(&self, files: &[Shaped]) -> &str {
        for f in files {
            std::fs::write(self.0.join(f.name), f.bytes).expect("plant");
        }
        self.0.to_str().expect("utf-8 scratch path")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `build_plan` over `files` in `scratch`, reduced to D24 §1's verdict.
fn build_plan_refuses(scratch: &Scratch, glob: &str, force_text: bool, files: &[Shaped]) -> bool {
    let args = antseal_cli::cli::SealArgs {
        paths: files.iter().map(|f| f.name.into()).collect(),
        title: None,
        split: Some(antseal_cli::cli::SplitMode::BlankLines),
        force_text,
        no_fine_tree: Some(glob.to_owned()),
        dry_run: false,
        yes: false,
        force_degraded: false,
        no_anchor: false,
    };
    match antseal_cli::seal_plan::build_plan(&args, NetworkId::Devnet, &scratch.0) {
        Ok(_) => false,
        Err(antseal_cli::error::CliError::InvalidSealArgument { .. }) => true,
        Err(other) => panic!("neither verdict: {other}"),
    }
}

/// **U85 (D152 §2 R9 T5).** The three doors out of a stranded work, driven
/// on one constructed work — and every one of them is shut.
///
/// This is what R5's copy asserts, pinned as fact rather than as prose:
/// re-running the recorded command is **27**, the same paths with a flag
/// dropped is **26**, and an overlapping subset is **25**. Doors 2 and 3
/// each send the user back to the command door 1 refuses, which is why
/// `list` is the venue that has to break the cycle — and why the copy never
/// says *drop a flag* or *seal it separately* without *at a different path*.
#[test]
fn all_three_doors_out_of_a_stranded_work_are_shut() {
    let files = [
        Shaped {
            name: "chapter one.txt",
            bytes: PROSE,
            matched: true,
            force_text: false,
        },
        Shaped {
            name: "notes.md",
            bytes: PROSE,
            matched: false,
            force_text: false,
        },
    ];
    let scratch = Scratch::new("doors");
    let root = scratch.plant(&files);
    let vault = IsolatedVault::create("u85-doors");
    seal_into(&vault, 0, "legacy work", "*.txt", root, &files);

    let absolute: Vec<String> = files.iter().map(|f| format!("{root}/{}", f.name)).collect();
    let recorded = SealShapingFlags {
        title: Some("legacy work".to_owned()),
        split_blank_lines: true,
        force_text: false,
        no_fine_tree: vec!["*.txt".to_owned()],
        no_anchor: false,
        force_degraded: false,
    };

    // Door 1 — re-run the printed command. `build_plan` refuses it before
    // the vault is even opened, so this needs no unlock.
    let door_one = antseal_cli::seal_plan::build_plan(
        &antseal_cli::cli::SealArgs {
            paths: files.iter().map(|f| f.name.into()).collect(),
            title: Some("legacy work".to_owned()),
            split: Some(antseal_cli::cli::SplitMode::BlankLines),
            force_text: false,
            no_fine_tree: Some("*.txt".to_owned()),
            dry_run: false,
            yes: false,
            force_degraded: false,
            no_anchor: false,
        },
        NetworkId::Devnet,
        &scratch.0,
    )
    .expect_err("the recorded command is refused");
    assert_eq!(door_one.class().name(), "invalid-seal-argument");
    assert_eq!(door_one.class().exit_code(), 27);

    let unlocked = vault.unlock();
    let store = WorkStore::new(&unlocked);

    // Door 2 — the same paths with `--split` dropped.
    let door_two = antseal_cli::seal_resume::detect(
        &store,
        NetworkId::Devnet,
        &absolute,
        &SealShapingFlags {
            split_blank_lines: false,
            ..recorded.clone()
        },
    )
    .expect_err("a flag-set mismatch on an exact path match");
    assert_eq!(door_two.class().name(), "resume-flag-mismatch");
    assert_eq!(door_two.class().exit_code(), 26);
    assert!(
        door_two.to_string().contains("--split blank-lines"),
        "and its detail reprints the very command door 1 refuses: {door_two}"
    );

    // Door 3 — an overlapping, non-exact path set.
    let door_three =
        antseal_cli::seal_resume::detect(&store, NetworkId::Devnet, &absolute[..1], &recorded)
            .expect_err("an overlapping subset");
    assert_eq!(door_three.class().name(), "resume-overlap-not-exact");
    assert_eq!(door_three.class().exit_code(), 25);
    assert!(
        door_three.to_string().contains("--no-fine-tree '*.txt'"),
        "and it too points back at the refused command: {door_three}"
    );

    // The one route that runs: a path set disjoint from every candidate.
    let elsewhere = vec![format!("{root}/copy/chapter one.txt")];
    assert!(
        antseal_cli::seal_resume::detect(&store, NetworkId::Devnet, &elsewhere, &recorded).is_ok(),
        "moving the files to a different path is the escape R5 names"
    );
}

/// **U85 (D152 §2 R9 T6).** `list`'s verdict and `build_plan`'s verdict are
/// the same rule read from two different media, over a matrix that makes
/// each term the deciding one somewhere.
///
/// Sharing the predicate (R3) cannot cover this: what is being tested is
/// that the *manifest* answers the same question the *filesystem* does, and
/// only driving both sides over the same bytes can show it.
///
/// Row (f) is the lone-BOM class, and it is why this suite's manifest side
/// carries a `pattern_matches` conjunct that D152 §2 R2 step 3 does not:
/// `describe_file` is handed the **canonical** byte count, so a file whose
/// raw bytes are a BOM alone has `fine_tree_present == false` with no glob
/// involved, while its raw-mirror length is 3. Read as D152 §1.6 states it,
/// `list` would call that work blocked and `build_plan` would accept the
/// re-run — the false-positive direction §1.5 refuses the cheap trigger for.
#[test]
fn the_manifest_verdict_agrees_with_build_plan_on_every_shape() {
    struct Row {
        title: &'static str,
        glob: &'static str,
        force_text: bool,
        files: Vec<Shaped>,
    }
    let matrix = vec![
        Row {
            title: "a: non-empty text, matched",
            glob: "*.txt",
            force_text: false,
            files: vec![Shaped {
                name: "a.txt",
                bytes: PROSE,
                matched: true,
                force_text: false,
            }],
        },
        Row {
            title: "b: binary, matched",
            glob: "*.dat",
            force_text: false,
            files: vec![Shaped {
                name: "b.dat",
                bytes: OPAQUE,
                matched: true,
                force_text: false,
            }],
        },
        Row {
            title: "c: empty file, matched",
            glob: "*.txt",
            force_text: false,
            files: vec![Shaped {
                name: "c.txt",
                bytes: b"",
                matched: true,
                force_text: false,
            }],
        },
        Row {
            title: "d: text NOT matched, beside a matched binary",
            glob: "*.dat",
            force_text: false,
            files: vec![
                Shaped {
                    name: "d.txt",
                    bytes: PROSE,
                    matched: false,
                    force_text: false,
                },
                Shaped {
                    name: "d.dat",
                    bytes: OPAQUE,
                    matched: true,
                    force_text: false,
                },
            ],
        },
        Row {
            title: "e: --force-text over the matched binary",
            glob: "*.dat",
            force_text: true,
            files: vec![Shaped {
                name: "e.dat",
                bytes: OPAQUE,
                matched: true,
                force_text: true,
            }],
        },
        Row {
            title: "f: lone BOM, NOT matched, beside a matched binary",
            glob: "*.dat",
            force_text: false,
            files: vec![
                Shaped {
                    name: "bom.txt",
                    bytes: LONE_BOM,
                    matched: false,
                    force_text: false,
                },
                Shaped {
                    name: "f.dat",
                    bytes: OPAQUE,
                    matched: true,
                    force_text: false,
                },
            ],
        },
        // (g) is (f)'s mirror image and pins the other half of the class:
        // matched, `build_plan` over-refuses it (raw 3 > 0 and the bytes are
        // valid UTF-8 — D149 §6), and `list` must AGREE with that
        // over-refusal rather than quietly correct it. It is the row that
        // makes the raw-mirror byte count load-bearing: `size()` alone is
        // the **canonical** count, which is 0 here.
        Row {
            title: "g: lone BOM, matched",
            glob: "*.txt",
            force_text: false,
            files: vec![Shaped {
                name: "bom2.txt",
                bytes: LONE_BOM,
                matched: true,
                force_text: false,
            }],
        },
    ];

    let vault = IsolatedVault::create("u85-differential");
    let mut plan_side = Vec::new();
    for (nth, row) in matrix.iter().enumerate() {
        let scratch = Scratch::new(&format!("diff{nth}"));
        let root = scratch.plant(&row.files);
        seal_into(
            &vault,
            u8::try_from(nth).expect("small matrix"),
            row.title,
            row.glob,
            root,
            &row.files,
        );
        plan_side.push(build_plan_refuses(
            &scratch,
            row.glob,
            row.force_text,
            &row.files,
        ));
    }

    let listing = listing(&vault);
    assert_eq!(listing.works.len(), matrix.len(), "one work per matrix row");
    let mut list_side = Vec::new();
    for row in &matrix {
        let work = listing
            .works
            .iter()
            .find(|w| w.title.as_deref() == Some(row.title))
            .unwrap_or_else(|| panic!("row {} is in the vault", row.title));
        list_side.push(matches!(
            work.resume_refusal,
            Some(ResumeRefusal::SplitOnNoFineTree { .. })
        ));
        assert_ne!(
            work.resume_refusal,
            Some(ResumeRefusal::Undetermined),
            "row {}: every work here has a journaled manifest",
            row.title
        );
    }

    for (index, row) in matrix.iter().enumerate() {
        assert_eq!(
            list_side[index], plan_side[index],
            "row {}: `list` says {}, `build_plan` says {}",
            row.title, list_side[index], plan_side[index]
        );
    }
    // Anti-vacuity: agreement over an all-false matrix is `assert_eq!(x, x)`.
    assert!(
        plan_side.contains(&true) && plan_side.contains(&false),
        "the matrix must exercise both verdicts, not one: {plan_side:?}"
    );
    assert!(
        list_side.contains(&true) && list_side.contains(&false),
        "and so must the manifest side: {list_side:?}"
    );
}
