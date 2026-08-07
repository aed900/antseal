//! U23's in-crate rows: the two invariants D98 states as permanently true of
//! this renderer, the claimed/verified boundary, the receipt rule, and the
//! three-way UNANCHORED ambiguity.
//!
//! The vault-backed fixtures, the committed snapshot and the `--upgrade`
//! transition live in `tests/status_command.rs`; these are the rows that need
//! no vault and therefore no Argon2id derivation to run.
//!
//! NON-SECRET: every digest, seal id and artifact here is a synthetic
//! fixture.

use antseal_core::anchor::testing::ots_writer;

use super::*;

/// A pinned verification time inside `MockTsaConfig`'s default validity
/// window, matching the literals the rest of this crate's suites use.
const VERIFY_AT: u64 = 1_800_000_000;

fn ctx() -> StatusContext {
    StatusContext::new(VERIFY_AT)
}

fn ots(
    bytes: Vec<u8>,
    upgrade: Option<antseal_core::bundle::schema::OtsUpgrade>,
) -> AnchorArtifact {
    AnchorArtifact {
        kind: ArtifactKind::OtsPending,
        endpoint: String::new(),
        fetch_date: 1_785_000_000,
        bytes,
        upgrade,
    }
}

/// Every `.ots` shape this renderer can be handed, paired with the digest it
/// was stamped over — the population the "never `proven`" invariant is
/// existential over.
fn every_ots_shape() -> Vec<(&'static str, [u8; 32], AnchorArtifact)> {
    let pending_digest = ots_writer::synthetic_digest(0x11);
    let unknown_digest = ots_writer::synthetic_digest(0x22);
    let bare_digest = ots_writer::synthetic_digest(0x33);
    let (committed_digest, committed_bytes, committed_upgrade) =
        ots_writer::committed_single_branch(0x44, ots_writer::ATTESTED_HEIGHT);

    vec![
        (
            "pending",
            pending_digest,
            ots(
                ots_writer::container(
                    &pending_digest,
                    &ots_writer::pending("https://calendar.example/alice"),
                ),
                None,
            ),
        ),
        (
            "an upgraded artifact whose ops commit its embedded header",
            committed_digest,
            ots(committed_bytes, Some(committed_upgrade)),
        ),
        (
            "an attestation type this verifier does not implement",
            unknown_digest,
            ots(
                ots_writer::container(&unknown_digest, &ots_writer::unknown()),
                None,
            ),
        ),
        (
            "a Bitcoin branch with no recorded upgrade group",
            bare_digest,
            ots(
                ots_writer::container(&bare_digest, &ots_writer::bitcoin(700_000)),
                None,
            ),
        ),
        (
            "bytes that are not an `.ots` file at all",
            bare_digest,
            ots(b"not an ots file".to_vec(), None),
        ),
        (
            "a well-formed artifact under the wrong digest",
            ots_writer::synthetic_digest(0x55),
            ots(
                ots_writer::container(
                    &pending_digest,
                    &ots_writer::pending("https://calendar.example/alice"),
                ),
                None,
            ),
        ),
    ]
}

/// **D98's first permanent statement**: an OTS anchor is never `proven` in
/// `status`.
///
/// Not a habit but a property: rule O3 needs an *online* block header, and
/// this renderer hands the evaluator [`BlockEvidence::new`] by construction.
/// Asserted over every `.ots` shape reachable from a vault record, including
/// the one whose ops genuinely do commit its embedded header — the shape that
/// renders `attested` here and that `verify --online` may promote.
///
/// What makes it fail: passing anything but empty block evidence to
/// `evaluate_ots_artifact`.
#[test]
fn an_ots_anchor_is_never_proven_in_status() {
    let mut seen = Vec::new();
    for (label, digest, artifact) in every_ots_shape() {
        let verdict = evaluate(&artifact, &digest, ctx());
        assert_ne!(
            verdict.state(),
            AnchorState::Proven,
            "{label}: `status` is offline, so no `.ots` may reach `proven`"
        );
        assert!(
            !verdict.is_headline_eligible(),
            "{label}: an offline OTS anchor can never carry the headline time"
        );
        seen.push(verdict.state());
    }
    // Anti-vacuity: the population must actually span the states, or the
    // assertion above is a claim about six copies of one shape.
    assert!(seen.contains(&AnchorState::Pending), "{seen:?}");
    assert!(seen.contains(&AnchorState::Attested), "{seen:?}");
    assert!(
        seen.contains(&AnchorState::InternallyConsistentOnly),
        "{seen:?}"
    );
    assert!(seen.contains(&AnchorState::Invalid), "{seen:?}");
}

/// The upgraded artifact renders `attested` **only** with its group recorded;
/// strip the group and D97's measured loss appears — `internally-consistent-only`,
/// strictly worse than the `pending` it replaced and unrescuable, because
/// `agreed` is derived from the group and no online evidence can reach it.
///
/// This is the row that says the vault's keys 4/5/6 are load-bearing rather
/// than decorative.
///
/// What makes it fail: `AnchorArtifact::decode` dropping the group, or
/// `evaluate` not forwarding it into the view.
#[test]
fn an_upgraded_artifact_without_its_group_falls_back_to_internally_consistent_only() {
    let (digest, bytes, upgrade) =
        ots_writer::committed_single_branch(0x61, ots_writer::ATTESTED_HEIGHT);
    assert_eq!(
        evaluate(&ots(bytes.clone(), Some(upgrade)), &digest, ctx()).state(),
        AnchorState::Attested
    );
    assert_eq!(
        evaluate(&ots(bytes, None), &digest, ctx()).state(),
        AnchorState::InternallyConsistentOnly,
        "D97 §1.2: an upgraded artifact with no group is worse than the pending one it replaced"
    );
}

/// A [`WorkStatus`] with no anchors at all — a `--no-anchor` seal, or a work
/// killed before the anchor gate ran.
fn unanchored_status() -> WorkStatus {
    WorkStatus {
        work_id: Some([0xA9; 32]),
        seal_id: SealId::from_bytes([0xE9; 16]),
        title: Some("dev smoke".to_owned()),
        network: "devnet".to_owned(),
        state: WorkState::Complete,
        degraded: false,
        anchors: Vec::new(),
        unclassifiable: Vec::new(),
        damaged: Vec::new(),
        absent: vec![
            AnchorVerdict::absent(AnchorKind::Ots),
            AnchorVerdict::absent(AnchorKind::Tsa),
        ],
        receipt: None,
        upgrade: None,
    }
}

/// **D98's second permanent statement**: `absent` is never an outcome.
///
/// R70 keeps it out of `outcomes()` entirely — it is a claim about a *kind*
/// with no artifact — so iterating the anchor rows of a `--no-anchor` work
/// prints nothing, and rendering it at all means asking for the kind-level
/// verdict by name. Both halves are asserted, because only the second one
/// fails if a future reader starts synthesising `absent` rows into
/// [`WorkStatus::anchors`].
///
/// What makes it fail: pushing an `AnchorVerdict::absent` into `anchors`, or
/// dropping the explicit `absent` section from the renderer.
#[test]
fn absent_is_never_an_outcome_and_must_be_asked_for_by_name() {
    let status = unanchored_status();
    assert!(
        status
            .anchors
            .iter()
            .all(|row| row.verdict.state() != AnchorState::Absent),
        "`absent` describes a kind, never an artifact"
    );

    let rendered = status.render().join("\n");
    assert!(
        rendered.contains("(no artifact)   ots   absent"),
        "the kind-level verdict must be rendered explicitly:\n{rendered}"
    );
    assert!(
        rendered.contains("(no artifact)   tsa   absent"),
        "both kinds, or one silently disappears:\n{rendered}"
    );

    // …and with the explicit section removed there would be nothing at all
    // to print, which is the whole of R70's point.
    let mut silent = status;
    silent.absent.clear();
    assert!(
        !silent.render().join("\n").contains("absent"),
        "iterating outcomes alone can never produce the word"
    );
}

/// Rider 3c: three predicates share the word UNANCHORED and `status` computes
/// **the spec's** one, from headline eligibility.
///
/// The trap made concrete: a `--force-degraded` work carrying one pending OTS
/// satisfies MVP-SPEC.md line 137's UNANCHORED, while `NagState` calls it
/// `OnlyPendingOts` and `WorkRecord.unanchored` — the `--no-anchor` shaping
/// flag `list` badges off — is `false`. This renderer never reads that flag.
///
/// What makes it fail: computing `is_unanchored` from anything but
/// `AnchorVerdict::is_headline_eligible`.
#[test]
fn unanchored_is_headline_eligibility_and_not_the_shaping_flag() {
    let digest = ots_writer::synthetic_digest(0x71);
    let pending = AnchorRow {
        slot: crate::pipeline::OTS_SLOT.to_owned(),
        verdict: evaluate(
            &ots(
                ots_writer::container(
                    &digest,
                    &ots_writer::pending("https://calendar.example/alice"),
                ),
                None,
            ),
            &digest,
            ctx(),
        ),
    };
    assert_eq!(pending.verdict.state(), AnchorState::Pending);

    let mut status = unanchored_status();
    status.anchors = vec![pending];
    status.absent = vec![AnchorVerdict::absent(AnchorKind::Tsa)];
    status.degraded = true;

    assert!(
        status.is_unanchored(),
        "one pending OTS is an anchor and not a headline"
    );
    assert_eq!(status.headline_eligible(), 0);
    assert!(status.headline().is_none());

    let rendered = status.render().join("\n");
    assert!(rendered.contains(UNANCHORED_NOTE), "{rendered}");
    assert_eq!(
        status.json()["unanchored"],
        serde_json::json!(true),
        "the machine field carries the same predicate as the sentence"
    );
}

/// Rider 4c: the receipt is not an anchor, and on **this** path nothing but a
/// test says so.
///
/// On the bundle path the type enforces it — `ReceiptEvidence` is a separate
/// field with a `const fn -> false` eligibility — but `receipt_evidence` is
/// private and `AnchorVerdicts` has no public constructor, so `status` cannot
/// reach any of that. The replacement guarantee: the receipt appears outside
/// the per-anchor section, its line carries the spec's exact sentence, and no
/// receipt line carries **any** `AnchorState` spelling.
///
/// What makes it fail: moving the receipt block above the anchor rows, or
/// labelling it with a state.
#[test]
fn the_receipt_renders_as_supporting_evidence_and_never_as_an_anchor() {
    let mut status = unanchored_status();
    status.receipt = Some(ReceiptRow {
        transactions: 1,
        block_numbers: vec![377_262_147],
    });
    let rendered = status.render();

    let receipt_line = rendered
        .iter()
        .position(|line| line.contains(RECEIPT_CLASS))
        .expect("the receipt renders under the spec's own sentence");
    let last_anchor_line = rendered
        .iter()
        .rposition(|line| line.contains("absent"))
        .expect("the fixture has kind-level rows");
    assert!(
        receipt_line > last_anchor_line,
        "the receipt sits outside the per-anchor section:\n{rendered:#?}"
    );

    for line in &rendered[receipt_line..] {
        // The spec's own sentence is the one licensed occurrence of the word
        // "proven" here — *"no independently proven time"*, which is the
        // opposite of a state claim. It is removed before the scan rather
        // than special-cased inside it, so anything else naming a state is
        // still caught.
        let residue = line.replace(RECEIPT_CLASS, "");
        for state in AnchorState::ALL {
            assert!(
                !residue.contains(state.wire_name()),
                "a receipt line must carry no anchor-state spelling; `{line}` names `{}`",
                state.wire_name()
            );
        }
        // …and it must not wear the per-anchor row's kind column either: the
        // structural half of "never rendered as an anchor".
        assert!(
            !residue.contains("   ots") && !residue.contains("   tsa"),
            "a receipt line must not take the shape of an anchor row: `{line}`"
        );
    }

    // Rider 4d: the block number is display-only, and no time of any kind is
    // rendered for it.
    assert!(
        rendered.iter().any(|line| line.contains("377262147")),
        "the block number is rendered:\n{rendered:#?}"
    );
    let json = status.json();
    assert_eq!(json["receipt"]["class"], serde_json::json!(RECEIPT_CLASS));
    assert!(
        json["receipt"].get("time").is_none() && json["receipt"].get("time_unix").is_none(),
        "the receipt carries no time in the machine document either"
    );
}

/// Rider 1b/1c: the source's `Verified`/`Claimed` discriminant survives to the
/// wording, and the word "verified" is never printed about anything this run
/// did not verify.
///
/// This is the first place in the tree that mechanises D53 §4's *"MUST render
/// as such"*: `AnchorVerdict::source` hands over the discriminant intact, and
/// the collapse R74 records happens in `to_anchor_result`, a boundary this
/// module never crosses.
///
/// What makes it fail: labelling from the state instead of from
/// `AnchorSource::is_verified`, or rendering the identity bare.
#[test]
fn a_claimed_source_is_never_presented_as_verified() {
    let claimed = AnchorSource::Claimed("https://calendar.example/alice".to_owned());
    let verified = AnchorSource::Verified("CN=a real TSA signer".to_owned());
    assert!(!source_label(&claimed).contains("verified by"));
    assert!(source_label(&verified).contains("verified by"));
    assert_ne!(source_label(&claimed), source_label(&verified));

    // …and end to end, over a verdict the evaluator itself built: a pending
    // `.ots` names its calendars, and they are a claim bound to nothing.
    let digest = ots_writer::synthetic_digest(0x81);
    let verdict = evaluate(
        &ots(
            ots_writer::container(
                &digest,
                &ots_writer::pending("https://calendar.example/alice"),
            ),
            None,
        ),
        &digest,
        ctx(),
    );
    let source = verdict
        .source()
        .expect("a pending `.ots` names its calendars");
    assert!(!source.is_verified(), "a calendar URI is a sealer's string");

    let detail = verdict_detail(&verdict, "aa").join("\n");
    assert!(
        detail.contains("claimed by the artifact — this run did not verify it"),
        "{detail}"
    );
    assert!(
        !detail.contains("verified by this run"),
        "never the word `verified` about a claim: {detail}"
    );
    assert_eq!(
        verdict_json(&verdict)["source"]["verified"],
        serde_json::json!(false)
    );
}

/// Rider 5: the pending hint is second-person, because this command's reader
/// **is** the sealer — MVP-SPEC.md line 130's "ask the sealer" copy is written
/// for the verifier page, whose reader is a third party.
///
/// What makes it fail: reinstating the page's wording here.
#[test]
fn the_pending_hint_addresses_the_sealer_and_names_the_work() {
    let digest = ots_writer::synthetic_digest(0x91);
    let verdict = evaluate(
        &ots(
            ots_writer::container(
                &digest,
                &ots_writer::pending("https://calendar.example/bob"),
            ),
            None,
        ),
        &digest,
        ctx(),
    );
    let detail = verdict_detail(&verdict, "0123abcd").join("\n");
    assert!(
        detail.contains("run `antseal status 0123abcd --upgrade`"),
        "{detail}"
    );
    assert!(
        !detail.contains("ask the sealer"),
        "that is the verifier page's copy, not this one: {detail}"
    );
}

/// `verify_at_unix` is one-sided (D53 §5(b)), and this is the row that pins
/// the *reason* it gets no user surface: an early value can never produce a
/// failure, only a false `proven`.
///
/// Asserted here on the OTS side, where the parameter is not even accepted —
/// so a future edit that started threading a clock into the offline evaluator
/// would have to change this row's shape to do it. The TSA half, where the
/// value genuinely flips a state, is `chain.rs`'s own
/// `one_fixture_two_verify_times_flips_proven_and_since_expired`.
///
/// What makes it fail: making the OTS verdict depend on the verification
/// time.
#[test]
fn the_verification_time_never_moves_an_offline_ots_verdict() {
    for (label, digest, artifact) in every_ots_shape() {
        let early = evaluate(&artifact, &digest, StatusContext::new(0));
        let late = evaluate(&artifact, &digest, StatusContext::new(u64::MAX));
        assert_eq!(early, late, "{label}: no OTS rule reads a clock");
    }
}

/// The state vocabulary `status` emits is A18's frozen names and nothing
/// else — spelled by `AnchorState::wire_name` in **both** renderings, never
/// by a local table.
///
/// The text half is the load-bearing one and was added because a planted
/// second spelling in `render` passed a first version of this row that only
/// read the verdict and the JSON: the two renderings are separate surfaces,
/// and a test that checks the datum checks neither.
///
/// What makes it fail: rendering a state through any second spelling, in
/// either surface.
#[test]
fn every_rendered_state_is_one_of_the_seven_frozen_names() {
    let mut status = unanchored_status();
    status.anchors = every_ots_shape()
        .into_iter()
        .enumerate()
        .map(|(index, (_, digest, artifact))| AnchorRow {
            slot: format!("ots-{index}"),
            verdict: evaluate(&artifact, &digest, ctx()),
        })
        .collect();

    let frozen: Vec<&str> = AnchorState::ALL.iter().map(|s| s.wire_name()).collect();
    for row in &status.anchors {
        assert!(
            frozen.contains(&row.verdict.state().wire_name()),
            "{:?} is outside the frozen set",
            row.verdict.state()
        );
    }
    for value in status.json()["anchors"].as_array().expect("an array") {
        let state = value["state"].as_str().expect("a state string");
        assert!(
            frozen.contains(&state),
            "`{state}` is outside the frozen set"
        );
    }

    // The text surface, read the way a user does: every anchor's state line
    // is `<slot>   <kind>   <state>`, and its last column must be a frozen
    // name spelled exactly.
    let rendered = status.render();
    let mut checked = 0;
    for row in &status.anchors {
        let line = rendered
            .iter()
            .find(|line| line.trim_start().starts_with(&format!("{}   ", row.slot)))
            .unwrap_or_else(|| panic!("no rendered line for slot {}", row.slot));
        let spelled = line.rsplit("   ").next().expect("a state column");
        assert_eq!(
            spelled,
            row.verdict.state().wire_name(),
            "the rendered line spells the state differently from the datum: `{line}`"
        );
        assert!(frozen.contains(&spelled), "`{spelled}` is not frozen");
        checked += 1;
    }
    assert_eq!(checked, status.anchors.len(), "every row was read");
}
