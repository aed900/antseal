//! **R18 — the frozen verdict-wording set, snapshot-tested.**
//!
//! MVP-SPEC.md line 127 requires *"one authoritative wording set (M3
//! snapshot-tests it)"*, and line 174 makes verdict-wording snapshot tests an
//! M3 verification item. This file is that snapshot: it renders every row of
//! `antseal_core::verify::wording` into one deterministic document and
//! compares it with the committed
//! `tests/snapshots/verdict-wording.txt`. To regenerate after a **deliberate**
//! wording change:
//!
//! ```text
//! ANTSEAL_BLESS=1 cargo test -p antseal-core --test verdict_wording
//! ```
//!
//! …and then justify the diff in review: after R18 the strings are frozen, so
//! a moved byte here is a **wording-snapshot event**, never a tidy-up.
//!
//! # Additions are not edits
//!
//! Section 11 (R19's redaction rows) is the first block added after the
//! freeze, and it moved **no byte of sections 1–10**: R18 froze the verdict
//! block before R19 authored the disclosure block, so the rows arrived as new
//! sentences rather than as respellings of existing ones. That is the cheap
//! case, and the distinction is worth keeping in view — a *new* section is a
//! reviewable addition, whereas changing a sentence above rewrites what the
//! product has already said.
//!
//! What nothing here enforces is that every `pub` row of
//! `antseal_core::verify::wording` **reaches** this document: the renderer
//! below is hand-written, so a row added to the table and not added here
//! ships unsnapshotted and this file's "renders every row" claim quietly
//! stops being true. R19 measured that gap rather than closing it.
//!
//! # Positioning checklist (MVP-SPEC.md line 28) — reviewed, and swept below
//!
//! Line 28: *"never call it a 'notary' in legal copy — and never claim
//! 'priority' unqualified. A seal proves the holder of key X possessed this
//! content by time T — not authorship, not exclusive possession… All verdict
//! copy uses possession language."*
//!
//! 1. **No "notary".** The word and its family (`notaris/ize`, `notarial`)
//!    appear in no row. Swept by
//!    `the_wording_set_satisfies_the_positioning_checklist`.
//! 2. **No unqualified "priority".** Swept as an outright ban: the table has
//!    no room for the qualifying paragraph a lawful use would need, so any
//!    occurrence is by definition unqualified. Qualified discussion lives in
//!    documentation (D57 §…, README), never in a verdict line.
//! 3. **Both limits stated.** [`SEAL_MEANING_NOTE`] says *possessed*, *not
//!    authorship*, *not exclusive possession* — asserted positively, so
//!    deleting the disclaimer reddens rather than passing quietly.
//! 4. **No legal-instrument vocabulary.** `certif{y,ied}` as a claim about
//!    the *work*, "legally binding", "copyright", "patent", "affidavit",
//!    "witness" are banned. ("certificate" survives, as the X.509 object in
//!    the `valid-at-stamping-cert-since-expired` row — the sweep bans the
//!    verb forms, not the noun.)
//! 5. **No claim of authorship or exclusivity anywhere else.** Only the
//!    disclaimer row may contain "authorship" or "exclusive", and it contains
//!    them under a negation — asserted.
//! 6. **Never "verified" about something this run did not verify.** The two
//!    sealer-written registers ([`CLAIMED_TIME_LABEL`], [`FETCH_DATE_LABEL`])
//!    both carry *NOT verified*; the claimed-source label says outright that
//!    the run did not verify it.
//! 7. **The time claim is the spec's own and no stronger.** The only
//!    time-shaped sentence in the set is the one headline template; nothing
//!    else says "existed no later than", and the receipt class says outright
//!    that it proves no time.
//!
//! # What the source scan does and does not cover (R18 Accept row 3)
//!
//! `no_renderer_source_spells_a_frozen_verdict_string` scans the **renderer**
//! sources — `crates/antseal-cli/src/**` and `verifier-web/**` — for the
//! table's own sentences. Two scoping decisions, both deliberate and neither
//! silent:
//!
//! - **Test files are excluded** (`tests.rs`, and the crate's `tests/`
//!   directories). A test naming a frozen string is a *pin* — an independent
//!   expectation of what a renderer prints — not a second source of truth.
//!   Rewriting those pins to read the table would make them tautological.
//! - **The residue is enumerated, not assumed away.** [`RESIDUE`] lists the
//!   verdict-shaped sentences that still live in `antseal-cli` and are *not*
//!   table rows today, each with its reason and the question that has to be
//!   answered before it can move. Every entry is asserted **present**, so the
//!   list cannot rot: moving one onto the table turns this test red until the
//!   entry is deliberately deleted.

use std::fs;
use std::path::{Path, PathBuf};

use antseal_core::verify::orchestration::FetchFailureClass;
use antseal_core::verify::report::{AnchorKind, AnchorState, SignatureScheme};
use antseal_core::verify::wording::*;

/// The workspace root (this crate sits at `crates/antseal-core`).
const WORKSPACE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// The committed document.
const SNAPSHOT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/snapshots/verdict-wording.txt"
);

// Fixture values. Fixed literals, never a clock: the document must be
// byte-identical on every machine, every run, and under wasm32 (Q5).
const FIXTURE_TIME: i64 = 1_785_000_000;
const FIXTURE_EARLIER_TIME: i64 = 1_780_000_000;
const FIXTURE_FETCH_DATE: &str = "1785600000";
const FIXTURE_CLAIMED_TIME: &str = "1779999999";
const FIXTURE_HEIGHT: u64 = 700_113;
const FIXTURE_TSA_SOURCE: &str = "CN=antseal mock TSA signer,O=antseal fixtures";
const FIXTURE_OTS_SOURCE: &str = "bitcoin-block-700113";
const FIXTURE_RECEIPT_BLOCK: u64 = 377_262_147;
// **D137 §3 R9 — two chain ids, not one, and that is what gives the snapshot
// teeth.** Both parameterised receipt lines are emitted TWICE below. Emitting
// one instance each would let a hard-coded `42161` sit in the committed
// snapshot indefinitely — the document would be byte-stable and the parameter
// could be ignored entirely. Two instances make an implementation that
// interpolates a constant show up as two identical rows, and redden
// `every_single_sourced_needle_occurs_in_the_rendered_set`'s companion
// differential in `wording/tests.rs`.
//
// Literals with the names they mirror: this crate cannot see `antseal-net`
// (D137 §1 (h)).
const FIXTURE_CHAIN_ID: u64 = 42_161; // antseal_net::network::ARBITRUM_ONE_CHAIN_ID
const FIXTURE_CHAIN_ID_TWIN: u64 = 421_614; // …::ARBITRUM_SEPOLIA_CHAIN_ID
// R19's redaction rows. The path is deliberately ordinary: the table's slot
// takes text the *renderer* has already escaped for its surface (D67 §3 R6),
// so a hostile path belongs in the renderer's own suite
// (`crates/antseal-cli/tests/redaction_view.rs`), not here.
const FIXTURE_PATH: &str = "pitch/chapter-1.md";
const FIXTURE_FILE_SIZE: u64 = 1024;
const FIXTURE_WITHHELD_SIZE: u64 = 49_152;

// ─────────────────────────────────────────────────────────────────────
// the document
// ─────────────────────────────────────────────────────────────────────

fn section(out: &mut String, title: &str) {
    out.push_str(&format!("\n════ {title} ════\n"));
}

fn subsection(out: &mut String, title: &str) {
    out.push_str(&format!("\n── {title} ──\n"));
}

/// The per-state block: the state row, the guidance the table attaches to
/// that state, its source line, and — under **every** state — the
/// sealer-recorded fetch date (D95 rider (a)).
fn state_block(out: &mut String, state: AnchorState) {
    subsection(out, &format!("state: {}", state.wire_name()));
    out.push_str(&anchor_state_line(state));
    out.push('\n');

    // Guidance is per state, wildcard-free so an eighth state must be given
    // one (or explicitly given none) rather than silently rendering bare.
    let guidance: Vec<String> = match state {
        AnchorState::Proven => vec![verified_time_line(FIXTURE_TIME)],
        AnchorState::ValidAtStampingCertSinceExpired => {
            vec![verified_time_line(FIXTURE_EARLIER_TIME)]
        }
        AnchorState::Attested => vec![attested_block_line(FIXTURE_HEIGHT)],
        AnchorState::Pending => vec![
            PENDING_GUIDANCE.to_owned(),
            pending_guidance_self_line("`antseal status <work-id> --upgrade`"),
        ],
        AnchorState::InternallyConsistentOnly | AnchorState::Invalid | AnchorState::Absent => {
            Vec::new()
        }
    };
    for line in guidance {
        out.push_str(&format!("    {line}\n"));
    }

    // `absent` is a statement about a *kind with no artifact* (R70): no
    // source, no time, no fetch date exist to render. Every other state
    // emits an artifact slot and therefore carries both subordinate rows.
    let identity = match state {
        AnchorState::Proven
        | AnchorState::ValidAtStampingCertSinceExpired
        | AnchorState::InternallyConsistentOnly
        | AnchorState::Invalid => Some(FIXTURE_TSA_SOURCE),
        AnchorState::Attested | AnchorState::Pending => Some(FIXTURE_OTS_SOURCE),
        AnchorState::Absent => None,
    };
    if let Some(identity) = identity {
        let verified_source = !headline_tag(state).is_empty();
        out.push_str(&format!("    {}\n", source_line(identity, verified_source)));
        out.push_str(&format!("    {}\n", fetch_date_line(FIXTURE_FETCH_DATE)));
    }
}

fn render_document() -> String {
    let mut out = String::new();
    out.push_str("antseal — the one authoritative verdict-wording set (R18, frozen)\n");
    out.push_str(
        "Every string below is final display text. Renderers — the CLI, the verifier page,\n\
         the online overlay — receive these strings and do layout only.\n",
    );

    section(&mut out, "1. what a seal proves");
    out.push_str(SEAL_MEANING_NOTE);
    out.push('\n');

    section(&mut out, "2. the one headline, and its absence");
    out.push_str(&format!(
        "{}\n",
        headline_sentence(
            FIXTURE_TIME,
            AnchorKind::Tsa,
            &source_slot(Some(FIXTURE_TSA_SOURCE))
        )
    ));
    out.push_str(&format!(
        "{}\n",
        headline_sentence(FIXTURE_TIME, AnchorKind::Ots, &source_slot(None))
    ));
    out.push_str(&format!("{UNANCHORED_BANNER}\n"));
    out.push_str(&format!(
        "{}\n",
        divergence_flag_line(FIXTURE_EARLIER_TIME, FIXTURE_TIME)
    ));

    section(
        &mut out,
        "3. the seven anchor states ([H] = headline-eligible)",
    );
    for state in AnchorState::ALL {
        out.push_str(&format!("{}\n", anchor_state_line(state)));
    }

    section(&mut out, "4. one slot block per state");
    out.push_str(
        "The fetch-date row renders under every state that emits a slot, `invalid` included: it\n\
         is gated by the artifact's recorded value and never by the verdict beside it (D95 rider\n\
         (a)). `absent` is a statement about a kind with no artifact (R70), so it has no source,\n\
         no time and no fetch date to render — an absent datum, not a state gate.\n\
         The `pending` block shows both audiences' guidance (declared divergence 1); a renderer\n\
         prints exactly one of them.\n",
    );
    for state in AnchorState::ALL {
        state_block(&mut out, state);
    }

    section(&mut out, "5. subordinate, sealer-written metadata");
    out.push_str(&format!("{}\n", claimed_time_line(FIXTURE_CLAIMED_TIME)));
    out.push_str(&format!("{}\n", fetch_date_line(FIXTURE_FETCH_DATE)));

    section(&mut out, "6. supporting evidence (never an anchor)");
    out.push_str(&format!("{}\n", receipt_class_line()));
    out.push_str(&format!(
        "{}\n",
        receipt_detail_line(FIXTURE_RECEIPT_BLOCK, 1)
    ));

    section(&mut out, "7. signature scheme");
    for scheme in SignatureScheme::ALL {
        out.push_str(&format!("{}\n", signature_scheme_line(scheme)));
    }

    section(&mut out, "8. the raw mirror (R53)");
    out.push_str(&format!("{}\n", mirror_full_reveal_line(4096)));
    out.push_str(&format!("{MIRROR_PARTIAL_REVEAL_POLICY}\n"));

    section(
        &mut out,
        "9. the two proof layers, and the advisory live check",
    );
    out.push_str(&format!("{EVIDENCE_LAYER_LABEL}\n"));
    out.push_str(&format!("{STORAGE_LINKAGE_LAYER_LABEL}\n"));
    out.push_str(&format!("{}\n", storage_linkage_not_evaluated_line()));
    out.push_str(&format!("{}\n", storage_linkage_pass_line(4)));
    out.push_str(&format!("{}\n", storage_linkage_fail_line(1, 4)));
    out.push_str(&format!("{LIVE_LAYER_LABEL}\n"));
    out.push_str(&format!("{}\n", live_all_persisted_line(4)));
    out.push_str(&format!("{}\n", live_divergent_line(1)));
    out.push_str(&format!("{}\n", live_some_missing_line(2)));
    out.push_str(&format!("{}\n", live_inconclusive_line(1)));
    out.push_str(&format!("{}\n", live_blob_identical_line("unit 7")));
    out.push_str(&format!("{}\n", live_blob_different_line("unit 7")));
    out.push_str(&format!("{}\n", live_blob_not_found_line("unit 7")));
    // R89 — **one row per class, derived from the class**, not one row per
    // remembered string. Before R89 this line was
    // `live_blob_fetch_error_line("unit 7", "transport failure")`: a literal
    // restating a label that lived in another crate, so the frozen document
    // and the shipped word agreed by *coincidence* — reword the class and
    // this file stayed green while the product's rendered line moved. Sweeping
    // `ALL` makes the agreement a checked fact and makes a third class arrive
    // as a snapshot event rather than silently unspelled.
    assert_eq!(
        FetchFailureClass::ALL.len(),
        2,
        "the sweep below is vacuous if ALL shrinks; grow or shrink it deliberately"
    );
    for class in FetchFailureClass::ALL {
        out.push_str(&format!(
            "{}\n",
            live_blob_fetch_error_line("unit 7", live_fetch_failure_class_label(class))
        ));
    }

    section(&mut out, "10. the online advisory overlay (D64)");
    out.push_str(&format!("{}\n", overlay_framing_line()));
    subsection(&mut out, "headline impact — exactly one of three");
    out.push_str(&format!(
        "{}\n",
        headline_sentence(
            FIXTURE_TIME,
            AnchorKind::Ots,
            &online_source_slot(Some(FIXTURE_OTS_SOURCE))
        )
    ));
    out.push_str(&format!("{}\n", stands_line()));
    out.push_str(&format!("{}\n", still_unanchored_line()));
    subsection(&mut out, "per-probed-anchor outcomes");
    let slot = slot_name(AnchorKind::Ots, 1);
    out.push_str(&format!(
        "{}\n",
        promoted_line(
            &slot,
            FIXTURE_HEIGHT,
            FIXTURE_TIME,
            Some(FIXTURE_OTS_SOURCE)
        )
    ));
    out.push_str(&format!(
        "{}\n",
        refuted_line(&slot, "anchor-ots-online-header-mismatch")
    ));
    out.push_str(&format!(
        "{}\n",
        refutation_suppressed_line(&slot, "anchor-ots-online-header-mismatch")
    ));
    out.push_str(&format!("{}\n", disagreed_line(&slot, FIXTURE_HEIGHT)));
    out.push_str(&format!(
        "{}\n",
        endpoint_failures_line(&slot, FIXTURE_HEIGHT, &[])
    ));
    out.push_str(&format!("{}\n", no_evidence_line(&slot, FIXTURE_HEIGHT)));
    subsection(&mut out, "receipt echo, endpoints, change-only deltas");
    out.push_str(&format!(
        "{}\n",
        receipt_confirmed_line(FIXTURE_CHAIN_ID, FIXTURE_RECEIPT_BLOCK, true)
    ));
    out.push_str(&format!(
        "{}\n",
        receipt_confirmed_line(FIXTURE_CHAIN_ID, FIXTURE_RECEIPT_BLOCK, false)
    ));
    out.push_str(&format!(
        "{}\n",
        receipt_not_on_chain_line(FIXTURE_CHAIN_ID)
    ));
    // The Sepolia twins (D137 §3 R9). Same block, same status, one different
    // chain id — so the pair reads as a differential in the committed file
    // itself and a reviewer can see the parameter is honoured without running
    // anything.
    out.push_str(&format!(
        "{}\n",
        receipt_confirmed_line(FIXTURE_CHAIN_ID_TWIN, FIXTURE_RECEIPT_BLOCK, true)
    ));
    out.push_str(&format!(
        "{}\n",
        receipt_not_on_chain_line(FIXTURE_CHAIN_ID_TWIN)
    ));
    out.push_str(&format!("{}\n", receipt_disagreed_line()));
    out.push_str(&format!("{}\n", receipt_failed_line(&[])));
    let endpoints = vec![
        "https://blockstream.example/api".to_owned(),
        "https://mempool.example/api".to_owned(),
    ];
    out.push_str(&format!("{}\n", endpoints_line(&endpoints, false)));
    out.push_str(&format!("{}\n", endpoints_line(&endpoints, true)));
    out.push_str(&format!(
        "{}\n",
        divergence_newly_flagged_line(FIXTURE_EARLIER_TIME, FIXTURE_TIME)
    ));

    section(&mut out, "11. the redaction view (R19)");
    out.push_str(
        "MVP-SPEC.md line 121's anti-out-of-context guardrail, as sentences. Both renderers\n\
         draw them: the CLI's `redaction_out` and R23's page. The `path` slot arrives already\n\
         escaped for the caller's surface (D67 §3 R6), which is why the fixture below carries\n\
         a plain one — the escaping is the renderer's, the sentence is the table's.\n",
    );
    out.push_str(&format!("{REDACTION_VIEW_LABEL}\n"));
    out.push_str(&format!("{DECLARED_SIZE_NOTE}\n"));
    subsection(&mut out, "a partially revealed file");
    out.push_str(&format!(
        "{}\n",
        redacted_file_line(0, FIXTURE_PATH, FIXTURE_FILE_SIZE, false)
    ));
    out.push_str(&format!(
        "{}\n",
        blackout_span_line(0, 0, 256, FIXTURE_FILE_SIZE)
    ));
    out.push_str(&format!(
        "{}\n",
        revealed_span_line(1, 256, 384, FIXTURE_FILE_SIZE)
    ));
    subsection(&mut out, "a fully revealed file, and its riding mirror");
    out.push_str(&format!(
        "{}\n",
        redacted_file_line(1, FIXTURE_PATH, FIXTURE_FILE_SIZE, true)
    ));
    out.push_str(&format!(
        "{}\n",
        revealed_span_line(2, 0, FIXTURE_FILE_SIZE, FIXTURE_FILE_SIZE)
    ));
    out.push_str(&format!("{}\n", mirror_full_reveal_line(FIXTURE_FILE_SIZE)));
    subsection(&mut out, "a wholly unrevealed file, and the work totals");
    out.push_str(&format!(
        "{}\n",
        withheld_file_line(2, FIXTURE_WITHHELD_SIZE)
    ));
    out.push_str(&format!(
        "{}\n",
        redaction_totals_line(
            u128::from(FIXTURE_FILE_SIZE) + 384,
            u128::from(FIXTURE_FILE_SIZE) * 2 + u128::from(FIXTURE_WITHHELD_SIZE),
            2,
            3
        )
    ));
    out.push_str(&format!(
        "{}\n",
        withheld_totals_line(640, u128::from(FIXTURE_WITHHELD_SIZE), 1)
    ));

    out
}

/// Every line of the rendered document that is a wording row (headers,
/// prose and blanks removed) — the corpus the checklist sweeps.
fn rendered_rows() -> Vec<String> {
    render_document()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('═') && !line.starts_with('─'))
        .map(str::to_owned)
        .collect()
}

// ─────────────────────────────────────────────────────────────────────
// the snapshot
// ─────────────────────────────────────────────────────────────────────

#[test]
fn the_wording_document_matches_the_committed_snapshot() {
    let rendered = render_document();
    let path = Path::new(SNAPSHOT_PATH);
    if std::env::var_os("ANTSEAL_BLESS").is_some() {
        fs::create_dir_all(path.parent().expect("snapshot path has a parent"))
            .expect("create snapshot directory");
        fs::write(path, &rendered).expect("write blessed snapshot");
        return;
    }
    let committed = fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "missing committed wording snapshot at {}: {e}\n\
             (generate once with ANTSEAL_BLESS=1 and review the diff)",
            path.display()
        )
    });
    assert!(
        committed == rendered,
        "the rendered wording set differs from the committed snapshot {}.\n\
         The set is FROZEN (R18): a change here is a wording-snapshot event — regenerate with \
         ANTSEAL_BLESS=1 only for a deliberate change, and justify the diff in review.",
        path.display()
    );
}

/// **R18 Accept row 1's teeth.** Every one of the seven states must have a
/// row *and* a slot block in the committed document. The match is
/// wildcard-free, so an eighth state cannot be added without deciding, here,
/// what it renders as — the build breaks first.
#[test]
fn every_anchor_state_has_a_snapshotted_row_and_a_slot_block() {
    let committed = fs::read_to_string(SNAPSHOT_PATH).expect("committed wording snapshot");
    for state in AnchorState::ALL {
        // An independent expectation of the row's shape: written by hand so
        // that a change to `anchor_state_line` or to the [H] map reddens
        // here as well as in the snapshot diff.
        let expected_prefix = match state {
            AnchorState::Proven => "proven [H] — ",
            AnchorState::ValidAtStampingCertSinceExpired => {
                "valid-at-stamping-cert-since-expired [H] — "
            }
            AnchorState::Attested => "attested — ",
            AnchorState::Pending => "pending — ",
            AnchorState::InternallyConsistentOnly => "internally-consistent-only — ",
            AnchorState::Invalid => "invalid — ",
            AnchorState::Absent => "absent — ",
        };
        let row = anchor_state_line(state);
        assert!(
            row.starts_with(expected_prefix),
            "`{}` renders as `{row}`, not as `{expected_prefix}…`",
            state.wire_name()
        );
        assert!(
            committed.contains(&row),
            "no snapshot row for `{}` — add it and re-bless",
            state.wire_name()
        );
        assert!(
            committed.contains(&format!("── state: {} ──", state.wire_name())),
            "no snapshot slot block for `{}`",
            state.wire_name()
        );
    }
    assert_eq!(
        AnchorState::ALL.len(),
        7,
        "MVP-SPEC.md lines 129–135 define seven states; a change here is a spec event"
    );
}

/// **R18 Accept row 2 / D95 rider (a).** The `fetch_date` row is exercised
/// beneath a **refuted** anchor — the state where an unlabelled date is
/// likeliest to be read as corroboration — and it is byte-identical to the
/// row rendered under every other state.
#[test]
fn the_fetch_date_row_is_exercised_beneath_a_refuted_anchor() {
    let committed = fs::read_to_string(SNAPSHOT_PATH).expect("committed wording snapshot");
    let row = fetch_date_line(FIXTURE_FETCH_DATE);

    let mut invalid_block = String::new();
    state_block(&mut invalid_block, AnchorState::Invalid);
    assert!(
        invalid_block.contains("invalid — "),
        "the block under test is the refuted one: {invalid_block}"
    );
    assert!(
        invalid_block.contains(&row),
        "the fetch date must render under `invalid`: {invalid_block}"
    );
    assert!(
        committed.contains(&invalid_block),
        "the refuted block is not in the committed snapshot — re-bless"
    );

    // One row, every slot-emitting state: the label cannot vary with the
    // verdict because there is no verdict in the input.
    for state in AnchorState::ALL {
        let mut block = String::new();
        state_block(&mut block, state);
        assert!(
            committed.contains(&block),
            "the `{}` block is not in the committed snapshot — re-bless",
            state.wire_name()
        );
        if state == AnchorState::Absent {
            assert!(
                !block.contains(&row),
                "an `absent` kind has no artifact, so it has no fetch date to render (R70)"
            );
        } else {
            assert!(
                block.contains(&row),
                "`{}` emits a slot, so D95's row must render under it — unchanged",
                state.wire_name()
            );
        }
    }
    assert!(
        row.contains("NOT verified") && row.contains("not evidence for the state above"),
        "beside a refutation the row must foreclose the corroboration reading: {row}"
    );
}

/// **R18 Accept row 1, the remaining elements.** Each named element of the
/// Accept row must be in the committed document — not merely renderable.
#[test]
fn the_snapshot_covers_every_element_the_accept_row_names() {
    let committed = fs::read_to_string(SNAPSHOT_PATH).expect("committed wording snapshot");
    let required: &[(&str, String)] = &[
        (
            "headline",
            headline_sentence(
                FIXTURE_TIME,
                AnchorKind::Tsa,
                &source_slot(Some(FIXTURE_TSA_SOURCE)),
            ),
        ),
        ("claimed time", claimed_time_line(FIXTURE_CLAIMED_TIME)),
        (
            "divergence",
            divergence_flag_line(FIXTURE_EARLIER_TIME, FIXTURE_TIME),
        ),
        ("UNANCHORED", UNANCHORED_BANNER.to_owned()),
        ("receipt class", receipt_class_line()),
        ("overlay framing", overlay_framing_line().to_owned()),
        (
            "signature label",
            signature_scheme_line(SignatureScheme::HybridPq),
        ),
        ("storage-linkage pass", storage_linkage_pass_line(4)),
        ("storage-linkage fail", storage_linkage_fail_line(1, 4)),
        ("live layer", LIVE_LAYER_LABEL.to_owned()),
        ("mirror policy", MIRROR_PARTIAL_REVEAL_POLICY.to_owned()),
    ];
    for (name, line) in required {
        assert!(
            committed.contains(line.as_str()),
            "the snapshot is missing the {name} row: {line}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// positioning (MVP-SPEC.md line 28)
// ─────────────────────────────────────────────────────────────────────

/// Tokens no verdict line may contain, with the reason each is banned. See
/// the checklist in this file's header.
const BANNED_TOKENS: &[(&str, &str)] = &[
    ("notary", "MVP-SPEC.md line 28: never call it a notary"),
    ("notaris", "the same ban, British spelling of the verb"),
    ("notariz", "the same ban, American spelling of the verb"),
    ("notarial", "the same ban, adjectival form"),
    (
        "priority",
        "MVP-SPEC.md line 28: never claim priority unqualified — and a verdict line has no room \
         to qualify it",
    ),
    (
        "legally binding",
        "a verdict is evidence, not an instrument",
    ),
    ("copyright", "a seal says nothing about rights"),
    ("patent", "a seal says nothing about rights"),
    ("affidavit", "legal-instrument vocabulary"),
    ("witness", "legal-instrument vocabulary"),
    ("certify", "the product certifies nothing about the work"),
    ("certified", "the product certifies nothing about the work"),
];

#[test]
fn the_wording_set_satisfies_the_positioning_checklist() {
    let rows = rendered_rows();
    assert!(
        rows.len() > 40,
        "the row sweep collected {} rows — the document builder is broken, not the copy clean",
        rows.len()
    );

    for row in &rows {
        let lowered = row.to_lowercase();
        for (token, reason) in BANNED_TOKENS {
            assert!(
                !lowered.contains(token),
                "positioning violation — `{token}` ({reason}): {row}"
            );
        }
    }

    // Checklist items 3 and 5: the two limits are stated, and the words
    // "authorship" / "exclusive" appear nowhere but inside that disclaimer.
    assert!(rows.iter().any(|row| row == SEAL_MEANING_NOTE));
    for word in ["authorship", "exclusive"] {
        let carriers: Vec<&String> = rows.iter().filter(|row| row.contains(word)).collect();
        assert_eq!(
            carriers.len(),
            1,
            "`{word}` may appear only in the disclaimer row, under a negation: {carriers:?}"
        );
        assert!(
            carriers[0].contains(&format!("not {word}")),
            "`{word}` must be negated: {}",
            carriers[0]
        );
    }

    // Checklist item 7: exactly one sentence shape claims a time.
    let time_claims: Vec<&String> = rows
        .iter()
        .filter(|row| row.contains("existed no later than"))
        .collect();
    assert_eq!(
        time_claims.len(),
        3,
        "the time claim is one template (offline headline ×2 + the overlay's attributed one); a \
         fourth shape is Q89's defect: {time_claims:?}"
    );
}

/// The checklist sweep must be able to fail. A planted line carrying the
/// product's most tempting wrong word goes through the same predicate.
#[test]
fn the_positioning_sweep_catches_a_planted_violation() {
    let planted = "antseal is a digital notary and establishes priority";
    let lowered = planted.to_lowercase();
    let hits: Vec<&str> = BANNED_TOKENS
        .iter()
        .filter(|(token, _)| lowered.contains(token))
        .map(|(token, _)| *token)
        .collect();
    assert_eq!(
        hits,
        vec!["notary", "priority"],
        "the ban list must catch both halves of line 28's prohibition"
    );
}

// ─────────────────────────────────────────────────────────────────────
// the source scan (R18 Accept row 3)
// ─────────────────────────────────────────────────────────────────────

/// Table strings that must live in exactly one place. Short needles are
/// deliberately avoided: every entry is a full sentence or a distinctive
/// clause, so a hit is a copy and not a coincidence.
fn single_sourced() -> Vec<(String, &'static str)> {
    vec![
        (UNANCHORED_BANNER.to_owned(), "the UNANCHORED banner"),
        (RECEIPT_CLASS.to_owned(), "the receipt class"),
        (CLAIMED_TIME_LABEL.to_owned(), "the claimed-time label"),
        (FETCH_DATE_LABEL.to_owned(), "the fetch-date label"),
        (PENDING_GUIDANCE.to_owned(), "the page's pending guidance"),
        (
            PENDING_GUIDANCE_SELF.to_owned(),
            "the sealer's pending guidance",
        ),
        (
            SOURCE_VERIFIED_LABEL.to_owned(),
            "the verified-source label",
        ),
        (SOURCE_CLAIMED_LABEL.to_owned(), "the claimed-source label"),
        (SEAL_MEANING_NOTE.to_owned(), "the possession disclaimer"),
        (
            MIRROR_PARTIAL_REVEAL_POLICY.to_owned(),
            "the R53 mirror policy",
        ),
        (EVIDENCE_LAYER_LABEL.to_owned(), "the evidence-layer label"),
        (
            STORAGE_LINKAGE_LAYER_LABEL.to_owned(),
            "the storage-linkage-layer label",
        ),
        (LIVE_LAYER_LABEL.to_owned(), "the --live layer label"),
        // R89's new frozen sentence. Only `BackendRefused`'s word joins the
        // table: `Transport`'s is `probe_failure_class_label`'s word for the
        // *online* class too, so it is shared by construction and a scan for
        // it would report the sharing as an offence. Derived from the table
        // rather than restated, so a deliberate reword moves needle and
        // sentence together — this entry guards against a *second copy* in a
        // renderer, which is a different claim from the wording being frozen.
        (
            live_fetch_failure_class_label(FetchFailureClass::BackendRefused).to_owned(),
            "the live backend-refused failure class",
        ),
        (
            "existed no later than".to_owned(),
            "the one headline template",
        ),
        (
            "independently proven time:".to_owned(),
            "the verified-time row",
        ),
        (
            "source not recorded".to_owned(),
            "the empty source-slot fallback",
        ),
        (
            overlay_framing_line().to_owned(),
            "the overlay framing sentence",
        ),
        (stands_line().to_owned(), "the Stands impact line"),
        (
            still_unanchored_line().to_owned(),
            "the StillUnanchored impact line",
        ),
        (
            signature_scheme_label(SignatureScheme::HybridPq).to_owned(),
            "the hybrid signature label",
        ),
        (
            signature_scheme_label(SignatureScheme::Ed25519Only).to_owned(),
            "the Ed25519-only signature label",
        ),
        // R19's redaction rows. Needles are the fixed tails and labels
        // rather than the whole formatted sentence: a row carrying four
        // interpolated numbers has no literal form to search for, and the
        // tail is the part a copy would carry over verbatim.
        (
            REDACTION_VIEW_LABEL.to_owned(),
            "the redaction view's section label",
        ),
        (
            DECLARED_SIZE_NOTE.to_owned(),
            "the declared-not-measured note",
        ),
        (
            "sealed, and not revealed by this bundle".to_owned(),
            "the blackout block's tail",
        ),
        (
            "path withheld: this bundle reveals nothing of this file".to_owned(),
            "the committed placeholder",
        ),
        (
            "disclosure totals:".to_owned(),
            "the work-level revealed total",
        ),
        (
            "byte(s) blacked out inside revealed files".to_owned(),
            "the work-level withheld total",
        ),
        // D137 §3 R10 — the two receipt-echo lines that assert something
        // about *where* the transaction is. D137 §1 (f) measured that neither
        // was on this table: both surfaces render `overlay.receipt.line`
        // verbatim — the CLI in `verify_out.rs`'s `overlay_lines`, the page in
        // `renderOverlay` — and **nothing stopped either from growing its own
        // copy**, because the sentences were snapshot-frozen without being
        // scan-protected. This is the entry that makes one edit to
        // `wording.rs` keep moving both surfaces.
        //
        // Needles are the fixed head clauses rather than whole sentences,
        // following R19's precedent above: the confirmation line already
        // interpolates a block number, and D137 §3 R1 makes both of them
        // interpolate a chain id, at which point neither has a literal form to
        // search for. `every_single_sourced_needle_occurs_in_the_rendered_set`
        // is what keeps these two spelled correctly.
        (
            "both RPC endpoints agree the recorded transaction is not on Arbitrum chain "
                .to_owned(),
            "the receipt echo's absence line",
        ),
        (
            "both RPC endpoints confirm the recorded transaction on Arbitrum chain ".to_owned(),
            "the receipt echo's confirmation line",
        ),
    ]
}

/// **D137 §3 R11 — a needle that cannot fire is an assertion that cannot
/// fail.**
///
/// [`single_sourced`] is a table of literals compared against renderer
/// sources. Nothing above checks that any given entry is spelled the way the
/// wording module actually spells it, and a misspelled needle scans every
/// renderer file for a string that can never occur: green for ever, catching
/// nothing. `the_source_scan_catches_a_planted_copy_of_a_frozen_sentence`
/// does not close this — it plants [`UNANCHORED_BANNER`] and so proves the
/// *predicate* is fallible, which is a different claim from "this needle is
/// the sentence it names".
///
/// The check is that each needle occurs in the rendered document — the same
/// corpus the committed snapshot is taken from. Misspell a needle, or respell
/// the sentence it targets without respelling the needle, and this reddens
/// naming the entry.
#[test]
fn every_single_sourced_needle_occurs_in_the_rendered_set() {
    let document = render_document();
    let table = single_sourced();

    // The loop below is vacuous over an empty or truncated table, which is
    // this project's dominant defect class. The floor is asserted first and
    // separately, so a table that shrank says so instead of passing quietly.
    // Raised 29 → 30 by R89, in the same act that added the entry: the floor
    // is only a shrink alarm if it tracks the table it guards.
    const NEEDLE_FLOOR: usize = 30;
    assert!(
        table.len() >= NEEDLE_FLOOR,
        "the single-sourced table holds {} needle(s), below the {NEEDLE_FLOOR} this floor was \
         written against. Entries are removed deliberately (a sentence deleted from the wording \
         set), so lower the floor in the same act — an unnoticed shrink makes both this test and \
         `no_renderer_source_spells_a_frozen_verdict_string` scan for less than they claim to.",
        table.len()
    );

    let mut unfirable = Vec::new();
    for (needle, what) in &table {
        if !document.contains(needle.as_str()) {
            unfirable.push(format!("{what} — `{needle}`"));
        }
    }
    assert!(
        unfirable.is_empty(),
        "these single-sourced needles occur nowhere in the rendered wording set, so the source \
         scan searches every renderer file for a string that cannot exist and can never catch a \
         copy:\n  {}\n\
         Either the needle is misspelled, or the sentence it targets was respelled and the needle \
         was not (D137 §3 R11).",
        unfirable.join("\n  ")
    );
}

/// Verdict-shaped sentences that still live in `antseal-cli` and are **not**
/// table rows today. Each is asserted **present**, so the list cannot go
/// stale: move one onto the table and this test reddens until the entry is
/// deleted on purpose.
///
/// This is the honest measurement R18's Accept row 3 asks for. What made the
/// difference between "moved" and "residue" is whether the move changes a
/// rendered byte: every string moved onto the table above renders exactly as
/// it did before (the committed `status-report.txt` snapshot did not move),
/// while each entry below would change a shipped U23 rendering, which is a
/// decision this task does not own.
const RESIDUE: &[(&str, &str, &str)] = &[
    (
        "a Bitcoin attestation is embedded",
        "status.rs renders its own `attested` guidance",
        "may `antseal status` adopt MVP-SPEC line 108's mandated sentence (which names block H), \
         given that the height is not on `AnchorVerdict` and the U23 snapshot moves?",
    ),
    (
        "fetch date: {fetch_date}",
        "status.rs renders the fetch date without D95's sealer-recorded/NOT-verified label",
        "does `antseal status` adopt `wording::fetch_date_line` — a U23 rendered-output change \
         that D95 rider (a) arguably already requires?",
    ),
    (
        "anchor artifact(s); {} can carry the headline time",
        "the eligible-count line is U23's own summary, not a spec-named verdict row",
        "is the [H] count line a wording-table row, or command-shaped summary the page has no \
         equivalent of?",
    ),
    (
        "paid in {} transaction(s)",
        "status.rs's receipt detail predates `wording::receipt_detail_line` and reads from the \
         vault, not a report",
        "which of the two receipt-detail spellings survives — and does the vault-side one need \
         the 'never this work's time' clause the table row carries?",
    ),
    (
        "UNANCHORED: this seal carries no timestamp attestations",
        "seal-time copy in seal_run.rs: a warning about a seal being made, not a verdict about \
         evidence being read",
        "is seal-time copy in R18's scope at all, or U-side copy with its own audience?",
    ),
    (
        "The payment receipt is supporting evidence only",
        "seal_run.rs's --force-degraded warning restates the receipt class in seal-time voice",
        "same question as above; if seal-time copy is in scope, this is a second spelling of \
         `RECEIPT_CLASS`",
    ),
];

/// The roots the scan covers, each with the floor its own file count must
/// clear.
///
/// The floors are per-root and that is the point (D131 §5 R2). A single
/// threshold over the union is green whenever *either* root is populated, so
/// with `verifier-web/` contributing nothing the scan reported 54 files, all
/// from the CLI, and page coverage was **zero** with nothing red. A guard over
/// a union of roots is not a guard on any of them.
const SCAN_ROOTS: [(&str, usize); 2] = [("crates/antseal-cli/src", 40), ("verifier-web", 1)];

/// The files one root contributes, excluding test files (see the header).
fn sources_under(relative: &str) -> Vec<(String, String)> {
    let root = Path::new(WORKSPACE_ROOT);
    let mut files = Vec::new();
    {
        let dir = root.join(relative);
        for path in walk(&dir) {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_owned();
            if name == "tests.rs" {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            files.push((
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
                text,
            ));
        }
    }
    files.sort();
    files
}

/// Every file the scan covers: `antseal-cli`'s renderer sources and the
/// verifier page's template.
fn renderer_sources() -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = SCAN_ROOTS
        .iter()
        .flat_map(|(relative, _)| sources_under(relative))
        .collect();
    files.sort();
    files
}

/// Where `needle` occurs in `sources`, ignoring comment lines — a prose
/// mention of a frozen sentence is documentation; a code literal is a second
/// source of truth.
fn occurrences(sources: &[(String, String)], needle: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for (path, text) in sources {
        for (number, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("<!--") || trimmed.starts_with('*')
            {
                continue;
            }
            if line.contains(needle) {
                hits.push(format!("{path}:{}", number + 1));
            }
        }
    }
    hits
}

#[test]
fn no_renderer_source_spells_a_frozen_verdict_string() {
    // Per-root, before anything is asserted about contents: a root that
    // contributes nothing is a scan that covers nothing, and it must say which
    // root went quiet (D131 §5 R2).
    for (relative, floor) in SCAN_ROOTS {
        let found = sources_under(relative).len();
        assert!(
            found >= floor,
            "the scan collected {found} file(s) under {relative}, below its floor of {floor} — \
             coverage of that root has gone to zero and the walk is broken, not the tree clean. \
             A file whose extension is outside `walk`'s list is invisible here: that is how \
             `index.html.template` would have been (D131 §1 a)."
        );
    }
    let sources = renderer_sources();

    let mut offenders = Vec::new();
    for (needle, what) in single_sourced() {
        for hit in occurrences(&sources, &needle) {
            offenders.push(format!("{hit}: {what} — `{needle}`"));
        }
    }
    assert!(
        offenders.is_empty(),
        "verdict wording is spelled outside the table in {} scanned renderer files:\n  {}\n\
         Renderers receive final strings from `antseal_core::verify::wording` (R18).",
        sources.len(),
        offenders.join("\n  ")
    );
}

#[test]
fn every_recorded_residue_is_still_there() {
    // The CLI root and nothing else (D131 §5 R3). `RESIDUE`'s own definition
    // says these are sentences that still live in **`antseal-cli`**, and over
    // the union a page-side copy of a needle keeps this test green through a
    // deletion of the CLI's copy — masking exactly the rot it exists to catch.
    // The two file-walking tests want opposite domains: the ban is about
    // everywhere, this is about one place.
    let sources = sources_under(SCAN_ROOTS[0].0);
    let mut vanished = Vec::new();
    for (needle, reason, question) in RESIDUE {
        if occurrences(&sources, needle).is_empty() {
            vanished.push(format!("`{needle}` ({reason}) — open question: {question}"));
        }
    }
    assert!(
        vanished.is_empty(),
        "these residue entries no longer exist. If the wording moved onto the table, delete the \
         entry deliberately (and answer its question in the row that moved it):\n  {}",
        vanished.join("\n  ")
    );
}

/// The scan must be able to fail — a nonzero result on a real tree proves
/// nothing about the predicate, so the predicate is run against a corpus
/// with a planted copy of a frozen sentence.
#[test]
fn the_source_scan_catches_a_planted_copy_of_a_frozen_sentence() {
    let planted = vec![
        (
            "crates/antseal-cli/src/planted.rs".to_owned(),
            format!("    out.push(\"{UNANCHORED_BANNER}\".to_owned());\n"),
        ),
        (
            "crates/antseal-cli/src/prose.rs".to_owned(),
            format!("    // the banner is `{UNANCHORED_BANNER}` and lives in the table\n"),
        ),
    ];
    let hits = occurrences(&planted, UNANCHORED_BANNER);
    assert_eq!(
        hits,
        vec!["crates/antseal-cli/src/planted.rs:1"],
        "the scan must catch the code literal and ignore the prose mention"
    );

    // R89's entry, planted on its own. The generic plant above proves the
    // *predicate* is fallible; this proves it fires on **this** needle, which
    // is the claim the entry actually makes. The live failure classes were
    // spelled in `antseal-net` until R89, so a renderer re-spelling one is
    // exactly the regression the entry exists to catch, and a needle that
    // could never be hit would be the silent version of that.
    let refused = live_fetch_failure_class_label(FetchFailureClass::BackendRefused);
    let planted_class = vec![
        (
            "crates/antseal-cli/src/planted_live.rs".to_owned(),
            format!("    rows.push(format!(\"{{subject}}: fetch failed ({refused})\"));\n"),
        ),
        (
            "crates/antseal-cli/src/live_prose.rs".to_owned(),
            format!("    // the class renders as `{refused}`; the table owns it\n"),
        ),
    ];
    assert_eq!(
        occurrences(&planted_class, refused),
        vec!["crates/antseal-cli/src/planted_live.rs:1"],
        "the backend-refused needle must catch a renderer copy and ignore prose"
    );
}

/// Every `.rs`, `.html`, `.js` and `.css` file under `dir`, recursively.
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                stack.push(path);
            } else if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| matches!(ext, "rs" | "html" | "js" | "css"))
            {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}
