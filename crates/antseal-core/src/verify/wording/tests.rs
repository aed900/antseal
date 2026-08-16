//! Row-level pins for the frozen wording set (**R18**).
//!
//! These are the per-row obligations — the spec's verbatim strings, D64's
//! structural tokens, D95 rider (a)'s ungated `fetch_date` label, Q89's
//! divergent datum names, R53's reserved phrase. The whole-document
//! **snapshot**, the exhaustive-enumeration sweep over [`AnchorState`], the
//! positioning checklist and the CLI/page source scan live in the integration
//! test `crates/antseal-core/tests/verdict_wording.rs`, which is native-only
//! (it reads committed files); everything here is pure string assembly and
//! runs in the wasm32 `--lib` lane too.

use super::*;

// ---------------------------------------------------------------------------
// the spec's own words
// ---------------------------------------------------------------------------

/// Every string MVP-SPEC.md dictates outright, checked as a literal against
/// the row that must carry it. A paraphrase here is a spec deviation, not a
/// style choice — so the expectations are written out rather than derived.
#[test]
fn the_spec_mandated_strings_appear_verbatim() {
    assert_eq!(
        UNANCHORED_BANNER, "UNANCHORED — integrity and signature only, no provable time",
        "MVP-SPEC.md line 137"
    );
    assert_eq!(
        RECEIPT_CLASS, "supporting evidence — no independently proven time",
        "MVP-SPEC.md lines 110 and 137"
    );
    assert_eq!(
        CLAIMED_TIME_LABEL, "asserted by sealer — NOT verified",
        "MVP-SPEC.md line 137"
    );
    assert_eq!(
        PENDING_GUIDANCE,
        "not yet independently provable — ask the sealer to run `status --upgrade`",
        "MVP-SPEC.md line 132"
    );
    assert_eq!(
        signature_scheme_label(SignatureScheme::HybridPq),
        "hybrid (PQ)",
        "MVP-SPEC.md line 97"
    );
    assert_eq!(
        signature_scheme_label(SignatureScheme::Ed25519Only),
        "Ed25519-only",
        "MVP-SPEC.md line 97"
    );
    // Line 108's `attested` sentence, with the spec's `H` filled in.
    assert_eq!(
        attested_block_line(700_113),
        "ops commit `anchor_digest` to the merkle root of Bitcoin block 700113 (header \
         embedded); a provable time requires `--online` confirmation",
        "MVP-SPEC.md line 108"
    );
    // Line 118's two clauses, each on the layer it belongs to.
    assert!(
        EVIDENCE_LAYER_LABEL.contains("this alone carries the evidentiary verdict"),
        "{EVIDENCE_LAYER_LABEL}"
    );
    assert!(
        STORAGE_LINKAGE_LAYER_LABEL.contains("storage is the product's bonus, not its proof"),
        "{STORAGE_LINKAGE_LAYER_LABEL}"
    );
}

/// MVP-SPEC.md line 137's headline template, and the two authored departures
/// from its rendering (module docs on [`headline_sentence`]): lower case, and
/// the kind inside the parenthesis beside the source.
#[test]
fn the_headline_sentence_is_the_spec_template_with_its_two_recorded_departures() {
    let line = headline_sentence(
        1_785_000_000,
        AnchorKind::Tsa,
        &source_slot(Some("CN=example")),
    );
    assert_eq!(line, "existed no later than 1785000000 (tsa, CN=example)");
    assert!(
        !line.starts_with("Existed"),
        "the lower-case rendering is the frozen one — it never starts a sentence"
    );
    assert_eq!(
        headline_sentence(1, AnchorKind::Ots, &source_slot(None)),
        format!("existed no later than 1 (ots, {SOURCE_NOT_RECORDED})"),
        "a missing source falls back inside the slot, never to an empty parenthesis"
    );
}

// ---------------------------------------------------------------------------
// the [H] map and the seven state rows
// ---------------------------------------------------------------------------

/// The `[H]` tag is A1's single predicate wearing a label — not a second
/// eligibility table. Checked against a hand-written expectation so that a
/// silent change to the predicate reddens here as well as in `aggregate`.
#[test]
fn exactly_the_two_time_proving_states_carry_the_headline_tag() {
    let mut tagged = Vec::new();
    for state in AnchorState::ALL {
        // Wildcard-free: an eighth state fails to compile until someone
        // decides, by hand, whether it proves a time.
        let expected_tag = match state {
            AnchorState::Proven | AnchorState::ValidAtStampingCertSinceExpired => "[H]",
            AnchorState::Attested
            | AnchorState::Pending
            | AnchorState::InternallyConsistentOnly
            | AnchorState::Invalid
            | AnchorState::Absent => "",
        };
        assert_eq!(
            headline_tag(state),
            expected_tag,
            "{} carries the wrong headline tag",
            state.wire_name()
        );
        if !expected_tag.is_empty() {
            tagged.push(state.wire_name());
        }
    }
    assert_eq!(
        tagged,
        vec!["proven", "valid-at-stamping-cert-since-expired"],
        "MVP-SPEC.md lines 129–130 tag exactly these two"
    );
}

/// Every state row names its state, carries its tag when it has one, and says
/// something distinct. The distinctness half is the negative control: two
/// states sharing a meaning would render one taxonomy under seven names.
#[test]
fn every_state_row_is_state_word_then_tag_then_a_distinct_meaning() {
    let mut seen: Vec<&'static str> = Vec::new();
    for state in AnchorState::ALL {
        let row = anchor_state_line(state);
        let word = state.wire_name();
        assert!(row.starts_with(word), "{row} does not lead with `{word}`");
        let tagged = row.starts_with(&format!("{word} {HEADLINE_TAG} — "));
        let untagged = row.starts_with(&format!("{word} — "));
        assert!(
            tagged != untagged,
            "the row must be `<state> [H] — <meaning>` or `<state> — <meaning>`: {row}"
        );
        assert_eq!(
            tagged,
            !headline_tag(state).is_empty(),
            "the row's tag disagrees with the predicate: {row}"
        );
        let meaning = state_meaning(state);
        assert!(
            !seen.contains(&meaning),
            "two states share one meaning: {word}"
        );
        seen.push(meaning);
    }
    assert_eq!(
        seen.len(),
        7,
        "MVP-SPEC.md lines 129–135 define seven states"
    );
}

/// R18's Do names one phrasing explicitly: the expired-certificate state must
/// still read as *proven at stamping*, because aging bundles must not
/// silently rot (MVP-SPEC.md line 130).
#[test]
fn the_expired_certificate_state_keeps_its_valid_at_stamping_phrasing() {
    let row = anchor_state_line(AnchorState::ValidAtStampingCertSinceExpired);
    assert!(
        row.contains("valid at stamping; certificate since expired"),
        "{row}"
    );
    assert!(row.contains("independently proven"), "{row}");
    assert!(
        row.contains(HEADLINE_TAG),
        "it stays headline-eligible: {row}"
    );
}

/// The two `pending` audiences are the table's first declared divergence: the
/// page tells a counterparty to ask the sealer; `antseal status` tells the
/// sealer to run it (D98 rider 5). They must not collapse into one string.
#[test]
fn the_pending_guidance_has_two_audiences_and_one_shared_opening() {
    assert_ne!(PENDING_GUIDANCE, PENDING_GUIDANCE_SELF);
    let opening = "not yet independently provable";
    assert!(PENDING_GUIDANCE.starts_with(opening), "{PENDING_GUIDANCE}");
    assert!(
        PENDING_GUIDANCE_SELF.starts_with(opening),
        "{PENDING_GUIDANCE_SELF}"
    );
    assert!(
        PENDING_GUIDANCE.contains("ask the sealer"),
        "the page's reader is a third party: {PENDING_GUIDANCE}"
    );
    assert!(
        !PENDING_GUIDANCE_SELF.contains("ask the sealer"),
        "status' reader is the sealer: {PENDING_GUIDANCE_SELF}"
    );
    assert_eq!(
        pending_guidance_self_line("`antseal status abc --upgrade`"),
        "not yet independently provable — run `antseal status abc --upgrade`"
    );
}

// ---------------------------------------------------------------------------
// the `claimed_time` register — D95 rider (a) and Q89
// ---------------------------------------------------------------------------

/// **D95 rider (a).** The fetch date renders subordinate, labelled
/// sealer-recorded and NOT verified, in *every* state — and the sentence
/// forecloses the corroboration reading a reader is likeliest to make beside
/// a refuted anchor.
///
/// The no-state-gate half is structural: [`fetch_date_line`] takes no
/// [`AnchorState`], so this asserts the property the type already enforces —
/// one string for all seven — rather than trusting a branch.
#[test]
fn the_fetch_date_row_is_ungated_by_state_and_claims_no_corroboration() {
    let line = fetch_date_line("1785600000");
    assert_eq!(
        line,
        "fetch date: 1785600000 (sealer-recorded — NOT verified; it is not evidence for the \
         state above)"
    );
    for state in AnchorState::ALL {
        // Every state's slot renders the same row beneath the same kind of
        // state line; `invalid` is the case D95 names and R18's Accept
        // demands (see the snapshot's per-state blocks).
        let block = format!("{}\n    {line}", anchor_state_line(state));
        assert!(
            block.contains(&line),
            "the fetch date must render under {}",
            state.wire_name()
        );
    }
    let refuted = format!("{}\n    {line}", anchor_state_line(AnchorState::Invalid));
    assert!(refuted.contains("this anchor proves nothing"), "{refuted}");
    assert!(
        line.contains("NOT verified") && line.contains("not evidence"),
        "beside a refutation an unlabelled date reads as corroboration: {line}"
    );
}

/// **Q89's rule applied to the two sealer-written times.** Both are unverified
/// and both are subordinate, so the only thing keeping them apart is their
/// datum names — "claimed time" vs "fetch date", "asserted by" vs
/// "sealer-recorded". A shared label would print one datum twice.
#[test]
fn the_claimed_time_and_fetch_date_registers_are_named_apart() {
    let claimed = claimed_time_line("1780000000");
    let fetched = fetch_date_line("1785600000");
    assert_ne!(CLAIMED_TIME_LABEL, FETCH_DATE_LABEL);
    assert!(claimed.starts_with("claimed time: "), "{claimed}");
    assert!(fetched.starts_with("fetch date: "), "{fetched}");
    for line in [&claimed, &fetched] {
        assert!(
            line.contains("NOT verified"),
            "both registers carry the un-verified marker: {line}"
        );
        assert!(
            !line.contains("existed no later than"),
            "neither may take a headline shape: {line}"
        );
    }
}

/// The verified time and the two sealer-written times are three different
/// claims, and only one of them says "independently proven".
#[test]
fn only_the_verified_time_row_claims_independent_proof() {
    let verified = verified_time_line(1_785_000_000);
    assert_eq!(verified, "independently proven time: 1785000000");
    for line in [claimed_time_line("1"), fetch_date_line("1")] {
        assert!(
            !line.contains("independently proven"),
            "a sealer-written time never claims proof: {line}"
        );
    }
}

/// R74/D95 rider (b): one table answers "was this identity verified?", so the
/// two answers are one function's two arms and are visibly different.
#[test]
fn the_source_line_labels_a_claimed_identity_apart_from_a_verified_one() {
    let verified = source_line("CN=example", true);
    let claimed = source_line("CN=example", false);
    assert_eq!(verified, "source: CN=example (verified by this run)");
    assert_eq!(
        claimed,
        "source: CN=example (claimed by the artifact — this run did not verify it)"
    );
    assert_ne!(verified, claimed);
    assert!(
        !claimed.contains("verified by"),
        "the claimed arm must not contain the verified arm's claim: {claimed}"
    );
}

// ---------------------------------------------------------------------------
// receipt, signature, layers, mirror
// ---------------------------------------------------------------------------

/// The receipt's own rows stay in the supporting-evidence register: the class
/// line is the spec's sentence, and the detail line carries figures with no
/// time and no state word.
#[test]
fn the_receipt_rows_carry_figures_but_never_a_time_or_a_state() {
    let class = receipt_class_line();
    let detail = receipt_detail_line(377_262_147, 1);
    assert_eq!(class, format!("receipt: {RECEIPT_CLASS}"));
    assert!(detail.contains("Arbitrum block 377262147"), "{detail}");
    assert!(detail.contains("never this work's time"), "{detail}");
    for line in [&class, &detail] {
        // The one "proven" the receipt register admits is the spec's own
        // negation; strip it and nothing state-shaped may remain.
        let residue = line.replace(RECEIPT_CLASS, "");
        for word in ["proven", "attested", "invalid", "existed no later than"] {
            assert!(
                !residue.contains(word),
                "the receipt register admits no `{word}`: {line}"
            );
        }
    }
}

/// Four schemes, four spellings, and the two that are *not* verdicts must not
/// read as one. `not-evaluated` in particular may never read as "unsigned" or
/// as "signatures failed" (the field's own doc makes that normative).
#[test]
fn the_signature_labels_are_distinct_and_the_unevaluated_one_claims_nothing() {
    let labels: Vec<&str> = SignatureScheme::ALL
        .iter()
        .map(|scheme| signature_scheme_label(*scheme))
        .collect();
    let mut unique = labels.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), labels.len(), "two schemes share a label");

    let not_evaluated = signature_scheme_label(SignatureScheme::NotEvaluated);
    assert!(
        not_evaluated.contains("says nothing about the bundle's signatures in either direction"),
        "{not_evaluated}"
    );
    for banned in ["unsigned", "failed", "invalid"] {
        assert!(
            !not_evaluated.contains(banned),
            "`{banned}` turns a not-run stage into a verdict: {not_evaluated}"
        );
    }
    let other = signature_scheme_label(SignatureScheme::Other);
    assert!(
        other.contains("checked and passed"),
        "a registered policy that passed must not read as unchecked: {other}"
    );
    assert!(
        !other.contains("ml-dsa") && !other.contains("ed25519"),
        "report v1 carries no algorithm list, so no row may name one: {other}"
    );
    assert_eq!(
        signature_scheme_line(SignatureScheme::HybridPq),
        "signature scheme: hybrid (PQ)"
    );
}

/// **R53's policy, as wording.** The phrase "the original file" is reserved
/// for a full reveal's mirror; the partial-reveal policy row exists to say so
/// and is the only other row allowed to contain the phrase — inside a
/// negation.
#[test]
fn the_original_file_phrase_is_reserved_to_a_full_reveals_mirror() {
    let full = mirror_full_reveal_line(4096);
    assert!(full.contains(MIRROR_ORIGINAL_FILE_PHRASE), "{full}");
    assert!(full.contains("open the raw commitment"), "{full}");
    assert!(
        MIRROR_PARTIAL_REVEAL_POLICY
            .contains(&format!("never presented as {MIRROR_ORIGINAL_FILE_PHRASE}")),
        "{MIRROR_PARTIAL_REVEAL_POLICY}"
    );
    assert!(
        MIRROR_PARTIAL_REVEAL_POLICY.contains("ordinary revealed unit"),
        "the partial-reveal mirror is verified — it is simply not the file: \
         {MIRROR_PARTIAL_REVEAL_POLICY}"
    );
    // Negative control: the phrase is short enough to appear by accident, so
    // the sweep that guards it (integration test) must be able to see a
    // planted violation. Prove the predicate it uses is not vacuous.
    let planted = format!("raw mirror: {MIRROR_ORIGINAL_FILE_PHRASE}, unbound");
    assert!(planted.contains(MIRROR_ORIGINAL_FILE_PHRASE));
}

/// The three layers are named apart, and only the evidence layer claims a
/// verdict — MVP-SPEC.md line 118's whole point, and the reason storage may
/// never gate it.
#[test]
fn only_the_evidence_layer_label_claims_the_verdict() {
    let labels = [
        EVIDENCE_LAYER_LABEL,
        STORAGE_LINKAGE_LAYER_LABEL,
        LIVE_LAYER_LABEL,
    ];
    let mut unique = labels.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), 3, "two layers share a label");
    assert!(
        EVIDENCE_LAYER_LABEL.contains("verdict"),
        "{EVIDENCE_LAYER_LABEL}"
    );
    assert!(
        STORAGE_LINKAGE_LAYER_LABEL.contains("not its proof"),
        "{STORAGE_LINKAGE_LAYER_LABEL}"
    );
    assert!(
        LIVE_LAYER_LABEL.contains("advisory") && LIVE_LAYER_LABEL.contains("gates no verdict"),
        "{LIVE_LAYER_LABEL}"
    );
    // The storage rows say the same thing the label does: a failure here
    // leaves the evidence verdict where it was.
    let fail = storage_linkage_fail_line(1, 4);
    assert!(
        fail.contains("the evidence verdict above is unchanged"),
        "{fail}"
    );
    assert!(
        storage_linkage_pass_line(4).contains("recompute to the addresses the manifest records"),
        "{}",
        storage_linkage_pass_line(4)
    );
    assert!(
        storage_linkage_not_evaluated_line().contains("says nothing about where the work is"),
        "{}",
        storage_linkage_not_evaluated_line()
    );
}

/// The four `--live` verdicts render four different sentences, and none of
/// them touches the evidence register.
#[test]
fn the_live_verdict_rows_are_four_distinct_advisory_sentences() {
    let rows = [
        live_all_persisted_line(3),
        live_divergent_line(1),
        live_some_missing_line(2),
        live_inconclusive_line(1),
    ];
    let mut unique = rows.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        rows.len(),
        "two live verdicts share a sentence"
    );
    for row in &rows {
        assert!(row.starts_with("live check: "), "{row}");
        for word in ["proven", "attested", "existed no later than"] {
            assert!(!row.contains(word), "the live layer proves no time: {row}");
        }
    }
    assert!(
        live_divergent_line(1).contains("should be impossible"),
        "content addressing makes divergence the loudest outcome"
    );
    let blob_rows = [
        live_blob_identical_line("unit 7"),
        live_blob_different_line("unit 7"),
        live_blob_not_found_line("unit 7"),
        live_blob_fetch_error_line("unit 7", "timeout"),
    ];
    let mut unique_blobs = blob_rows.to_vec();
    unique_blobs.sort_unstable();
    unique_blobs.dedup();
    assert_eq!(
        unique_blobs.len(),
        4,
        "two per-blob outcomes share a sentence"
    );
}

/// One spelling of the >48 h rule, two prefixes — the offline flag and the
/// overlay's change-only delta must not drift into two different thresholds
/// in prose.
#[test]
fn the_two_divergence_lines_share_one_spelling_of_the_48_hour_rule() {
    let flagged = divergence_flag_line(1_000, 200_000);
    let newly = divergence_newly_flagged_line(1_000, 200_000);
    assert_ne!(flagged, newly);
    for line in [&flagged, &newly] {
        assert!(line.contains(DIVERGENCE_PHRASE), "{line}");
        assert!(line.contains("(earliest 1000, latest 200000)"), "{line}");
    }
    assert!(flagged.starts_with("flagged: "), "{flagged}");
    assert!(newly.starts_with("newly flagged: "), "{newly}");
}

/// MVP-SPEC.md line 28's two limits, stated in the verdict's own copy.
#[test]
fn the_seal_meaning_note_states_both_limits() {
    assert!(
        SEAL_MEANING_NOTE.contains("possessed"),
        "{SEAL_MEANING_NOTE}"
    );
    assert!(
        SEAL_MEANING_NOTE.contains("not authorship"),
        "{SEAL_MEANING_NOTE}"
    );
    assert!(
        SEAL_MEANING_NOTE.contains("not exclusive possession"),
        "{SEAL_MEANING_NOTE}"
    );
}

// ---------------------------------------------------------------------------
// D64's overlay structure (R17's rows, frozen unchanged)
// ---------------------------------------------------------------------------

/// D64 §3's frozen template unity, checked mechanically: the Supplies
/// line **is** the one headline template with a decorated source slot —
/// not a second sentence shape. Fails if `supplies_line` ever composes
/// its own "existed no later than"-class string.
#[test]
fn the_supplies_line_is_the_one_headline_template_with_the_marker_in_the_source_slot() {
    let headline = Headline::fixture(1_700_000_000, AnchorKind::Ots, Some("bitcoin-block-42"));
    let line = supplies_line(&headline);
    assert_eq!(
        line,
        headline_sentence(
            1_700_000_000,
            AnchorKind::Ots,
            &online_source_slot(Some("bitcoin-block-42")),
        )
    );
    assert!(
        line.contains(ONLINE_ATTRIBUTION_MARKER),
        "the attribution marker is D64 §3.1's mandatory element: {line}"
    );
    // The offline form of the same headline differs ONLY in the slot
    // decoration — same template, two provenance labels (Q89 via D64 §3).
    let offline = headline_sentence(
        1_700_000_000,
        AnchorKind::Ots,
        &source_slot(Some("bitcoin-block-42")),
    );
    assert_ne!(line, offline, "the marker must be visible");
    assert_eq!(
        line.replace(&online_source_slot(Some("bitcoin-block-42")), ""),
        offline.replace(&source_slot(Some("bitcoin-block-42")), ""),
        "outside the source slot the two sentences are byte-identical — one template"
    );
}

/// D64 §8's structural obligations on the framing sentence — these
/// tokens are frozen structure: the heading contains "online" and
/// "advisory", refers to the verdict **above**, and discloses refutation.
#[test]
fn the_framing_line_carries_every_d64_structural_token() {
    let framing = overlay_framing_line();
    for token in ["online", "advisory", "above", "refute"] {
        assert!(
            framing.contains(token),
            "D64 §8 freezes `{token}` into the framing structure: {framing}"
        );
    }
}

/// D64 §8: a state word appears **only** on the refutation line. The
/// promotion, disagreement, failure and no-evidence lines must not spell
/// one — `proven` on the promoted line is the natural wrong rendering
/// this pins against.
#[test]
fn state_words_appear_on_the_refutation_line_and_nowhere_else() {
    let failures = [EndpointProbeFailure {
        endpoint: "https://esplora.example".to_owned(),
        class: ProbeFailureClass::Transport,
    }];
    let stateless = [
        promoted_line("ots-1", 42, 1_700_000_000, Some("bitcoin-block-42")),
        disagreed_line("ots-1", 42),
        endpoint_failures_line("ots-1", 42, &failures),
        no_evidence_line("ots-1", 42),
    ];
    for line in &stateless {
        for word in ["proven", "invalid", "attested"] {
            assert!(
                !line.contains(word),
                "`{word}` is a state word; D64 §8 allows one only on refutation: {line}"
            );
        }
    }
    assert!(
        refuted_line("ots-1", "anchor-ots-online-header-mismatch").contains("invalid"),
        "the refutation line is the one place the state word is mandatory"
    );
}

/// The receipt echo lines stay in the supporting-evidence register: no state
/// word, no time-shaped claim (D64 §5's report-side model — the arm
/// carries "no time field and no state field").
#[test]
fn receipt_lines_carry_no_state_word_and_no_headline_shape() {
    let lines = [
        receipt_confirmed_line(ARBITRUM_ONE, 200_000_001, true),
        receipt_confirmed_line(ARBITRUM_ONE, 200_000_001, false),
        receipt_not_on_chain_line(ARBITRUM_ONE),
        receipt_disagreed_line().to_owned(),
        receipt_failed_line(&[]),
    ];
    for line in &lines {
        for word in ["proven", "invalid", "attested", "existed no later than"] {
            assert!(
                !line.contains(word),
                "the receipt register admits no `{word}`: {line}"
            );
        }
    }
}

// ── D137 §3 R1/R2 — the receipt lines name the chain they were probed on ───

/// The two chain ids the surfaces can actually probe.
///
/// Literals, with the names they mirror: **core cannot see `antseal-net`**
/// (D137 §1 (h)), which is the same measurement that makes the wording
/// parameter a `u64` rather than a network name. If either ever disagrees with
/// `antseal_net::network`, the guard's own test — which asserts against the
/// real constants — is what says so: `chain_id_mismatch_is_unavailable_not_agreed`,
/// in the **antseal-anchor** crate at `src/arbitrum/confirm/tests.rs:438`.
/// Two corrections carried here rather than left to the next reader: it is not
/// "the CLI's" (the CLI renders the guard's outcome and owns none of it), and
/// this crate's `doc_pointer_liveness` sweep is scoped to `antseal-core`, so
/// the pointer cannot resolve from here and is carried in that test's
/// `ALLOWED` list with its reason, in the cross-crate form Q70 will one day
/// retire.
const ARBITRUM_ONE: u64 = 42_161; // antseal_net::network::ARBITRUM_ONE_CHAIN_ID
const ARBITRUM_SEPOLIA: u64 = 421_614; // antseal_net::network::ARBITRUM_SEPOLIA_CHAIN_ID

/// **D137 §3 R1 — the two receipt lines that assert *where* a transaction is
/// must name the chain they were probed on.**
///
/// The defect this pins (R85): *"both RPC endpoints agree the recorded
/// transaction is not on chain"* asserts absence from **every** chain, from a
/// measurement that only ever reached one. Its neighbour was wrong in the
/// worse direction — an unqualified *"on Arbitrum"* confirmation renders a
/// **testnet** payment as evidence for the seal.
///
/// The first assertion is the one with teeth. On the page the chain id can only
/// ever be 42161, so an implementation that interpolated the page's pinned
/// constant instead of its own parameter would satisfy every `contains` check
/// here and fail **only** the differential (D137 §2 (c)'s recorded trap).
#[test]
fn the_receipt_lines_name_the_chain_they_were_probed_on() {
    const BLOCK: u64 = 200_000_001;

    let absent_one = receipt_not_on_chain_line(ARBITRUM_ONE);
    let absent_sepolia = receipt_not_on_chain_line(ARBITRUM_SEPOLIA);
    let confirmed_one = receipt_confirmed_line(ARBITRUM_ONE, BLOCK, true);
    let confirmed_sepolia = receipt_confirmed_line(ARBITRUM_SEPOLIA, BLOCK, true);

    // 1. The differential: two chains must render two different lines.
    assert_ne!(
        absent_one, absent_sepolia,
        "two chains must render two different lines, and the absence line rendered one string for \
         both:\n  42161  -> {absent_one}\n  421614 -> {absent_sepolia}\nAn implementation that \
         interpolates a pinned constant instead of its `chain_id` parameter fails here and \
         nowhere else (D137 §6.1)"
    );
    assert_ne!(
        confirmed_one, confirmed_sepolia,
        "two chains must render two different lines, and the confirmation line rendered one \
         string for both:\n  42161  -> {confirmed_one}\n  421614 -> {confirmed_sepolia}\nAn \
         implementation that interpolates a pinned constant instead of its `chain_id` parameter \
         fails here and nowhere else (D137 §6.1)"
    );

    // 2. Exact values, read back in full. NEVER `contains`: "42161" is a
    //    prefix of "421614", so a containment check for the mainnet id passes
    //    on the Sepolia line — an assertion that cannot fail in the one
    //    direction it exists to catch.
    assert_eq!(
        absent_one,
        "receipt: both RPC endpoints agree the recorded transaction is not on Arbitrum chain \
         42161 — supporting evidence only"
    );
    assert_eq!(
        absent_sepolia,
        "receipt: both RPC endpoints agree the recorded transaction is not on Arbitrum chain \
         421614 — supporting evidence only"
    );
    assert_eq!(
        confirmed_one,
        "receipt: both RPC endpoints confirm the recorded transaction on Arbitrum chain 42161 \
         (block 200000001) — supporting evidence only"
    );
    assert_eq!(
        confirmed_sepolia,
        "receipt: both RPC endpoints confirm the recorded transaction on Arbitrum chain 421614 \
         (block 200000001) — supporting evidence only"
    );
    assert_eq!(
        receipt_confirmed_line(ARBITRUM_SEPOLIA, BLOCK, false),
        "receipt: both RPC endpoints confirm the recorded transaction on Arbitrum chain 421614 \
         (block 200000001; the transaction reverted) — supporting evidence only"
    );

    // 3. The old universal claim is gone. A "fix" that appended the chain id
    //    while leaving "is not on chain" intact would read as two claims, the
    //    first of them still false.
    for line in [&absent_one, &absent_sepolia] {
        assert!(
            !line.contains("is not on chain "),
            "the unqualified clause `is not on chain ` survives in: {line}"
        );
    }

    // 4. Neither line names the other's chain. One direction only, and that is
    //    the point: 42161 IS a substring of 421614, so the reverse check is
    //    unwritable and assertion 2 is what covers it.
    for line in [&absent_one, &confirmed_one] {
        assert!(
            !line.contains("421614"),
            "a mainnet line names Sepolia's chain id: {line}"
        );
    }
}

/// The endpoints disclosure flips its label with the override flag — the
/// R24 "departing from pinned defaults" datum, sourced here and nowhere
/// page-authored (D64 §8 edit 5). Differential: same identities, one
/// flag, two different lines.
#[test]
fn the_endpoints_line_labels_an_override_as_departing_from_pinned_defaults() {
    let identities = vec![
        "https://a.example".to_owned(),
        "https://b.example".to_owned(),
    ];
    let pinned = endpoints_line(&identities, false);
    let overridden = endpoints_line(&identities, true);
    assert_ne!(pinned, overridden);
    assert!(pinned.contains("pinned defaults"), "{pinned}");
    assert!(
        overridden.contains("departing from pinned defaults"),
        "{overridden}"
    );
}

/// Slot names follow the U23 kind-plus-ordinal convention the overlay's
/// rows must share with the offline block (D64 §6.2).
#[test]
fn slot_names_are_kind_dash_ordinal() {
    assert_eq!(slot_name(AnchorKind::Ots, 1), "ots-1");
    assert_eq!(slot_name(AnchorKind::Tsa, 2), "tsa-2");
}
