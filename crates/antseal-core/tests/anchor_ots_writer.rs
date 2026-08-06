//! **A82's reachability proof.** The synthetic `.ots` writer is usable from a
//! separate crate.
//!
//! That is the whole point of promoting it out of `anchor::verdicts::tests`,
//! and it is not something the unit suite can demonstrate: a `#[cfg(test)]`
//! item in `antseal-core` is invisible to `crates/antseal-core/tests/`, which
//! compiles as its own crate against the *library*. A21's tamper rows and
//! every future `anchor-*` row live on this side of that boundary, so if this
//! file does not compile, the promotion did not happen.
//!
//! # The artifact it mints, and why that one
//!
//! A **single-branch, ops-committing** upgraded `.ots` — the shape no captured
//! artifact contains and the one D56's online refutation rules are actually
//! about (D93 §3). It is exercised through all three online answers, because a
//! row built on the wrong shape passes without the online gate ever running:
//! the *uncommitted* forgery is already `invalid` offline through rule O8, and
//! an artifact with a pending sibling renders `pending` under rule O5.
//!
//! # Not on wasm32
//!
//! `anchor::testing` is gated `cfg(any(test, feature = "test-util"))`, and the
//! wasm32 dev-dependency edge enables `test-vectors` only (`proptest` pulls
//! `getrandom`). The `wasm32-core-tests` lane runs `--lib`, so integration
//! targets are not built there at all; the attribute makes that a fact about
//! this file rather than a property of the lane's argv.

#![cfg(not(target_arch = "wasm32"))]

use antseal_core::anchor::model::{
    AnchorState, BlockEvidence, OnlineBlockResult, OnlineEvidence, OtsArtifactView,
};
use antseal_core::anchor::testing::ots_writer::{
    ATTESTED_HEIGHT, HEADER_NTIME, bitcoin, committed_single_branch, container, fork, header_with,
    pending, synthetic_digest,
};
use antseal_core::anchor::verdicts::{
    OTS_ONLINE_BLOCK_ABSENT_CODE, OTS_ONLINE_HEADER_MISMATCH_CODE, evaluate_ots_artifact,
};

/// The three answers one minted artifact gives, one per online input.
///
/// What makes it fail: any of the faults D93 §9 row 4 plants — reverting O4's
/// `!refuted_online` guard (`invalid` becomes `attested`), dropping the online
/// evidence (likewise), or weakening rule O3's whole-header equality to a
/// merkle-root comparison (`invalid` becomes `proven`).
#[test]
fn a_minted_single_branch_committed_ots_answers_all_three_online_cases() {
    let (digest, bytes, upgrade) = committed_single_branch(0x5e, ATTESTED_HEIGHT);
    let view = OtsArtifactView::from_parts(&bytes, Some(&upgrade));
    let embedded = *upgrade.block_header();

    // No evidence -> attested. The artifact is well-formed and its ops commit
    // the header, so there is nothing offline left to say about it.
    let offline = evaluate_ots_artifact(&view, &digest, &BlockEvidence::new());
    assert_eq!(offline.verdict().state(), AnchorState::Attested);
    assert_eq!(offline.verdict().verified_time_unix(), None);

    // The agreed header is the embedded one -> proven, at that header's nTime.
    let agreeing =
        OnlineEvidence::new().with_block(ATTESTED_HEIGHT, OnlineBlockResult::Header(embedded));
    let proven = evaluate_ots_artifact(&view, &digest, agreeing.blocks());
    assert_eq!(proven.verdict().state(), AnchorState::Proven);
    assert_eq!(
        proven.verdict().verified_time_unix(),
        Some(i64::from(HEADER_NTIME))
    );

    // Any other agreed header -> invalid, with rule O6's code.
    let refuting = OnlineEvidence::new().with_block(
        ATTESTED_HEIGHT,
        OnlineBlockResult::Header(header_with(&digest, HEADER_NTIME + 3600)),
    );
    let refuted = evaluate_ots_artifact(&view, &digest, refuting.blocks());
    assert_eq!(refuted.verdict().state(), AnchorState::Invalid);
    assert_eq!(
        refuted.verdict().diagnostic().map(|d| d.code()),
        Some(OTS_ONLINE_HEADER_MISMATCH_CODE)
    );

    // Agreed absence of the block -> invalid, with rule O7's code.
    let absent = OnlineEvidence::new().with_block(ATTESTED_HEIGHT, OnlineBlockResult::NoSuchBlock);
    let absent = evaluate_ots_artifact(&view, &digest, absent.blocks());
    assert_eq!(absent.verdict().state(), AnchorState::Invalid);
    assert_eq!(
        absent.verdict().diagnostic().map(|d| d.code()),
        Some(OTS_ONLINE_BLOCK_ABSENT_CODE)
    );
}

/// The two traps a row built on the wrong fixture falls into, measured here so
/// a lane writing an `anchor-*` row can see them fail rather than read about
/// them.
///
/// What makes it fail: nothing in the writer — this row is about the *shape*,
/// and it goes red if `committed_single_branch` ever stops being single-branch
/// or stops committing.
#[test]
fn the_two_wrong_fixture_shapes_never_reach_the_online_gate() {
    let refuting = OnlineEvidence::new().with_block(
        ATTESTED_HEIGHT,
        OnlineBlockResult::Header(header_with(&synthetic_digest(0x00), HEADER_NTIME)),
    );

    // (a) uncommitted: the header's merkle root is not what the ops derive, so
    // rule O8 convicts it with no online evidence at all.
    let digest = synthetic_digest(0x5f);
    let bytes = container(&digest, &bitcoin(ATTESTED_HEIGHT));
    let (_, _, elsewhere) = committed_single_branch(0x60, ATTESTED_HEIGHT);
    let view = OtsArtifactView::from_parts(&bytes, Some(&elsewhere));
    let outcome = evaluate_ots_artifact(&view, &digest, &BlockEvidence::new());
    assert_eq!(
        outcome.verdict().state(),
        AnchorState::Invalid,
        "the uncommitted forgery is already invalid offline"
    );

    // (b) a pending sibling: rule O5 fires first and the artifact is `pending`
    // whatever the online evidence says.
    let digest = synthetic_digest(0x61);
    let bytes = container(
        &digest,
        &fork(&[
            pending("https://alice.btc.calendar.opentimestamps.org"),
            bitcoin(ATTESTED_HEIGHT),
        ]),
    );
    let upgrade = committed_single_branch(0x61, ATTESTED_HEIGHT).2;
    let view = OtsArtifactView::from_parts(&bytes, Some(&upgrade));
    let outcome = evaluate_ots_artifact(&view, &digest, refuting.blocks());
    assert_eq!(
        outcome.verdict().state(),
        AnchorState::Pending,
        "a pending sibling out-votes every refutation (D56 section 4)"
    );
}
