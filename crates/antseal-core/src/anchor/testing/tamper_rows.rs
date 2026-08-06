//! **A21's eight M2 anchor tamper rows**, as exercises that both homes call.
//!
//! # Why the exercises live here and not in the row slice
//!
//! A21's Accept requires all eight rows to execute in the native **and** the
//! `wasm32-unknown-unknown` suites, and the two lanes cannot share a home:
//!
//! - the tamper harness ([`crate::test_util::tamper`]) is gated
//!   `#[cfg(feature = "test-util")]`, and the wasm32 dev edge enables
//!   `test-vectors` only — so the matrix slice is not even *compiled* for
//!   wasm32, let alone run;
//! - the wasm32 lane runs `cargo test -p antseal-core --lib`, so every target
//!   under `crates/antseal-core/tests/` is a separate crate that never
//!   executes there at all.
//!
//! A90's ruling (recorded in `tasks/A.md` before this task began) is
//! therefore that the rows are *driven from the matrix natively* and each
//! row's verdict assertion is *additionally* pinned as an in-module
//! `#[cfg(test)]` test beside A18's. That ruling leaves one hazard it does
//! not close: two homes asserting the same claim through two hand-written
//! copies of the exercise, which drift the first time a row is corrected in
//! one of them.
//!
//! This module closes it. Each row's exercise is written **once**, here,
//! under the same `any(test, feature = "test-util")` gate [`MockTsa`] and
//! [`ots_writer`](super::ots_writer) already carry — which is exactly the
//! pair of homes A21 needs, and the reason A82 promoted the `.ots` writer to
//! this module in the first place. The matrix slice
//! ([`crate::test_util::tamper_rows_anchor_verdicts`]) wraps each into an
//! `ActualOutcome`; the wasm32 half
//! (`crate::anchor::verdicts::tests`) asserts the same values. Native and
//! wasm32 therefore run the *same computation*, not two descriptions of it.
//!
//! # Reading the outcome: state or code, per row, never both by default
//!
//! [`RowOutcome`] is deliberately not derived from an `AnchorOutcome` by one
//! blanket rule. Row 4 renders `Invalid` **and** carries a diagnostic, and
//! D53 §8 binds it to the *state* (`verdict:invalid` is claimed exactly once
//! across the eight); rows 2, 6 and 8 also render `Invalid` and must pin
//! their *codes*, which is the structural reason those codes were minted at
//! all. A helper that guessed would silently re-bind row 4.
//!
//! So each row names its reader — [`code_of`] or [`state_of`] — and
//! [`code_of`] additionally refuses a verdict whose state is not `Invalid`,
//! so a row cannot keep reporting its code while the state regresses
//! underneath it.
//!
//! # Preconditions are outcomes, not `assert!`s
//!
//! Three rows depend on a fact about their *base* that is not the thing the
//! row asserts: row 3's mock token must really be provable against its own
//! root, row 4's forgery must be `attested` when evaluated offline, and row
//! 5's `attested` artifact must not be headline-eligible. Each is checked
//! inside the exercise and reported as [`RowOutcome::Precondition`], whose
//! payload is deliberately **not** a valid state name or code. The row then
//! goes red naming the reason instead of passing for the wrong one.
//!
//! Row 4's latch is the one D93 §9 requires by name: the uncommitted forgery
//! is already `invalid` offline through rule O8, so a lane that rebuilds the
//! row with that shape gets a green row that never ran the online gate. With
//! the latch it gets a red row that says so.

use crate::anchor::model::{
    AnchorState, BlockEvidence, OnlineBlockResult, OtsArtifactView, TsaArtifactView,
};
use crate::anchor::roots::{PinnedRoot, TsaRootStore};
use crate::anchor::verdicts::{AnchorOutcome, evaluate_ots_artifact, evaluate_tsa_artifact};
use crate::bundle::schema::OtsUpgrade;

use super::ots_writer::{
    ATTESTED_HEIGHT, DIGEST_UPGRADED_LARGE_TEST, FETCH_DATE, HEADER_NTIME, UPGRADED_LARGE_TEST,
    committing_upgrade, synthetic_digest,
};
use super::{MockTsa, MockTsaConfig};

// ── committed fixture material ──────────────────────────────────────────

/// A real merged **pending** `.ots` over three calendars (A25, 2026-08-02),
/// stamped over [`DIGEST_A`].
pub const MERGED_A: &[u8] =
    include_bytes!("../../../../../testdata/anchors/A25-bootstrap/merged-A.ots");

/// The digest [`MERGED_A`] was stamped over.
pub const DIGEST_A: [u8; 32] =
    *include_bytes!("../../../../../testdata/anchors/A25-bootstrap/digest-A.bin");

/// The **other** committed golden digest (the bundle vector's). Row 1 needs a
/// second real digest rather than a synthetic one so the mutation is
/// "verified against the wrong seal", not "verified against nonsense".
pub const DIGEST_B: [u8; 32] =
    *include_bytes!("../../../../../testdata/anchors/A25-bootstrap/digest-B.bin");

/// FreeTSA's real captured `TimeStampResp` (ECDSA P-384), stamped over
/// [`D60_STAMPED`].
pub const FREETSA: &[u8] =
    include_bytes!("../../../../../testdata/anchors/A25-bootstrap/D60-tsa-freetsa-resp.tsr");

/// The **BER twin** of [`FREETSA`]: the same token with its outer three
/// nesting levels re-encoded with BER indefinite lengths and EOC markers.
///
/// Proven to be *valid BER* — `TimeStampResp::from_ber` accepts it
/// (`tests/der_pin_eval.rs::der_pin_rejects_indefinite_length`) — so row 8
/// cannot pass by the artifact merely being malformed. One of the four
/// rejecting BER captures; the other three produce the same code and stay
/// named tests in that file, per D93 §9 row 8.
pub const BER_INDEFINITE_FREETSA: &[u8] =
    include_bytes!("../../../../../testdata/anchors/A25-bootstrap/D60-ber-indefinite-freetsa.tsr");

/// The digest all nine D60 TSA captures were taken over.
pub const D60_STAMPED: [u8; 32] = [
    0x08, 0x3f, 0x87, 0xdf, 0x00, 0xfd, 0x5c, 0x70, 0x3d, 0x35, 0xb8, 0x83, 0xd8, 0x35, 0x35, 0x64,
    0x4c, 0x68, 0x6f, 0x9e, 0x53, 0xf1, 0x58, 0x4d, 0x7d, 0xf1, 0x26, 0xab, 0xda, 0xbd, 0x69, 0xdf,
];

/// A verification instant comfortably inside every captured certificate's
/// validity window.
pub const AFTER_CAPTURE: u64 = 1_785_000_000;

/// The `genTime` the expiry pair's mock asserts. Equal to
/// [`super::DEFAULT_GEN_TIME`]; restated as `G` because rows 6 and 7 are one
/// differential expressed as offsets from it.
const G: u64 = super::DEFAULT_GEN_TIME;

/// A root store that trusts nothing.
///
/// Rows 2 and 3 both need it, for different reasons that are worth keeping
/// apart: row 3 *is* the untrusted-root case, while row 2 uses it as the
/// instrument that makes its ordering claim observable (see
/// [`row_2_tsa_imprint_mismatch`]).
fn empty_store() -> TsaRootStore {
    const NONE: &[PinnedRoot] = &[];
    TsaRootStore::from_static(NONE)
}

// ── outcome readers ─────────────────────────────────────────────────────

/// What one row's exercise observed.
///
/// Deliberately free of any dependency on the tamper harness's own
/// `ActualOutcome`, which lives behind the `test-util` feature the wasm32
/// lane does not enable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowOutcome {
    /// The verdict is `invalid` and carries this stable diagnostic code.
    Error(&'static str),
    /// The verdict rendered this state (wire name).
    Verdict(&'static str),
    /// A fact the row's *base* depends on did not hold. The payload is not a
    /// state name or a code, so whichever home reads it goes red naming the
    /// reason rather than passing for a different one.
    Precondition(&'static str),
}

/// Read a row's outcome as a **diagnostic code**, refusing a verdict whose
/// state is not `Invalid`.
///
/// The state check is what stops the code from being reported while the
/// state regresses underneath it — a code without its state is half a claim.
fn code_of(outcome: &AnchorOutcome) -> RowOutcome {
    let verdict = outcome.verdict();
    if verdict.state() != AnchorState::Invalid {
        return RowOutcome::Precondition("expected-invalid-state");
    }
    match verdict.diagnostic() {
        Some(diagnostic) => RowOutcome::Error(diagnostic.code()),
        None => RowOutcome::Precondition("invalid-without-a-diagnostic"),
    }
}

/// Read a row's outcome as a **verdict state**.
fn state_of(outcome: &AnchorOutcome) -> RowOutcome {
    RowOutcome::Verdict(outcome.verdict().state().wire_name())
}

// ── the eight rows ──────────────────────────────────────────────────────

/// **Row 1** — `anchor-ots-digest-mismatch`.
///
/// A real merged pending `.ots` verified against the *other* committed golden
/// digest. No byte of the artifact is patched: the mutation is which seal it
/// is checked against, which is the shape D56 rule O2 is about.
///
/// The check is one 32-byte comparison inside `parse_ots`, before the walk
/// (D58 §10.3 step 5), so a wrong-digest `.ots` is never a work amplifier.
///
/// **Planted faults that must redden it** (D93 §9): make `parse_ots` ignore
/// its `anchor_digest` argument, or point the row at [`DIGEST_A`] — either
/// way the base's three live calendars render `pending`.
#[must_use]
pub fn row_1_ots_digest_mismatch() -> RowOutcome {
    let view = OtsArtifactView::from_parts(MERGED_A, None);
    code_of(&evaluate_ots_artifact(
        &view,
        &DIGEST_B,
        &BlockEvidence::new(),
    ))
}

/// **Row 2** — `anchor-tsa-imprint-mismatch`.
///
/// A real FreeTSA token verified against a digest it was not stamped over.
///
/// **The empty root store is mandatory, not incidental.** D53 fixes that the
/// imprint check fires at stage T2, *before* any chain rule, so a token for a
/// different digest is never classified by its chain. Against a pinned store
/// both orders — T2-then-T3 and T3-then-T2 — give the same answer, and the
/// row would be blind to the only ruling it exists to pin. Against an empty
/// store the swapped order renders `internally-consistent-only` and the row
/// goes red, which is D93 §9's planted fault for it.
#[must_use]
pub fn row_2_tsa_imprint_mismatch() -> RowOutcome {
    let view = TsaArtifactView::from_parts(FREETSA, &[], FETCH_DATE);
    code_of(&evaluate_tsa_artifact(
        &view,
        &synthetic_digest(0x2b),
        &empty_store(),
        AFTER_CAPTURE,
    ))
}

/// **Row 3** — `anchor-untrusted-root` → `internally-consistent-only`.
///
/// A well-formed [`MockTsa`] token, with the CA certificate travelling
/// *inside* the token's bag, evaluated against a store that trusts nothing.
/// An untrusted root does not error: D53 rule C6 (and MVP-SPEC.md:133) puts
/// it in a named non-headline state.
///
/// **The positive twin is inside the row** (A21 Accept; D57 §8 item 4).
/// Three of the five real tokens ship their own root inside the chain and
/// must still reach `proven`, so a negative with nothing opposite it is
/// passed by an implementation that rejects any chain containing a
/// self-signed certificate. The twin is checked here as a precondition — the
/// same token against `mock.root_store()` must be `proven` — so both
/// directions run over one artifact and neither can pass vacuously. D57's
/// twin over the *real* FreeTSA/DFN/SwissSign tokens is A43's and is cited,
/// not rebuilt.
#[must_use]
pub fn row_3_untrusted_root() -> RowOutcome {
    let Ok(mock) = MockTsa::granted() else {
        return RowOutcome::Precondition("mock-tsa-would-not-mint");
    };
    let digest = synthetic_digest(0x33);
    let Ok(token) = mock.issue(&digest, None) else {
        return RowOutcome::Precondition("mock-tsa-would-not-issue");
    };
    let view = TsaArtifactView::from_parts(&token, &[], FETCH_DATE);

    // The positive twin: trusted, this exact token is provable.
    let trusted = evaluate_tsa_artifact(&view, &digest, &mock.root_store(), G);
    if trusted.verdict().state() != AnchorState::Proven {
        return RowOutcome::Precondition("trusted-twin-is-not-proven");
    }

    state_of(&evaluate_tsa_artifact(&view, &digest, &empty_store(), G))
}

/// **Row 4** — `anchor-forged-header` → `invalid`.
///
/// The one row that claims `verdict:invalid`, and the reachable form of the
/// test D56 §9 could not write (D93 §8).
///
/// The base is a **single-branch, ops-committing** upgraded `.ots` that
/// renders `proven` when its embedded header is the agreed one. The mutation
/// is that embedded header's `nTime`, with bytes 36..68 — the merkle root —
/// untouched, so the ops still commit it; the agreed header is unchanged.
/// Rule O6 then fires.
///
/// Both halves of the base are load-bearing, and both were built wrong once
/// before D93 caught them:
///
/// - a **pending sibling** makes rule O5 fire first and the row renders
///   `pending` whatever the evidence says;
/// - an **uncommitted** forgery is already `invalid` offline through rule
///   O8, so the row is green with the online gate never having run.
///
/// The second is what the offline latch below catches, because it is the
/// shape that passes.
///
/// **Planted faults that must redden it** (D93 §9): restore D56 §5's shipped
/// rule order, so O4 sits above O6 and the artifact renders `attested`; drop
/// the online evidence, same result, which proves the gate is threaded and
/// not decoration; or weaken O3's whole-header equality to a merkle-root
/// comparison, which renders `proven`.
#[must_use]
pub fn row_4_forged_header() -> RowOutcome {
    let (digest, bytes, upgrade) =
        super::ots_writer::committed_single_branch(0x4f, ATTESTED_HEIGHT);
    let agreed = *upgrade.block_header();

    let mut forged = agreed;
    forged[68..72].copy_from_slice(&(HEADER_NTIME + 3600).to_le_bytes());
    let forged_upgrade = OtsUpgrade::new(ATTESTED_HEIGHT, forged, upgrade.fetch_date());
    let view = OtsArtifactView::from_parts(&bytes, Some(&forged_upgrade));

    // The vacuity latch (D93 §9 row 4): evaluated offline the forgery must be
    // `attested`. An UNCOMMITTED forgery is `invalid` here through O8, which
    // is the shape that satisfies `verdict:invalid` without the online gate
    // ever running.
    let offline = evaluate_ots_artifact(&view, &digest, &BlockEvidence::new());
    if offline.verdict().state() != AnchorState::Attested {
        return RowOutcome::Precondition("attested-offline-precondition-failed");
    }

    let evidence =
        BlockEvidence::new().with_block(ATTESTED_HEIGHT, OnlineBlockResult::Header(agreed));
    state_of(&evaluate_ots_artifact(&view, &digest, &evidence))
}

/// **Row 5** — `anchor-attested-not-headline` → `attested`.
///
/// The positive control: the artifact is honest — the real upgraded mainnet
/// proof with the upgrade group its own ops commit — and what the row pins is
/// that the verdict machine *withholds* it from the offline headline
/// (D56 rule O4).
///
/// **A plain state name is blind to the rule this row is named after.**
/// Adding `Attested` to the headline-eligible set does not move the state, so
/// the exercise returns `attested` only when `!is_headline_eligible()` and a
/// distinguishable string otherwise (D93 §9 row 5). The crate-level guard
/// `exactly_the_two_spec_h_states_are_headline_eligible` stays as the
/// independent second surface.
///
/// **Planted fault:** promote on the embedded header alone — drop O3's online
/// conjunct — and the artifact renders `proven`.
#[must_use]
pub fn row_5_attested_not_headline() -> RowOutcome {
    let upgrade = committing_upgrade();
    let view = OtsArtifactView::from_parts(UPGRADED_LARGE_TEST, Some(&upgrade));
    let outcome = evaluate_ots_artifact(&view, &DIGEST_UPGRADED_LARGE_TEST, &BlockEvidence::new());
    let verdict = outcome.verdict();

    if verdict.state() == AnchorState::Attested && verdict.is_headline_eligible() {
        return RowOutcome::Precondition("attested-but-headline-eligible");
    }
    state_of(&outcome)
}

/// **Row 6** — `anchor-expired-at-gentime` → `anchor-cert-not-valid-at-gentime`.
///
/// The signing certificate had already expired when the token's `genTime`
/// claims it signed (D53 rule C3). One code covers both temporal directions
/// (D85: a cause belongs in rendering, not the code set); this row exercises
/// the expired direction, and the not-yet-valid direction is the named test
/// `chain::tests::a_certificate_not_yet_valid_at_gentime_is_the_same_code`,
/// which is why there is no ninth row — a second row would claim this row's
/// outcome key and `check_registry` would correctly refuse the pair.
///
/// **`verify_at` sits INSIDE the signer window, deliberately.** The planted
/// fault is validating the chain at `verify_at` instead of at `genTime` —
/// the whole of C3 — and only a `verify_at` inside the window makes that
/// fault render `proven`. A `verify_at` outside it would leave the row green
/// under the fault and blind to the ruling.
#[must_use]
pub fn row_6_expired_at_gentime() -> RowOutcome {
    let config = MockTsaConfig {
        gen_time_unix: G,
        signer_validity: (G - 200_000, G - 100_000),
        ..MockTsaConfig::default()
    };
    let Ok(mock) = MockTsa::new(config) else {
        return RowOutcome::Precondition("mock-tsa-would-not-mint");
    };
    let digest = synthetic_digest(0x66);
    let Ok(token) = mock.issue(&digest, None) else {
        return RowOutcome::Precondition("mock-tsa-would-not-issue");
    };
    let view = TsaArtifactView::from_parts(&token, &[], FETCH_DATE);

    code_of(&evaluate_tsa_artifact(
        &view,
        &digest,
        &mock.root_store(),
        G - 150_000,
    ))
}

/// **Row 7** — `anchor-expired-after-gentime` →
/// `valid-at-stamping-cert-since-expired`.
///
/// The positive control for the expiry pair (D53 rule C2): the certificate
/// was valid **at** `genTime` and expired later, which must still verify.
/// `expired != invalid`, or aging bundles silently rot (MVP-SPEC.md:109/130).
///
/// Rows 6 and 7 are **one differential over one mock** — same signer, two
/// windows — which is what makes that claim measured rather than two
/// independent green rows. The planted fault is the same fault in the other
/// direction: validating at `verify_at = G + 200_000` renders `Invalid` with
/// row 6's code.
#[must_use]
pub fn row_7_expired_after_gentime() -> RowOutcome {
    let config = MockTsaConfig {
        gen_time_unix: G,
        signer_validity: (G - 100_000, G + 100_000),
        ..MockTsaConfig::default()
    };
    let Ok(mock) = MockTsa::new(config) else {
        return RowOutcome::Precondition("mock-tsa-would-not-mint");
    };
    let digest = synthetic_digest(0x77);
    let Ok(token) = mock.issue(&digest, None) else {
        return RowOutcome::Precondition("mock-tsa-would-not-issue");
    };
    let view = TsaArtifactView::from_parts(&token, &[], FETCH_DATE);

    state_of(&evaluate_tsa_artifact(
        &view,
        &digest,
        &mock.root_store(),
        G + 200_000,
    ))
}

/// **Row 8** — `anchor-ber-not-der` → `anchor-der-not-strict`.
///
/// The committed BER twin of a real token, substituted for the DER original.
/// RFC 3161 requires strict DER; the fixture is **valid BER**, so the row
/// cannot pass by the artifact merely being malformed.
///
/// The store is empty because the rejection happens at the parse, before any
/// trust question is asked — pinning the row to a store's contents would make
/// it depend on which roots happen to be pinned. **Planted fault:** parse
/// with `from_ber` instead of the strict-DER pin, and the token verifies —
/// the row then renders `internally-consistent-only` against this store (and
/// `proven` against a pinned one), red either way.
#[must_use]
pub fn row_8_ber_not_der() -> RowOutcome {
    let view = TsaArtifactView::from_parts(BER_INDEFINITE_FREETSA, &[], FETCH_DATE);
    code_of(&evaluate_tsa_artifact(
        &view,
        &D60_STAMPED,
        &empty_store(),
        AFTER_CAPTURE,
    ))
}
