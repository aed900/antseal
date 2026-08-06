//! **A's registry slice for the M2 anchor verdict rows** (task **A21**): the
//! eight semantic tamper rows over anchor artifacts, each pinned to the
//! distinct error code or verdict state the machine must produce
//! (MVP-SPEC.md line 168, the `(M2)` half).
//!
//! F20's slice — `crates/antseal-core/tests/tamper_rows_anchor/` — owns the
//! *schema*-level anchor rows and is prefixed `anchor-schema-` precisely so
//! the global matrix cannot double-claim against these. These are the
//! semantic ones: what an upgraded attestation proves, chain validation, the
//! `--online` gate.
//!
//! **This slice mints nothing.** Every code it binds already existed —
//! `anchor-ots-digest-mismatch` (A11, raised on D56's behalf),
//! `anchor-tsa-imprint-mismatch` (A8), `anchor-cert-not-valid-at-gentime`
//! (A9's `ChainFault`), `anchor-der-not-strict` (A5, named by D60 §7.3) — and
//! all four verdict states are A18's.
//!
//! # Eight rows, six families, and why the count is not seven
//!
//! Line 168's `(M2)` half is six semicolon clauses of which **two are
//! compound**, expanding to eight cases (D53 §8). The project reached "seven"
//! twice by *different* routes — `MATRIX.json` splitting the expiry clause and
//! A21's own entry splitting the digest clause — so the two sevens were never
//! the same seven, and nothing went red because the case count was not pinned.
//! It is pinned now (`EXPECTED_M2_CASES`).
//!
//! | # | row | binds | decided by |
//! | --- | --- | --- | --- |
//! | 1 | `anchor-ots-digest-mismatch` | `error:anchor-ots-digest-mismatch` | D56 rule O2, code named by D91 §6.2 |
//! | 2 | `anchor-tsa-imprint-mismatch` | `error:anchor-tsa-imprint-mismatch` | A8 owns the code; **D53 fixes it fires at T2**, before any chain rule |
//! | 3 | `anchor-untrusted-root` | `verdict:internally-consistent-only` | D53 rule C6, and MVP-SPEC.md:133 states the outcome inline |
//! | 4 | `anchor-forged-header` | `verdict:invalid` | D56 rule O6 **as amended by D93** |
//! | 5 | `anchor-attested-not-headline` | `verdict:attested` | D56 rule O4 |
//! | 6 | `anchor-expired-at-gentime` | `error:anchor-cert-not-valid-at-gentime` | D53 rule C3 |
//! | 7 | `anchor-expired-after-gentime` | `verdict:valid-at-stamping-cert-since-expired` | D53 rule C2 |
//! | 8 | `anchor-ber-not-der` | `error:anchor-der-not-strict` | D53 §8 row 8; A5/D60 |
//!
//! **`verdict:invalid` is claimed exactly once**, by row 4 — which is why
//! rows 2, 6 and 8, all of which also *render* `Invalid`, pin codes instead.
//! D93 §6 clarified that the dependency runs one way: the single claim is a
//! *consequence* of those three minting codes, not a premise of it, because
//! the checker enforces distinctness and not coverage.
//!
//! # There is no ninth row, and the reason is the harness's own rule
//!
//! A9's **not-yet-valid-at-genTime** direction carries the *same* code as the
//! expired direction — `TemporalBound` is diagnostic payload only (D85: a
//! cause belongs in rendering, not in the code set). A row for it would claim
//! row 6's outcome key and [`check_registry`](super::tamper::check_registry)
//! would correctly refuse the pair. It is a named test instead —
//! `anchor::chain::tests::a_certificate_not_yet_valid_at_gentime_is_the_same_code`
//! — exactly as the 81-byte block header is in F20's slice. (A21's task entry
//! called this direction "the eighth row"; D53 §8 had already ruled it a named
//! test, and the entry is corrected as of this task.)
//!
//! # Where the exercises live, and why not here
//!
//! The bodies are in [`crate::anchor::testing::tamper_rows`], not in this
//! file. A21's Accept requires all eight rows to execute on
//! `wasm32-unknown-unknown` as well as natively, and this slice cannot: it is
//! gated `feature = "test-util"`, the wasm32 dev edge enables `test-vectors`
//! only, and the matrix is driven from an integration target that the
//! `--lib`-only wasm32 lane never runs at all. So each row is *additionally*
//! pinned as an in-module `#[cfg(test)]` test beside A18's (A90's ruling), and
//! the two homes call **one** exercise so they cannot drift into two
//! descriptions of one claim.
//!
//! What this slice adds that the in-module tests cannot is the thing the
//! matrix exists for: cross-domain distinctness. A row asserting
//! `internally-consistent-only` in isolation says nothing about whether the
//! machine can tell that case apart from the other 96.

use crate::anchor::testing::tamper_rows::{self, RowOutcome};

use super::tamper::{ActualOutcome, ExpectedOutcome, TamperRow};

/// Map an exercise's outcome onto the harness's.
///
/// [`RowOutcome::Precondition`] deliberately becomes a `VerdictState` whose
/// name is the failure reason: it can never equal a row's `expected`, so the
/// row goes red **naming what stopped being true about its base** rather than
/// reporting a plausible wrong answer. That is the difference between a row
/// that failed and a row that lied.
fn actual(outcome: RowOutcome) -> ActualOutcome {
    match outcome {
        RowOutcome::Error(code) => ActualOutcome::ErrorCode(code.to_owned()),
        RowOutcome::Verdict(state) | RowOutcome::Precondition(state) => {
            ActualOutcome::VerdictState(state.to_owned())
        }
    }
}

fn row_1() -> ActualOutcome {
    actual(tamper_rows::row_1_ots_digest_mismatch())
}
fn row_2() -> ActualOutcome {
    actual(tamper_rows::row_2_tsa_imprint_mismatch())
}
fn row_3() -> ActualOutcome {
    actual(tamper_rows::row_3_untrusted_root())
}
fn row_4() -> ActualOutcome {
    actual(tamper_rows::row_4_forged_header())
}
fn row_5() -> ActualOutcome {
    actual(tamper_rows::row_5_attested_not_headline())
}
fn row_6() -> ActualOutcome {
    actual(tamper_rows::row_6_expired_at_gentime())
}
fn row_7() -> ActualOutcome {
    actual(tamper_rows::row_7_expired_after_gentime())
}
fn row_8() -> ActualOutcome {
    actual(tamper_rows::row_8_ber_not_der())
}

/// A21's eight rows. Ids are permanent handles and match the `row_id` each
/// case reserved in `testdata/tamper/MATRIX.json` before the row existed.
pub const ROWS: &[TamperRow] = &[
    TamperRow {
        id: "anchor-ots-digest-mismatch",
        base: "merged-A.ots (real, three live calendars, stamped over digest A)",
        mutation: "verify it against digest B — the other committed golden digest; no byte patched",
        expected: ExpectedOutcome::ErrorCode("anchor-ots-digest-mismatch"),
        exercise: row_1,
    },
    TamperRow {
        id: "anchor-tsa-imprint-mismatch",
        base: "D60-tsa-freetsa-resp.tsr (real ECDSA P-384 token)",
        mutation: "verify against a digest it was not stamped over, with an empty root store",
        expected: ExpectedOutcome::ErrorCode("anchor-tsa-imprint-mismatch"),
        exercise: row_2,
    },
    TamperRow {
        id: "anchor-untrusted-root",
        base: "a MockTsa `granted` token with its CA certificate inside the bag",
        mutation: "evaluate against a store that trusts nothing instead of the mock's own root",
        expected: ExpectedOutcome::VerdictState("internally-consistent-only"),
        exercise: row_3,
    },
    TamperRow {
        id: "anchor-forged-header",
        base: "a single-branch, ops-committing upgraded .ots that renders proven",
        mutation: "forge the embedded header's nTime; merkle root untouched, agreed header unchanged",
        expected: ExpectedOutcome::VerdictState("invalid"),
        exercise: row_4,
    },
    TamperRow {
        id: "anchor-attested-not-headline",
        base: "the real upgraded mainnet .ots with the upgrade group its ops commit",
        mutation: "none — the artifact is honest; the online evidence is withheld",
        expected: ExpectedOutcome::VerdictState("attested"),
        exercise: row_5,
    },
    TamperRow {
        id: "anchor-expired-at-gentime",
        base: "a MockTsa token whose signer window closed before its genTime",
        mutation: "none — the window itself is the case; verified at an instant inside it",
        expected: ExpectedOutcome::ErrorCode("anchor-cert-not-valid-at-gentime"),
        exercise: row_6,
    },
    TamperRow {
        id: "anchor-expired-after-gentime",
        base: "the same mock with a signer window spanning genTime",
        mutation: "none — verify long after the window closed (the LTV control)",
        expected: ExpectedOutcome::VerdictState("valid-at-stamping-cert-since-expired"),
        exercise: row_7,
    },
    TamperRow {
        id: "anchor-ber-not-der",
        base: "D60-tsa-freetsa-resp.tsr (real, strict DER)",
        mutation: "substitute the committed BER twin — valid BER, indefinite lengths and EOC",
        expected: ExpectedOutcome::ErrorCode("anchor-der-not-strict"),
        exercise: row_8,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The slice is internally distinct, asserted here as well as globally.
    ///
    /// `check_registry` proves it across all domains, but only once every
    /// slice is assembled; this fails at the owning slice instead of in a
    /// cross-domain run whose message names two rows from different tasks.
    #[test]
    fn the_slice_is_internally_distinct() {
        let mut keys: Vec<String> = ROWS.iter().map(|row| row.expected.key()).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(
            before,
            keys.len(),
            "two A21 rows claim one outcome: {keys:?}"
        );
    }

    /// The row count is **eight**, and the number is a spec reading rather
    /// than a constant to adjust.
    ///
    /// Changing it means re-reading MVP-SPEC.md line 168's `(M2)` half —
    /// six clauses, two compound — not editing this line to fit. The project
    /// reached "seven" twice, by two different routes, before D53 §8 counted.
    #[test]
    fn the_slice_has_all_eight_rows() {
        assert_eq!(ROWS.len(), 8);
    }

    /// **`verdict:invalid` is claimed exactly once**, by the forged-header
    /// row (D53 §8).
    ///
    /// Rows 2, 6 and 8 all *render* `Invalid` too. If any of them regressed to
    /// pinning the bare state, `check_registry` would refuse the pair — but it
    /// would name a collision, not the rule that was lost. This names it.
    #[test]
    fn exactly_one_row_claims_the_bare_invalid_state() {
        let claimants: Vec<&str> = ROWS
            .iter()
            .filter(|row| row.expected == ExpectedOutcome::VerdictState("invalid"))
            .map(|row| row.id)
            .collect();
        assert_eq!(claimants, ["anchor-forged-header"]);
    }

    /// No row reports `Accepted`, which the harness documents as *"always a
    /// failure"* — and row 5, the positive-shaped one, is the reason to say so
    /// out loud (D56 §8).
    #[test]
    fn no_row_reports_accepted() {
        for row in ROWS {
            let outcome = (row.exercise)();
            assert_ne!(
                outcome,
                ActualOutcome::Accepted,
                "row `{}` accepted the artifact",
                row.id
            );
        }
    }
}
