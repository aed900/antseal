//! The tamper-matrix harness (task Q7).
//!
//! The spec's tamper matrix (MVP-SPEC.md line 168) requires that **every**
//! mutation of a valid artifact fails, that each one fails **distinctly**,
//! and — the working principle "parse defensively" — that adversarial input
//! never crashes a verifier. This module is the shared runner all domains
//! register rows with; the rows themselves are domain-owned (F15, C17, G19,
//! A21, R7/R8), and the completeness registry against the spec's row list is
//! Q8's.
//!
//! A row is `{id, base fixture, mutation, expected outcome}`
//! ([`TamperRow`]). An expected outcome is either a **stable
//! machine-readable error code** ([`ExpectedOutcome::ErrorCode`] — the D30
//! contract, `docs/testing/error-code-contract.md`) or a **named verdict
//! state** ([`ExpectedOutcome::VerdictState`]), which M2 anchor rows need:
//! an untrusted-root token does not error, it lands in a specific
//! non-headline verdict state.
//!
//! [`check_registry`] asserts, for a whole registry at once:
//!
//! 1. **row ids are unique** — a row id is a permanent handle (Q8 tracks
//!    coverage by it, and tamper-matrix failures are cited by it);
//! 2. **expected outcomes are pairwise distinct** — the spec's
//!    "every mutation fails with a distinct error". Two rows expecting the
//!    same code is a *harness* failure, not a passing test: it means one of
//!    the two mutations is not actually distinguishable;
//! 3. **each row produces exactly its expected outcome**;
//! 4. **no row panics** — a mutation that panics fails the harness with a
//!    dedicated message (native targets run each row inside
//!    [`std::panic::catch_unwind`]).
//!
//! Failures are collected across the whole registry rather than aborting at
//! the first, so one run reports every broken row.
//!
//! # Adding a row (the procedure for F/C/G/A/R)
//!
//! 1. Pick the surface's stable code (or verdict state). If the mutation
//!    you want to pin is not yet distinguishable from another row's,
//!    **that is the finding** — add the distinct error variant + code to
//!    your domain first (append-only; see the contract doc).
//! 2. Write an `fn() -> ActualOutcome` that builds the valid base fixture,
//!    applies exactly one mutation, feeds it to the surface, and reports
//!    what happened via [`ActualOutcome`]. Return
//!    [`ActualOutcome::Accepted`] when the surface accepts the tampered
//!    input — the harness turns that into a failure with the row's id.
//! 3. Append a [`TamperRow`] to your domain's registry slice with a stable
//!    kebab-case id prefixed by the domain (`cbor-…`, `crypto-…`,
//!    `content-…`, `verify-…`), the base-fixture name, and a one-line
//!    mutation description.
//! 4. Never renumber or reuse a row id, and never change a row's expected
//!    code to make a failing run pass — a changed code is a contract event
//!    (contract doc, "Append-only").
//!
//! # WASM
//!
//! Row execution, comparison, and the distinctness check are pure and
//! WASM-safe. Only the panic guard is native-only (`wasm32-unknown-unknown`
//! aborts rather than unwinding, so there is nothing to catch); on wasm the
//! row runs directly and a panic aborts the test binary, which is still a
//! loud failure.

/// What a row asserts the surface will do with the tampered artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedOutcome {
    /// A stable machine-readable error code, e.g. `"cbor-non-shortest-int"`
    /// (D30 contract).
    ErrorCode(&'static str),
    /// A named non-headline verdict state, e.g.
    /// `"internally-consistent-only"` — the M2 shape where a tampered
    /// anchor does not error but must not be headline-eligible
    /// (A18/R17 own the state set; the harness only compares names).
    VerdictState(&'static str),
}

impl ExpectedOutcome {
    /// The distinctness key: outcomes of different kinds never collide even
    /// if their names coincide.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::ErrorCode(code) => format!("error:{code}"),
            Self::VerdictState(state) => format!("verdict:{state}"),
        }
    }
}

/// What the surface actually did — reported by a row's exercise function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActualOutcome {
    /// The surface **accepted** the tampered artifact. Always a failure: a
    /// tamper row exists precisely because this input must be rejected.
    Accepted,
    /// The surface rejected it with this stable code.
    ErrorCode(String),
    /// The surface produced this verdict state.
    VerdictState(String),
}

impl ActualOutcome {
    /// Convenience for the common shape: map a `Result` to an outcome via
    /// the error's stable code.
    pub fn from_result<T, E>(result: Result<T, E>, code: impl Fn(&E) -> &'static str) -> Self {
        match result {
            Ok(_) => Self::Accepted,
            Err(err) => Self::ErrorCode(code(&err).to_owned()),
        }
    }

    fn key(&self) -> String {
        match self {
            Self::Accepted => "accepted".to_owned(),
            Self::ErrorCode(code) => format!("error:{code}"),
            Self::VerdictState(state) => format!("verdict:{state}"),
        }
    }
}

/// One tamper-matrix row: a base fixture, one mutation, one expected
/// outcome.
#[derive(Clone, Copy)]
pub struct TamperRow {
    /// Permanent, unique, kebab-case row id (domain-prefixed).
    pub id: &'static str,
    /// The valid artifact the mutation starts from (documentation + Q8
    /// grouping).
    pub base: &'static str,
    /// One-line description of the single mutation applied.
    pub mutation: &'static str,
    /// What the surface must do with the mutated artifact.
    pub expected: ExpectedOutcome,
    /// Builds the base, applies the mutation, runs the surface, and reports
    /// what happened.
    pub exercise: fn() -> ActualOutcome,
}

/// One harness failure, tied to the row (or row pair) that caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TamperFailure {
    /// The offending row's id.
    pub row_id: &'static str,
    /// What went wrong, in reviewer-readable prose.
    pub reason: String,
}

/// Run a registry and assert every harness rule (module docs).
///
/// # Errors
///
/// Every violation found, in registry order: duplicate row ids, colliding
/// expected outcomes, wrong outcomes, accepted mutations, and panics.
pub fn check_registry(rows: &[TamperRow]) -> Result<usize, Vec<TamperFailure>> {
    let mut failures = Vec::new();

    for (index, row) in rows.iter().enumerate() {
        if let Some(earlier) = rows[..index].iter().find(|other| other.id == row.id) {
            failures.push(TamperFailure {
                row_id: row.id,
                reason: format!(
                    "duplicate row id (already used by the row mutating `{}`); row ids are \
                     permanent handles and must be unique",
                    earlier.base
                ),
            });
        }
        if let Some(earlier) = rows[..index]
            .iter()
            .find(|other| other.expected.key() == row.expected.key())
        {
            failures.push(TamperFailure {
                row_id: row.id,
                reason: format!(
                    "expected outcome `{}` is already claimed by row `{}` — the tamper matrix \
                     requires every mutation to fail distinguishably, so one of these two \
                     mutations needs its own error variant + code",
                    row.expected.key(),
                    earlier.id
                ),
            });
        }
    }

    for row in rows {
        match run_guarded(row.exercise) {
            Err(()) => failures.push(TamperFailure {
                row_id: row.id,
                reason: format!(
                    "PANICKED while exercising `{}` — adversarial input must error, never crash \
                     (spec: parse defensively)",
                    row.mutation
                ),
            }),
            Ok(ActualOutcome::Accepted) => failures.push(TamperFailure {
                row_id: row.id,
                reason: format!(
                    "the surface ACCEPTED the tampered artifact (`{}` applied to `{}`); it must \
                     fail with {}",
                    row.mutation,
                    row.base,
                    row.expected.key()
                ),
            }),
            Ok(actual) if actual.key() != row.expected.key() => failures.push(TamperFailure {
                row_id: row.id,
                reason: format!("expected {} but got {}", row.expected.key(), actual.key()),
            }),
            Ok(_) => {}
        }
    }

    if failures.is_empty() {
        Ok(rows.len())
    } else {
        Err(failures)
    }
}

/// Render harness failures as one panic message (what a test does with the
/// `Err` arm of [`check_registry`]).
#[must_use]
pub fn render_failures(failures: &[TamperFailure]) -> String {
    let mut out = format!("{} tamper-matrix failure(s):\n", failures.len());
    for failure in failures {
        out.push_str(&format!("  [{}] {}\n", failure.row_id, failure.reason));
    }
    out
}

/// Run one row's exercise function, catching a panic on targets that unwind.
///
/// `Err(())` means the row panicked. The panic message still reaches stderr
/// (the harness deliberately does not install a global panic hook — that
/// would race with other tests in the same binary), so a panicking row
/// prints its backtrace *and* fails with the harness's own message.
#[cfg(not(target_arch = "wasm32"))]
fn run_guarded(exercise: fn() -> ActualOutcome) -> Result<ActualOutcome, ()> {
    std::panic::catch_unwind(exercise).map_err(|_| ())
}

#[cfg(target_arch = "wasm32")]
fn run_guarded(exercise: fn() -> ActualOutcome) -> Result<ActualOutcome, ()> {
    Ok(exercise())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_outcome() -> ActualOutcome {
        ActualOutcome::ErrorCode("test-alpha".to_owned())
    }

    fn other_outcome() -> ActualOutcome {
        ActualOutcome::ErrorCode("test-beta".to_owned())
    }

    fn accepts() -> ActualOutcome {
        ActualOutcome::Accepted
    }

    fn panics() -> ActualOutcome {
        panic!("deliberate panic: the test-of-the-test for the no-panic rule")
    }

    fn row(id: &'static str, expected: &'static str, exercise: fn() -> ActualOutcome) -> TamperRow {
        TamperRow {
            id,
            base: "synthetic",
            mutation: "synthetic",
            expected: ExpectedOutcome::ErrorCode(expected),
            exercise,
        }
    }

    #[test]
    fn a_correct_registry_passes() {
        let rows = [
            row("alpha", "test-alpha", ok_outcome),
            row("beta", "test-beta", other_outcome),
        ];
        assert_eq!(check_registry(&rows).expect("registry is correct"), 2);
    }

    /// Test-of-the-test: two rows declaring the same expected code fail the
    /// distinctness assertion (Q7 accept).
    #[test]
    fn two_rows_with_the_same_expected_code_fail_distinctness() {
        let rows = [
            row("alpha", "test-alpha", ok_outcome),
            row("alpha-again", "test-alpha", ok_outcome),
        ];
        let failures = check_registry(&rows).expect_err("colliding outcomes must fail");
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].row_id, "alpha-again");
        assert!(
            failures[0]
                .reason
                .contains("already claimed by row `alpha`"),
            "reason should name the colliding row: {}",
            failures[0].reason
        );
    }

    #[test]
    fn duplicate_row_ids_fail() {
        let rows = [
            row("alpha", "test-alpha", ok_outcome),
            row("alpha", "test-beta", other_outcome),
        ];
        let failures = check_registry(&rows).expect_err("duplicate ids must fail");
        assert!(
            failures
                .iter()
                .any(|f| f.reason.contains("duplicate row id"))
        );
    }

    /// Test-of-the-test: a mutation that panics instead of erroring fails
    /// the harness (Q7 accept). The deliberate panic's own message is
    /// printed by the default hook — expected noise, not a failure.
    #[test]
    fn a_panicking_row_fails_the_harness() {
        let rows = [row("panicker", "test-alpha", panics)];
        let failures = check_registry(&rows).expect_err("a panicking row must fail");
        assert_eq!(failures.len(), 1);
        assert!(
            failures[0].reason.contains("PANICKED"),
            "reason should report the panic: {}",
            failures[0].reason
        );
    }

    /// A surface that accepts the tampered artifact fails loudly, and the
    /// message says so rather than reporting a code mismatch.
    #[test]
    fn an_accepted_mutation_fails() {
        let rows = [row("accepter", "test-alpha", accepts)];
        let failures = check_registry(&rows).expect_err("acceptance must fail");
        assert!(failures[0].reason.contains("ACCEPTED"));
    }

    #[test]
    fn a_wrong_code_is_reported_with_both_sides() {
        let rows = [row("wrong", "test-expected", ok_outcome)];
        let failures = check_registry(&rows).expect_err("a wrong code must fail");
        assert!(failures[0].reason.contains("expected error:test-expected"));
        assert!(failures[0].reason.contains("got error:test-alpha"));
    }

    /// Error codes and verdict states occupy separate namespaces, so an
    /// M2 verdict row can share a name with an error code without
    /// tripping distinctness.
    #[test]
    fn error_codes_and_verdict_states_do_not_collide() {
        fn verdict() -> ActualOutcome {
            ActualOutcome::VerdictState("shared-name".to_owned())
        }
        fn error() -> ActualOutcome {
            ActualOutcome::ErrorCode("shared-name".to_owned())
        }
        let rows = [
            TamperRow {
                id: "as-error",
                base: "synthetic",
                mutation: "synthetic",
                expected: ExpectedOutcome::ErrorCode("shared-name"),
                exercise: error,
            },
            TamperRow {
                id: "as-verdict",
                base: "synthetic",
                mutation: "synthetic",
                expected: ExpectedOutcome::VerdictState("shared-name"),
                exercise: verdict,
            },
        ];
        assert_eq!(check_registry(&rows).expect("distinct namespaces"), 2);
    }

    #[test]
    fn failures_render_with_row_ids() {
        let rows = [row("accepter", "test-alpha", accepts)];
        let failures = check_registry(&rows).expect_err("acceptance must fail");
        let rendered = render_failures(&failures);
        assert!(rendered.starts_with("1 tamper-matrix failure(s):"));
        assert!(rendered.contains("[accepter]"));
    }
}
