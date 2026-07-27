# D27 — `verify_bundle` error mode: fail-fast authoritative, collect-all for rendering

- **Status: RESOLVED**
- **Date: 2026-07-27**
- **Owning task: R1** (consumed by R5 orchestration, R7/R8 tamper fixtures,
  Q7 tamper-matrix harness, R21/U30 rendering)
- Index note: this record was authored on the R1 branch; the
  `docs/decisions/README.md` index (which lives on `main`) gains its row at
  merge.

## Context

The spec's tamper matrix demands that *every mutation fails with a distinct
error* (MVP-SPEC.md line 168), and the Q7 harness asserts, per row, one
stable machine-readable expected outcome, pairwise-distinct across the
registry. That pulls toward **fail-fast**: one authoritative, typed first
error per hostile bundle.

Rendering pulls the other way: a CLI/page user staring at a failed bundle
is better served by *all* independent findings ("three units over-padded,
one path commit wrong") than by one. That pulls toward **collect-all**.

R's open-decisions list flags this ("fail-fast single distinct error
(tamper-matrix authoritative) vs collect-all for rendering, and which the
report exposes — blocks R1/R5/R7; by M0"). The R1 task note prescribes the
shape of the resolution: design for both.

## Decision

**Hybrid: typed first-error is the one normative mode; multi-error
collection is an optional rendering aid layered on top of it.**

1. **Normative entry point (tamper-authoritative), R5:**

   ```rust
   pub fn verify_bundle(bytes: &[u8], opts: &VerifyOpts)
       -> Result<VerificationReport, VerifyError>
   ```

   Fail-fast: the **first** failure in the normative stage order — F strict
   decode → structural pre-validation (R3) → per-unit stages (R2) →
   file-level checks (R4) → signature/`sig_policy` stage (C) → anchor stage
   — aborts verification with a single typed `VerifyError`. Within a stage,
   checks run in a fixed documented order (subjects in manifest order,
   checks in the order the spec lists them), so "first" is deterministic
   for every input. **This is the only signature that tamper rows (R7/R8),
   the Q7 harness, and golden vectors bind to.** Each `VerifyError` variant
   carries a stable machine-readable code (`VerifyError::code()`, kebab-case,
   pairwise-distinct — the R-side implementation of Q7's error-code
   stability contract).

2. **Rendering entry point (optional collection), R5:**

   ```rust
   pub fn verify_bundle_collecting(bytes: &[u8], opts: &VerifyOpts)
       -> Result<VerificationReport, VerifyFailures>
   ```

   `VerifyFailures` (defined in R1) is a non-empty, ordered collection of
   `VerifyError` with an invariant that is the heart of this decision:

   > **`VerifyFailures::primary()` — the first element — MUST be exactly
   > the error the fail-fast path returns for the same input.**

   R5 must implement both entry points over one shared stage list so the
   two cannot drift; R7/R10 property-test the invariant (for every tamper
   fixture and every fuzz/proptest mutation: collecting-primary ==
   fail-fast error).

3. **Collection semantics (no speculative cascades):** collection is
   best-effort over *independent* checks only. A check whose prerequisite
   failed is **skipped, never speculatively reported** — e.g. a unit whose
   AEAD decrypt failed gets no padding/true-length/binding findings (they
   need the plaintext); a bundle that fails strict decode yields exactly
   one finding (nothing downstream has trustworthy input). Findings are
   ordered by stage, then by subject id (unit/file id) — deterministic.

4. **The report never carries errors.** `VerificationReport` exists only
   for a bundle that passed the evidence pipeline; failures live in
   `VerifyError`/`VerifyFailures`. Per-anchor *states* (`invalid`,
   `internally-consistent-only`, `absent`, …) are report data, not errors —
   Q7 explicitly allows "a specific non-headline verdict state" as a tamper
   row's expected outcome, and that is how most M2 anchor rows resolve.
   Renderers of failed verifications consume the typed error list (codes,
   Display strings, subject ids), not a partial report.

## Rationale

- **Distinctness needs a single answer.** "Every mutation fails with a
  distinct error" is only testable if one error is *the* answer for a
  fixture. Making fail-fast normative gives R7/Q7 a deterministic target;
  a collect-only design would force every row to assert over a set, and
  set membership is a weaker, drift-prone contract.
- **Rendering needs more than one answer.** M3's CLI/page UX (R21/U30)
  wants everything independently wrong with a bundle. Layering collection
  *on top of* the fail-fast order — rather than beside it — means the
  rendering view can never contradict the authoritative verdict: it starts
  with it.
- **The primary-equals-fail-fast invariant is cheap to enforce** (shared
  stage list; property test) and turns "which mode is authoritative?" from
  a doc convention into a tested equality.
- **No-cascade skipping** keeps the collection honest: reporting a padding
  "finding" computed from an unauthenticated decrypt would be exactly the
  malformed-proof-bundle confusion this project exists to prevent.
- **Report-only-on-success** keeps the report a positive statement whose
  serialized bytes are the Q4/Q5 vector contract (D29); tamper vectors map
  to error codes instead, so the two vector families stay disjoint.

## Consequences

- R1 ships `VerifyError` (typed first-error, stable `code()`) and
  `VerifyFailures` (the collection container, non-empty, `primary()`
  first). Shipped in `antseal-core::verify::error`.
- R5 implements both entry points over one stage list; R7/R10 test the
  primary invariant; Q7 rows key on `VerifyError::code()` values (or, for
  M2 anchor rows, on report anchor states).
- `--json` rendering of *failures* (U30's envelope) consumes `code()` +
  Display + subject ids; `serde` impls on the error types are deliberately
  deferred until U30 defines that envelope (adding them later is
  non-breaking).
- Cross-domain failures (F decode, C signature, G canonicalization/tree,
  A anchor-artifact structure) surface through the same enum via wrapper
  arms added at integration — see the documented extension point at the
  end of `VerifyError` (`crates/antseal-core/src/verify/error.rs`).
