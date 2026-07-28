# Verification-coverage traceability matrix (Q13)

> **Owning task: Q13** (`tasks/Q.md`), milestone **M0** — tagged M0 because it
> must exist at the freeze; maintained continuously through M4.
> **Spec basis: MVP-SPEC.md lines 165–175**, the Verification section, every
> bullet of it.
>
> **This file is machine-checked.** `scripts/check-traceability.py --matrix`
> parses the tables below and asserts that **every** reference in a
> `tests / evidence` cell resolves — a named Rust test must be defined in the
> named file, a named doc-test line must land on a fence, a named path must
> exist. A row with no reference must say `NONE` out loud; a blank cell is a
> failure, because a blank cell reads as covered.
>
> **The `status` column is machine-checked too, since Q51.** Every row at or
> before the milestone under review must read `covered`; later milestones are
> unconstrained. Until Q51 the check resolved references and never read this
> column, so a row could sit at `gap` through a milestone review with the lint
> green — which is what happened to V3.4 (see the Findings section).
>
> **References are by name, never by line number.** D83 will move the GGM
> cover-node wire encoding and tests will move with it; a line-number matrix
> would rot silently on the first refactor, and a rotted matrix is worse than
> none because it is trusted.

## How the gate uses this

- **M0 rows must be complete before the `format-v1-freeze` tag** — that is a
  Q14 gate condition, and Q14's checklist cites this file.
- **M1/M2/M3/M4 rows are checked at their own milestone reviews** (M4 via
  Q34, which requires the whole matrix green). Their rows read `NONE` today
  and that is correct, not a gap: the crates they test are stubs.
- Status vocabulary: **`covered`** (a test exists and is named here);
  **`gap`** (the milestone owns the bullet and no test exists — this blocks
  that milestone's gate); **`deferred`** (a later milestone owns it). Nothing
  else parses: an unrecognised status is a typo and fails the check, at every
  milestone, because a typo at a not-yet-gated one would otherwise stay
  invisible until that milestone's review.
- **The gate that enforces the first two bullets** is
  `scripts/check-traceability.py --matrix`, and the milestone it enforces is
  the constant `CURRENT_MILESTONE` in that script — **the line a milestone
  review bumps.** It is a constant and not a required flag on purpose: a gate
  that runs only when someone remembers to pass `--milestone` is the same
  unenforced prose the gate replaces. The rule is cumulative — at the M1
  review, M0's rows must *still* read `covered`, so a milestone cannot
  regress once its own review has passed. `--milestone M1` answers the
  one-off question "would M1 pass today?" without moving the gate.

## M0 — the rows the format freeze depends on

### Line 167 — unit/property tests, golden vectors, WASM bit-match, retention

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V1.1 | 167 | Unit/property tests per crate | M0 | all | covered | `crates/antseal-core/tests/proptest_example.rs::example_unit_tilings_are_exact_and_derive_distinct_unit_keys`, `crates/antseal-core/tests/crypto_properties.rs::commitment_verifies_iff_salt_and_message_match_exactly`, `crates/antseal-core/tests/codec_properties.rs::bundle_round_trips_and_re_encodes_byte_identically`, `crates/antseal-core/tests/content_properties.rs::prove_then_verify_round_trips_over_arbitrary_ranges`, `crates/wasm-bitmatch/tests/bitmatch.rs::bitmatch_transcript_is_deterministic`, `docs/testing/proptest-conventions.md` | **Read "per crate" as "per crate that exists at this milestone."** Two of five workspace crates carry tests: `antseal-core` and `wasm-bitmatch`. `antseal-net` (M1), `antseal-anchor` (M2) and `antseal-cli` (M3) are doc-comment stubs with zero tests — correct for M0, and tracked as rows V6.x/V7.x/V8.x rather than as a gap here. |
| V1.2 | 167 | Committed golden vectors | M0 | Q/F/C/G/R | covered | `crates/antseal-core/tests/vector_runner.rs::vector_runner_discovers_and_executes_every_committed_vector`, `crates/antseal-core/tests/vector_index.rs::vector_index_exists_and_matches_the_committed_tree`, `testdata/vectors/v1` | Runner discovers by directory walk, no hardcoded list. **11 registered kinds across 12 committed files in 8 directories** under `v1/` at the freeze (corrected 2026-07-28 — this note read "seven vector families", which was true before `sig-reject`, `content-model` and the four crypto kinds landed; a count kept by hand goes stale silently, which is why it is stated with the way to recount it: `find testdata/vectors/v1 -name '*.json' -not -name INDEX.json`). |
| V1.3 | 167 | The WASM build must bit-match native verification | M0 | Q5 | covered | `crates/wasm-bitmatch/tests/bitmatch.rs::bitmatch_transcript_is_non_vacuous`, `crates/wasm-bitmatch/tests/bitmatch.rs::bitmatch_embedded_bytes_are_the_committed_bytes`, `scripts/wasm-bitmatch.sh`, `scripts/wasm-bitmatch.mjs` | The lane byte-compares a native transcript against the wasm32 one. `scripts/wasm-bitmatch.sh --self-test` injects a divergence and requires red, so the lane is proven able to fail; CI runs the self-test *before* the real lane. |
| V1.4 | 167 | Empty-anchor vectors | M0 | F13 | covered | `crates/antseal-core/tests/bundle_vectors.rs::vector_bundle_carries_the_empty_anchor_milestone_case`, `testdata/vectors/v1/bundle/bundle.json` | Case id `empty-anchor-unanchored`. |
| V1.5 | 167 | Per-version vectors retained in CI forever | M0 | Q6 | covered | `crates/antseal-core/tests/vector_freeze.rs::vector_freeze_manifest_pins_every_committed_vector`, `crates/antseal-core/tests/vector_freeze.rs::vector_freeze_checks_every_retained_version_independently`, `crates/antseal-core/tests/vector_freeze.rs::vector_freeze_pending_must_exist_list_is_complete`, `scripts/vector-freeze.sh`, `testdata/vectors/v1/FROZEN.sha256` | Retention is enforced per version directory, not globally, so adding `v2` cannot weaken `v1`. Red-path proofs: `vector_freeze_red_on_a_mutated_vector`, `vector_freeze_red_on_a_deleted_vector`, `vector_freeze_green_on_an_added_vector`. |

### Line 168 — the tamper matrix

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V2.1 | 168 | Tamper matrix harness — every mutation fails with a **distinct** error | M0 | Q7 | covered | `crates/antseal-core/tests/tamper_matrix.rs::tamper_registry_is_green`, `crates/antseal-core/tests/tamper_matrix.rs::seeded_rows_span_multiple_domains` | The harness asserts unique row ids, pairwise-distinct expected outcomes, exact outcome per row, and no panic (`catch_unwind`). Its own red-path proofs live in `crates/antseal-core/src/test_util/tamper.rs` (`two_rows_with_the_same_expected_code_fail_distinctness`, `a_panicking_row_fails_the_harness`). |
| V2.2 | 168 | The **M0** mutation families (format / commitment / signature / structural), all of them | M0 | Q8 | covered | `crates/antseal-core/tests/tamper_matrix.rs::tamper_matrix_is_mapped_1_to_1_onto_the_spec_row_list`, `crates/antseal-core/tests/tamper_matrix.rs::tamper_matrix_records_its_deliberate_non_rows`, `crates/antseal-core/tests/tamper_matrix.rs::tamper_matrix_reports_the_q14_gate`, `testdata/tamper/MATRIX.json` | **Deliberately delegated, not re-listed.** `MATRIX.json` already enumerates every spec-mandated family and is asserted 1:1 against the spec's own sentence; copying those ~20 rows here would create a third hand-maintained list of one fact, which is the failure mode this file exists to prevent. What *is* recorded here: the registry carries **zero pending M0 rows**, and one family — **swapped unit** — is a deliberate recorded `non_row` (its AEAD tag failure is one observable with `verify-flipped-ciphertext-byte`, per D81), discharged by three named tests rather than a matrix row. `tamper_matrix_records_its_deliberate_non_rows` is what stops that discharge from decaying into an omission. |
| V2.3 | 168 | The **M2** anchor rows (untrusted TSA root, forged header, `.ots` not committing `anchor_digest`, expired-at-vs-after-genTime, BER-where-DER) | M2 | A21 | deferred | NONE at M0 — registered and pending in the tamper registry, implemented by A21 | Present in `MATRIX.json` as pending families; the completeness checker keeps them visible instead of letting them be forgotten. Checked at the M2 review, not at Q14. |

### Line 169 — fine-tree E2E, perf budget, CBOR fuzzing

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V3.1 | 169 | Fine-tree range-proof E2E | M0 | G | covered | `crates/antseal-core/src/content/openings_e2e.rs::per_unit_openings_verify_against_the_committed_fine_root`, `crates/antseal-core/src/content/openings_e2e.rs::arbitrary_byte_ranges_verify_including_across_unit_boundaries`, `crates/antseal-core/src/content/openings_e2e.rs::per_unit_and_byte_range_openings_are_identical_on_the_same_span`, `crates/antseal-core/src/content/openings_e2e.rs::openings_do_not_verify_against_the_wrong_bytes_or_the_wrong_root` | Lives in `src/` deliberately, so the wasm32 `--lib` lane executes it too. Covers both halves the spec names: a leaf-aligned (per-unit) opening and an arbitrary byte-range opening, both against `fine_root`. |
| V3.2 | 169 | Unbalanced-`n` golden vector (n = 6) pinning MSB-first GGM indexing | M0 | G15 | covered | `crates/antseal-core/tests/fine_tree_vectors.rs::vector_fine_tree_document_covers_the_mandated_cases`, `crates/antseal-core/tests/cover_disclosure.rs::leaf_exact_cover_at_n6_reveal_2_discloses_exactly_salt_2`, `testdata/vectors/v1/fine-tree/fine-tree.json` | The vector's `msb-first-indexing` case computes the LSB-first walk as well and **requires the two to diverge**, so the vector cannot pass under the wrong indexing. The leaf-exact-cover test is the spec's own n=6-reveal-{2} example. |
| V3.3 | 169 | Perf / memory budget | M0 | G | covered | `crates/antseal-core/src/content/fine_tree/cost.rs::large_files_sit_at_the_bottom_of_the_spec_envelope`, `crates/antseal-core/src/content/fine_tree/cost.rs::estimate_matches_measured_counts`, `crates/antseal-core/src/content/fine_tree/build.rs::memory_stays_logarithmic`, `crates/antseal-core/src/content/fine_tree/proof.rs::proof_size_is_logarithmic` | Budget is asserted against a measured count, not a wall-clock timing, so it is stable in CI. |
| V3.4 | 169 | **bundle/manifest CBOR fuzzing in CI** | M0 | F17 + Q39 + Q9 | covered | `fuzz/fuzz_targets/manifest_decode.rs`, `fuzz/fuzz_targets/bundle_decode.rs`, `fuzz/fuzz_targets/codec_round_trip.rs`, `scripts/fuzz.sh`, `fuzz/rust-toolchain.toml`, `.github/workflows/ci.yml` | **Closed 2026-07-28 (M0 wave 6); this row read `gap` and was the last open M0 row.** All three missing pieces landed together: F17's three CBOR targets (`manifest_decode`, `bundle_decode`, `codec_round_trip`), Q39's dated nightly pin (`fuzz/rust-toolchain.toml` = `nightly-2026-01-26`, scoped to `fuzz/` only so the workspace stable pin and the MSRV are untouched), and Q9's `fuzz-smoke` lane, which is no longer a mount point: it installs pinned cargo-fuzz 0.13.2, builds the instrumented targets, runs `scripts/fuzz.sh selftest` — a permanent tripwire that fails the lane unless an injected panic both crashes the target **and** leaves a reproducer artifact — then fuzzes 90 s per target over `testdata/fuzz-seeds/`. Only after the self-test is a clean run treated as evidence. The in-suite property tests (`verify_fuzz.rs::arbitrary_bytes_never_panic`, `codec_properties.rs::arbitrary_bytes_never_panic_the_decoder`) remain as a cheap always-on complement, not as the coverage for this row. **Recorded limitation:** the lane's present content has not yet run on the remote (see `docs/ci-verification.md`); a lane that has never run remotely is weaker evidence than one that has. |
| V3.5 | 169 | Anchor-parser fuzzing | M2 | A23 + Q17 | deferred | NONE at M0 — spec places it at M2 explicitly | Blocked behind the same nightly pin as V3.4. |

### Line 170 — the UTF-8 corpus

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V4.1 | 170 | UTF-8 corpus: CRLF, NFD vs NFC, BOM, emoji/ZWJ, mixed scripts | M0 | G3 | covered | `crates/antseal-core/tests/utf8_corpus.rs::corpus_golden_outputs_match`, `crates/antseal-core/tests/utf8_corpus.rs::corpus_nfd_nfc_pairs_converge`, `crates/antseal-core/tests/utf8_corpus.rs::corpus_coverage_guard`, `testdata/utf8-corpus` | `corpus_coverage_guard` is what stops the corpus quietly losing a category: it asserts every spec-named class is still present. |
| V4.2 | 170 | Canonicalization idempotent | M0 | G3 | covered | `crates/antseal-core/tests/utf8_corpus.rs::corpus_idempotence`, `crates/antseal-core/tests/content_properties.rs::canonicalization_is_idempotent_over_arbitrary_bytes`, `crates/antseal-core/src/canon/pipeline.rs::forced_mode_is_total_idempotent_and_canonical` | Fixture-level and property-level, plus totality on invalid input. |
| V4.3 | 170 | Canonicalization cross-platform stable | M0 | G3 + Q1 | covered | `crates/antseal-core/tests/utf8_corpus.rs::corpus_canonical_form_invariant`, `.github/workflows/ci.yml`, `.gitattributes` | The `cross-os` CI job runs the `corpus_` and `vector_` filters on linux, macOS and Windows. `.gitattributes` marks `testdata/** -text` so a Windows checkout cannot rewrite fixture line endings and turn a real divergence into a green run. |

### Line 171 — adversarial doc-tests

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V5.1 | 171 | Confirmation attack against an unsalted **unit** variant | M0 | C19 | covered | `crates/antseal-core/src/crypto/confirmation_attack.rs (doctest: line 67)` | Executable doc-test: builds the unsalted commitment, brute-forces a guess set to recover the exact plaintext, then shows the salted `unit_commit` defeats the same attack. |
| V5.2 | 171 | Confirmation attack against an unsalted **file-hash** variant | M0 | C19 | covered | `crates/antseal-core/src/crypto/confirmation_attack.rs (doctest: line 155)` | Executable doc-test: a recipient of a **one-unit** reveal confirms the *entire* document against the unsalted file hash; the salted `canon_commit` blocks it. |

## M1 — storage (line 172)

Checked at the M1 review, not at Q14. Every row is `NONE` today because
`antseal-net` is a doc-comment stub with no `StorageBackend` and no
`MockBackend`, and no devnet script exists.

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V6.1 | 172 | Devnet E2E: multi-file seal with `--split` | M1 | S17 + Q15 | deferred | NONE at M0 | Venue decision is Q15's. |
| V6.2 | 172 | Kill **between pay and finalize** to resume, verifying no double payment | M1 | S18 | deferred | NONE at M0 | The spec calls this out specifically; it is the highest-value M1 row. |
| V6.3 | 172 | Kill **mid-upload** to resume: byte-identical ciphertext, and abort rather than re-encrypt under a journaled nonce | M1 | S18 | deferred | NONE at M0 | The `(k_u, nonce)`-reuse guard. |
| V6.4 | 172 | `restore` from vault backup on a clean tree | M1 | S14 | deferred | NONE at M0 | |
| V6.5 | 172 | UNANCHORED library-verify | M1 | A1 | deferred | NONE at M0 | Consumes V1.4's empty-anchor vector, which already exists. |
| V6.6 | 172 | `--live` re-fetch passes | M1 | S | deferred | NONE at M0 | Storage-linkage layer. |

## M2 — anchors (line 173)

Checked at the M2 review. `antseal-anchor` is a doc-comment stub;
`testdata/anchors/` holds a README and nothing else.

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V7.1 | 173 | Real OTS calendars: pending, then upgraded the next day | M2 | A25 + Q16 | deferred | NONE at M0 | Two-day protocol; non-CI lane by policy. |
| V7.2 | 173 | Real FreeTSA (ECDSA P-384) and DigiCert tokens verified against the pinned roots | M2 | A25 + A7 | deferred | NONE at M0 | |
| V7.3 | 173 | CI uses a mock TSA + recorded OTS fixtures (no real anchor network in CI) | M2 | A24 + Q16 | deferred | NONE at M0 | |

## M3 — reveal and verifier page (line 174)

Checked at the M3 review. `verifier-web/` holds a 484-byte `index.html`;
there is no playwright configuration.

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V8.1 | 174 | Reveal subset, verified offline via the **CLI** | M3 | R + U | deferred | NONE at M0 | |
| V8.2 | 174 | Reveal subset, verified offline via the **WASM page** in a headless browser | M3 | R27 + Q19 | deferred | NONE at M0 | Offline enforcement (external requests blocked, verdict still renders) is part of the row. |
| V8.3 | 174 | Verdict-wording snapshot tests | M3 | R18 | deferred | NONE at M0 | One authoritative wording set, per spec line 127. |
| V8.4 | 174 | Online-mode endpoint-disagreement case | M3 | A16 + R | deferred | NONE at M0 | Built on A16's typed disagreement outcome. |

## M4 — the release gate (line 175)

Checked at the M4 review via Q34, which requires this whole matrix green.

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V9.1 | 175 | Sepolia-mode seal | M4 | Q32 | deferred | NONE at M0 | |
| V9.2 | 175 | One small **real mainnet** seal, verified end-to-end from a clean machine using only the released signed binary and the hosted page | M4 | Q34 | deferred | NONE at M0 | The only pre-release public-network exposure; accepted and recorded. |
| V9.3 | 175 | Disk-loss restore drill | M4 | Q32 | deferred | NONE at M0 | Second clean machine, vault backup only. |

## Findings from building this matrix (2026-07-28, M0 wave 6)

1. **~~One M0 bullet has no test: V3.4, "bundle/manifest CBOR fuzzing in
   CI"~~ — CLOSED in wave 6; this finding was itself stale for a full wave.**
   As written (wave 6) it said three separate pieces were absent — targets,
   nightly toolchain pin, lane — and that *"Q14's M0 rows cannot be complete
   until F17, Q39 and Q9 land"*. All three landed in that same wave. The
   V3.4 row was corrected to `covered`; **this paragraph was not**, and
   `--matrix` could not see the difference because it never read the status
   column. Corrected 2026-07-28 (M0 wave 7).

   The finding worth keeping is the second-order one, and it is why `Q51`
   exists: *a matrix maintained by hand goes stale in the direction of
   pessimism, and a stale row asserting that a milestone is blocked is more
   expensive than a missing row* — Q14's normative row N7 reproduced this
   claim verbatim and told a gate executor that the freeze was blocked by
   completed work. The status column is machine-checked from wave 7 onward.
2. **"Unit/property tests per crate" (V1.1) needed a reading, not a tick.**
   Three of five workspace crates have zero tests. All three are stubs whose
   milestones have not arrived, so the honest row states the reading rather
   than claiming five-crate coverage.
3. **Line 168's M0 families are delegated, not duplicated.** `MATRIX.json`
   plus `tamper_matrix_is_mapped_1_to_1_onto_the_spec_row_list` already binds
   the registry to the spec's own sentence. This matrix names that binding
   instead of copying ~20 rows into a third list.
4. **One family in that set is a deliberate non-row and is worth knowing at
   the gate**: *swapped unit* has no tamper row because its failure is one
   observable with `verify-flipped-ciphertext-byte` (D81). It is discharged
   by three named tests and pinned by
   `tamper_matrix_records_its_deliberate_non_rows`.

## Changelog

- **2026-07-28 (M0 wave 6, Q13)** — matrix created from the tree as it
  actually stands, not from task text. 34 rows over every bullet of spec
  lines 167–175. One M0 gap found and named (V3.4). Machine-checked by
  `scripts/check-traceability.py --matrix`, which is proven able to fail via
  `--self-test`.
