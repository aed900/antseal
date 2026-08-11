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
  Q34, which requires the whole matrix green). **M1's review has happened and
  M1 is gated from 2026-08-10** (D118); M2's has not. A later milestone's row
  reading `NONE` is correct, not a gap — but only while the crates it tests
  are stubs, and that sentence outlived its truth here by eight days.
- Status vocabulary: **`covered`** (a test exists and is named here);
  **`gap`** (the milestone owns the bullet and no test exists — this blocks
  that milestone's gate); **`deferred`** (a later milestone owns it). Nothing
  else parses: an unrecognised status is a typo and fails the check, at every
  milestone, because a typo at a not-yet-gated one would otherwise stay
  invisible until that milestone's review.
- **`deferred` is the one status that decays on its own, and D118 is what it
  cost.** It is not a property of the row; it is a *relation* between the
  row's milestone and `CURRENT_MILESTONE`. A row is correctly `deferred` only
  while its own milestone is strictly later than the constant. The moment the
  constant reaches that milestone, `deferred` is a category error and the row
  must be re-read as `covered` or `gap`. All eleven rows D118 adjudicated had
  decayed exactly this way, and none of them changed a character while doing
  it — the constant moved underneath them, or rather failed to.
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
| V2.3 | 168 | The **M2** anchor rows (untrusted TSA root, forged header, `.ots` not committing `anchor_digest`, expired-at-vs-after-genTime, BER-where-DER) | M2 | A21 | covered | `crates/antseal-core/src/test_util/tamper_rows_anchor_verdicts.rs`, `crates/antseal-core/tests/tamper_matrix.rs::tamper_matrix_m2_anchor_set_is_the_pinned_size_and_armed`, `crates/antseal-core/tests/tamper_matrix.rs::tamper_matrix_is_mapped_1_to_1_onto_the_spec_row_list`, `testdata/tamper/MATRIX.json` | **A21 landed 2026-08-06; this row went on reading `deferred` for four days (D118).** The five clauses the bullet names are **eight** live rows in `tamper_rows_anchor_verdicts.rs::ROWS` over six `MATRIX.json` families — `anchor-token-for-a-different-digest` is two rows and not one, because D53 §8 found the spec clause compound and the two checks sit in different stages on different artifact kinds, so one row cannot discharge both. `tamper_matrix_m2_anchor_set_is_the_pinned_size_and_armed` pins the count **and** that every case supplies an outcome key, so the layer-3 distinctness check cannot silently skip the anchor half. |

### Line 169 — fine-tree E2E, perf budget, CBOR fuzzing

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V3.1 | 169 | Fine-tree range-proof E2E | M0 | G | covered | `crates/antseal-core/src/content/openings_e2e.rs::per_unit_openings_verify_against_the_committed_fine_root`, `crates/antseal-core/src/content/openings_e2e.rs::arbitrary_byte_ranges_verify_including_across_unit_boundaries`, `crates/antseal-core/src/content/openings_e2e.rs::per_unit_and_byte_range_openings_are_identical_on_the_same_span`, `crates/antseal-core/src/content/openings_e2e.rs::openings_do_not_verify_against_the_wrong_bytes_or_the_wrong_root` | Lives in `src/` deliberately, so the wasm32 `--lib` lane executes it too. Covers both halves the spec names: a leaf-aligned (per-unit) opening and an arbitrary byte-range opening, both against `fine_root`. |
| V3.2 | 169 | Unbalanced-`n` golden vector (n = 6) pinning MSB-first GGM indexing | M0 | G15 | covered | `crates/antseal-core/tests/fine_tree_vectors.rs::vector_fine_tree_document_covers_the_mandated_cases`, `crates/antseal-core/tests/cover_disclosure.rs::leaf_exact_cover_at_n6_reveal_2_discloses_exactly_salt_2`, `testdata/vectors/v1/fine-tree/fine-tree.json` | The vector's `msb-first-indexing` case computes the LSB-first walk as well and **requires the two to diverge**, so the vector cannot pass under the wrong indexing. The leaf-exact-cover test is the spec's own n=6-reveal-{2} example. |
| V3.3 | 169 | Perf / memory budget | M0 | G | covered | `crates/antseal-core/src/content/fine_tree/cost.rs::large_files_sit_at_the_bottom_of_the_spec_envelope`, `crates/antseal-core/src/content/fine_tree/cost.rs::estimate_matches_measured_counts`, `crates/antseal-core/src/content/fine_tree/build.rs::memory_stays_logarithmic`, `crates/antseal-core/src/content/fine_tree/proof.rs::proof_size_is_logarithmic` | Budget is asserted against a measured count, not a wall-clock timing, so it is stable in CI. |
| V3.4 | 169 | **bundle/manifest CBOR fuzzing in CI** | M0 | F17 + Q39 + Q9 | covered | `fuzz/fuzz_targets/manifest_decode.rs`, `fuzz/fuzz_targets/bundle_decode.rs`, `fuzz/fuzz_targets/codec_round_trip.rs`, `scripts/fuzz.sh`, `fuzz/rust-toolchain.toml`, `.github/workflows/ci.yml` | **Closed 2026-07-28 (M0 wave 6); this row read `gap` and was the last open M0 row.** All three missing pieces landed together: F17's three CBOR targets (`manifest_decode`, `bundle_decode`, `codec_round_trip`), Q39's dated nightly pin (`fuzz/rust-toolchain.toml` = `nightly-2026-01-26`, scoped to `fuzz/` only so the workspace stable pin and the MSRV are untouched), and Q9's `fuzz-smoke` lane, which is no longer a mount point: it installs pinned cargo-fuzz 0.13.2, builds the instrumented targets, runs `scripts/fuzz.sh selftest` — a permanent tripwire that fails the lane unless an injected panic both crashes the target **and** leaves a reproducer artifact — then fuzzes 90 s per target over `testdata/fuzz-seeds/`. Only after the self-test is a clean run treated as evidence. The in-suite property tests (`verify_fuzz.rs::arbitrary_bytes_never_panic`, `codec_properties.rs::arbitrary_bytes_never_panic_the_decoder`) remain as a cheap always-on complement, not as the coverage for this row. **Recorded limitation:** the lane's present content has not yet run on the remote (see `docs/ci-verification.md`); a lane that has never run remotely is weaker evidence than one that has. |
| V3.5 | 169 | Anchor-parser fuzzing | M2 | A23 + Q17 | covered | `fuzz/fuzz_targets/anchor_token.rs`, `fuzz/fuzz_targets/anchor_ots.rs`, `crates/antseal-core/src/anchor/fuzz_entry.rs::the_driver_is_exercised_by_the_normal_suite`, `crates/antseal-core/src/anchor/fuzz_entry.rs::the_ots_driver_is_exercised_by_the_normal_suite`, `crates/antseal-core/src/anchor/fuzz_entry.rs::the_ots_driver_reaches_the_walk_rather_than_stalling_at_the_digest`, `scripts/fuzz.sh` | **A23 and Q17 both landed 2026-08-05; this row read `deferred` for five days (D118).** Both targets — `anchor_token` (DER/CMS/X.509) and `anchor_ots` (decode, op execution, all seven D58 limits) — sit in `scripts/fuzz.sh`'s `TARGETS`, so `fuzz-smoke` and `fuzz-long` pick them up with no workflow edit, and they are seeded from the real `testdata/anchors/A25-bootstrap/` captures rather than a synthetic corpus. The drivers are in-crate, so the ordinary suite executes both entry points even where nothing runs libFuzzer; `the_ots_driver_reaches_the_walk_rather_than_stalling_at_the_digest` is what stops that in-suite exercise decaying into a call that returns at the first length check. The nightly pin V3.4 records is shared, not a blocker: it is `fuzz/rust-toolchain.toml`, scoped to `fuzz/` only. |

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

**M1 is complete and this section is gated.** `CURRENT_MILESTONE` reached
`M1` on 2026-08-10 (D118) and `M2` on 2026-08-11 (Q236), so every row here
must read `covered` on the ordinary flagless run, cumulatively with M0's.

The paragraph that stood here said *"every row is `NONE` today because
`antseal-net` is a doc-comment stub with no `StorageBackend` and no
`MockBackend`, and no devnet script exists"*. **All three clauses were false
from 2026-08-02**, and all six rows below went on reading `deferred` for eight
days after the work landed — invisibly, because `CURRENT_MILESTONE` was still
`M0` and no runbook asks anyone to type `--milestone`. The venue is
`scripts/e2e-devnet.sh`, D52's required **local** gate and scheduled lane —
one script for both — whose `suite_registry` names every suite below as
`live` and refuses to go quiet if one is deleted or renamed.

**Recorded limitation, and it applies to all six rows.** These suites run
against a live 14-node devnet, in a local gate and a scheduled lane. They are
not a required remote context, so this section's evidence has never gated a
pull request. That is weaker evidence than a required lane, in exactly the
sense V3.4's note records for `fuzz-smoke`.

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V6.1 | 172 | Devnet E2E: multi-file seal with `--split` | M1 | S17 + Q15 | covered | `crates/antseal-cli/tests/e2e_devnet.rs::the_multi_file_split_seal_round_trips_against_a_live_devnet`, `scripts/e2e-devnet.sh` | Venue decision was Q15's and it landed 2026-08-02 with S17, on a live 14-node devnet. The suite is registered `live` in `e2e-devnet.sh`'s `suite_registry`, which is a second, independent statement that this row's test exists — the script fails if the named suite is missing. |
| V6.2 | 172 | Kill **between pay and finalize** to resume, verifying no double payment | M1 | S18 | covered | `crates/antseal-cli/tests/e2e_kill_resume.rs::case1_a_kill_between_pay_and_finalize_never_pays_twice`, `crates/antseal-cli/tests/e2e_kill_resume.rs::case1_a_real_sigkill_between_pay_and_finalize_never_pays_twice`, `crates/antseal-cli/tests/e2e_kill_resume.rs::case1c_a_sigkill_between_sub_batch_txs_pays_each_sub_batch_once` | The spec calls this out specifically; it is the highest-value M1 row, and S18 landed it 2026-08-02. **Two kill shapes, not one** — a cooperative barrier and a real `SIGKILL` — and every payment claim is settled **on-chain** by counting Anvil transactions rather than by an in-process ledger, so the assertion does not depend on the code under test being honest about what it paid. The negative twin `case1c_without_a_durable_sink_the_same_kill_re_pays_the_landed_sub_batches` is what proves the guard is the durable sink and not the harness. |
| V6.3 | 172 | Kill **mid-upload** to resume: byte-identical ciphertext, and abort rather than re-encrypt under a journaled nonce | M1 | S18 | covered | `crates/antseal-cli/tests/e2e_kill_resume.rs::case2_a_sigkill_mid_upload_resumes_byte_identically`, `crates/antseal-cli/tests/e2e_kill_resume.rs::case3_changed_sources_with_staged_bytes_gone_abandons`, `crates/antseal-cli/tests/e2e_kill_resume.rs::case3_changed_sources_with_staged_bytes_intact_resume_from_staged_bytes` | **Both halves of the bullet, and they are different tests.** `case2` reads every staged nonce before the kill and re-reads them after the resume, so a re-encryption is caught as a *changed nonce* rather than inferred from byte equality alone. `case3` is the `(k_u, nonce)`-reuse guard the bullet's second clause names: changed sources with the staged bytes gone **abandon** rather than re-encrypt, and the intact-bytes twin shows the abandon is a decision and not the only reachable path. |
| V6.4 | 172 | `restore` from vault backup on a clean tree | M1 | S14 | covered | `crates/antseal-cli/tests/e2e_restore.rs::a_clean_machine_restores_from_the_vault_backup_and_the_network`, `crates/antseal-cli/tests/e2e_restore.rs::a_clean_machine_without_the_vault_fails_with_a_clear_no_vault_error`, `scripts/e2e-devnet.sh` | S19's suite over S14's `RestoreEngine`; the row's owner column names the engine, the registry names the suite. The clean tree is a **real child process** with its own root, not a reset directory in the parent. The no-vault twin is the anti-vacuity arm: without it, a restore reading the parent's residual state would pass and nothing would say so. |
| V6.5 | 172 | UNANCHORED library-verify | M1 | A1 | covered | `crates/antseal-cli/tests/e2e_devnet.rs::a_zero_anchor_seal_library_verifies_as_unanchored` | Consumes V1.4's empty-anchor vector, which already existed at M0 — the row predicted this and was right. A1's `AnchorGate`/`NoAnchorGate` zero-anchor contract is what the test drives, through library APIs and not the M3 `verify` CLI, per the spec bullet's own parenthesis. |
| V6.6 | 172 | `--live` re-fetch passes | M1 | S | covered | `crates/antseal-net/tests/devnet_backend.rs::devnet_s15_live_persistence_identical_missing_and_different`, `crates/antseal-cli/tests/e2e_devnet.rs::the_multi_file_split_seal_round_trips_against_a_live_devnet`, `scripts/e2e-devnet.sh` | Storage-linkage layer. The named devnet test separates the **three** outcomes a live re-fetch can have — identical, missing, different — so a pass is not merely "the fetch returned something", which is the failure a single happy-path assertion would have shipped. |

## M2 — anchors (line 173)

Checked at the M2 review, which ran 2026-08-11 (Q236).
`CURRENT_MILESTONE` is `M2`, so every row here is gated by the ordinary
flagless run, cumulatively with M0's and M1's. Four rows read `covered`;
`V7.1` reads `gap` under the register's first `ACCEPTED_NON_COVERED`
entry (D127) — M2 shipped with that one hole recorded, closure owed as a
consented submit→upgrade pair (maintainer-actions), the entry's removal
enforced by the checker's staleness arms.

The paragraph that stood here said *"`antseal-anchor` is a doc-comment stub;
`testdata/anchors/` holds a README and nothing else"*. `antseal-anchor` has
carried a TSA layer, an OTS engine, an esplora client, an Arbitrum client and
a stub/replay test substrate since the M2 wave opened, and `testdata/anchors/`
holds **88 files** across three real capture campaigns (`A25-bootstrap/` 61,
`A25-upgrade-headers/` 14, `A16-A17-live/` 12, plus the directory README).

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V7.1 | 173 | Real OTS calendars: pending, then upgraded the next day | M2 | A25 + Q16 | gap | `testdata/anchors/A25-bootstrap`, `testdata/anchors/A25-bootstrap/upgraded`, `docs/anchors/real-smoke-runbook.md`, `crates/antseal-core/tests/anchor_vectors.rs::vector_anchor_upgraded_artifact_has_the_shape_the_f4_registry_records`, `crates/antseal-core/tests/anchor_vectors.rs::vector_anchor_ops_derive_the_fetched_mainnet_headers_merkle_root` | **The one genuine hole among the eleven D118 adjudicated, and the reason this row is `gap` rather than `covered`.** The cycle really happened and is fully logged — submit 2026-08-02T19:16:18Z, upgrade 2026-08-03T09:03:38Z, six commitments all `200` — and the resulting bytes are verified offline by the named tests. But **it was performed by hand with `curl`, before the OTS client existed**: `CAPTURE.log` still carries curl's own *"Could not resolve host"* line for the `finney` calendar. A25's Accept row 1 is adjudicated **PARTIAL** for exactly this reason. The spec's own heading for this bullet is **"Anchor smoke tests"**, so offline replay of captured bytes is not the thing being asked for. **2026-08-11: the script half landed and the row stays `gap`, with the reason recorded.** `scripts/anchor-smoke` now exists (runbook §0 deleted in the same change, per Q99 row 1), drives antseal's own clients — `submit_to_calendars`, `pending_refs`/`poll_upgrade`, `capture_one` against the pinned store — through the dev-only `anchor-smoke-driver` binary, and its loopback selftest proves every mode's code path plus four refusal arms by message. What it does not change: **antseal's own path has still never spoken to a real calendar** — the selftest is loopback by policy, and the script's real-endpoint branch is unproven until the maintainer-consented day-2 run (script-driven upgrades of `testdata/anchors/A25-wave16-cycle`'s eight pendings), which is exactly what the script now exists to make repeatable. **2026-08-11 ~17:55Z: the consented run happened through the script, and the sentence that stood here — *this row moves when that consented run has happened through the script* — was met and is REPLACED as insufficient (D117): it conflated proving the script's real branch with proving both client paths.** What the run proved: antseal's A14 **upgrade** path spoke to real calendars (6 of 8 upgraded, 2 honestly `not-yet-confirmed` and kept re-pollable; logs at `testdata/anchors/A25-wave16-cycle/upgraded/`), and A10/A16/A17 ran their real legs (both TSA tokens `Proven` against the pinned store; both must-agree rounds agreed over extracted tuples). What it could not prove: the **submit** path — day-1's pendings were created by hand, and the run's recorded consent scope excluded fresh submissions. The row stays `gap` on exactly that residue; **one consented script-driven submit pair closes it**, or the M2 review rules it on the record (Q236's Accept forbids sliding past it). Non-CI by policy either way — `docs/testing/anchor-ci-policy.md`. **2026-08-11, the M2 review (Q236 / D127): ruled on the record — the second arm of exactly the disjunction this cell's last sentence named.** The review neither slid past the residue (a gated `gap` without a register entry is red — the checker forbids the slide mechanically) nor parked on an absent third party: `ACCEPTED_NON_COVERED` gains its first entry (reason verbatim from D127 §6 E1) in the same change as the M1 → M2 bump, so M2 ships with the hole recorded and loud rather than mis-marked `covered`. What a real submit pair still proves above everything banked (D127 §2): real pool-host acceptance of the client-built `POST /digest` — day-1's eight pendings went to the four `DEFAULT_OTS_CALENDARS` pool hosts (`a.pool.opentimestamps.org`, `b.pool.opentimestamps.org`, `a.pool.eternitywall.com`, `ots.btc.catallaxy.com`) by hand, while the day-2 upgrades spoke to the *calendar* hosts the attestations name, so the product's client has never contacted the pool set in any mode — fresh-response validation in situ, and the composed product cycle (client-submitted pending → client-upgraded), which has never run. Closure is unchanged and now machine-enforced: on the first consented script-driven submit→upgrade pair (D127 §5's predicate: submits accepted through the client AND ≥1 client-submitted commitment upgraded through the client), this row flips `covered` and the register entry is removed **in one change** — the checker reds either half alone — with the campaign owed at TODO.md's maintainer-actions list. |
| V7.2 | 173 | Real FreeTSA (ECDSA P-384) and DigiCert tokens verified against the pinned roots | M2 | A25 + A7 | covered | `crates/antseal-core/tests/anchor_real_tokens.rs::freetsa_verifies_ecdsa_p384_sha512`, `crates/antseal-core/tests/anchor_real_tokens.rs::digicert_verifies_rsa_pkcs1v15_sha256`, `crates/antseal-core/src/anchor/verdicts/tests.rs::a_token_whose_cms_signature_fails_never_reaches_chain_classification`, `crates/antseal-core/src/anchor/verdicts/tests.rs::a_malformed_bundle_intermediate_is_invalid_with_a5s_der_code`, `testdata/anchors/A25-bootstrap` | Real 2026-08-02 captures, not synthetic tokens; A7 admitted the roots with a written provenance record. A25's Accept row 2 is adjudicated **SATISFIED**. **Recorded limitation, and it is why `A105` is open:** the two assertions carrying the *pinned-store* half — `FREETSA` and `DIGICERT` reaching `proven` under `TsaRootStore::pinned()` — are the **anti-vacuity arms** of the two `verdicts` tests named here, which are named for something else. The pin is real and the build reddens if either token stops reaching `proven`, but the exposure is **asymmetric**: `DIGICERT` reaches `proven` at three further places and `FREETSA` at exactly one, so a tamper-test rewrite could delete the FreeTSA half and take the milestone criterion with it. A105 gives the property its own named home at the verdict level; this cell names it when it lands. |
| V7.3 | 173 | CI uses a mock TSA + recorded OTS fixtures (no real anchor network in CI) | M2 | A24 + Q16 | covered | `crates/antseal-anchor/tests/no_real_network.rs::the_environment_arm_gates_the_dialling_path_in_a_non_cfg_test_build`, `crates/antseal-anchor/src/testing/stub.rs`, `crates/antseal-anchor/src/testing/replay.rs::the_committed_captures_have_their_recorded_shapes`, `crates/antseal-anchor/src/testing/replay.rs::the_attested_block_captures_have_their_recorded_shapes`, `scripts/check-anchor-net.py`, `docs/testing/anchor-ci-policy.md`, `testdata/anchors` | **The policy is enforced, not merely stated.** The runtime gate lives in `HttpClient::attempt` — the one function in the workspace that hands a URL to `ureq` — and refuses any endpoint that is not a loopback literal; its `cfg(test)` arm is armed by the compiler with no off switch, and `ANTSEAL_NO_REAL_ANCHOR_NETWORK` arms every other test binary. `check-anchor-net.py` checks the three things a runtime gate structurally cannot see: that the arming is declared in every committed workflow, that there is exactly **one** HTTP client in the workspace, and that the endpoint inventory is closed. The stubs match on the **request** rather than on position, so a client retry cannot be handed the next scripted body — a sequential script would have passed while testing the wrong thing. |

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

## Findings from adjudicating the eleven deferred rows (2026-08-10, D118)

5. **Finding 1 recurred, and Q51's fix did not stop it — it moved it.**
   Q51 made the status column machine-checked so a stale row could not
   survive a milestone review. It checks the column *against
   `CURRENT_MILESTONE`*, and that constant sat at `M0` from the freeze until
   2026-08-10 while M1 shipped and M2 reached its halfway point. So the gate
   was green over sixteen M0 rows and blind to eighteen others, and the six
   M1 rows repeated V3.4's failure — **stale in the direction of pessimism,
   asserting work was missing that was already done** — for eight days, with
   the lint green the whole time. The instrument was correct and unarmed.
   **A gate parameterised by a hand-maintained constant is only as current as
   the constant**, and nothing in this file, in the checker, or in any runbook
   compared that constant to the milestone the project was actually in.
6. **Ten of the eleven were stale; exactly one was real.** The comfortable
   reading — *"it is all bookkeeping"* — is wrong by one row, and the
   uncomfortable one — *"eleven live claims that work is missing"* — is wrong
   by ten. `V7.1` is the survivor, and it survives on a distinction no status
   column can express: the real two-day calendar cycle **happened**, but
   `curl` performed it, not antseal. Replaying captured bytes offline proves
   the parser; it does not prove the client. The rows that record a real
   campaign are the ones most likely to be mistaken for coverage.
7. **The `deferred` status is a relation, not a property, and it is the only
   status in the vocabulary that can rot without being edited.** `covered`
   and `gap` are claims about the tree; `deferred` is a claim about the
   *calendar*. Every one of the eleven became wrong without a character
   changing. This is now stated in the vocabulary note above.
8. **Both self-test fixtures for the status gate were pinned to `V6.1`'s
   cell** (`| M1 | S17 + Q15 | deferred |`), one asserting green and one
   asserting red. Marking `V6.1` covered would have made both mutations
   match nothing — and the harness fails loudly on a no-op mutation, so the
   fixtures were retargeted to `V9.2`'s `| M4 | Q34 | deferred |` in the same
   change. `V9.2` is the real-mainnet-seal row: it cannot be covered before
   the release gate, and at that gate Q34 requires the whole matrix green, so
   the fixture's expiry now coincides with a moment somebody is already
   forced to look. **A self-test fixture pinned to a row's status inherits
   that row's lifetime**, which is the same class of defect as this file's
   own hand-maintained counts.

## Changelog

- **2026-07-28 (M0 wave 6, Q13)** — matrix created from the tree as it
  actually stands, not from task text. 34 rows over every bullet of spec
  lines 167–175. One M0 gap found and named (V3.4). Machine-checked by
  `scripts/check-traceability.py --matrix`, which is proven able to fail via
  `--self-test`.
- **2026-08-10 (M2 wave 14, Q165 / D118)** — the eleven rows reading
  `deferred` at or before M2 adjudicated one by one against the tree, and
  **`CURRENT_MILESTONE` moved `M0` → `M1`**, the milestone whose review has
  actually passed. Ten rows were stale and are now `covered` with named
  evidence: `V2.3` (A21, eight live anchor tamper rows), `V3.5` (A23 + Q17,
  both fuzz targets), `V6.1`–`V6.6` (S17/S18/S14/A1 + Q15's venue), `V7.2`
  (A25 row 2, with A105's asymmetry recorded as a limitation) and `V7.3`
  (A24 + Q16's enforced policy). **One was real**: `V7.1` is now `gap` — the
  real calendar cycle was run by hand with `curl` and antseal's own path has
  never performed it. `ACCEPTED_NON_COVERED` stays empty; nothing was
  exempted, because exempting an in-progress milestone's row would mute it at
  the review that is supposed to read it. The M1 and M2 section preambles
  were rewritten: both described a tree that stopped existing on 2026-08-02.
