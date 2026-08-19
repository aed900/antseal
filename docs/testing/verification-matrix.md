# Verification-coverage traceability matrix (Q13)

> **Owning task: Q13** (`tasks/Q.md`), milestone **M0** — tagged M0 because it
> must exist at the freeze; maintained continuously through M4.
> **Spec basis: MVP-SPEC.md lines 165–175**, the Verification section, every
> bullet of it — **plus one declared extension: MVP-SPEC.md line 143**, the
> Vault paragraph, whose clause-by-clause conformance table is the last
> section of this file. That extension is **Q251**'s and is stated here
> rather than left implicit, because a table sitting inside a file whose
> declared basis excludes it is the same silent divergence Q251 exists to
> collect. What it costs is recorded at that section's preamble.
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
>
> **The rule binds the whole file, not only the checked column** — stated
> because Q251 arrived with an `Accept` row asking for `path:line` citations
> and the two had to be reconciled rather than both obeyed. The checker
> resolves the `tests / evidence` cell and never reads `notes`, so a line
> number in `notes` would be a pointer nothing verifies: the worst of the two
> shapes, not a compromise between them. Shipped behaviour is therefore named
> by **symbol** here — `KdfParams::check_ranges`, not `kdf.rs:280` — which is
> exact, greppable and survives an edit above it. Q251 supplied the
> demonstration as well as the request: of the eighteen `path:line` locators
> its own row and the records feeding it carried, **three did not survive
> re-measurement** — one naming an unrelated line, one naming an unrelated
> section of the record it quotes, and one naming the first guard inside a
> match arm rather than the arm (see that section's preamble). The dated
> `path:line` measurements live in `TODO.md`'s row and the `tasks/Q.md`
> entry, where they are timestamped claims about one tree state; this file
> carries the durable form.

## How the gate uses this

- **M0 rows must be complete before the `format-v1-freeze` tag** — that is a
  Q14 gate condition, and Q14's checklist cites this file.
- **M1/M2/M3/M4 rows are checked at their own milestone reviews** (M4 via
  Q34, which requires the whole matrix green). **Which reviews have passed is
  deliberately not restated here.** The sentence that stood in this position
  said M1 was gated and M2's review had not happened; M2's review ran the
  next day and the sentence went on saying it for five more days, which is
  **Q230**'s class exactly — a second, unchecked copy of a value that changes
  at the one event it describes. The script's constant is the only copy; read
  it there. A later milestone's row reading `NONE` is correct, not a gap —
  but only while the crates it tests are stubs, and that sentence outlived
  its truth here by eight days.
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
  the constant `CURRENT_MILESTONE` in that script. **It names the last
  milestone whose review has passed, and what moves it is that milestone's
  own gate row** (`Q14` did it for M0, `Q236` for M2, `Q237` for M3; `Q34`
  will for M4) — `TODO.md` rule 4. It is deliberately **one behind**
  `TODO.md`'s Current-focus block, which names the milestone in progress:
  nothing compares the two, and D122 rules that nothing should. It is a
  constant and not a required flag on purpose: a gate
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
**M2's review has passed**, so every row here is gated by the ordinary
flagless run, cumulatively with M0's and M1's — and it stays gated as later
reviews pass, which is what *cumulative* means. The constant's current value
is the script's to state and is not repeated here (Q230). **All five rows now read `covered`.** `V7.1` read `gap`
under the register's first `ACCEPTED_NON_COVERED` entry (D127) from the M2
review until **2026-08-12**, when the consented submit→upgrade pair ran and
D127 §5's predicate was met — so the cell flipped and the entry was removed
in one change, which is the only way the checker permits either. The
register is empty again and its first entry lasted a day; the mechanism, not
the entry, was what D118 §5's price bought.

The paragraph that stood here said *"`antseal-anchor` is a doc-comment stub;
`testdata/anchors/` holds a README and nothing else"*. `antseal-anchor` has
carried a TSA layer, an OTS engine, an esplora client, an Arbitrum client and
a stub/replay test substrate since the M2 wave opened, and `testdata/anchors/`
holds **88 files** across three real capture campaigns (`A25-bootstrap/` 61,
`A25-upgrade-headers/` 14, `A16-A17-live/` 12, plus the directory README).

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V7.1 | 173 | Real OTS calendars: pending, then upgraded the next day | M2 | A25 + Q16 | covered | `testdata/anchors/A25-bootstrap`, `testdata/anchors/A25-bootstrap/upgraded`, `docs/anchors/real-smoke-runbook.md`, `crates/antseal-core/tests/anchor_vectors.rs::vector_anchor_upgraded_artifact_has_the_shape_the_f4_registry_records`, `crates/antseal-core/tests/anchor_vectors.rs::vector_anchor_ops_derive_the_fetched_mainnet_headers_merkle_root` | **The one genuine hole among the eleven D118 adjudicated, and the reason this row is `gap` rather than `covered`.** The cycle really happened and is fully logged — submit 2026-08-02T19:16:18Z, upgrade 2026-08-03T09:03:38Z, six commitments all `200` — and the resulting bytes are verified offline by the named tests. But **it was performed by hand with `curl`, before the OTS client existed**: `CAPTURE.log` still carries curl's own *"Could not resolve host"* line for the `finney` calendar. A25's Accept row 1 is adjudicated **PARTIAL** for exactly this reason. The spec's own heading for this bullet is **"Anchor smoke tests"**, so offline replay of captured bytes is not the thing being asked for. **2026-08-11: the script half landed and the row stays `gap`, with the reason recorded.** `scripts/anchor-smoke` now exists (runbook §0 deleted in the same change, per Q99 row 1), drives antseal's own clients — `submit_to_calendars`, `pending_refs`/`poll_upgrade`, `capture_one` against the pinned store — through the dev-only `anchor-smoke-driver` binary, and its loopback selftest proves every mode's code path plus four refusal arms by message. What it does not change: **antseal's own path has still never spoken to a real calendar** — the selftest is loopback by policy, and the script's real-endpoint branch is unproven until the maintainer-consented day-2 run (script-driven upgrades of `testdata/anchors/A25-wave16-cycle`'s eight pendings), which is exactly what the script now exists to make repeatable. **2026-08-11 ~17:55Z: the consented run happened through the script, and the sentence that stood here — *this row moves when that consented run has happened through the script* — was met and is REPLACED as insufficient (D117): it conflated proving the script's real branch with proving both client paths.** What the run proved: antseal's A14 **upgrade** path spoke to real calendars (6 of 8 upgraded, 2 honestly `not-yet-confirmed` and kept re-pollable; logs at `testdata/anchors/A25-wave16-cycle/upgraded/`), and A10/A16/A17 ran their real legs (both TSA tokens `Proven` against the pinned store; both must-agree rounds agreed over extracted tuples). What it could not prove: the **submit** path — day-1's pendings were created by hand, and the run's recorded consent scope excluded fresh submissions. The row stays `gap` on exactly that residue; **one consented script-driven submit pair closes it**, or the M2 review rules it on the record (Q236's Accept forbids sliding past it). Non-CI by policy either way — `docs/testing/anchor-ci-policy.md`. **2026-08-11, the M2 review (Q236 / D127): ruled on the record — the second arm of exactly the disjunction this cell's last sentence named.** The review neither slid past the residue (a gated `gap` without a register entry is red — the checker forbids the slide mechanically) nor parked on an absent third party: `ACCEPTED_NON_COVERED` gains its first entry (reason verbatim from D127 §6 E1) in the same change as the M1 → M2 bump, so M2 ships with the hole recorded and loud rather than mis-marked `covered`. What a real submit pair still proves above everything banked (D127 §2): real pool-host acceptance of the client-built `POST /digest` — day-1's eight pendings went to the four `DEFAULT_OTS_CALENDARS` pool hosts (`a.pool.opentimestamps.org`, `b.pool.opentimestamps.org`, `a.pool.eternitywall.com`, `ots.btc.catallaxy.com`) by hand, while the day-2 upgrades spoke to the *calendar* hosts the attestations name, so the product's client has never contacted the pool set in any mode — fresh-response validation in situ, and the composed product cycle (client-submitted pending → client-upgraded), which has never run. Closure is unchanged and now machine-enforced: on the first consented script-driven submit→upgrade pair (D127 §5's predicate: submits accepted through the client AND ≥1 client-submitted commitment upgraded through the client), this row flips `covered` and the register entry is removed **in one change** — the checker reds either half alone — with the campaign owed at TODO.md's maintainer-actions list. **2026-08-12 — CLOSED, by the composed cycle D127 §2 said had never run.** Both halves ran through antseal's own clients under separately recorded, in-the-moment maintainer consent: **2026-08-11T23:39–23:40Z, 8 of 8 `pending-accepted`** through A13's `submit_to_calendars` at all four `DEFAULT_OTS_CALENDARS` **pool** hosts — the set D127 measured the product had never contacted in any mode — and **2026-08-12, 6 of those same 8 upgraded** through A14's `poll_upgrade` (`alice`, `bob`, `catallaxy` for both committed golden-vector digests; the two `eternitywall` pendings honestly `not-yet-confirmed` and left re-pollable, which is the same outcome the wave-16 cycle recorded and is a calendar's cadence, not a defect). That satisfies D127 §5's predicate — submits accepted through the client **and** ≥1 **client-submitted** commitment upgraded through the client — six times over, and it is the first time the two halves have been the *same* commitments. Captures: `testdata/anchors/A25-wave17-cycle/` (day 1) and `testdata/anchors/A25-wave17-cycle/upgraded/` (day 2), each with its consent recorded verbatim in its own capture log per runbook §1. The cell's flip and the removal of the register's `ACCEPTED_NON_COVERED` entry landed in **one change**, because the checker reds either half alone. Non-CI by policy, unchanged (`docs/testing/anchor-ci-policy.md`). |
| V7.2 | 173 | Real FreeTSA (ECDSA P-384) and DigiCert tokens verified against the pinned roots | M2 | A25 + A7 | covered | `crates/antseal-core/tests/anchor_real_tokens.rs::freetsa_verifies_ecdsa_p384_sha512`, `crates/antseal-core/tests/anchor_real_tokens.rs::digicert_verifies_rsa_pkcs1v15_sha256`, `crates/antseal-core/src/anchor/verdicts/tests.rs::a_token_whose_cms_signature_fails_never_reaches_chain_classification`, `crates/antseal-core/src/anchor/verdicts/tests.rs::a_malformed_bundle_intermediate_is_invalid_with_a5s_der_code`, `testdata/anchors/A25-bootstrap` | Real 2026-08-02 captures, not synthetic tokens; A7 admitted the roots with a written provenance record. A25's Accept row 2 is adjudicated **SATISFIED**. **Recorded limitation, and it is why `A105` is open:** the two assertions carrying the *pinned-store* half — `FREETSA` and `DIGICERT` reaching `proven` under `TsaRootStore::pinned()` — are the **anti-vacuity arms** of the two `verdicts` tests named here, which are named for something else. The pin is real and the build reddens if either token stops reaching `proven`, but the exposure is **asymmetric**: `DIGICERT` reaches `proven` at three further places and `FREETSA` at exactly one, so a tamper-test rewrite could delete the FreeTSA half and take the milestone criterion with it. A105 gives the property its own named home at the verdict level; this cell names it when it lands. |
| V7.3 | 173 | CI uses a mock TSA + recorded OTS fixtures (no real anchor network in CI) | M2 | A24 + Q16 | covered | `crates/antseal-anchor/tests/no_real_network.rs::the_environment_arm_gates_the_dialling_path_in_a_non_cfg_test_build`, `crates/antseal-anchor/src/testing/stub.rs`, `crates/antseal-anchor/src/testing/replay.rs::the_committed_captures_have_their_recorded_shapes`, `crates/antseal-anchor/src/testing/replay.rs::the_attested_block_captures_have_their_recorded_shapes`, `scripts/check-anchor-net.py`, `docs/testing/anchor-ci-policy.md`, `testdata/anchors` | **The policy is enforced, not merely stated.** The runtime gate lives in `HttpClient::attempt` — the one function in the workspace that hands a URL to `ureq` — and refuses any endpoint that is not a loopback literal; its `cfg(test)` arm is armed by the compiler with no off switch, and `ANTSEAL_NO_REAL_ANCHOR_NETWORK` arms every other test binary. `check-anchor-net.py` checks the three things a runtime gate structurally cannot see: that the arming is declared in every committed workflow, that there is exactly **one** HTTP client in the workspace, and that the endpoint inventory is closed. The stubs match on the **request** rather than on position, so a client retry cannot be handed the next scripted body — a sequential script would have passed while testing the wrong thing. |

## M3 — reveal and verifier page (line 174)

**Checked at the M3 review, which ran 2026-08-16 (Q237).** All four rows
below read `covered` when it ran, `ACCEPTED_NON_COVERED` was empty on both
sides of the bump, and the section is gated from that date cumulatively with
M0's, M1's and M2's. Two of the four carry a venue caveat rather than a
coverage one — V8.2 and the page half of V8.4 were proven on a local host and
by no hosted runner — and the gate records that at its own site rather than
here. **Both halves of the sentence that stood here are replaced,
2026-08-16.** `verifier-web/` does **not** hold a 484-byte
`index.html`: **D131** ruled the built page is never committed and never written
there — it is built to `target/verifier-web/index.html`, which `.gitignore`
already covers — so the directory holds exactly one file, the committed
template `index.template.html` (37 497 B, measured at this review). And *"there
is no playwright configuration"* has stopped being an observation and become a
**ruling**: **D133 §5.4** refuses playwright outright and **D136 §2 R1**
replaces all three of Q19's playwright clauses verbatim — the page is loaded
from a `file://` origin and the online cases are driven by CDP
`Fetch.enable`/`requestPaused`/`fulfillRequest` over the existing session, with
no stub server and no listening socket. A future reader must not "fix" the
absence.

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V8.1 | 174 | Reveal subset, verified offline via the **CLI** | M3 | R + U | covered | `crates/antseal-cli/tests/reveal_flow.rs::a_unit_subset_stays_partial_and_opens_no_whole_file_commitment`, `crates/antseal-cli/tests/reveal_flow.rs::a_subset_completing_a_file_promotes_and_its_mirror_rides`, `crates/antseal-cli/tests/reveal_flow.rs::reveal_all_builds_a_verifying_bundle_matching_its_preview`, `crates/antseal-cli/tests/verify_command.rs::verify_runs_on_a_vault_less_machine_without_prompting`, `crates/antseal-cli/tests/redaction_view.rs::the_redaction_view_matches_the_committed_snapshot`, `scripts/verifier-page-browser.sh` | **Moved `deferred` → `covered` 2026-08-16, at the wave that closed R16/R27/U28-U30.** Three layers, deliberately, because the bullet names both a reveal and a verify: the subset reveals go through the reveal engine and are verified offline by its own `reveal_verified` helper (`verify_bundle` under `VerifyOptions::new()`, with the preview asserted against the built bundle's actual content set); the binary row proves the same verdict is reachable **through `antseal verify` on a vault-less machine without prompting**; and the redaction row covers the partial-reveal shape the M3 gate names. The last reference is the parity baseline — `verifier-page-browser.sh` captures `antseal verify <fixture>`'s own stdout per fixture from a binary built in the same run, which is the CLI side of V8.2's comparison. **Venue: `test` lane for the first four, this local host only for the script (see V8.2).** |
| V8.2 | 174 | Reveal subset, verified offline via the **WASM page** in a headless browser | M3 | R27 + Q19 | covered | `scripts/verifier-page-browser.sh`, `scripts/verifier-page-browser.mjs`, `crates/antseal-core/tests/page_fixtures.rs`, `.github/workflows/verifier-page.yml` | **Moved `deferred` → `covered` 2026-08-16 (R27), with its venue named rather than assumed.** `--check` drives **13 fixtures** and asserts **86 rows** (100 after R85), string-identically against the CLI capture; the fixtures are **materialised into `target/`, never committed**, and asserted on every `cargo test` by `page_fixtures.rs`. Offline enforcement is the stronger form D136 §2 R1 ruled: the page loads from a `file://` origin and the driver asserts it **attempts** zero further requests — *"a page that asked and was refused has still asked"* — rather than blocking requests at the network layer. **There is no playwright and none is to be added** (D133 §5.4, D136 §2 R1). **The venue caveat is load-bearing and Q237 must carry it: every row here was proven on the LOCAL host.** `verifier-page.yml` is `workflow_dispatch:`-only and `gh run list --workflow verifier-page.yml` returned `[]` at this review — the lane has never executed on a hosted runner, which is why **Q19 is still open** under D136 §2 R6. |
| V8.3 | 174 | Verdict-wording snapshot tests | M3 | R18 | covered | `crates/antseal-core/tests/verdict_wording.rs::the_wording_document_matches_the_committed_snapshot`, `crates/antseal-core/tests/verdict_wording.rs::every_anchor_state_has_a_snapshotted_row_and_a_slot_block`, `crates/antseal-core/tests/verdict_wording.rs::the_fetch_date_row_is_exercised_beneath_a_refuted_anchor`, `crates/antseal-core/tests/verdict_wording.rs::no_renderer_source_spells_a_frozen_verdict_string`, `crates/antseal-core/tests/verdict_wording.rs::the_wording_set_satisfies_the_positioning_checklist`, `crates/antseal-core/tests/snapshots/verdict-wording.txt`, `crates/antseal-core/src/verify/wording.rs` | One authoritative wording set, per spec line 127. **Moved `deferred` → `covered` 2026-08-11, the hour R18 landed** — the eight-day lag D118 §6 measured on M1's six rows is the failure this timing exists to avoid. The snapshot is the repo's own idiom (committed `.txt` + `ANTSEAL_BLESS=1`, the `cli-surface.help.txt` pattern), **no snapshot dependency added**. Two properties beyond the row's words, both load-bearing: the enumeration test is a **wildcard-free match over `AnchorState`**, so an eighth state fails the build rather than silently lacking a row, and `no_renderer_source_spells_a_frozen_verdict_string` scans `antseal-cli/src/**` + `verifier-web/**` for 21 needles so "shared verbatim by CLI and page" is asserted rather than assumed. Both proven fallible by real failures (a one-character snapshot drift; a deleted state row), the scan additionally by a planted corpus. **Recorded limitation**: the scan excludes test files by ruling (a test naming a frozen string is an independent pin, not a second source), and six `antseal-cli` sentences whose adoption would move shipped U23 output bytes are **enumerated as declared residue** with their open questions and pinned *present* by `every_recorded_residue_is_still_there`, so the list cannot rot into silence — R18's row carries them, U30 is their first natural consumer. |
| V8.4 | 174 | Online-mode endpoint-disagreement case | M3 | A16 + R | covered | `crates/antseal-cli/tests/verify_command.rs::disagreeing_endpoints_render_the_advisory_and_move_nothing`, `crates/antseal-core/src/verify/orchestration/tests.rs::disagreement_is_advisory_and_leaves_the_offline_verdict_untouched`, `crates/antseal-core/src/verify/overlay/tests.rs::endpoint_disagreement_suppresses_promotion_for_that_anchor_alone`, `scripts/verifier-page-browser.sh` | **Moved `deferred` → `covered` 2026-08-16.** Built on A16's typed disagreement outcome, and asserted on **both surfaces** as the M3 gate clause requires: the CLI row drives **two real loopback stub servers** through the production collector `probe_online`, the two core rows pin that the disagreement is advisory and moves neither the offline verdict nor the report bytes (and run on `wasm32-unknown-unknown` too, via the `wasm32-core-tests` lane's `--lib` run), and the page row is one of R27's four online cases over CDP-mocked routes carrying **real captured mainnet bytes**. **One correction the reader needs**: the sibling *mismatch* case does **not** reach `Refuted` — D133 §3 R8 and §5.2 predict it and the corpus cannot produce it, because the only committed upgraded `.ots` carries pending branches and D56's O5 out-ranks O6/O7, so the render is `NotPromoted{RefutationSuppressed}`. That is **R88**, and it is not this row. Venue: `test` lane for the three Rust rows, **this local host only** for the script. |

## M4 — the release gate (line 175)

Checked at the M4 review via Q34, which requires this whole matrix green.

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V9.1 | 175 | Sepolia-mode seal | M4 | Q32 | deferred | NONE at M0 | |
| V9.2 | 175 | One small **real mainnet** seal, verified end-to-end from a clean machine using only the released signed binary and the hosted page | M4 | Q34 | deferred | NONE at M0 | The only pre-release public-network exposure; accepted and recorded. |
| V9.3 | 175 | Disk-loss restore drill | M4 | Q32 | deferred | NONE at M0 | Second clean machine, vault backup only. |

## MVP-SPEC.md line 143 — the Vault paragraph, clause by clause (Q251)

**Why this section is in this file, and what it costs.** The rest of the
matrix is keyed to the Verification section's bullets. Line 143 is a *Vault*
line, so this section is a declared extension of the file's spec basis rather
than a new group of ordinary rows, and the header says so. It is here because
**Q34**'s gate reads *"traceability matrix 100 % green"* and nothing else the
M4 gate reads holds line 143's conformance. Each divergence below was flagged
where it was found and nowhere else — one record apiece, scattered across a
task file, the register, six separate decision records and an audit — so no
document held them against the line, and one of them was held by nothing at
all. A
collection in a file the gate does not read would have reproduced exactly that.

**The cost, stated rather than absorbed.** `covered` means something slightly
wider here than in the V-series. There it reads *"a test exists for this
verification bullet"*. Here it reads **"this clause's disposition is decided
below AND its shipped behaviour is pinned by at least one named test or
committed document"**. The vocabulary is machine-fixed to three words, so
there is no fourth status to mint: `gap` would mean the clause's shipped
behaviour is pinned by nothing, and `deferred` is a category error for a
clause whose behaviour already ships. A row here going to `gap` is a real
finding and blocks the M4 gate exactly as a V-row does.

**A `covered` status is NOT a claim that the clause is satisfied.** Seven of
the fifteen rows record a **divergence** — six standing and one closed — and
all seven stay `covered`, because what the status certifies is that the
divergence is measured, disposed and pinned, not that the code agrees with the
sentence. Read the `notes` cell, always. The disposition vocabulary is Q251's:
*satisfied*, *satisfied-and-stronger*, *stricter than spec*, *deviation in
mechanism*, *half deferred*, *incomplete spec*, *interpretation*, and *closed*
for a divergence that no longer stands.

**Derivation.** The list below is derived by reading line 143's own clauses in
their own order, not by transcribing the task row — the row's `Accept`
requires that, because a collection that only collects what was already known
repeats the defect one level up. **`L143.5` is a divergence no record names**
— the spec states parameter *floors* and shipped enforces two-sided *windows*,
so a spec-conformant hardening is refused — and the wording conflict recorded
inside `L143.2` is likewise named nowhere, though the divergence containing it
is D42's. Both were found by the clause-by-clause read and neither appears in
the row that commissioned this section.

**Locator hygiene, and why this section names symbols.** Every divergence
below arrived cited by line number. Eighteen such locators were re-measured
against the tree for this section and **three did not survive**: the exit-14
mapping was cited at a line holding an unrelated enum entry in a different
list; a record's §Spec-conformance quotation was cited some seventy lines past
the section it quotes; and *"the Argon2id arm"* was cited at the first range
guard inside that arm rather than at the arm. **None had rotted** — all three
were wrong the day they were written, two on 2026-08-17 and one on 2026-08-18.
That is the file's by-name rule earning its keep on its own subject matter, so
this section obeys it: shipped behaviour is named by symbol and by file,
records by file and section. The dated `path:line` form lives in `TODO.md`'s
row and the `tasks/Q.md` entry, where it is a timestamped claim about one tree
state rather than a durable pointer.

**No code change is licensed by any row here.** Every divergence is either
stronger than the spec, a recorded deferral, an under-specified spec line, or
an interpretation. `MVP-SPEC.md` is frozen; the protocol is *the spec wins,
flag the conflict, do not silently diverge*, and this section is the flag.

**Ids.** `L143.n`, for the spec **L**ine they key to. Deliberately not
`S143.n`: `S` is a task-id domain, and that id written alone inside a
backtick span is exactly the shape `scripts/check-traceability.py`'s task
half reds as a freshly minted, never-registered citation — the id is above
S's ceiling, where only a marked occurrence fires. `L` is in no domain, as
the `V` series is in none.

| id | spec line | spec bullet | milestone | owner | status | tests / evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| L143.1 | 143 | *"config + per-work records (`W`, seal journal, receipts, `.ots`, TSA tokens, addresses, paths, costs)"* — the per-work enumeration is inside the vault AEAD | M4 | U5/U9/D42 | covered | `crates/antseal-cli/tests/work_store.rs::fixture_states_round_trip_across_reopen`, `crates/antseal-cli/tests/work_store.rs::receipt_survives_reopen_byte_identically`, `crates/antseal-cli/tests/work_store.rs::enumeration_never_touches_journal_bodies`, `crates/antseal-cli/tests/anchor_stage.rs::one_verified_tsa_lets_the_seal_proceed_and_journals_its_artifacts`, `crates/antseal-cli/src/vault/mod.rs` | **SATISFIED.** The `vault` module's layout map carries the enumeration item for item — meta (`W`, seal id, work id, title, network, source paths, costs, state), `journal/` (staged ciphertext, nonce, address), `receipt`, `anchors/` (`.ots`, TSA tokens, fetch dates) — and every content byte under `works/` is AEAD ciphertext under the vault key. Honest limit, recorded at D42's rider and not a divergence: the **filesystem metadata** of a locked vault is visible — how many work directories exist, entry counts, sizes, mtimes. Directory names are random hex and content-free, so nothing links a locked vault to a bundle, anchor, digest or title. |
| L143.2 | 143 | *"…, encrypted at rest with a passphrase"* — read as covering **config** as well as the per-work records | M4 | U4/D42 | covered | `crates/antseal-cli/tests/vault_store.rs::beside_set_is_exactly_the_three_d42_files`, `crates/antseal-cli/tests/config_file.rs::binary_resolves_network_through_the_config`, `docs/decisions/D42-vault-encryption-boundary.md` | **DIVERGENCE — interpretation, disposed at D42.** The sentence's grammar puts *config* under "encrypted at rest"; shipped leaves `config.toml` in the clear as one of exactly three beside-the-AEAD files (config, the vault header, the lockfile), and that list is asserted exhaustive by a test. D42's §Spec-conformance rejects the config-inside reading and not on convenience: `verify --online` reads the endpoint overrides and **must** run vault-less and prompt-free, so config-inside-AEAD would force it either to prompt (forbidden) or to ignore the owner's configured overrides (a worse divergence). Priced there: plaintext config is tamperable by a local file-writer, which cannot forge a verdict but can redirect a probe; the optional hardening (a config digest witnessed inside the vault, warn-only) is recorded and not taken. **Found by this collection and left standing, because no code change is licensed here:** the `vault` module's own D42 paragraph says the mandate *"holds with no carve-outs"* in the same breath as naming config beside the AEAD. That is true only under D42's reading, and the sentence does not say which reading it is using. |
| L143.3 | 143 | *"Argon2id, m ≥ 256 MiB, t = 3, p = 1 (default), random 16-B salt"* — the creation values | M4 | U6/D40 | covered | `crates/antseal-cli/tests/vault_encryption.rs::generated_params_are_frozen_values_and_round_trip`, `crates/antseal-cli/tests/vault_encryption.rs::rfc9106_argon2id_known_answer`, `crates/antseal-cli/tests/vault_encryption.rs::kdf_block_golden_vectors`, `crates/antseal-cli/src/vault/kdf.rs` | **SATISFIED, exactly.** `ARGON2ID_M_COST_KIB` = 262 144 KiB, which is 256 MiB at the floor rather than above it; `ARGON2ID_T_COST` = 3; `ARGON2ID_P_COST` = 1; `KDF_SALT_LEN` = 16, drawn from the CSPRNG per vault. Argon2id is the **sole** default — D40 overturned the fallback-prompt lean U6 carried, because the fallback it imagined does not exist: scrypt at its own spec floor needs 1 GiB, four times Argon2id's 256 MiB. A machine that cannot allocate gets the typed `vault-kdf-memory` refusal at create **and** at unlock, with no prompt and no silent substitution. |
| L143.4 | 143 | *"with `scrypt N ≥ 2²⁰` as an alternative"* | M4 | D40 | covered | `crates/antseal-cli/tests/vault_encryption.rs::rfc7914_scrypt_known_answer_at_production_n`, `crates/antseal-cli/tests/vault_encryption.rs::scrypt_round_trip`, `crates/antseal-cli/tests/vault_encryption.rs::rfc7914_scrypt_known_answers`, `docs/decisions/D40-vault-kdf-selection.md` | **DIVERGENCE — incomplete spec, completed writer-side.** The line names an N floor and **no r or p**, which is not implementable as written: RFC 7914 has no default pairing. D40 fixes `r` = 8 and `p` = 1 as the creation values (the conventional pairing the N-floor implies) and the header records them explicitly either way, so this is a writer-side completion of an under-specified line, not a format change. D40's §Spec-conformance flags it and recommends a one-word spec amendment — *"N ≥ 2²⁰, r = 8, p = 1"* — at the next spec-touching pass; the spec is frozen, so the amendment is **owed and not taken**, and this row is where that debt is readable. Consistent with *"as an alternative"* and worth stating because it is easy to misread as a divergence: scrypt is selectable only as an explicit `init`-time choice, never automatically and never as a low-RAM escape. |
| L143.5 | 143 | The parameter bounds themselves — the line states **floors** (*"m ≥ 256 MiB"*, *"N ≥ 2²⁰"*) and shipped enforces two-sided **windows** | M4 | D40/U6 | covered | `crates/antseal-cli/tests/vault_encryption.rs::pre_auth_caps_reject_out_of_range_params`, `crates/antseal-cli/tests/vault_export.rs::kdf_bomb_header_is_rejected_pre_allocation_and_pre_passphrase`, `crates/antseal-cli/src/vault/kdf.rs`, `docs/decisions/D40-vault-kdf-selection.md` | **DIVERGENCE — stricter than spec. Found by this collection; no record states it.** `KdfParams::check_ranges` caps Argon2id `m_cost` at 4 194 304 KiB (4 GiB) and scrypt log₂ N at 24, and pins Argon2id `p` and scrypt `r`/`p` to exact values. So a header carrying m = 8 GiB or N = 2²⁵ — *spec-conformant hardening* under the line's own `≥` — is refused **pre-auth** with `vault-kdf-params-out-of-range`, exit **14**, before the KDF allocates. D40's §3 states the cap table and D40's §Spec-conformance accounts only for *"Parameters, floors, salt size, AAD binding … No deviation"*, never for the ceilings introduced one section earlier; U6's execution note enumerates three tested directions — lowered params to cap rejection, raised-within-window to auth failure, pure-AAD header edit to auth failure — and raised-**above**-window is not among them. **Disposition: accepted as stronger than spec.** The cap is the reason D40 §3 exists: the KDF runs before any key exists, so a substituted header demanding 1 TiB is a resource bomb no AAD check can reach, and the same caps serve `vault import`. D40 already rules that raising a parameter is a header-version event that revisits the caps with it, which is the route if a future build wants the range the spec's `≥` implies. |
| L143.6 | 143 | *"the algorithm id + full parameters live in the vault header"* | M4 | U5/U6 | covered | `crates/antseal-cli/tests/vault_store.rs::golden_header_vector_is_byte_exact`, `crates/antseal-cli/tests/vault_store.rs::header_round_trips_across_the_field_space`, `crates/antseal-cli/tests/vault_encryption.rs::kdf_block_golden_vectors`, `crates/antseal-cli/tests/vault_store.rs::tamper_kdf_block_over_cap_rejected` | **SATISFIED.** The header is magic plus a canonical-CBOR `[format_version, body]` envelope, the body carrying the KDF block (algorithm id, full parameters, salt) at key 0, the D50 wrap mode at key 1, and an optional recorded keyfile path at key 2. The KDF block is deliberately opaque to the header layer, which caps only its size; the schema inside it belongs to the KDF module, and its parse is total over adversarial input. |
| L143.7 | 143 | *"the entire KDF header is bound into the vault AEAD as AAD"* | M4 | U6/D42 | covered | `crates/antseal-cli/src/vault/cipher.rs::identity_and_header_axes_all_bind`, `crates/antseal-cli/tests/vault_encryption.rs::flipped_salt_fails_authentication`, `crates/antseal-cli/tests/vault_encryption.rs::wrap_mode_flip_is_refused`, `crates/antseal-cli/tests/work_store.rs::spliced_record_files_fail_authentication`, `crates/antseal-cli/tests/wallet_record.rs::wallet_and_work_records_do_not_splice` | **SATISFIED, and stronger than asked.** Every record AEAD binds the exact bytes `VaultHeader::encode` produces — magic, version envelope, KDF block **and** wrap mode, plus the optional keyfile path — not the KDF block alone, and appends a canonical-CBOR record identity, so a valid blob moved between slots of one vault or between vaults fails authentication instead of being silently accepted. Naming note, recorded so a reader is not misled: the vault module and the cipher module both call those whole-header bytes *"the KDF header"* in this rider's wording, which is the spec's phrase and not the header's own name. Honest limit at D42: whole-vault rollback — restoring an older copy of the directory — is undetectable offline and out of scope; no offline scheme detects it. |
| L143.8 | 143 | *"so a parameter downgrade (e.g. lowering `m`/`N`) is a detected authentication failure, not a silent weakening"* | M4 | U6/D40 | covered | `crates/antseal-cli/tests/vault_encryption.rs::downgraded_params_are_rejected_pre_auth`, `crates/antseal-cli/tests/vault_encryption.rs::raised_params_within_caps_fail_authentication`, `crates/antseal-cli/tests/vault_encryption.rs::wrap_mode_flip_is_refused`, `crates/antseal-cli/tests/vault_encryption.rs::malformed_blocks_collapse_to_vault_auth` | **DIVERGENCE — deviation in mechanism, not in property.** Shipped refuses a lowered `m`/`N` **before** the KDF runs and before any AEAD can authenticate anything: `KdfParams::check_ranges`, called from `KdfParams::decode`, reached from the vault session's unlock one step ahead of key derivation, with its own class `vault-kdf-params-out-of-range` and exit **14** rather than the vault-auth collapse the sentence describes. D40's floors sit **at** the frozen creation values, so the literal sentence is unreachable by construction for the very example it names. The property the sentence protects — no silent weakening — holds strictly harder, and the AEAD path it describes stays live for the two directions the cap does not take: params raised within the window derive a different key and fail authentication, and a header edit that leaves the KDF inputs fixed (a wrap-mode flip) fails at the cipher layer on the AAD alone. Flagged at U6's execution note item 1, 2026-08-01, as *"a deviation-in-mechanism, not in property"*, with all three directions tested; collected here for the first time. |
| L143.9 | 143 | *"`init` enforces a passphrase-strength floor"* | M4 | U7/U11/D41 | covered | `crates/antseal-cli/tests/passphrase_channel.rs::create_floor_is_twelve_bytes_and_unlock_has_none`, `crates/antseal-cli/src/passphrase.rs::create_floor_rejects_eleven_bytes_and_accepts_twelve`, `crates/antseal-cli/src/passphrase.rs::unlock_prompts_once_and_applies_no_floor`, `crates/antseal-cli/src/passphrase.rs` | **SATISFIED.** A documented byte-length floor of 12, enforced at vault creation and at the import re-passphrase, and deliberately **not** at unlock — an existing vault's owner is not re-judged on a passphrase they already have. The recorded choice is a length floor rather than a strength estimator, with the reasoning at the module docs: the floor exists to stop trivially short passphrases, and the real work is done by the memory floor. **Measured for this collection, because it is the obvious place for a hole:** the floor applies on the `--passphrase-fd` channel too. D41 exempts that channel from the *confirmation prompt* only, and the code says so at the branch. |
| L143.10 | 143 | *"offers a high-entropy keyfile / OS-keystore wrap for `W`"* | M4 | U8/D50/D72 | covered | `crates/antseal-cli/tests/vault_keyfile.rs::the_header_records_the_mode_a_flip_fails_auth_and_mode_two_is_its_own_refusal`, `crates/antseal-cli/tests/vault_keyfile.rs::a_keyfile_vault_round_trips_and_refuses_distinctly_without_its_keyfile`, `crates/antseal-cli/tests/vault_keyfile.rs::declining_the_wrap_leaves_a_plain_mode_zero_vault`, `crates/antseal-cli/tests/init_command.rs::the_wizard_asks_d39s_questions_in_d39s_order`, `docs/decisions/D50-os-keystore-scope.md` | **DIVERGENCE — half deferred.** Only the **keyfile** half ships. Wrap mode 2, the OS keystore, is a *registered* id with no implementation: the vault session's unlock dispatches it before any expensive work and refuses with its own class `vault-wrap-mode-unsupported`, exit **19**, a refusal that says the vault is intact and is emphatically not the generic auth collapse — nothing secret is involved in reading a mode byte. D50 ruled M1 keyfile-only on measured evidence (keyring churn, reboot-volatile keyutils, and machine-bound factors breaking the clean-machine restore drill), and **D72 answered the follow-up no**, so this is a recorded deferral and not an omission. The *offer* half is met and was measured rather than assumed: `init`'s wizard asks the wrap question in D39's order, and the choice set it offers is exactly none-or-keyfile, which is the honest surface for a two-mode implementation. Flagged throughout U8, whose own spec citation quotes this clause verbatim. |
| L143.11 | 143 | *"The Arbitrum wallet key lives inside the encrypted vault but under its own sub-key"* | M4 | U10 | covered | `crates/antseal-cli/tests/wallet_record.rs::wallet_key_round_trips_across_reopen`, `crates/antseal-cli/tests/wallet_record.rs::wallet_and_work_records_do_not_splice`, `crates/antseal-cli/tests/wallet_record.rs::corruption_blast_radius_is_decoupled`, `crates/antseal-cli/tests/wallet_record.rs::tampered_wallet_record_fails_authentication`, `crates/antseal-cli/src/vault/wallet.rs` | **SATISFIED.** The 32 secret bytes live at their own store slot under `HKDF-SHA256(ikm = the vault key, info = a versioned label)` — the one recorded exception to the single-vault-key schedule — so the wallet and work domains share no AEAD key and the decoupled blast radius the clause asks for is a property of the derivation rather than a claim. The accessor surface is one narrow method on a non-`Clone`, redacted-`Debug`, zeroize-on-drop handle. *"external-signer support may come later"* is permissive; nothing is owed at M4, and the sub-key is what makes it additive — a future external-signer build deletes this record and its derivation without touching any work record's schedule. |
| L143.12 | 143 | *"`zeroize` on `W`, unit keys, and passphrase buffers"* | M4 | C21/C22/D88 | covered | `crates/antseal-core/tests/zeroization_residue.rs::dropped_hkdf_extract_context_retains_no_verbatim_master_secret`, `crates/antseal-core/tests/zeroization_residue.rs::dropped_hkdf_state_retains_no_master_secret_bytes`, `crates/antseal-core/tests/zeroization_residue.rs::dropped_sha256_retains_no_ggm_seed`, `crates/antseal-core/tests/feature_pins.rs::sha2_pin_declares_the_zeroize_feature`, `crates/antseal-core/tests/digest_zeroize_link.rs::digest_reexports_a_working_zeroize`, `docs/zeroization-audit.md` | **DIVERGENCE — CLOSED, and this row exists to say so.** All three subjects the line names are `ZeroizeOnDrop` today: the master-secret type holding `W`, the unit-key type, and the passphrase buffer (which wipes its spare capacity too and withholds even its length from `Debug`). C21's audit found the HKDF/HMAC internal key state un-zeroizable on the pins and recorded it as *"a live contradiction of MVP-SPEC.md line 143"*; C22 resolved it the same day via D88 by enabling `sha2`'s non-default `zeroize` feature — an option C22's own three-way question had not listed, and C21's premise that no feature fixes it was false. Measured red-first against a control: 114 of 144 bytes to 0, and an extract context holding `W` verbatim to 0. **Permanently accepted narrowed residue:** four `hybrid_array` stack temporaries have no `Drop` under any feature; stack-resident, never heap, never logged, never serialized, for the duration of one derivation — the same window in which `W` is resident anyway. Closing them means reimplementing HKDF *and* HMAC in-house. Three separate test binaries guard the pin so this cannot silently reopen, and each states the contradiction **conditionally** in its failure message, which is why a grep for that phrase still returns hits in a tree where the contradiction is closed. Residual limits outside the three named subjects — a disclosure `Vec`'s growth stranding un-wiped salts, decrypted unit plaintext returned caller-owned, non-wiping byte-extractor copies — are the audit's and are not line-143 divergences. |
| L143.13 | 143 | *"documented caveat: the WASM verifier cannot guarantee this for bundle-supplied keys in browser memory"* | M4 | C21/Q21 | covered | `crates/antseal-core/tests/security_assumptions_drift.rs::the_wasm_zeroize_caveat_is_on_the_module_root_and_in_the_threat_model`, `crates/antseal-core/src/crypto.rs`, `docs/threat-model.md`, `docs/zeroization-audit.md` | **SATISFIED.** The clause mandates a *documented caveat*, not a mitigation, and the caveat is carried in one wording on the crypto module root and in the threat model, with the drift test pinning the two copies to each other so a reworded one cannot drift from the other. The audit records the same limit as a residual risk. |
| L143.14 | 143 | *"`vault export`/`import` for encrypted backup"* — read together with the keyfile wrap of `L143.10`, which the same line offers | M4 | U12/D47/U84/D151 | covered | `crates/antseal-cli/tests/vault_keyfile.rs::a_wrapped_vault_is_refused_by_export_and_a_wrapped_payload_by_import`, `crates/antseal-cli/tests/vault_export.rs::round_trip_preserves_the_full_logical_state`, `crates/antseal-cli/tests/vault_export.rs::wrong_passphrase_fails_with_the_import_auth_class`, `docs/decisions/D151-vault-export-backup-advice.md` | **DIVERGENCE — mutually exclusive clauses.** The encrypted backup itself ships and round-trips. What diverges is that line 143 offers the backup **and** the keyfile wrap and shipped antseal makes them exclusive: the export gatherer refuses any vault whose header wrap mode is not none, and the payload validator refuses any payload carrying one — both `usage`, exit **2**, both before anything is read or written, both saying *"nothing was written"*. A user who takes this line's wrap loses this line's backup command for the life of the vault and backs up by hand instead, which the two user pages document. **Structural, not an oversight:** the wrap flag would have to live in the export **header**, which is read before any key exists, and the v1 header body has no slot for it; the payload's own wrap-mode slot sits *inside* the AEAD, so no reader can learn a keyfile is needed without already holding the key the keyfile helps derive; and the spec's own CLI-surface line gives `vault export` and `vault import` no flags for a keyfile to arrive through. Carrying the wrap is therefore a D47 **format event** and is not taken at MVP. **Ruled by D151, 2026-08-18, and the owning-record situation inverts what a reader would expect:** D47's format section *mandates* that the keyfile factor is preserved and its §Spec-conformance says *"no divergence"*, while shipped code has refused both directions since U8 — a deliberate overturn recorded in U8's register row and in the export module's own docs, and **never written into D47**, which D151 amends by dated addendum. Do not read D47 as agreeing with shipped behaviour until that addendum is on disk. |
| L143.15 | 143 | *"Docs and CLI must nag on both failure modes: loss … and theft"* | M4 | U18/U78/Q24 | covered | `crates/antseal-cli/tests/init_command.rs::the_golden_carries_the_standing_warnings_by_identity`, `crates/antseal-cli/tests/init_command.rs::the_init_report_matches_its_committed_golden`, `crates/antseal-cli/tests/snapshots/init-report.txt`, `docs/user/vault-loss.md`, `docs/user/vault-theft.md` | **SATISFIED, with one live caveat owned elsewhere.** Docs half: the two user pages, which quote the CLI's own constants byte for byte rather than paraphrasing them. CLI half: the loss and theft warnings live as constants in the vault bookkeeping module, are rendered by `init`'s closing report, and are pinned in U78's committed golden **by identity** rather than by containment — a one-character reword of either constant reddens three independent tests. The nag after the first successful seal is the third surface. **Caveat, measured at D151 and not licensed here:** a keyfile-wrapped vault can never record a backup, because the export counter is incremented only after a successful export and export refuses such a vault, so the first-seal nag fires on every seal for ever and names a command that will not run for that user. That is a behaviour defect against this clause rather than a divergence from it, and it is **U84**'s. |

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
- **2026-08-11 / 12 (M2 wave 17, Q236 / D127)** — *entry added retroactively
  by Q237 on 2026-08-16; the M2 review made its edits here and left this log
  unchanged, which is why the entry is dated to the events and attributed to
  the row that noticed.* M2's review ran and **`CURRENT_MILESTONE` moved
  `M1` → `M2`**, bump-atomic with the register's first
  `ACCEPTED_NON_COVERED` entry (`V7.1`, D127), because the check reds either
  half without the other. The entry lasted one day: the consented
  submit→upgrade pair ran 2026-08-12 through antseal's own clients, so the
  cell flipped `covered` and the entry was removed in one change. The
  register has been empty since.
- **2026-08-16 (M3 wave 21, Q237)** — M3's review ran and
  **`CURRENT_MILESTONE` moved `M2` → `M3`**. **This bump exempted nothing**:
  all 31 rows at or before M3 already read `covered` when it was taken, and
  `ACCEPTED_NON_COVERED` was `{}` on both sides of it — the first gate-row
  bump of which that is true. The four M3 rows had moved `deferred` →
  `covered` earlier the same day as their work closed (V8.1, V8.2, V8.3,
  V8.4), so what this review adjudicated was **venue rather than coverage**:
  two of the four are witnessed only by a local host, and that is recorded at
  the rows and at the gate rather than as a status. Three preamble copies of
  the constant's value were retired to the rule in the same act (**Q230**'s
  class), and D122 §7.2's replacement for the *"how the gate uses this"*
  bullet landed with them.
- **2026-08-19 (M4 wave 26, Q251)** — the file gains **one declared extension
  to its spec basis** and fifteen rows under it: `L143.1`–`L143.15`, the
  clause-by-clause conformance of **MVP-SPEC.md line 143**, the Vault
  paragraph. The M4 gate reads *"traceability matrix 100 % green"* and this
  is the only place line 143's status is decided; before it the flags sat one
  per record, scattered, and nothing held them against the line. **Seven of
  the fifteen record a divergence — six standing, one closed** — and **one of
  the seven is named by no record at all**: `L143.5`, where the spec states
  parameter *floors* and shipped
  enforces two-sided *windows*, so a spec-conformant hardening (m = 8 GiB,
  N = 2²⁵) is refused pre-auth at exit 14 while D40's §Spec-conformance
  accounts only for the floors it introduced the caps beside. A second thing
  nobody had named sits inside `L143.2`, whose divergence is D42's: the vault
  module says the encrypted-at-rest mandate *"holds with no carve-outs"* in
  the same breath as naming config beside the AEAD. The remaining four
  divergences are collected, not re-litigated: the
  downgrade mechanism (U6, 2026-08-01), the keystore half that does not ship
  (U8/D50/D72), the scrypt `r`/`p` the spec never names (D40), and the export
  that refuses a keyfile-wrapped vault (D151, 2026-08-18). **The zeroization
  contradiction C21 recorded against this line is CLOSED**, not standing, and
  `L143.12` says so — a grep for its wording still returns hits because the
  three guards state it conditionally. **No code change is licensed by any of
  it.** The by-name rule was extended to the `notes` column rather than
  waived for it, against Q251's own `Accept`: eighteen `path:line` locators
  were re-measured for this section and three were wrong the day they were
  written, which is the rule's own argument arriving as evidence.
