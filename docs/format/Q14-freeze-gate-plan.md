# Q14 — the M0 format-v1 freeze gate: executable procedure, freeze mechanisms, and the adversarial sweep

> **Status: PLAN. Nothing here has been executed.** This document turns
> `tasks/Q.md` §Q14 and its `#### Q14 freeze checklist — normative rows` block
> into a run sheet that can be executed and objectively judged, records the
> mechanism each of D17/D29/D30 needs for its freeze to be real rather than
> declared, and lists what freezes at Q14 that no open task covers.
>
> **Planned against commit `5f794ff`** (`main`, clean tree, 2026-07-28).
> Every command below was checked against this tree; commands marked
> **[RUN]** were executed read-only while writing this and their output is
> quoted. Commands marked **[NEW]** do not exist yet and are part of the work
> this plan proposes.
>
> **Nothing in this plan pushes anything anywhere.** The tag is local. See §4.

---

## 0. How to read this

`tasks/Q.md` §Q14 is the authority. It has three lists, and this plan treats
all three as checklist rows:

| Source | Rows | Where |
|---|---|---|
| Q14 `Do` | **15** | `tasks/Q.md:160` |
| Q14 `Accept` | **5** | `tasks/Q.md:161–166` |
| `#### Q14 freeze checklist — normative rows` | **8** | `tasks/Q.md:168–321` |
| | **28 total** | |

Rows marked *verbatim* in the normative block are byte-identical copies of a
decision record and **must not be paraphrased**. This plan never restates
them; it names the command that verifies them.

Q14's `Accept` contains the sentence that governs everything below:

> a row that says "known-and-accepted, not open" is ticked **by verifying the
> evidence it names, not by agreeing with it**

So every row that records something as *closed* gets a command too. Four of
the eight normative rows are of that kind (N2, N4, N5, N6) and all four are
given commands in §1.3.

### The run order

The gate is not a checklist to be ticked in file order. It is four phases:

1. **Phase A — unblock.** The gate cannot currently run (finding **A1**) and
   three of its rows are un-tickable as written (**A4**, **A5**, **A6**).
   Land §3's blocking set first.
2. **Phase B — evidence.** Run §1's commands, all of them, in one session,
   from a clean tree at the freeze candidate commit. Capture output.
3. **Phase C — freeze.** Execute §2's three mechanisms (D17, D29, D30) and
   the two status flips (`registry-v1.json`, `FROZEN.sha256`). These are
   *edits*, so they change the commit — re-run Phase B after them. That
   re-run is the one whose output goes in the tag.
4. **Phase D — tag.** §4.

Phase C changing the tree after Phase B measured it is not a flaw to be
engineered away; it is why the tag annotation must name the **post-flip**
commit and why §4's abort conditions include "Phase B was not re-run".

---

## 1. The executable procedure

Legend for the **Pass** column: a pass condition is objective only if a
machine could decide it. Where the only available evidence is a human reading
or a `grep`, the row is marked **[HUMAN]** or **[GREP]** and §1.4 says whether
it can be machine-checked cheaply.

Evidence sink for every row: a new dated section
`## Q14 — format-v1 freeze gate, <date>` appended to `docs/ci-verification.md`,
with the command, its exit status, and the one-line summary it printed. That
section is what the tag annotation cites.

### 1.1 Q14 `Do` — the 15 items

| # | Row | Command | Pass condition |
|---|---|---|---|
| **D1** | Definitions frozen: CBOR profile | `cargo test -p antseal-core --locked --test cbor_pin_eval` **[RUN-equivalent]** | 13 tests pass. This asserts the *profile* (shortest form, definite length, no floats, sorted keys) behaviourally against `minicbor`'s public probes. |
| **D2** | Definitions frozen: **pinned encoder** | `grep -n '^minicbor' Cargo.toml` → `minicbor = { version = "=2.3.0", …}`; `grep -A1 'name = "minicbor"' Cargo.lock` → `version = "2.3.0"` **[GREP]** | Both read `2.3.0`. **No test asserts this** — see finding **B3**; the fix is `Q53`. |
| **D3** | Definitions frozen: domain-tag registry `0x00`–`0x06` | `cargo test -p antseal-core --locked --lib crypto::domain::tests::` | `tag_values_match_spec_line_79` green (`crates/antseal-core/src/crypto/domain.rs:149`) — asserts each of the 7 tags equals its spec ordinal via `ALL_TAGS`, plus `MAX_DOMAIN_TAG == 0x06` and `no_other_module_hardcodes_domain_tag_bytes`. |
| **D4** | Definitions frozen: id encodings (`file_id`/`unit_id` LE64) | `cargo test -p antseal-core --locked --lib crypto::hkdf::tests::le64_is_little_endian crypto::hkdf::tests::info_bytes_match_hand_computed_fixture` | Both green. The hand-computed fixture at `crypto/hkdf.rs:388` pins the byte layout, not the intent. |
| **D5** | Definitions frozen: length-prefixed HKDF info | `cargo test -p antseal-core --locked --lib crypto::hkdf::tests::registry_is_frozen_and_consistent crypto::hkdf::tests::sentinel_encodes_as_eight_ff_bytes` **and** `cargo test -p antseal-core --locked --test hkdf_golden` | `registry_is_frozen_and_consistent` (`crypto/hkdf.rs:430`) pins all 8 label literals + output lengths + id domains positionally; `hkdf-labels.json` commits the full hex `info` per label (e.g. `0c6d616e69666573742d6b6579ffffffffffffffff`) and is digest-frozen. |
| **D6** | Definitions frozen: pinned Unicode version | `cargo test -p antseal-core --locked --lib canon::unicode::tests::` | `pinned_crate_ships_the_recorded_unicode_data_version` (`canon/unicode.rs:211`) green — it ties the string `unicode-17.0.0` to `unicode_normalization::UNICODE_VERSION == (17,0,0)`, i.e. to the dependency's own table, not to itself. This is the strongest pin in the Definitions set. |
| **D7** | Definitions frozen: signature context string | `cargo test -p antseal-core --locked --lib crypto::sig_ed25519::tests::signing_message_is_the_frozen_prefix_construction` **and** `cargo test -p antseal-core --locked --test crypto_vectors` | The unit test pins `SIG_CONTEXT == b"antseal-manifest-v1"`, `len == 19`, no embedded `0x00`, and the `ctx‖0x00‖body` split. `signatures.json` commits `inputs.context` and `expect.ed25519.signing_message` as frozen hex. |
| **D8** | All M0 golden vectors committed and frozen (Q6), **incl. must-exist** | `./scripts/vector-freeze.sh --self-test && ./scripts/vector-freeze.sh` | Self-test prints `mutation and deletion both turn the lane red`; the lane prints `v1: <n> frozen vector(s) OK` and `vector freeze [v1]: <n> frozen vector(s), status …, 11 kind(s), 0 pending`. **Pass requires `0 pending`** — the parser refuses `status frozen` while pending is non-empty (`tests/vector_freeze.rs:249`). |
| **D9** | Independent cross-check clean (Q11) | `./scripts/cross-check.sh --self-test --require && ./scripts/cross-check.sh --check --require` **[RUN]** | Exit 0 from both. Last line at `5f794ff`: `cross-check PASSED: 225 checks over 14 case(s) in 2 CBOR-committing vector(s) of 12 committed v1 vector file(s)`. **See N8 — the lane being green is not the whole row.** |
| **D10** | Tamper M0 registry fully implemented (Q8) | `cargo test -p antseal-core --locked --lib -- test_util::tamper` then `cargo test -p antseal-core --locked --test tamper_matrix --test tamper_crypto -- --nocapture` | `tamper_matrix_reports_the_q14_gate` green and the `--nocapture` output shows the gate line. `EXPECTED_M0_PENDING` is `&[]` at `tests/tamper_completeness/mod.rs:114` and `assert_pending_set_is_the_pinned_one` checks it in both directions. |
| **D11** | HKDF-distinctness golden test green | `cargo test -p antseal-core --locked --test hkdf_golden -- m0_golden_all_registered_hkdf_infos_pairwise_distinct` | Green. Note `PROPTEST_CASES` overrides a hardcoded `cases` (corrected at C3) — the spec-mandated ≥10 000-case floor is driven through `TestRunner` directly, not through the macro. |
| **D12** | WASM bit-match green (Q5) | `./scripts/wasm-bitmatch.sh --self-test && ./scripts/wasm-bitmatch.sh` | Self-test red-then-green on an injected wasm32-only divergence; the lane byte-identical over all 12 committed vector files. **Debug codegen only** — see finding **C4**. |
| **D13** | WASM probe decision recorded | `test -f docs/research/C11-signature-probe.md && grep -n 'VIABLE\|wasm32' docs/research/C11-signature-probe.md \| head` **[HUMAN]** | The record exists and states the verdict (`ml-dsa =0.1.1` wasm32 VIABLE, executed bit-match, ctx first-class, no C13 pre-validation layer). Machine-checkable cheaply — see §1.4. |
| **D14** | Security-assumptions sign-off recorded (Q12) | `cargo test -p antseal-core --locked --test security_assumptions_drift` | 6 drift tests green: byte-identity between `docs/security-assumptions.md` and `docs/threat-model.md` §1 with no normalization, a >4 kB floor on **both** copies, the AEAD rule in both modules and the block, all ten M4 headings, the WASM caveat in all three places. Sign-off rows: `docs/security-assumptions.md:15` and `docs/threat-model.md:23`, both `aed900`, both dated. |
| **D15** | Traceability M0 rows filled (Q13) | `python3 scripts/check-traceability.py --self-test && python3 scripts/check-traceability.py --matrix` **[RUN]** | Self-test red on corruption; then `[matrix] ok — 34 rows over 34 spec bullets, 49 references resolved (M0=16, M1=6, M2=5, M3=4, M4=3)`. **This is necessary and not sufficient** — the check does not read the `status` column. See **A4** and `Q51`. |

### 1.2 Q14 `Accept` — the 5 criteria

| # | Row | Command | Pass condition |
|---|---|---|---|
| **A1** | Checklist committed; every item objectively green before the tag | `git -C . status --porcelain` → empty, at the freeze commit; then the full §1 sweep, all exit 0 | Every command in §1.1/§1.3 exits 0 **at the same commit**, recorded together in one `docs/ci-verification.md` section. Not "each was green once". |
| **A2** | Tag + CHANGELOG entry present; sign-off names/dates recorded | `git tag -v format-v1-freeze` (after §4) and `test -f CHANGELOG.md` | **`CHANGELOG.md` does not exist in this repo** (`find . -iname 'CHANGELOG*'` → nothing outside `docs/` prose references). Q14 creates it. See §4.2 and finding **A7**. |
| **A3** | Any post-tag change to frozen material requires a format-version bump per Q27 policy | `./scripts/vector-freeze.sh --update` after flipping `#! status frozen`, with a byte changed → must refuse | The refusal is real: `scripts/vector-freeze.sh:169–180` rejects any modified-or-dropped line once `status` is `frozen`, printing *"After Q14 the only legal change is an addition"*. **Prove it, do not assume it** — §4.1 makes this a mandatory post-flip demonstration. Q27 itself is M4; the *enforcement* is this refusal plus §2's three mechanisms. |
| **A4** | Every normative row ticked, **including the closed ones** | §1.3, all 8 rows | See §1.3. Note that ticking rows N1/N2 as written turns `--freeze-boundary` red — finding **A1**. |
| **A5** | `scripts/check-traceability.py --freeze-boundary` green | `python3 scripts/check-traceability.py --freeze-boundary` **[RUN]** | `[freeze-boundary] ok — 2 copies byte-identical to docs/decisions/D84…md §7 (1898 bytes)`. **Green today; goes red the moment A4 is satisfied.** Proven, §3 finding **A1**. |

### 1.3 The 8 normative rows

| # | Row (`tasks/Q.md`) | Command | Pass condition |
|---|---|---|---|
| **N1** | Anchor-artifact freeze scope (D84) — *verbatim*, `:182–201` | `python3 scripts/check-traceability.py --freeze-boundary` **plus** `cargo test -p antseal-core --locked --test parser_caps -- cap_ots_anchor_count cap_tsa_anchor_count cap_intermediate_count cap_tx_hash_count` **plus** `cargo test -p antseal-core --locked --test format_registry_draft -- code_caps_match_the_registry` **plus** `cargo test -p antseal-core --locked --test verify_fuzz -- anchor_artifact_bytes_never_change_the_bundles_accept_reject_outcome` | All green. The last one is the row's own load-bearing evidence, and **its claim was overstated here until 2026-08-06** (R67/D94 §4): it pins, *as an equality*, rule **F2** — no anchor byte moves the bundle's accept/reject outcome — which is what makes F1/F2 true rather than intended, and which R12 left green because F2 is permanent. It never pinned that *no verdict depends on artifact internals*; that was true at M0 by construction and nothing asserted it. R12 ended it, and its instruments are `tests/anchor_aggregate.rs::vector_every_anchor_kind_bundle_is_all_invalid_and_unanchored_at_m2` (red at R12, now pinning `invalid`) plus A21 rows 1–2 against A25's real material. |
| **N2** | Report-version evolution is not blocked — *verbatim*, `:202–208` | `grep -n 'pub const REPORT_VERSION' crates/antseal-core/src/verify/report.rs` → `= 1;` **plus** `cargo test -p antseal-core --locked --lib verify::tests::snapshot_bytes_are_stable` | The constant reads `1` and `EXPECTED_CANONICAL_JSON` (`verify/mod.rs:350`) begins `{"report_version":1,`. This row records something as *open* (v2 is permitted), so its verification is that v1 is actually fixed at 1 — nothing else. |
| **N3** | `REPORT_VERSION` coupled edits, three sites, third a NEGATIVE — `:215–253` | Site 1: `cargo test -p antseal-core --features test-util --locked --test report_vectors` and `./scripts/vector-freeze.sh`. Site 2: `cargo test -p antseal-core --locked --lib verify::tests::snapshot_bytes_are_stable`. Site 3: `grep -n 'pub const TRANSCRIPT_VERSION' crates/wasm-bitmatch/src/lib.rs` → `= 0;` and `grep -n 'EXPECTED_TRANSCRIPT_VERSION =' scripts/wasm-bitmatch.mjs` → `= 0;`; then `./scripts/wasm-bitmatch.sh` | (1) and (2) read `1`, (3) reads `0`, `FROZEN.sha256` matches, and the `wasm-bitmatch` lane is green **after** the bump. The row says *"the gate confirms by `grep`, not by memory"* — **[GREP]** for site 3. Cheaply machine-checkable: see §1.4 and `Q53`. |
| **N4** | The decode layer is never a report field (D86, permanent) — `:257–266` | `grep -c '"layer"' testdata/vectors/v1/report/verification-reports.json` → `0` **plus** `cargo test -p antseal-core --locked --lib verify::` | Zero occurrences of `layer` across all 21 pinned report strings, and D27 §4's structural unreachability (`VerificationReport` exists only for a bundle that passed) still holds. This is a **closed** row and this is the evidence it names. **[GREP]** — the count is the check; make it a test (§1.4). |
| **N5** | Zeroization dispositions closed (C21/C22/D88) — `:271–276` | `grep -n 'sha2 = ' Cargo.toml` → `features = ["zeroize"]` **plus** `cargo test -p antseal-core --locked --test zeroization_residue --test digest_zeroize_link --test feature_pins` **plus** `grep -n 'R1\|R2\|R3\|R4\|R5' docs/zeroization-audit.md` | The three C24 guard layers live in **three separate test binaries** deliberately, so layer 1's `E0432` cannot bury layer 2's message or layer 3's residue counts — run all three. `docs/zeroization-audit.md` R1 carries the dated D88 disposition; R2–R5 carry dated accepted dispositions. This is a **closed** row and this is the evidence it names. |
| **N6** | Full-reveal cover shape (D75) — closed *contingent on D83* — `:278–291` | `grep -n 'Status' docs/decisions/D83-…md` → `RESOLVED — option B` **plus** `grep -n 'Amendment\|^## ' docs/decisions/D75-full-reveal-cover-shape.md` **plus** `cargo test -p antseal-core --locked --test d83_leaf_payload_bundles` | D83 is RESOLVED (option B, canonical zero tail). **D75's amendment does not exist** — its last section is *"Wave-6 ratification and corrections"*, written while D83 was open, and its status line still reads *"contingent on D83 — see the amendment"*. **This row cannot be ticked today.** See finding **A6**. |
| **N7** | Traceability matrix M0 rows complete (Q13) — `:295–308` | `python3 scripts/check-traceability.py --matrix` **plus** `awk -F'\\|' '$5 ~ /M0/ {print $2, $7}' docs/testing/verification-matrix.md` **[HUMAN]** | Every M0 row must read `covered`. **V3.4 still reads `gap`** and its cell reads `NONE`, asserting F17/Q39/Q9 are missing — all three landed in wave 6. See finding **A4**. The `--matrix` check cannot see this: a `NONE` cell is legal by design. |
| **N8** | Independent cross-check clean (Q11/F14/D31) — *verbatim*, `:312–321` | `./scripts/cross-check.sh --self-test --require && ./scripts/cross-check.sh --check --require` **plus** a **new dated section** in `docs/testing/cross-check.md` naming the freeze commit **plus** `grep -n 'testdata/vectors/v\*' scripts/cross-check.sh` | Lane green *and* the document carries a dated report **for the freeze commit** with per-surface vehicle/version/count/tier and zero discrepancies, and every D31 §2 row 1–13 present at T0 or T1 with row 14 excluded. **The existing §3 is dated at commit `788519b` and describes a different tree** — see finding **A3**. |

### 1.4 Rows whose evidence is a `grep` or a human reading

Six of the 28 rows resolve to a `grep` or an eyeball. Five can be machine-checked cheaply.

| Row | Evidence kind | Cheap machine check? |
|---|---|---|
| **D2** — the encoder pin `=2.3.0` | grep of `Cargo.toml`/`Cargo.lock` | **Yes.** `crates/antseal-core/tests/feature_pins.rs` already scrapes `Cargo.toml` and asserts pin lines — but only for `sha2` (`:110`) and `hmac` (`:129`). Extend it to the whole exact-pin class from `docs/dependency-policy.md` §1 (`minicbor`, `serde`, `serde_json`, `ed25519-dalek`, `ml-dsa`, `fips204`, `unicode-normalization`, `chacha20poly1305`, `zeroize`, `subtle`, `rand_core`, `ant-core`). ~12 lines. → **`Q53`** |
| **D13** — WASM probe verdict recorded | reading a research doc | **Yes, but low value.** A test asserting a marker string in `docs/research/C11-signature-probe.md` pins prose, not a fact. Better: the *fact* is already machine-asserted — C13 reproduces the C11 probe transcript golden, and `ml-dsa` runs in `wasm32-core-tests`. Cite those instead of the doc and the row becomes a test. Recommended, not a new task: change the row's evidence to `cargo test -p antseal-core --lib --target wasm32-unknown-unknown -- crypto::sig_mldsa`. |
| **N3** site 3 — `TRANSCRIPT_VERSION == 0` | grep, by the row's own instruction | **Yes.** No Rust test asserts the numeral today (`crates/wasm-bitmatch/tests/bitmatch.rs` has zero `transcript_version` hits); only `scripts/wasm-bitmatch.mjs:65` compares at lane runtime. A three-line `assert_eq!(TRANSCRIPT_VERSION, 0)` in `bitmatch.rs`, with the doc-comment rule beside it, converts the row. → **`Q53`** |
| **N4** — `layer` absent from all report strings | grep count | **Yes.** Turn the count into a test in `crates/antseal-core/tests/report_vectors.rs`: assert the substring `"layer"` occurs zero times in the committed document *and* that `VerificationReport`'s field list contains no `layer`. Two asserts. → **`Q53`** |
| **N7** — "every M0 row reads `covered`" | reading the matrix table | **Yes, and this is the important one.** `scripts/check-traceability.py` already parses the table into `dict(zip(header, cells))` including the `status` column — it just never reads it. Add `--matrix` logic: for each row, if `milestone` is at or before a `--milestone` argument, `status` must be `covered` (or `deferred` with a later milestone). ~15 lines. Without it, a stale `gap` row passes forever — which is exactly what happened. → **`Q51`** |
| **A2** — CHANGELOG present | file existence | Trivially machine-checked once the file exists; the *content* convention is what needs defining (§4.2). |

---

## 2. The three formal freezes Q14 must execute

D17, D29 and D30 are each recorded in the TODO decision register as ratified
or formalized with *"formal freeze remains Q14"*, and all three checkboxes are
still open (`TODO.md:433`, `:445`, `:446`). A freeze that is only a sentence
in a changelog is not a freeze. For each: the artifact that must change, the
test that makes it enforceable, and what would silently un-freeze it.

### 2.1 D17 — `sig_policy` algorithm ids (`0 = ed25519`, `1 = ml-dsa-65`, `2–15` reserved)

**What must change for the freeze to be real.**

1. `docs/format/registry-v1.json` — the **9 items marked `status: "pending-D17"`** flip to the frozen status value.
2. `crates/antseal-core/tests/format_registry_draft.rs:56` — `ALLOWED_ITEM_STATUSES` gains the frozen value (it is `["proposed", "pending-D9", "pending-D17"]` today, with no frozen member and a dead `pending-D9` entry).
3. The register row `TODO.md:433` is checked, dated, and its *"Cleanup noted: F duplicates the mapping rather than delegating to C"* is either done or recorded as deliberate.

**The test that makes it enforceable — it already exists, in two halves that check each other.**

- `crates/antseal-core/src/crypto/sig_policy.rs:346` `crypto_and_manifest_registries_agree` — asserts `sig_alg_to_id(Ed25519) == 0`, `…(MlDsa65) == 1`, round-trips, and cross-checks C's semantic registry against F's wire registry `for id in 0..=20u64`.
- `crates/antseal-core/src/manifest/registry.rs:566` `sig_alg_wire_mapping_matches_d17` — `from_wire(0) == Ed25519`, `from_wire(1) == MlDsa65`, `for reserved in 2..=15 → None`, `from_wire(u64::MAX) == None`.

Both mapping functions are wildcard-free `match`es, so a new algorithm cannot
be added without a compile error at both sites. That is the strongest half of
the mechanism and it is already in place. **D17 needs no new test** — it needs
the status flip and the vocabulary edit.

**What would silently un-freeze it.** Nothing in the id range `0..=15`: it is
covered in both directions. The one real hole is **ids `21..u64::MAX-1`**,
unexercised by either test — but `from_wire` has no wildcard arm returning
`Some`, so an unregistered id cannot be represented. Rated: closed.

The *documentation* half is weaker. `docs/format/registry-v1.md` §0 and §13
carry status prose that contradicts the resolved state (see finding **A2**);
that is F4's to fix, and D17's flip should land in the same commit so the
registry has one status story.

### 2.2 D29 — the deterministic verification-report byte format (report v1)

**What must change for the freeze to be real.**

1. `docs/decisions/D29-report-byte-format.md` header — `Status: RECOMMENDED` becomes `Status: FROZEN at Q14 as report v1`, with the date and the freeze commit.
2. D29 rule 8's own text — *"`report_version`, first field; `0` until Q14 freezes `1`"* — is now history. `REPORT_VERSION` is already `1` (`verify/report.rs:72`, landed at R32). Record that the promise was discharged, and by which commit.
3. D29's *"Option to move to canonical CBOR later — and what would force it"* section says the re-base *"is a Q4/Q5/Q14 call, to be made **before** the Q14 freeze"*. **Q14 must make that call explicitly and record it**, one way or the other. None of the three forcing conditions has fired: `serde_json` output is bit-stable native↔wasm32 (12 vectors, `wasm-bitmatch`), there is no size pressure, and no repo-wide one-encoding ruling exists. The expected outcome is *"freeze JSON"*, but it must be **recorded as a decision**, not inherited by silence.
4. The `TODO.md:445` checkbox is ticked with the date.

**The test that makes it enforceable — three layers, and layer 2 is the one nobody watches.**

| Layer | Artifact | What it catches |
|---|---|---|
| 1 | `testdata/vectors/v1/report/verification-reports.json`, 21 byte-pinned strings, digest-frozen in `FROZEN.sha256` | Any change to any report byte for any of the 21 M0 shapes. After the `status frozen` flip, `--update` **refuses** to modify the entry — a report-format change becomes structurally impossible without a new format version. This is the load-bearing layer. |
| 2 | `EXPECTED_CANONICAL_JSON`, `crates/antseal-core/src/verify/mod.rs:350`, asserted by `snapshot_bytes_are_stable` (`:260`) | D29's fixed-fixture snapshot. **Enforced by nothing else.** It is a `#[cfg(test)]` unit test, so on `wasm32-core-tests` a failure is `the test binary trapped: unreachable` with no test name, no assertion and no message. R32 missed this site and passed every other lane. Native reproduction: `cargo test -p antseal-core --lib`. **R41** makes that lane name its failing test. |
| 3 | `crates/wasm-bitmatch` transcript, `scripts/wasm-bitmatch.sh` | Report bytes differing between native and wasm32 for any vector. |

**What would silently un-freeze it.**

- **A new report field.** D29 rule 4 bans `skip_serializing_if`, so every field of a version serializes every time — a new field changes all 21 strings and layer 1 refuses. Closed by mechanism.
- **A field reorder.** Declaration order *is* wire order (D29 rule 1). Same refusal. Closed.
- **A `serde`/`serde_json` bump.** Escaping or integer-formatting drift is a silent vector break. `serde = "=1.0.229"` / `serde_json = "=1.0.151"` are exact-pinned — **but no test asserts those declarations** (see D2/`Q53`). This is the real residual risk and it is why `Q53` covers the whole pin class, not just `minicbor`.
- **The bit-match running only in `debug`.** See finding **C4**.
- **Nothing independent checks the report bytes at all** — no second implementation, by D31 §7's own admission. Registered as **Q38**. Non-blocking: see §3.

### 2.3 D30 — the stable machine-readable error-code contract

This is the freeze with the weakest mechanism, and it is the one that most
needs a new one.

**What must change for the freeze to be real.**

1. `docs/testing/error-code-contract.md` §7 gains a dated `2026-…-… — FROZEN at Q14` entry recording the exact code count per family at the freeze commit.
2. §3's sentence *"Before the Q14 freeze a code may still be corrected… After Q14 the code set of frozen surfaces is permanent"* stops being conditional.
3. The `TODO.md:446` checkbox is ticked.

**The test that makes it enforceable — it does not exist, and this is finding B1.**

Today D30's append-only rule rests on three distinctness layers
(per-domain meta-tests → the Q7 registry sweep → Q8 completeness). **None of
them detects a rename**: a renamed code stays distinct and stays correctly
prefixed. The universe is 190 codes across 8 exemplar functions:

| Family | Enumerator | Codes | Rename goes red? |
|---|---|---|---|
| `cbor-` | inline array, `src/codec/decode.rs:1245` | 15 | 13 of 15 |
| `manifest-` | `manifest::error::all_code_exemplars:835` | 48 | **9 of 48** |
| `bundle-` | `bundle::error::all_code_exemplars:775` | 47 | 47 of 47 |
| `crypto-` | `crypto::error::all_code_exemplars:319` | 25 | 21 of 25 |
| `content-` | `content::error::all_code_exemplars:220` + `canon::canon_code_exemplars:50` | 12 + 2 | **5 of 14** |
| `fine-root-` | `content::fine_tree::error::all_code_exemplars:227` | 8 | 8 of 8 |
| R (unprefixed) | `verify::error::all_error_exemplars:880` | 33 | 33 of 33 |

**54 of 190 codes (28 %) can be renamed today with a fully green suite** — 39
`manifest-`, 9 `content-`, 4 `crypto-`, 2 `cbor-`.

**The mechanism to add: a frozen code-universe snapshot.** One test that
collects every code from the 8 exemplar functions into one sorted list and
byte-compares it against a committed file, with an explicit
`additions-only` rule mirroring `vector-freeze.sh`'s. That single artifact
makes D30's append-only rule enforceable instead of declared: a rename
removes a line and goes red; an addition appends and passes. It costs one
test and one file, and it needs the eight enumerators made `pub` behind
`test-util` (three already are). → **`Q52`**, blocking.

**What would silently un-freeze it, even with the snapshot.**

- **A code minted with no owner and no row.** The snapshot pins *existence*, not *coverage*. Five `crypto-` codes have neither a tamper row nor a named owner today (`crypto-fine-root-commit-mismatch`, `crypto-rng-failure`, `crypto-signature-missing-ed25519`, `crypto-signature-unlisted-ed25519`, `crypto-signature-invalid-ml-dsa-65` — the last is covered by C15's reject vectors, the other four by nothing), and the entire 14-code `content-`/G family has **zero** reverse coverage and **no owning task at all**. F23 owns `bundle-`/`manifest-`, F24 owns `cbor-`, R7's `every_unprefixed_verify_code_has_a_row_or_a_named_owner` (`src/test_util/tamper_rows_structural.rs:874`) owns R's — and it *explicitly skips* the other six prefixes by name at `:875–882`. **C and G have nobody.** → **`Q55`**, non-blocking (see §3).
- **Editing a code to make a failing test pass.** §3's third bullet forbids it and nothing detects it — except the snapshot, which is precisely why the snapshot is the mechanism.

---

## 3. The adversarial sweep

Findings are ranked. **A** = blocking, must land before the tag. **B** =
blocking, cheap. **C** = safe to land after the tag, with the reason.
Errors found in existing records are collected separately in §5.

### Blocking — the gate cannot run or cannot be honestly ticked without these

#### A1. Ticking the checklist breaks the checklist's own lint. **The gate is unrunnable as written.**

Q14 `Accept` requires *both* `scripts/check-traceability.py --freeze-boundary`
green **and** every normative row ticked. Rows N1 and N2 live *inside* the
`<!-- FREEZE-BOUNDARY:BEGIN … END -->` markers in `tasks/Q.md:180–210`, and
that block is byte-compared against `docs/decisions/D84-…md` §7, which
contains the literal `- [ ]` checkboxes. Changing `- [ ]` to `- [x]` is a byte
change.

Proven, not reasoned — on a scratch copy of the four relevant files:

```
--- baseline (untouched copy) ---
[freeze-boundary] ok — 2 copies byte-identical to …D84…md §7 (1898 bytes)
exit=0
--- now tick the two D84 rows in tasks/Q.md, as Q14's Accept requires ---
ticked 2 rows
::error::check-traceability [freeze-boundary] tasks/Q.md has drifted from …D84…md §7.
  First difference: line 1: expected '- [ ] **Anchor-artifact freeze scope (D84).** …',
                    found    '- [x] **Anchor-artifact freeze scope (D84).** …'
exit=1
```

**Why freeze-permanent:** it is not — this is a gate-mechanics defect, not
format surface. But it blocks absolutely: there is no ordering of the two
Accept criteria that satisfies both.

**Disposition — must land before the tag.** Two viable fixes; the second is
better:

1. Move the tick outside the markers — record gate state in a sibling table
   keyed on row id. Cost: the rows lose their checkbox affordance and a
   reader must cross-reference.
2. **Normalise the checkbox marker before comparing.** In
   `check-traceability.py`, apply `re.sub(r'^- \[[ xX]\] ', '- [ ] ', line)`
   to both sides in `extract_boundary` and `extract_source_block`. The rule
   *text* stays verbatim — which is the property the lint exists to protect —
   while the tick, which is gate state and not rule text, stops being
   drift. Add a self-test case asserting a *word* change still goes red so
   the normalisation cannot decay into "compare nothing". ~8 lines.

Owner: no existing task. → **`Q49`**.

#### A2. F4 is open, and the frozen registry contradicts the decisions it records.

`docs/format/registry-v1.md` + `registry-v1.json` **are** the definition of
format v1, and F4 (`TODO.md:88`) is still `- [ ] ⏳ WIP`, listed as a Q14 dep.
Concretely, at `5f794ff`:

- `registry-v1.json` root is `"status": "draft-until-Q14"`; **147 items** carry `status: "proposed"` and **9** carry `"pending-D17"`. `ALLOWED_ITEM_STATUSES` (`tests/format_registry_draft.rs:56`) has no frozen member.
- `registry-v1.md` §0 (line ~48) says D77 and D76 are *"Still open and **not** resolved here"*, while §13 (line 1385) says *"**D77** — **RESOLVED 2026-07-28: reject at F5.** … The draft's 'no registry change either way' note is thereby falsified"*. The document contradicts itself about a resolved decision.
- §7.11 key 3 (line 812) and §13 (line 1384) still describe D75 as a draft lean (*"the draft leans 'both', with reasons, as D75 input"*) though D75 is RESOLVED. D75 §"Verbatim artifacts" lists the four exact edits (§7.11 paragraph, §13 table row, §0 bullet, `registry-v1.json` `fed_but_not_resolved_here[]`) — **none has been applied**.

**Why freeze-permanent:** the registry is the artifact a third-party verifier
implements from. A registry that says a resolved rule is "proposed" freezes
ambiguity.

**Disposition — must land before the tag. Owner: F4** (existing, already a
Q14 dependency). The two tripwires are already armed and will fire on the
flip, deliberately: `registry_json_parses` asserts the root status is exactly
`"draft-until-Q14"` (*"flip deliberately"*), and
`every_draft_item_carries_a_registered_status_marker` rejects any status
outside the vocabulary.

#### A3. The cross-check freeze report describes a **different tree**.

Normative row N8 requires *"a dated report **for this freeze commit** with
zero discrepancies"*. `docs/testing/cross-check.md` §3 reads *"Freeze report —
2026-07-28. Commit `788519b` (the Q11 landing)."* Between `788519b` and
`5f794ff`:

```
$ git diff --stat 788519b 5f794ff -- testdata/vectors/v1
 FROZEN.sha256                          |   6 +-
 INDEX.json                             |   9 +-
 content-model/content-model.json       | 256 +++++++++++++++  (did not exist)
 fine-tree/fine-tree.json               |   8 +-             (G23 / D83)
 report/verification-reports.json       |  88 +++----        (R32)
```

The report's own count says *"11 committed v1 vector files"*; the lane at HEAD
prints **12**. So the report predates D83's format event, predates R32's
report-version bump, and predates the `content-model` kind entirely.

The lane itself is green at HEAD (**[RUN]**, exit 0, 225 checks / 14 cases /
12 files, zero discrepancies) — so this is not a correctness problem. It is
exactly the failure Q14's `Accept` warns about: a reader ticks N8 by
*agreeing with* the document instead of *verifying the evidence it names*.

**Disposition — must land before the tag; owned by Q14 itself.** Append a new
dated section to `docs/testing/cross-check.md` naming the freeze commit, with
the per-surface table regenerated from an actual run. §6 of that document
already prescribes exactly this (*"This document gains a new dated section at
each format freeze. Earlier sections are never rewritten."*). Two things the
new section must add that §3 does not have: the `content-model` row (see
**C1**) and the runner's `unicodedata.unidata_version`, because the
NormalizationTest counts are environment-dependent (this machine: 3.11.2 /
14.0.0, *"70 skipped as unassigned"*; the CI runner is 3.12).

#### A4. The traceability matrix's one `gap` row is stale, and the lint cannot see it.

`docs/testing/verification-matrix.md:58`, row **V3.4**, reads `**gap**` /
`NONE — see notes`, and its note says *"`fuzz/fuzz_targets/` holds exactly one
target"*, *"the CI job `fuzz-smoke` is a reserved mount point"*, and
*"`rust-toolchain.toml` pins stable while cargo-fuzz needs nightly"*. All
three statements are false at `5f794ff`:

```
$ ls fuzz/fuzz_targets/
bundle_decode.rs  codec_round_trip.rs  manifest_decode.rs  verify_bundle.rs
$ grep channel fuzz/rust-toolchain.toml
channel = "nightly-2026-01-26"
$ grep -n TARGETS scripts/fuzz.sh
32:TARGETS=(manifest_decode bundle_decode codec_round_trip verify_bundle)
```

F17, Q39 and Q9 all landed in wave 6 and `ci.yml`'s `fuzz-smoke` job has real
steps. The matrix's "Findings" section (line 126) and V1.2's note
(*"Seven vector families under `v1/`"* — there are 8 directories, 11 kinds,
12 files) are stale the same way.

`scripts/check-traceability.py --matrix` cannot detect any of this: it only
resolves references, and a row whose cell says `NONE` is legal by design
(`:254–261`).

Normative row N7 repeats the stale claim verbatim and says
*"**This row blocks the freeze tag.**"* A gate executor following the row
literally would conclude the freeze is blocked by work that is already done.

**Disposition — must land before the tag, two parts.**
(a) Correct V3.4 to `covered` with real references (`fuzz/fuzz_targets/manifest_decode.rs`, `fuzz/fuzz_targets/bundle_decode.rs`, `scripts/fuzz.sh`, `fuzz/rust-toolchain.toml`, `.github/workflows/ci.yml`), correct V1.2's family count, and rewrite N7's text in `tasks/Q.md` to record that the gap closed and when. **Owner: Q13** (matrix maintenance) executing inside Q14.
(b) Make the status column machine-checked so this cannot recur: `--matrix` gains a milestone-status gate. **Owner: none.** → **`Q51`**.

#### A5. Normative row N6 is un-tickable: D75's post-D83 amendment does not exist.

Row N6 says, in its own words: *"Tick this row only once D83 is RESOLVED and
D75's amendment records which branch was taken."*

- D83 **is** RESOLVED — option B, canonical zero tail (`docs/decisions/D83-…md:3`).
- D75's last section is `## Wave-6 ratification and corrections (2026-07-28)`; there is no amendment section after it, and its status line still reads *"the discharged open action is now **contingent on D83** — see the amendment"*.

Under option B the answer is determinate and the row itself states it: *"If
D83 shortens or canonicalizes the tail, D75's original discharge becomes true
as written and **the exception is deleted**."* Option B canonicalizes the
tail. So D75's Correction 3 exception must be **deleted**, its status line
must drop *"contingent on D83"*, and the `fed_but_not_resolved_here[]` JSON
blob at D75 §"Verbatim artifacts" item 4 must be re-cut.

**Disposition — must land before the tag; owned by Q14 itself** (it is a
decision-record edit, ~15 lines, with a determinate answer). Pipeline
evidence already exists and should be cited in the amendment:
`crates/antseal-core/tests/d83_leaf_payload_bundles.rs`, 6 tests driving both
D83 sites end to end through `verify_bundle`.

#### A6. No `CHANGELOG` exists, and no task other than Q14 mentions one.

`find . -iname 'CHANGELOG*'` (excluding `target/`, `.git/`) returns nothing;
`git tag -l` returns nothing. Q14's `Do` and `Accept` both require *"an
annotated `format-v1-freeze` tag plus CHANGELOG entry"*, and a grep of
`tasks/` finds the word only in Q14's own two lines. So Q14 creates the file
from scratch and defines its convention. §4.2 specifies both.

**Disposition — owned by Q14. Not a new task.**

### Blocking, cheap — small edits that convert a prose freeze into a real one

#### B1. D30's freeze has no mechanism. 54 of 190 codes are renameable with a green suite.

Full evidence in §2.3. The append-only rule that third-party verifiers depend
on is enforced by review discipline for 28 % of the code universe, and the
`content-`/G family is the worst case (5 of 14 rename-detectable, zero
reverse coverage, no owner).

**Why freeze-permanent:** codes are permanent from the moment a released
verifier compares against one (contract §3). Q14 is what makes that
permanence start.

**Disposition — must land before the tag.** The snapshot artifact is the
minimum viable freeze mechanism and it is small: collect from the 8 existing
enumerators, sort, commit, compare, additions-only. → **`Q52`**. The
*reverse-coverage* half (rows or named owners for `crypto-` and `content-`)
is a separate, larger job and is **not** blocking — see **C3**.

#### B2. The frozen wire registry has no freeze digest, and the 19 caps are pinned only by two files agreeing.

`docs/format/registry-v1.md` and `registry-v1.json` are outside every freeze
mechanism in the project: `scripts/vector-freeze.sh` covers
`testdata/vectors/v<n>/*.json` **only** (`vector-freeze.sh:50`, `:166`), and
`FROZEN.sha256` has no entry for either file.

The consequence is sharpest for the 19 D10 parser caps. They are pinned by
`crates/antseal-core/tests/format_registry_draft.rs:869`
`code_caps_match_the_registry`, which asserts in both directions that
`codec::caps`'s constants equal `registry-v1.json`'s `caps.entries[].value`.
That is a **consistency** check, not a **pin**: a coordinated edit of both
files in one commit passes the whole suite. Post-freeze that is a silent
format change — the caps decide whether a given `.sealproof` is a valid v1
bundle (D84 §7 puts rows 6–9 and 16–19 explicitly *inside* the freeze).

The same shape covers every other registry fact: map keys, reserved bands,
scalar lengths, tuple arities, enum values, version dispatch. All are
"code ⟷ JSON must agree", none is "this value is X".

**Why freeze-permanent:** the registry *is* format v1.

**Disposition — must land before the tag.** Add `docs/format/registry-v1.md`
and `registry-v1.json` to a freeze manifest with the same
append-only/refuse-on-change semantics `vector-freeze.sh` already implements
(a `docs/format/FROZEN.sha256` reusing the existing directive parser is the
cheapest route, and it reuses a mechanism that already has tests-of-the-test).
→ **`Q50`**.

#### B3. The pinned CBOR encoder — item 1 of Q14's own `Do` — is asserted by no test.

`minicbor = "=2.3.0"` (D7/P10) is enforced by `Cargo.toml`, `Cargo.lock`,
`--locked`, and `deny.toml`'s `wildcards = "deny"` (which bans `*`, not a
version). `crates/antseal-core/tests/cbor_pin_eval.rs` names the version only
in a doc comment; all 13 of its assertions are behavioural and would pass on
any conforming minicbor. `crates/antseal-core/tests/feature_pins.rs` **already
scrapes `Cargo.toml` and asserts pin lines** — for `sha2` (`:110`) and `hmac`
(`:129`) only.

The same hole covers `serde`/`serde_json` (D29's own pin consequence — a
serializer behaviour change is a silent report-vector break),
`ed25519-dalek`, `ml-dsa`, `fips204`, `unicode-normalization`,
`chacha20poly1305`, `zeroize`, `subtle`, `rand_core` and `ant-core`. Every one
is format-affecting by `docs/dependency-policy.md` §1's own definition.

**Why freeze-permanent:** MVP-SPEC.md line 73 makes the encoder pin part of
the Definitions section, and the Definitions section is what Q14 freezes.

**Disposition — must land before the tag.** Extend `feature_pins.rs` to the
whole exact-pin class, and fold in the three other cheap conversions from
§1.4 (N3 site 3's `TRANSCRIPT_VERSION == 0`, N4's zero-`layer` count, D13's
probe evidence). One test file, ~40 lines total. → **`Q53`**.

### Non-blocking — safe to land after the tag, with the reason

#### C1. `content-model` is a frozen v1 vector kind with **no independent vehicle**, and the gate's completeness rule structurally cannot notice.

Normative row N8 says *"Every surface in **D31 §2 rows 1–13** is present at T0
or T1."* D31 §2's register has 15 rows and was written before G21 landed the
`content-model` kind. The cross-check run at HEAD confirms:

```
--  testdata/vectors/v1/content-model/content-model.json: kind 'content-model',
    no diagnostic sidecar (out of scope for the CBOR cross-check)
```

and there is no `content-model/gen_vectors.py` — `cross-check.sh` discovers
exactly 4 generators (crypto, hkdf, fine-tree, utf8-corpus). So the kind is
checked by nothing independent, and N8's completeness rule is keyed on a
register that predates the artifact, meaning **a vector kind added after D31
satisfies the row vacuously**. That is the "coupled edit enforced by nothing"
shape: adding a vector kind must add a D31 row, and nothing enforces it.
F31 is adjacent but scoped to *"commits format CBOR"*, not *"has any
vehicle"*.

**Why non-blocking:** what `content-model.json` pins is *composition* — unit
ordering, LE64 `unit_id` assignment, D23 mirror-last placement — and every
underlying primitive is already covered at T1 (commitments row 5,
canonicalization row 10, fine tree row 9). It also pins no proof bytes (G21
asserts that mechanically). And the honest tier for composition is T1 with no
T0 anchor possible, exactly like rows 5/6/9, which D31 §2 already states
plainly.

**But the *recording* is blocking**, because N8 demands the report name the
vehicle *per surface*: A3's new dated section must carry a `content-model`
row reading "no vehicle — composition is ours; primitives covered at rows
5/9/10", or the report is incomplete by its own rule.

**Disposition — record now (in A3), fix after.** → **`Q54`**: make "every
registered vector kind has a named cross-check vehicle, or a recorded
'none possible' with its reason" a checked property, so the next kind cannot
land silently uncovered. Extends F31 rather than duplicating it.

#### C2. Seven of the 18 CI contexts have **never executed their present content on a remote runner**.

`docs/ci-verification.md:87` records exactly one remote run in the project's
history — GitHub Actions run `30309407509`, 2026-07-27, **14 contexts**,
green. Against today's 18:

- **Four did not exist**: `wasm32-core-tests` (P14), `vector-freeze` (Q6), `cross-check` (Q11/F14), `traceability` (Q13/Q37).
- **Three were content-free mount points** whose only step printed that green there asserted nothing: `wasm-bitmatch` (claimed at Q5), `tamper-matrix` (claimed at Q8), `fuzz-smoke` (claimed at Q9).
- The remaining **11 did run** — but against a tree of a few hundred tests (`docs/ci-verification.md:203` records the Q1-tree `test` lane as *"1 passed, rest empty"*), not today's 1113.

The `cross-os` macOS and Windows legs have therefore not run since the
`corpus_`/`vector_` suites were populated, so G3's cross-OS byte-stability
evidence for the current corpus is local-only (TODO's G3 entry already
carries `⛔ cross-OS byte-stability evidence needs the next maintainer
push`).

Q43 exists precisely because of this class: *"a `tamper-matrix` guard command
was malformed since Q8 and sat latent because the lane had **never run
remotely**; the guard worked, its own command had never been executed"* —
fixed at HEAD (`5f794ff`).

**Why non-blocking:** the tag is local (§4.3) and pushing needs separate
maintainer consent, so a remote-green precondition cannot be met without an
action Q14 is not authorised to take. Making remote-green a gate condition
would deadlock the gate on an external approval.

**Disposition — do not block; make it a recorded limitation.** The tag
annotation and the sign-off record must state, in one sentence, that all gate
evidence is local at the freeze commit and that 7 of the 18 contexts have
never executed their present content remotely. That is honest and it is
exactly the kind of thing a future reader needs. Related: `scripts/local-gate.sh` runs **5 of the 18 contexts**
(fmt, clippy, test, wasm32, cross-check) — the gate procedure in §1 must call
the lane scripts individually and must not be replaced by `local-gate.sh`.

#### C3. Reverse coverage for `crypto-` and `content-` is owned by nobody.

Detailed in §2.3. F23 owns `bundle-`/`manifest-`, F24 owns `cbor-`, R7's
check owns R's and skips the rest by name. C's 5 uncovered codes and G's
entire 14-code family have no task.

**Why non-blocking:** with `Q52`'s snapshot in place, the *codes* are frozen
and a rename is caught. Reverse coverage answers a different question — "does
some mutation reach this code?" — and adding a tamper row later changes
nothing frozen: rows are test artifacts, not format surface, and D30 §3 says
adding is *"routine and unrestricted"*. Blocking on it would hold the tag for
work that has no permanence consequence.

**Disposition — after the tag.** → **`Q55`** (C-side + G-side reverse
coverage, the twin of F23/F24), sequenced with F23/F24 so all four families
land one mechanism rather than four.

#### C4. The bit-match covers `debug` codegen only, on one OS.

Verified at `5f794ff`: `grep -n '^\[profile' Cargo.toml crates/*/Cargo.toml`
returns nothing, and `grep -- '--release' .github/workflows/*.yml scripts/*.sh`
returns nothing. So native↔wasm32 byte-identity is proven for
the debug codegen path only, while the M3 verifier page ships a release
wasm-bindgen build — the codegen path a third party actually runs has never
been compared. Registered as **F29**.

**Why non-blocking:** the consumer does not exist yet. No released verifier
runs release-codegen wasm today, so no v1 bundle's verdict depends on it, and
if release codegen ever *did* diverge, that would be a compiler bug affecting
the page — fixable without a format-version bump, because the frozen artifact
is the vector bytes, not the binary. F29 must land before the M3 page ships;
it does not gate v1.

#### C5. The report byte format freezes with no independent check (Q38).

D31 §7 found it and says so: *"D29 freezes a v1 format at Q14 with 21
byte-pinned strings and no independent implementation checking any of it. Not
a blocker for this report, but it is a hole in a v1 format."*

**Why non-blocking, and this deserves the argument rather than the citation:**
report v1 is the one frozen format with a *sanctioned escape hatch*. Normative
row N2 (D84 §7, verbatim) establishes that M2's anchor stage ships **report
v2** as ordinary versioned evolution under line 123. So a defect found in
report v1 after the tag is repaired by the version bump that is already
scheduled — unlike a manifest or bundle defect, which would need a wire-format
version. The pinning that *does* exist is also unusually dense: 21 committed
strings, a fixed-fixture snapshot, and native↔wasm32 byte-identity.

**Disposition — after the tag, before M2's report v2.** **Q38** (existing).

#### C6. Items on TODO's own "still open for the freeze" list that are **not** blocking

`TODO.md:48` lists F4, F18, F20, F22–F25, F30, R36/R37/R42, Q38/Q40/Q41 as
open for the freeze. Only **F4** is genuinely blocking (finding A2). The rest:

| Item | Verdict | Reason |
|---|---|---|
| **F18** | after | Adds tamper rows for 4 codes that already exist and already freeze. A row is a test artifact; adding one changes nothing frozen. |
| **F20** | after | Anchor-artifact schema rows. D84 puts artifact internals outside the freeze; M0 renders every anchor `absent`. |
| **F22** | after | Rows for the 18 cap codes. Same as F18: the codes and the values freeze, the rows do not. |
| **F23 / F24** | after | Superseded in the freeze-critical half by `Q52`'s snapshot; the residue is coverage, not permanence. |
| **F25** | after | A test primitive. |
| **F30** | after | Element-aware clamping. **No verdict moves** — capacity is a hint. The cap *values* are frozen and unchanged; the allocation strategy is not format surface. |
| **R36 / R37 / G24** | after | R37/G24 note that no *committed bundle fixture* exercises a `level == d` cover node. Worth a hard look, and the answer is still "after": the freeze manifest is **append-only** (`vector-freeze.sh:169–180` — *"After Q14 the only legal change is an addition"*), so a bundle vector for that shape may be added later without a format event. Pipeline coverage already exists at `tests/d83_leaf_payload_bundles.rs` (6 tests, both D83 sites, end to end through `verify_bundle`, via the one-byte R6 shape where `d == 0`). |
| **R38 / R39 / R40 / R41** | after | Fixture-construction quality and a wasm32 diagnostics improvement. R41 is high-value (it is how R32's fourth coupled site hid) but touches no frozen artifact. |
| **R42** | **already done — close it** | R42 asks to carry `REPORT_VERSION`'s coupled-edit row, including the negative third clause, into Q14's checklist. It is in the tree at `tasks/Q.md:215–253`, landed by commit `88526bb`. |
| **Q40** | **already superseded — close it** | R32 disproved its premise; `TODO.md:216` already records this. Close via R42's disposition. |
| **Q38** | after | See **C5**. |
| **Q41** | after | Enforcing external-fixture provenance digests offline is defence in depth; the ACVP and Unicode fixtures are committed and git-integrity-protected, and D31 §6 already retains them forever. |
| **Q43** | after, but see **C2** | Its subject matter (CI shell steps never executed) is real and is why C2's limitation must be recorded in the tag. |
| **G18** | after | `TODO.md:48` already records D26's ruling: **not a Q14 dependency**. |
| **C25 / C26 / C27** | after | C27 is completeness of the ML-DSA cross-check; the surface is covered at **T0** by ACVP, which is strictly stronger. |

#### C7. One item **missing** from that list which *is* blocking: **R33**.

`tasks/R.md:394` reads `Milestone: M0 (before Q14 — **it is a code-set
question**)` and its Accept is *"A decision record, or a recorded ratification
of the existing non-row, **before Q14**"*. It does not appear in
`TODO.md:48`'s "still open for the freeze" list.

The substance is real, not bookkeeping. R33 asks whether `unit-commit-mismatch`
deserves a cause discriminator. If the answer is "yes" after the tag, the fix
is not an addition — it **narrows the meaning of an already-frozen code**, and
`docs/testing/error-code-contract.md` §3 forbids exactly that (*"Never
renumber or re-scope an existing code"*). So the question must be answered
before the freeze even though the expected answer is "no code".

**Disposition — must land before the tag. Owner: R33** (existing). Expected
outcome: ratify the existing non-row `pipeline-level-wrong-unit-salt` in a
short record, on D81's argument — a salted commitment opening is one
comparison over two inputs and cannot attribute itself.

### Ranked summary

| Rank | Finding | Blocking? | Owner |
|---|---|---|---|
| 1 | **A1** — ticking the checklist breaks its own lint (proven) | **yes** | **Q49** (new) |
| 2 | **A2** — F4 open; registry contradicts resolved D74/D75/D77 | **yes** | F4 |
| 3 | **B1** — D30 has no freeze mechanism; 54/190 codes renameable green | **yes** | **Q52** (new) |
| 4 | **B2** — the wire registry has no freeze digest; caps pinned by agreement only | **yes** | **Q50** (new) |
| 5 | **A3** — the cross-check freeze report describes a different tree | **yes** | Q14 itself |
| 6 | **A4** — V3.4 stale `gap`; the lint cannot read the status column | **yes** | Q13 + **Q51** (new) |
| 7 | **C7** — R33 is a code-set question due before the tag, missing from TODO's list | **yes** | R33 |
| 8 | **A5** — D75 has no post-D83 amendment, so N6 is un-tickable | **yes** | Q14 itself |
| 9 | **B3** — the pinned encoder (Do item 1) is asserted by no test | **yes** | **Q53** (new) |
| 10 | **A6** — no CHANGELOG exists | **yes** | Q14 itself |
| 11 | **C1** — `content-model` has no vehicle; N8's rule cannot notice a new kind | record now, fix after | **Q54** (new) |
| 12 | **C2** — 7 of 18 contexts never ran their present content remotely | no — record as a limitation | (Q43) |
| 13 | **C3** — `crypto-`/`content-` reverse coverage owned by nobody | no | **Q55** (new) |
| 14 | **C5** — report v1 freezes with no independent check | no | Q38 |
| 15 | **C4** — bit-match is debug-codegen, one-OS only | no | F29 |
| 16 | **§5** — errors on disk (`docs/ci-verification.md` context set, and others) | no | **Q56** (new) + §5 edits |

**Counts: 10 blocking, 6 non-blocking.** Of the 10 blocking, four are Q14's
own execution (A3, A5, A6, and half of A4), two belong to existing tasks (F4,
R33), and four need new tasks (Q49, Q50, Q52, Q53). Q51 is blocking as a
recurrence guard and is trivial; it may land with Q49 in one commit.

### Reserved task IDs (block Q49–Q56)

| ID | Title | Blocking |
|---|---|---|
| **Q49** | Make the freeze-boundary lint tolerate a ticked checkbox — normalise the marker on both sides, with a self-test proving a word change still goes red | yes |
| **Q50** | Freeze digest for the v1 wire registry — `docs/format/registry-v1.{md,json}` under an append-only manifest reusing Q6's directive parser | yes |
| **Q51** | `check-traceability.py --matrix` gains a per-milestone status gate, so a stale `gap` row cannot pass a milestone review | yes (trivial) |
| **Q52** | Frozen snapshot of the stable error-code universe (190 codes, 8 enumerators), additions-only — the mechanism that makes D30's freeze enforceable | yes |
| **Q53** | Assert the exact-pin class declarations, plus the three cheap grep→test conversions (`TRANSCRIPT_VERSION == 0`, zero-`layer` in report strings, probe evidence) | yes |
| **Q54** | Every registered vector kind must have a named cross-check vehicle or a recorded "none possible" with its reason — extends F31 from "commits CBOR" to "has any vehicle" | no |
| **Q55** | Reverse coverage for `crypto-` and `content-`/`fine-root-` — the two families no task owns; sequence with F23/F24 as one mechanism | no |
| **Q56** | Generate `docs/ci-verification.md`'s context set from `ci.yml` rather than hand-maintaining it (it currently disagrees with the workflow *and with itself*) | no |

---

## 4. The tag procedure

### 4.1 Preconditions, in order

1. All 10 blocking findings of §3 landed and committed.
2. Working tree clean: `git status --porcelain` prints nothing.
3. Phase B evidence sweep (§1) run **at the freeze candidate commit**, all commands exit 0, output captured.
4. **Phase C flips**, in one commit:
   - `testdata/vectors/v1/FROZEN.sha256`: `#! status pre-freeze` → `#! status frozen` (pending set is already empty — verified: no `#! pending` lines at `5f794ff`).
   - `docs/format/registry-v1.json`: root `"status": "draft-until-Q14"` → the frozen value; the 147 `proposed` and 9 `pending-D17` item statuses likewise; `ALLOWED_ITEM_STATUSES` and `registry_json_parses`'s literal updated to match (both are deliberate tripwires and will fire).
   - D17, D29, D30 freeze markers per §2, and the three TODO register checkboxes.
5. **Prove the refusal, then revert it.** After the `FROZEN.sha256` flip:
   ```
   printf '\n' >> testdata/vectors/v1/report/verification-reports.json
   ./scripts/vector-freeze.sh --update      # MUST fail, naming the file
   git checkout -- testdata/vectors/v1/report/verification-reports.json
   ```
   The expected output is `::error::…FROZEN: \`report/verification-reports.json\` would be modified or dropped.` Record it. A freeze whose refusal has never been observed is a freeze nobody has tested — the same discipline every lane in this project already applies.
6. **Re-run the whole of Phase B** at the post-flip commit. This second run is the one the tag cites.

### 4.2 The CHANGELOG

Create `CHANGELOG.md` at the repository root, Keep-a-Changelog shape, with
the freeze as its first entry. The file does not exist today, so this defines
the convention.

```markdown
# Changelog

All notable changes to antseal's **frozen formats** are recorded here.
Format-affecting entries are the point of this file; ordinary code changes
live in the git history. Versions here are format versions, not release
versions.

## [format-v1] — <YYYY-MM-DD>

### Frozen

Manifest and `.sealproof` bundle wire format v1, and everything the
Definitions section (MVP-SPEC.md line 73 onward) names:

- **CBOR profile**: RFC 8949 §4.2.1 Core Deterministic Encoding; encoder
  `minicbor = "=2.3.0"` (D7/P10).
- **Hash domain tags** `0x00`–`0x06` (C1).
- **HKDF label registry**: 8 labels, info = `u8(len(label)) ‖ label ‖ LE64(id)`,
  sentinel id `0xFFFFFFFFFFFFFFFF` (C2).
- **Unicode/NFC version descriptor** `unicode-17.0.0` (G1/D25).
- **Signature context string** `antseal-manifest-v1`; Ed25519 pre-image
  `ctx ‖ 0x00 ‖ body` (C12).
- **`sig_policy` algorithm ids**: `0 = ed25519`, `1 = ml-dsa-65`, `2–15`
  reserved and rejected (**D17**).
- **Wire registry**: `docs/format/registry-v1.md` + `registry-v1.json` —
  every map key, type, presence rule, byte length and reserved slot (F4).
- **Parser caps**: D10's 19 constants, with their error codes.
- **Verification report v1**: `REPORT_VERSION = 1`, deterministic compact
  JSON per **D29** rules 1–9.
- **Stable error codes**: <N> codes across `cbor-`/`manifest-`/`bundle-`/
  `crypto-`/`content-`/`fine-root-`/unprefixed, append-only per **D30**.
- **Golden vectors**: `testdata/vectors/v1/`, <N> files, `FROZEN.sha256`
  `status frozen` — additions only, retained indefinitely.

### Explicitly NOT frozen

- Numeric limits on the **internal** structure of anchor artifacts (`.ots`
  ops, DER nesting, chain certificate count/size, signed attributes) — these
  are verifier policy over foreign formats, set at M2, and are **not** an
  exception to MVP-SPEC.md line 123 (**D84** rules F1–F4).
- The report **version**: report v2 ships with M2's anchor stage as ordinary
  versioned evolution (D84 §7).
- `wasm_bitmatch::TRANSCRIPT_VERSION` (stays `0`) — it versions a test
  transcript envelope, not a format (R32).

### Known limitations recorded at the freeze

- All gate evidence is **local**. 7 of the 18 CI contexts have never
  executed their present content on a remote runner (see
  `docs/ci-verification.md`).
- <the content-model vehicle gap, and any others open at the tag>
```

### 4.3 The annotated tag

```
git tag -a format-v1-freeze -m "$(cat <<'EOF'
antseal format v1 — FROZEN

Gate: tasks/Q.md Q14. Checklist: 15 Do items, 8 normative rows, 5 Accept
criteria — 28 rows, every one verified by a named command at this commit.
Procedure and evidence: docs/format/Q14-freeze-gate-plan.md;
run log: docs/ci-verification.md § "Q14 — format-v1 freeze gate".

Frozen at this commit (see CHANGELOG.md [format-v1] for the itemised list):
the CBOR profile and encoder pin, the 0x00-0x06 domain-tag registry, the
8-label HKDF registry and its length-prefixed info encoding, the sentinel
id, the unicode-17.0.0 descriptor, the antseal-manifest-v1 signature
context, D17's sig-policy algorithm ids, the v1 wire registry, D10's 19
parser caps, D29's report v1 byte format, D30's stable error-code set, and
testdata/vectors/v1 (FROZEN.sha256 status: frozen, additions only).

NOT frozen: anchor-artifact-internal limits (D84 F1-F4, set at M2);
the report VERSION (v2 ships with M2's anchor stage).

Evidence:
  independent cross-check   0 discrepancies, <N> surfaces, D31 tiers T0/T1
                            (docs/testing/cross-check.md, dated section)
  golden vectors            <N> files frozen, 0 pending must-exist
  tamper matrix             M0 COMPLETE, EXPECTED_M0_PENDING empty
  native<->wasm32 bit-match byte-identical over <N> vectors
  traceability              34 rows, all M0 rows covered
  test suite                <N> tests green (fmt, clippy -D warnings, wasm32)

Limitation, recorded deliberately: all evidence above is LOCAL. 7 of the 18
CI contexts have never executed their present content on a remote runner.

After this tag, any change to frozen material is a format-version event
(Q27 policy). scripts/vector-freeze.sh refuses to modify or drop a frozen
digest; the refusal was demonstrated at this commit before tagging.

Signed off: aed900, <YYYY-MM-DD>
EOF
)"
```

### 4.4 The sign-off record

Recorded in **three** places, all local, all with the same names and dates —
following the precedent `docs/security-assumptions.md:15` and
`docs/threat-model.md:23` already set:

| Where | Shape |
|---|---|
| The tag annotation | `Signed off: aed900, <date>` (above) |
| `CHANGELOG.md` `[format-v1]` entry | a `### Sign-off` block: maintainer `aed900`, date, freeze commit SHA, and the `docs/ci-verification.md` section that holds the run log |
| `docs/ci-verification.md`, new `## Q14 — format-v1 freeze gate, <date>` section | a table with one row per checklist row: row id, command, exit status, one-line output; plus the sign-off line and the recorded limitations |

`aed900` is the sole maintainer identity; no `Co-Authored-By` trailer appears
on any freeze commit.

### 4.5 Abort conditions — what makes the gate refuse to tag

Any one of these means **stop, do not tag**:

1. **Any §1 command exits non-zero** at the freeze commit — including a
   self-test that fails to go red. A checker never observed failing is not
   evidence (D31 §11 item 6).
2. **`--freeze-boundary` red** for any reason other than finding A1's ticked
   checkbox — and A1 must be *fixed*, never worked around by leaving the rows
   unticked.
3. **Any `#! pending` line** in any `FROZEN.sha256`, or `EXPECTED_M0_PENDING`
   non-empty, or the tamper matrix reporting anything but M0 COMPLETE.
4. **Any discrepancy > 0** in the freeze-commit cross-check run, or the new
   dated section naming a commit other than the freeze commit.
5. **Any M0 row of the traceability matrix reading anything but `covered`.**
6. **`registry-v1.json` still reading `draft-until-Q14`**, or any item still
   carrying `proposed`/`pending-D17`, or `registry-v1.md` still containing a
   status contradiction.
7. **D17, D29 or D30's register checkbox still open**, or any of the three
   lacking the mechanism §2 specifies.
8. **The `--update` refusal was not demonstrated** after the `status frozen`
   flip (§4.1 step 5).
9. **Phase B was not re-run after Phase C's edits.** Evidence measured before
   the flip does not describe the tagged commit.
10. **The working tree is dirty**, or the tag would land on a commit that is
    not the one the evidence describes.
11. **A blocking finding of §3 is open.**

### 4.6 Publication

**Nothing is pushed.** The tag is created locally with `git tag -a`, on the
local `main`, and stays there.

- No `git push`, no `git push --tags`, no release, no crates.io publish, no
  GitHub release object.
- The remote `aed900/antseal` is at `c85d963` and roughly 150 commits behind
  local `main`. Publishing the freeze — the commits, the tag, or both —
  requires **express in-the-moment maintainer confirmation naming the action,
  the destination and the account**. A task list, a plan, or this document is
  not that confirmation.
- Branch protection is a separate external action, likewise unauthorised
  here. It is already outstanding for two required contexts (`traceability`
  and `cross-check`) and the payload has not been applied.
- Consequence to state plainly in the sign-off: because nothing is pushed,
  the freeze evidence is local-only and 7 of the 18 CI contexts remain
  remote-unproven in their present form at the tag. That is a recorded
  limitation (finding **C2**), not a defect the gate can close by itself.

---

## 5. Errors found on disk

Every item here is wrong in the tree at `5f794ff` and was found while
verifying this plan. Location is exact.

| # | Location | What is wrong |
|---|---|---|
| 1 | `docs/format/anchor-artifact-limits.md:60` | **F4's mirror has drifted from its source and nothing checks it.** D84 §4's F4 now reads `full freeze procedure (**Q27** — see the 2026-07-28 correction below).`; the A27 mirror still reads `full freeze procedure (Q19).` A27's own editorial note (`:64–73`) claims the rule *"is reproduced unaltered because A27's Accept criterion requires byte-identity with D84"* — that sentence is now false. D84 was corrected at source in commit `5994365` and nobody re-spliced. `check-traceability.py --freeze-boundary` covers only the `FREEZE-BOUNDARY` block (D84 §7 ↔ §2); **F1–F4 (D84 §4 ↔ §1) are outside the lint entirely**, and F1–F4 *are* frozen at Q14. Fix: re-splice §1 from D84 §4, delete or rewrite the editorial note, and extend the lint to a second marked block. |
| 2 | `docs/testing/cross-check.md:218` | §6 cites *"spec line 123, **Q19**"* for the format-stability policy. Same slip as #1; it is **Q27**. D84's correction claims all three sites were fixed and that *"`tasks/Q.md` and `tasks/A.md` already say Q27"* — this is a **fourth** site nobody counted. |
| 3 | `docs/ci-verification.md:927` | **"Authoritative context set (now 17)"** lists 17 contexts and **omits `traceability`**. `.github/workflows/ci.yml` defines 18 jobs. The workflow's own header (`ci.yml:34–38`) says the doc needs the row and that it was not done. |
| 4 | `docs/ci-verification.md:982` | A **second** "Authoritative context set (still 16)" appears *after* the "now 17" section, and the Q11 cross-check evidence rows are appended below it. The Q11 material was interleaved into the Q9 section (`## What changed — Q11` sits under `# Q9`), so the file states two different context counts, neither of which is the real 18. → `Q56`. |
| 5 | `docs/testing/verification-matrix.md:58` | Row **V3.4** reads `gap`/`NONE` and asserts three things that are all false at HEAD (one fuzz target; `fuzz-smoke` a mount point; no nightly pin). F17, Q39 and Q9 landed in wave 6. |
| 6 | `docs/testing/verification-matrix.md:126` | The "Findings" section repeats #5 as a standing finding. |
| 7 | `docs/testing/verification-matrix.md:38` | V1.2's note says *"Seven vector families under `v1/`"*. There are 8 directories, 11 registered kinds and 12 vector files. |
| 8 | `tasks/Q.md:295–308` (normative row N7) | Reproduces #5 verbatim and adds *"**This row blocks the freeze tag.**"* An executor following the row literally would conclude the freeze is blocked by completed work. |
| 9 | `tasks/Q.md:236–237` (normative row N3, clause 3) | *"aggregates all **seven** vector kinds"*. `KNOWN_KINDS` has **11** entries (`src/test_util/vectors.rs:61`) over 12 files in 8 directories. The argument the clause makes is unaffected; the number is wrong. |
| 10 | `crates/wasm-bitmatch/src/lib.rs:79–82` | Source of #9: *"The report is 1 of **7** kinds … (`hkdf`, `crypto`, `manifest`, `bundle`, `fine-tree`, `sig-reject`, `report`)"*. That list is 7 *directories* and omits `content-model`, added by G21 in the same wave. |
| 11 | `docs/testing/cross-check.md:79, :97` | The freeze report is dated at commit `788519b` and says *"11 committed v1 vector files"*. The tree has 12 and the lane prints 12. See finding **A3**. |
| 12 | `docs/decisions/D75-full-reveal-cover-shape.md:3–8` | Status still reads *"the discharged open action is now **contingent on D83** — see the amendment"*. D83 resolved (option B) and no amendment exists. See **A5**. |
| 13 | `docs/format/registry-v1.md` §0 (~line 48) vs §13 (line 1385) | §0: D77 *"Still open and **not** resolved here"*. §13: *"**D77** — **RESOLVED 2026-07-28: reject at F5.**"* The document contradicts itself. §7.11 (line 812) and §13 (line 1384) likewise still describe D75 as a draft lean. D75's four "Verbatim artifacts" edits were never applied. |
| 14 | `crates/antseal-core/tests/format_registry_draft.rs:56` | `ALLOWED_ITEM_STATUSES = ["proposed", "pending-D9", "pending-D17"]` — `pending-D9` is dead (D9 resolved; zero occurrences in `registry-v1.json`) and there is no frozen member, so the Q14 flip cannot be expressed in the current vocabulary. |
| 15 | `TODO.md:48` | The "Still open for the freeze" list **omits R33**, whose own entry (`tasks/R.md:394`) reads `Milestone: M0 (before Q14 — it is a code-set question)` with an Accept that says *"before Q14"*. See **C7**. |
| 16 | `TODO.md:48` | The same list still names **R42**, whose work is already in the tree (`tasks/Q.md:215–253`, commit `88526bb`), and **Q40**, which `TODO.md:216` itself records as superseded. Both should be closed rather than carried as freeze blockers. |
| 17 | `tasks/Q.md:161–166` (Q14 `Accept`) | The two criteria *"Every row in the normative-rows block below is ticked"* and *"`scripts/check-traceability.py --freeze-boundary` green"* are **mutually exclusive as written**. Proven in §3 **A1**. |
| 18 | `docs/decisions/D84-…md:341–360` | The correction states *"the corrected reference lives here, at the source, and `tasks/Q.md` and `tasks/A.md` already say Q27"* — accurate for those two files, but it left the A27 mirror (#1) and `docs/testing/cross-check.md` (#2) still saying Q19, and it broke the byte-identity it was preserving. The record's own lesson (*"the argument for splicing normative text programmatically rather than retyping it"*) applies to itself: correcting the source without re-running the splice is the same failure one step later. |

---

## 6. What this plan does not settle

- **Whether the tag should wait for a remote green run.** §3 **C2** argues no,
  because the required push needs consent Q14 cannot grant, and recommends
  recording the limitation instead. A maintainer may reasonably decide the
  opposite; if so, the push and the branch-protection payload become explicit
  preconditions in §4.1 and need their own in-the-moment confirmation.
- **D29's canonical-CBOR re-base.** §2.2 item 3 requires Q14 to *record* the
  call. The evidence points at "freeze JSON" (no forcing condition has fired),
  but the decision is Q14's to make, not this plan's.
- **The exact frozen-status vocabulary** for `registry-v1.json` (#14 above).
  F4 owns it.
