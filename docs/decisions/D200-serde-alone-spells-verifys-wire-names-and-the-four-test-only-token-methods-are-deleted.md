# D200 — **serde alone spells `verify`'s wire names**: the four test-only `token()` methods are **deleted**, every enum on `verify`'s JSON path and in antseal-net's live report family serializes **kebab-case** (variants only, struct fields stay snake_case), and an at-rest format keeps its own **versioned** convention

- **Status: RESOLVED. H6, for `R99`, fared (b): both of its directions survived — delete all
  four, and let serde be the single source — and two of its premises fell.**
  - **H6 — *delete all four test-only `token()`s (D190's precedent) and give antseal-net's
    report types serde kebab-case (`rename_all`) — one house pattern: serde is the single
    source of wire names*.** (b):
    - **"One house pattern" falls as a crate-wide claim.** antseal-net's at-rest receipt enums
      are externally tagged by variant name under a **versioned format rule**: the module doc
      (`crates/antseal-net/src/receipt.rs:27-28`) and `RECEIPT_JOURNAL_VERSION`
      (`:205-210`, *"Bump on any reshaping of the receipt/quote types or their serde
      attributes"*). Kebab-casing them is a journal-format change, not `R99`. The ruled
      pattern covers `verify`'s JSON path and antseal-net's live report family (§2 R2).
    - **"Give the report types kebab-case" falls as literally worded.** `rename_all` on the
      five live **structs** would respell their fields (`expected_len`, `not_found`,
      `fetch_error` → `expected-len`, …) against every CLI key (`exit_code`, `failure_class`,
      `fetch_failed`). Only the four live **enums** take it.
    - **What survived is stronger than its precedent.** Deleting the four loses no check: no
      test asserts `serde == token`, none ties a token to an R18 row (§1.2), and D64's L2 is
      held by the wildcard-free renderers, not by `token()` (§1.3).
  - **Found with it:** D137 §12 (D137:950-954) recommended **adding** a `token()` to
    `ReceiptEchoOutcome`, as *"a separate small row"* that was never minted. This record
    answers it in the opposite direction (§2 R4).
- **Date: 2026-10-19**
- Owner row: **`R99`** (§2 R1–R4).
- Related:
  - **D190** §2 R2 (`FetchFailureClass::token()` deleted under `R91`'s Accept clause 2, the
    rule this record extends to the family) and §4 (its `R99` bullet, answered here); D190
    takes a dated addendum;
  - **D137** §12 (D137:950-954), which takes a dated addendum;
  - **D64** L2 (D64:407-409: *"every §6.2 outcome class has an R18 row; a new class without
    one fails"*);
  - **D65** (no `--json` key or value moves);
  - **`R91`** (Accept clause 2: a public method *"either has a production caller or does not
    exist"*), **`R79`**, **`R89`**, **`U32`**.

## 0. What was measured against

`HEAD` `07a170c` (= `origin/main`). The tree was clean when planning began.

Planning lane P3 (wave 39, 2026-10-19) worked read-only and built nothing; every claim below
comes from reading code, tests and records.

Before this record was written, the records lane re-read the load-bearing lines through
`git show 07a170c:<path>`, because round-1 lanes were already editing the shared tree. Every
figure held, with one correction and three locator refinements:
- **the correction**: P3's example of struct fields that a struct-level `rename_all` would
  respell lists `first_diff_offset`, which is a field of `PersistenceOutcome::Different`, an
  enum's struct variant, so no struct-level attribute reaches it. The measured struct fields
  are `BlobPersistence`'s `expected_len` and `PersistenceSummary`'s `not_found` and
  `fetch_error`; the argument stands on them;
- the at-rest convention P3 cited as `receipt.rs:24-28` and `:203-207` is the module doc's
  enum clause at `:27-28` and `RECEIPT_JOURNAL_VERSION`'s doc and constant at `:205-210`;
- `R99`'s own locator for `LiveBlobOutcome::token()` (`tasks/R.md:1275`, `:346`) is stale: the
  method is `orchestration.rs:350` (P3 found this too);
- D137's note is `:950-954` (P3 and the rulings wrote `:950-953`).

## 1. What was measured

### 1.1 The four methods, and every caller

- `git grep -n -E 'fn token\(' -- 'crates/*.rs'` at `07a170c` finds the four class methods,
  each `pub const fn token(&self) -> &'static str` with a wildcard-free match:
  `LiveBlobOutcome` (`crates/antseal-core/src/verify/orchestration.rs:350`, its `impl` at
  `:339`), `HeadlineImpact` (`crates/antseal-core/src/verify/overlay.rs:384`, `impl` at
  `:365`), `OverlayOutcomeClass` (`:466`, `impl` at `:463`) and `AggregateDelta` (`:579`,
  `impl` at `:576`). The other three hits (`anchor/model.rs:208`, `anchor/chain.rs:1130`,
  `bundle/schema.rs:664`) are RFC 3161 token-byte accessors, out of scope.
- **Every caller is a test.** `git grep -n -E '\.token\(\)|::token\b' -- crates verifier-web`,
  less the token-byte accessors: `crates/antseal-core/src/verify/overlay/tests.rs:261`,
  `:349`, `:891`, `:930` and `:975`, and `crates/antseal-core/tests/r89_live_outcome_json.rs:133`
  and `:140` (inside `the_outcome_token_is_unchanged_by_the_payload`). None in
  `crates/antseal-wasm`, `verifier-web` or `crates/antseal-cli/src`.

### 1.2 What the tests assert with them

- **Closed-set literal pins.** `overlay/tests.rs:889-905` maps the class exemplars through
  `OverlayOutcomeClass::token` and compares them with a literal list, failing with *"D64 §6.2's
  closed class tokens moved; write the new one down here and give it a line"*; `:930-931`
  does the same for `HeadlineImpact` (`["supplies", "stands", "still-unanchored"]`); `:975`
  pins `"divergence-newly-flagged"`.
- **Two serde samples only** (`:977-982`: `"stands"`, and a value starting `{"refuted":`).
- **No `serde == token` equivalence, and no tie to the frozen wording.** P3: for each of the 11
  tokens, `command grep -c '"<tok>"'` over `wording.rs` and `verdict_wording.rs` → 0; the frozen
  snapshot holds prose (*"…the offline headline above stands…"*), not tokens.

### 1.3 Where D64's L2 actually lives

- L2 is *"every §6.2 outcome class has an R18 row; a new class without one fails"*
  (D64:407-409).
- It is held by the wildcard-free renderers: `headline_impact_line` (`overlay.rs:769`),
  `anchor_outcome_line` (`:856-858`, doc *"L2: every class renders"*) and `LiveSection::new`
  (`orchestration.rs:796-845`). The `token()` docs claim the L2 discipline for themselves
  (`overlay.rs:464`, `:577`), but they are a second exhaustive match, not the one that renders.
- `AggregateDelta::token()` is that type's only exhaustive match, but the type has one variant,
  built together with its line at its one construction site (`overlay.rs:745`), so a new
  variant cannot exist without a new line.

### 1.4 The house pattern, measured in both crates

- **Core.** `rename_all = "kebab-case"` sits on **every** `Serialize` enum under
  `crates/antseal-core/src/verify/`: 14 of 14 at `07a170c` (`git grep -n 'serde(rename_all =
  "kebab-case")' -- crates/antseal-core/src/verify` → 14 lines; an independent count of
  `Serialize`-deriving `pub enum`s in the same tree → 14). It sits on **no** struct: struct
  fields stay snake_case (`exit_code`, `fetch_failed`, `headline_impact_line`), and
  `rename_all` renames variants only, so a struct variant's fields (`time_unix`, `class`) stay
  snake_case too.
- **antseal-net.** No serde naming attribute anywhere: `git grep -n -E
  'serde\((tag|rename_all|untagged)' -- crates/antseal-net crates/antseal-cli/src` → 0 lines;
  positive control, the same pathspec with `serde\(` finds `#[serde(with = "tx_map_pairs")]`
  at `crates/antseal-net/src/receipt.rs:175`.
- **The live report family is four enums inside five structs.** `PersistenceOutcome`
  (`crates/antseal-net/src/live.rs:190-191`), `UnitKindTag`
  (`crates/antseal-net/src/live/manifest.rs:88-89`), `LiveSubject` (`:106-107`) and
  `LiveVerdict` (`:251-252`), inside `BlobPersistence`, `PersistenceSummary`,
  `PersistenceReport`, `LiveCheckRow` and `LiveCheckReport`.
- **The crate's PascalCase is a recorded convention for the at-rest journal, and the live
  types borrow it.** `receipt.rs:24-30` describes the journaled envelope (*"enums are
  externally tagged by variant name"*, `:27-28`), versioned by `RECEIPT_JOURNAL_VERSION`
  (`:205-210`). `live.rs:188-189` cites it: *"Serialized externally tagged (serde default,
  matching the house convention recorded on the receipt envelope)."*
- **Nothing ships the live types' serde output.** Every serializer call is a test:
  `live.rs:673` and `:685` (inside `#[cfg(test)] mod tests`, `:416`), `live/manifest.rs:816`
  (inside `#[cfg(test)]`, `:474`), and the integration test `live_display_channel.rs:401`. The
  CLI projects `LiveCheckReport` into core's `LiveInputs`, and `--json`'s `live` member is
  core's `LiveSection::to_canonical_json()` (`crates/antseal-cli/src/verify_out.rs:222-223`).
  No fixture, snapshot or `--json` shape carries an antseal-net spelling (P3: `git grep -c -E
  'AllPersisted|FetchError|RawMirror|SomeMissing|"Identical"'` over the snapshots,
  `verifier-web` and `crates/antseal-wasm` → no match; positive control `"live":null` at
  `json-envelopes.txt:44`).
- **Two tests pin the PascalCase today and move with the casing**: `live.rs:681-683`
  (`json.contains("Identical") && json.contains("Different")`, `json.contains("NotFound")`)
  and `live/manifest.rs:819-820` (`json.contains("AllPersisted")`,
  `json.contains("RawMirror")`).

### 1.5 The one consumer reads serde, not `token()`

`verifier-web/index.template.html:744-754` derives a token from the serde shape — *"An
externally-tagged serde enum: a unit variant is its name, a struct variant is a one-key
object"* — and feeds `IMPACT_CLASS` (`"supplies"`) and `OUTCOME_CLASS` (`"promoted"`,
`"refuted"`) (`:758-762`), which select CSS classes with a fallback. Nothing pins those three
page keys to the Rust spellings (`git grep -n -E 'IMPACT_CLASS|OUTCOME_CLASS'` → the template
only). P3 recorded that, and refused a checker for it: measured drift 0 of 3, consequence
cosmetic.

### 1.6 A prior record leaned the other way

D137 §12 (D137:950-954): *"`ReceiptEchoOutcome` has no `token()` method, unlike
`OverlayOutcomeClass` and `AggregateDelta`, which both carry wildcard-free ones (L2). It relies
on `rename_all` alone, so its tokens are un-greppable and un-asserted. R3 is the moment to
notice this; adding the method is a separate small row."* That row was never minted (P3:
`git grep ReceiptEchoOutcome -- TODO.md tasks` → `R85`'s prose only). `ReceiptEchoOutcome`
(`overlay.rs:497-499`) derives `Serialize` with `rename_all = "kebab-case"` and has no
`token()`: it already has the shape this record rules.

## 2. RULING

### §2 R1 — The four `token()` methods are deleted

Delete `LiveBlobOutcome::token()`, `HeadlineImpact::token()`, `OverlayOutcomeClass::token()`
and `AggregateDelta::token()`. An `impl` block left empty goes with its method
(`OverlayOutcomeClass`'s and `AggregateDelta`'s); `impl LiveBlobOutcome` keeps `is_identical`
and `impl HeadlineImpact` keeps `classify`.

The tests move to **serde-tag sweeps**: a unit variant serializes to its string, a struct
variant to a one-key object whose key is the tag — the page's own rule (§1.5). They keep the
literal lists and the *"write the new one down here and give it a line"* message, and fold in
the two serde samples. `overlay/tests.rs:261` and `:349` become
`matches!(…, OverlayOutcomeClass::Promoted { .. })`.
`r89_live_outcome_json.rs`'s `the_outcome_token_is_unchanged_by_the_payload` is deleted or
becomes an outer-tag assertion; `every_live_outcome_serializes_to_its_pinned_shape` already
pins both `fetch-failed` shapes.

*Why:* D190 §2 R2's rule, from `R91`'s Accept clause 2 — a public method either has a
production caller or does not exist — and none of the four has one (§1.1). The one consumer of
these spellings reads serde (§1.5), so a `token()` is a second spelling path nobody reads.
Deleting it loses no check (§1.2, §1.3).

Refused: keeping the four as public API with a `serde == token` assertion each. That is four
test-only `pub fn`s and four equivalence tests to maintain a path no consumer uses — what
D190 §2 R2 refused for the fifth.

### §2 R2 — The house pattern, and where it stops

- **Every enum on `verify`'s JSON path, and every enum in antseal-net's live report family,
  serializes `#[serde(rename_all = "kebab-case")]`.** It renames variants only; struct fields
  stay snake_case.
- **At-rest formats keep their own versioned convention.** The receipt journal's
  variant-name tagging (`receipt.rs:27-28`) is a format rule whose change needs a
  `RECEIPT_JOURNAL_VERSION` bump (`:205-210`). That is not this row.
- So `PersistenceOutcome`, `UnitKindTag`, `LiveSubject` and `LiveVerdict` take kebab-case; the
  five structs do not; and `live.rs:188-189`'s sentence, which cites the receipt envelope's
  convention, is rewritten to cite this one.

The wire after: `{"FetchError":{"class":"transport"}}` becomes
`{"fetch-error":{"class":"transport"}}`; `AllPersisted` becomes `all-persisted`, now equal to
core's `LiveLayerVerdict` spelling; `{"Unit":{"unit_id":0,"kind":"RawMirror"}}` becomes
`{"unit":{"unit_id":0,"kind":"raw-mirror"}}`; `EncryptedManifest` becomes
`encrypted-manifest`.

*Why:* `R99`'s Notes ask for the casing to be ruled *"before any of them gains a machine
consumer"*, and nothing can detect that moment, so it is ruled now, while no consumer exists
(§1.4). The family then speaks the spelling the core already speaks. The at-rest boundary is
drawn where a version number already governs the bytes.

Recorded, not fixed: antseal-net says `fetch-error` and `fetch_error` where core says
`fetch-failed` and `fetch_failed`. The variant and field names differ across the crates;
renaming one is not a casing question.

### §2 R3 — One absence assertion, and no broader checker

`R99`'s Accept allows *"asserted per type or by absence"*. One test `include_str!`s
`src/verify/orchestration.rs` and `src/verify/overlay.rs` and asserts that `pub const fn
token(` occurs 0 times in each. Its measured yield is 4 → 0, with one historical recurrence
(`FetchFailureClass`, removed by D190).

Refused, with its counts: a checker that every `Serialize` enum carries `rename_all`. Its
yield in core is 0 of 14 today, and its only past offender (`R91`) is now pinned per type by
`r89_live_outcome_json`. antseal-net's four are pinned per type by the two edited round-trip
tests (§3).

### §2 R4 — D137's note is answered, and D190's rule reaches the family

- **D137 §12** (D137:950-954) recommended adding a `token()` to `ReceiptEchoOutcome` as *"a
  separate small row"*, never minted. This record answers it in the opposite direction: serde
  is the single source, and `ReceiptEchoOutcome` already has the ruled shape (§1.6). D137
  takes a dated addendum.
- **D190** takes a dated addendum: §2 R2's rule now covers the whole family, and §4's `R99`
  bullet is answered.

No `U32`-frozen surface moves: no `--json` key or value (the antseal-net types reach no
envelope, and core's spellings are unchanged — deletion only), no snapshot, exit code, help
text or config key.

## 3. Fault plants

The implementing lane owes these. Green baselines come first; each plant is judged by its
message, and every restore is followed by a `touch`.

**Green — the load-bearing half.**
- The rewritten `overlay/tests.rs` class, impact and delta sweeps: the serde tags equal the
  literal lists.
- `r89_live_outcome_json`'s `every_live_outcome_serializes_to_its_pinned_shape` (`fn` at
  `:58`) and `the_storage_and_online_failure_classes_share_one_wire_spelling` (`:158`), plus
  the absence assertion (§2 R3).
- `live.rs`'s `the_report_round_trips_through_serde_and_carries_no_blob_bytes` (`:658`) with
  kebab needles (`"identical"`, `"different"`, `"not-found"`), and its namesake in
  `live/manifest.rs` (`:807`) with `"all-persisted"` and `"raw-mirror"`.
- Unchanged: `live_display_channel`'s
  `the_serialized_outcome_carries_a_token_and_not_the_backend_string` (`:385`, needle
  `"class":"transport"`); `verdict_wording`'s snapshot, byte-identical because no label moves;
  the wasm32 check of `antseal-core`.

**Red — each watched red by its message.**

| Plant | Must redden |
|---|---|
| P1: drop `rename_all` from `OverlayOutcomeClass` | the class sweep (*"D64 §6.2's closed class tokens moved…"*, values `Promoted`…) |
| P2: drop it from `PersistenceOutcome` | `live.rs`'s round-trip test, on `"identical"` |
| P3: drop it from `LiveVerdict` | `live/manifest.rs`'s round-trip test, on `"all-persisted"` |
| P4: re-add a `pub const fn token` to `AggregateDelta` | the absence assertion |

A plant that re-adds a method **and** a caller is a compile check, not a message check, and is
not one of these.

Venue, in-process only: `cargo test -p antseal-core --lib verify::overlay`,
`cargo test -p antseal-core --test r89_live_outcome_json`, `cargo test -p antseal-net --lib
live` and `--test live_display_channel`, and `cargo check -p antseal-core --target
wasm32-unknown-unknown`. The edit touches no storage or payment code and not `commands.rs`
(P3), but `crates/antseal-net/` is on `scripts/gate-features.sh`'s `HEAVY_TRIGGER_PATHS`
(`:112-121`), so the heavy tier runs for it automatically, and `scripts/local-gate.sh:714-720`
calls that list the same storage-touching list the D52 devnet E2E gate uses. P3's *"(j) no"*
was a reading of the code, not of the trigger list. This wave's close gate forces both tiers
for other rows anyway.

## 4. What this record does NOT decide

- **The receipt journal's casing.** It is an at-rest format with its own version (§2 R2).
  Changing it would be a `RECEIPT_JOURNAL_VERSION` event argued on its own.
- **The cross-crate variant names** (`fetch-error` against `fetch-failed`). Recorded as a
  residual (§2 R2), not ruled.
- **A pin between the page's three CSS keys and the Rust spellings.** Refused by P3 on its
  measured yield (§1.5); this record names the page as the spellings' one consumer and does
  not reopen the refusal.
- **Whether antseal-net's live types keep `Serialize`/`Deserialize` at all.** They stay:
  removing them is public-API churn, it removes the subject of `R79`'s serialized
  hostile-string check (`live_display_channel.rs:385`), and D190 §6 kept
  `FetchFailureClass`'s `Deserialize` for these round trips.
- Every build and test duration: the planning lane built nothing.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-VOCAB2 (round 1)

- `crates/antseal-core/src/verify/orchestration.rs` — delete `LiveBlobOutcome::token()`
  (§2 R1).
- `crates/antseal-core/src/verify/overlay.rs` and `crates/antseal-core/src/verify/overlay/tests.rs`
  — delete the three methods and their emptied `impl` blocks; the serde-tag sweeps (§2 R1).
- `crates/antseal-core/tests/r89_live_outcome_json.rs` — the deleted or rewritten test, and the
  absence assertion (§2 R1, R3).
- `crates/antseal-net/src/live.rs` and `crates/antseal-net/src/live/manifest.rs` — `rename_all`
  on the four enums, the doc at `~:188-189`, and the test needles (§2 R2).
- Not touched: `receipt.rs` and `quote.rs` (at rest), every snapshot, the page, the wasm crate.

### Orchestrator — `TODO.md`, `tasks/R.md`, `docs/decisions/README.md`

- `R99` is ticked when the lane's greens and plants are in its report; the index row and the
  register row.

### RECORDS-C — dated addenda

D137 §12, and D190 (one addendum, shared with D199's answer to its §4 `R98` bullet) (§2 R4).

## 6. As built — wave 39, lane L-VOCAB2 (recorded in place before this record was first committed)

This was the lane's round 1. Every verdict below was read from an exit file, per the lane's
report, and every red was judged by its message. Plants ran in a shadow (`HEAD` plus the lane's
files, parity re-verified before each batch) with a private target. Each was restored by a fresh
write and verified by sha256.

- **§2 R1 (`R99`).** The four methods are deleted. `fn token(` now occurs 0 times in
  `crates/antseal-core/src/verify/orchestration.rs` and in `overlay.rs`, against 1 and 3 at
  `HEAD`. `impl LiveBlobOutcome` keeps `is_identical` and `impl HeadlineImpact` keeps `classify`.
  The emptied `impl` blocks of `OverlayOutcomeClass` and `AggregateDelta` are gone. Per the
  lane's report, no caller remains anywhere.
  - The tests read serde through a new helper, `serde_tag` (`overlay/tests.rs:871`). A unit
    variant gives its string, and a struct variant its one key. The two `"promoted"` asserts are
    now `matches!(…, OverlayOutcomeClass::Promoted { .. })` (`:264`, `:359`).
  - `every_overlay_class_has_a_spelled_token_and_a_distinct_rendered_line` (`:890`) keeps its
    name, because `TODO.md` cites it. It also keeps its literal lists and the *"write the new one
    down here and give it a line"* message.
  - `LiveBlobOutcome`'s rustdoc gains *"The machine spelling is serde's and nothing else's (D200,
    R99)"* (`orchestration.rs:308`).
  - **Deviation (one the ruling allowed):** `the_outcome_token_is_unchanged_by_the_payload`
    (`crates/antseal-core/tests/r89_live_outcome_json.rs:132`) was rewritten, not deleted. It
    keeps its name and becomes an outer-tag assertion: `ALL.len() == 2` first, then every
    `FetchFailed` is a one-key object keyed `"fetch-failed"`.
  - **Deviation: two more pins.** The sweep also pins the four `NotPromotedReason` tags and the
    four `ReceiptEchoOutcome` tags. The test's own rustdoc already claimed both, and D137 had
    called the echo tokens *"un-greppable and un-asserted"*.
  - **Deviation: a compile-time stop restored.** `AggregateDelta::token()` was that enum's only
    exhaustive match, so deleting it removed the "a new delta fails until it is named" stop. The
    irrefutable `let AggregateDelta::DivergenceNewlyFlagged { .. } = &delta;`
    (`overlay/tests.rs:1039`) puts that stop back at compile time.
- **§2 R2.** `#[serde(rename_all = "kebab-case")]` is on the four live enums:
  - `PersistenceOutcome` (`crates/antseal-net/src/live.rs:196`);
  - `UnitKindTag`, `LiveSubject` and `LiveVerdict` (`live/manifest.rs:89`, `:108`, `:254`).

  No struct carries it. The doc sentence (`live.rs:188-194`) now cites this house pattern, and
  names the receipt journal's tagging as *"an at-rest format rule versioned by
  `RECEIPT_JOURNAL_VERSION`, not this one"*. `receipt.rs` was not touched.
  - Both round-trip tests' needles now sit in value position (`"outcome":"identical"`,
    `"verdict":"all-persisted"`, `"kind":"raw-mirror"`, …), so no field name can satisfy them.
  - **Deviation: each type is pinned on its own.** `UnitKindTag` is pinned on both values, and
    `LiveSubject` on both variants, `"encrypted-manifest"` directly.
  - The wire after is the ruled one. Per the lane's report, no production serializer, snapshot
    or fixture carries these types, and a `git grep` for the PascalCase spellings finds only
    `Debug` counts and error labels. No `U32`-frozen surface moves.
  - **The Accept's census, per the lane's report.** All 14 `Serialize` enums under
    `crates/antseal-core/src/verify/` carry kebab-case `rename_all`, and so do the 4 live
    enums.
- **§2 R3.** The absence assertion is `no_hand_written_token_method_mirrors_a_verify_class_enum`
  (`r89_live_outcome_json.rs:234`). It `include_str!`s both files and asserts:
  - the needle against the deleted methods' own signature (count 1), as a self-check;
  - the operand count (2);
  - a positive control per file;
  - 0 hits, with *"{path} defines a `token()` again: a class enum's wire name has one spelling,
    its serde tag (D200, R99) — delete the method and read the tag in the test instead"*.
  - **Deviation: the needle is `fn token(`,** a superset of the ruled `pub const fn token(`. It
    also catches a non-`const` or crate-private re-introduction. The yield is 4 → 0 under either
    needle.
- **§2 R4.** The records half is RECORDS-C's. D137 and D190 carry their dated addenda.
- **§3, the greens.**
  - Shadow: `antseal-core --lib verify::overlay` 16 passed; `r89_live_outcome_json` 5;
    `antseal-net --lib live` 23, both round-trip tests by name; `live_display_channel` 5.
    `clippy -- -D warnings` exited 0 for `antseal-core` and for `antseal-net`.
  - Shared tree, under the lock protocol: `antseal-core --lib` 1188 passed, with 1 ignored (the
    pre-existing `emit_r30_report_digest_table`); `r89_live_outcome_json` 5; `antseal-net --lib`
    115; `live_display_channel` 5. `cargo check -p antseal-core --target wasm32-unknown-unknown`
    exited 0. rustfmt passed on all six files.
- **Plants: eight. P1–P5, P7 and P8 were red by message, and P6 was a compile stop by design.**
  - P1 drops `rename_all` from `OverlayOutcomeClass`: *"D64 §6.2's closed class tokens moved;
    write the new one down here and give it a line — left: ["Promoted", "Refuted", …]"*.
  - P2 drops it from `PersistenceOutcome`: *"the outcome tag `"outcome":"identical"` is missing —
    outcome variants serialize kebab-case (D200, R99)"*.
  - P3 drops it from `LiveVerdict`: *"the tag `"verdict":"all-persisted"` is missing"*.
  - P4 re-adds `pub const fn token` to `AggregateDelta` with no caller: *"src/verify/overlay.rs
    defines a `token()` again … — left: 1, right: 0"*.
  - P5 drops it from `ReceiptEchoOutcome`: *"the receipt echo's outcome tokens moved; … — left:
    ["Confirmed", "NotOnChain", "Disagreed", "Failed"]"*.
  - P6 adds a second `AggregateDelta` variant. Exactly one error: *"error[E0005]: refutable
    pattern in local binding"* at `overlay/tests.rs:1039`.
  - P7 drops it from `UnitKindTag`: *"the tag `"kind":"normal"` is missing"*. P8 drops it from
    `LiveSubject`: *"the tag `"subject":{"unit":{` is missing"*.
  - Restore: every sha256 equals its pre-plant value, and `git grep --untracked -n W39-PLANT`
    exits 1.
- **Further deviations.**
  - **D195's optional doc line was applied.** In `overlay.rs:146`, `EndpointProbeFailure::endpoint`
    is now *"The endpoint's identity, as the host discloses it (the CLI: its origin)."* The lane
    made it conditional on D195 R2 landing. It did land: `probe_failure` passes
    `disclosed(failure.endpoint())` (`crates/antseal-cli/src/verify_host.rs:450`), so the line is
    true.
  - **Venue.** Clippy ran in the shadow, not under the shared lock. The queued shared batch was
    stopped before it ran. The lane did not run `verdict_wording` in round 1, because its edits
    touch no wording. The round-2 re-bless for D199 then changed exactly one line, D199's
    (`97a98`).
  - **wasm32.** The overlay unit tests were not executed on wasm32. The repository's runner
    refuses a filtered run by design: *"libtest arguments are NOT forwarded on
    wasm32-unknown-unknown … Run the unfiltered suite"*. The wasm32 evidence is the `cargo check`
    above and the compiled wasm32 test binary.
- **The tree, re-read for this section.** Eight of round 1's nine files equal the lane's round-1
  hashes. `orchestration.rs` also carries round 2, and it equals the round-2 final hash.
- **Left open.**
  - **The unfiltered wasm32 run** is the close gate's `wasm32-core-tests` lane.
  - **The cross-crate names stay a residual,** recorded and not fixed, as §2 R2 says:
    antseal-net's `fetch-error` against core's `fetch-failed`.
  - **`L-LOC` owns the moved citations** into `orchestration.rs`, which the lane listed:
    `docs/drills/clean-machine-verify.md`'s `:552-565` and `:902-915`.
  - **Not this record's.** The same round's `U102` work found that `antseal init` replaces an
    existing `config.toml` without a word when no `vault.header` exists. It was minted as `U105`,
    and `U105` owns it.
  - **`R99`'s tick is the orchestrator's (§5).**

## Closing — this record is not consent

It changes code, tests and module documentation in the tree. Nothing in it authorises a push,
a dispatch, a deploy or any other outward act, and its tests open no socket.
