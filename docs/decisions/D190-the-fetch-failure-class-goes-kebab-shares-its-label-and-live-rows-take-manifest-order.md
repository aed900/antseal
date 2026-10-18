# D190 — One wire spelling, one label, one order: `FetchFailureClass` serializes **kebab-case** and loses its test-only `token()`, the two *"transport failure"* labels become **one constant**, and `verify --live`'s rows come in **manifest order with the manifest row last** — all before `U32` freezes tier C

- **Status: RESOLVED. H8's direction survived, on stronger premises than the ones it carried,
  which fell (b). H9, for the one sentence of `U50` this record carries, fell (a), on its
  premise.**
  - **H8 — *kebab on the wire everywhere, delete `token()`, one ruled order (manifest
    order)*.** All three parts survive. What fell is why:
    - *"The two builders order differently and nothing asserts either"* was half false when
      `R90` was minted. `records_from_manifest`'s manifest order and manifest-last have been
      asserted since `R11` (`c37f778`, 2026-08-02; `crates/antseal-net/src/live/manifest.rs:565`,
      `:585`), and it has **no production caller**. Only `collect_live` is on the production
      path, and only its *unit* order is unpinned.
    - Kebab-case is not a house-wide move. `FetchFailureClass` is the **only** `Serialize` enum
      under `crates/antseal-core/src/verify/` without `rename_all = "kebab-case"` (1 of 14), and
      one value mixes casings: `{"fetch-failed":{"class":"Transport"}}`.
    - The planning brief's pre-measured `token()` callers were wrong for two of three.
      `r89_live_outcome_json.rs:109` and `:116` call `LiveBlobOutcome::token()`;
      `FetchFailureClass::token()` has one caller in the workspace,
      `crates/antseal-net/tests/live_display_channel.rs:315`.
    - `R91` Problem (iv)'s mechanism is false though its hole is real. The comment at
      `crates/antseal-core/tests/verdict_wording.rs:738-744` says a needle for *"transport
      failure"* would report the sharing as an offence; the scan it means never reads
      `antseal-core` (§1.2). What is actually missing is any test that compares the two table
      functions.
  - **H9 — *document the `anchors` object in a docs page plus a schema-shaped test*.** It fell
    on its premise. D65 §8.1 refuses a docs page: `machine.rs`'s module doc is the contract's
    home, and `U32` lifts it into release docs. D134 §2 R3 (2) makes tier C stable-additive at
    `U32`, so an exact-key test is the wrong instrument: it reddens on additions exactly as the
    byte snapshot already does. `U50`'s one sentence lands in `machine.rs` (§2 R7). Its
    presence-only instrument is ruled without a record (§4).
- **Date: 2026-10-17**
- Owner rows: **`R90`** (§2 R5); **`R91`** (§2 R1–R4, R6); **`U50`** (§2 R7, the sentence
  only).
- Related:
  - **D65**: §3 tier C (`:457-474`), §6 (`:627-634`) and its rider 1 (`:638-644`), §7
    (`:686-693`), §8.1 (`:700-712`), §9.2 (`:763-772`);
  - **D134** §2 R3 (2) (tier C becomes stable-additive at `U32`);
  - **`R11`** (the second producer's existing witness), **`R79`** (one closed-class discipline
    at both boundaries), **`R89`** (the frozen live sentence and the guard's entry), **`R18`**
    (the frozen wording snapshot), **D64** §3;
  - **`U32`** (the freeze this lands before);
  - minted with this wave's rulings and **not decided here**: **`R98`** and **`R99`** (§4).

## 0. What was measured against

`HEAD` `23f3093` (local `main`; `origin/main` `cfd5868`), tree clean, 2026-10-17.

Planning lane P3 (wave 38) worked read-only and built nothing: every claim it made comes from
reading code, git history and decision records. The availability survey (PS) found both rows
available, every `after` term `[x]` (`R11`, `R81`, `R21` for `R90`; `R89`, `R79`, `R21`, `R11`,
D65, D64 §3 for `R91`), and neither row complete.

Before this record was written, the records lane re-read the load-bearing lines through
`git show 23f3093:<path>`, because round-1 lanes were already editing the tree. Two of P3's
figures moved under that re-read, and the corrected figures are the ones written below:
- P3 and the ruling say *"the only non-kebab of the 8 `Serialize` enums"*. Measured: 9
  `Serialize` enums in `orchestration.rs` and `overlay.rs` (8 kebab-case), and 14 across
  `crates/antseal-core/src/verify/` once `report.rs`'s five are counted (13 kebab-case).
  `FetchFailureClass` is the only exception at both scopes, so the ruling's premise holds and
  only the count changes.
- P3 moved the guard comment from `R91`'s `verdict_wording.rs:738-748` to `:739-745`.
  Measured: the comment is `:738-744` and the entry it explains `:745-748`, so `R91`'s own
  locator was right.

## 1. What was measured

### 1.1 `R91`: the type, the wire and the token

- **The type.** `crates/antseal-core/src/verify/orchestration.rs:262` derives
  `Serialize, Deserialize` with no `rename_all`; `:263` is `pub enum FetchFailureClass`. Its
  doc (`:258-261`) records the choice as inherited, not ruled: *"Serialized with its variant
  names unrenamed (`"Transport"`, `"BackendRefused"`), which is the form `antseal-net`'s
  `PersistenceOutcome` already emitted for it before the move"*.
- **The enclosing value is kebab-case.** `LiveBlobOutcome` carries
  `#[serde(rename_all = "kebab-case")]` (`:304`), so one serialized value mixes casings:
  `{"fetch-failed":{"class":"Transport"}}`.
- **The sibling enums.** Every other `Serialize` enum on the path is kebab-case:
  `LiveBlobOutcome` (`orchestration.rs:304`), `LiveLayerVerdict` (`:723`), and in `overlay.rs`
  `ProbeFailureClass` (`:123`), `HeadlineImpact` (`:343`), `NotPromotedReason` (`:396`),
  `OverlayOutcomeClass` (`:431`), `ReceiptEchoOutcome` (`:498`), `AggregateDelta` (`:562`);
  `report.rs` adds five more, all kebab-case.
- **The declared pair has no `token()`.** `ProbeFailureClass` (`overlay.rs:122-124`) is
  kebab-case and `Serialize` only. `FetchFailureClass` also derives `Deserialize` because
  `antseal-net`'s `PersistenceOutcome`, `BlobPersistence` and `PersistenceReport` round-trip it
  (`crates/antseal-net/src/live.rs:74`, `:190`, `:236-239`, `:251`, `:281`).
- **The token.** `FetchFailureClass::token()` (`orchestration.rs:286`) returns `"transport"`
  and `"backend-refused"` (`:288-289`). Its one caller in the workspace is
  `crates/antseal-net/tests/live_display_channel.rs:315`, inside
  `the_fetch_failure_vocabulary_is_finite_and_static` (`:296`), which asserts only that the
  tokens are pairwise distinct (`:322`). `git grep '\.token()'` over `crates/` finds no `src`
  caller on a `FetchFailureClass`.
- **Nothing consumes the PascalCase form.** The verifier page runs no live check (the live
  section is CLI-only, `overlay.rs:113-116`); no committed envelope carries a live section
  (`crates/antseal-cli/tests/snapshots/json-envelopes.txt:42`, `"live":null,"overlay":null`);
  `antseal-net`'s PascalCase JSON is test round-trips only. Every hop of the sibling vocabulary
  that has a consumer is kebab-case: the page's `"transport"`/`"payload"`/`"wrong-chain"`
  (`verifier-web/index.template.html:583-688`), the wasm binding
  (`crates/antseal-wasm/src/online.rs:174-180`), the overlay, and `seal --json`'s
  `failure_class` (D65 §6 rider 1).
- **What pins the PascalCase wire today.** `crates/antseal-core/tests/r89_live_outcome_json.rs:65-71`
  (the pinned shapes) and `:93-96`, whose positive half asserts that the Debug name appears in
  the JSON — so the move reddens two assertions there by design, and one in
  `live_display_channel.rs:395-398`.

### 1.2 `R91`: the rendered word and the guard

- **Two literals, equal by coincidence.** `crates/antseal-core/src/verify/wording.rs:781`
  (`live_fetch_failure_class_label`, `:779`) and `:896` (`probe_failure_class_label`, `:894`)
  each spell `"transport failure"` in an independent match arm. The live doc already states the
  equality as fact (`:773-774`, *"`Transport`'s word is [`probe_failure_class_label`]'s for the
  same class"*); the probe doc (`:891-893`) says nothing of its sibling.
- **Only one side is frozen.** `crates/antseal-core/tests/snapshots/verdict-wording.txt:101-102`
  carries the live rows, generated by an `ALL` sweep. The probe word is in no snapshot (section
  10 renders `endpoint_failures_line` with an empty failure list,
  `crates/antseal-core/tests/verdict_wording.rs:333-336`); only
  `crates/antseal-core/src/verify/overlay/tests.rs:402`'s `contains("transport failure")`
  would notice a probe-side reword, and only by accident.
- **The guard's comment is false on both counts.** `verdict_wording.rs:738-744` reads: *"Only
  `BackendRefused`'s word joins the table: `Transport`'s is `probe_failure_class_label`'s word
  for the *online* class too, so it is shared by construction and a scan for it would report
  the sharing as an offence."* The two literals are not shared by construction (two arms), and
  the scan (`no_renderer_source_spells_a_frozen_verdict_string`) walks only `SCAN_ROOTS` =
  `crates/antseal-cli/src` and `verifier-web` (`:945`). Both literals live in `antseal-core`.
  P3 emulated the scan: 0 non-comment hits for the phrase over 57 files. A needle could
  therefore be added, and it would still not see the two table functions drift apart.

### 1.3 `R90`: the order each builder emits

- **`collect_live` is the only production builder.** It sits at
  `crates/antseal-cli/src/verify_host.rs:486` (`R90` says `:412`). It emits the bundle's
  covered reveals, then its non-covered reveals (`:511-522`, commented *"Embedded ciphertexts,
  in bundle order — the revealed side."* at `:511`), then the encrypted-manifest record
  (`LiveSubject::EncryptedManifest`, `:578`). The bundle decoder makes each list strictly
  ascending by `unit_id`, so the emitted order is `[covered ↑] ++ [non-covered ↑] ++
  [manifest]`: deterministic per bundle, not ascending overall. `R90`'s measured `unit 0, unit
  2, unit 3, unit 4, unit 1 (raw mirror), unit 5` is consistent with this code (P3 did not
  re-run it).
- **No hop after it sorts.** `live_check` keeps one row per expectation in input order,
  `live_inputs` keeps report order, `LiveInputs::from_rows` keeps supply order, and
  `LiveSection.rows` is *"One row per checked blob, in the order the host supplied them"*
  (`crates/antseal-net/src/live/manifest.rs:332-333`, `:455`;
  `crates/antseal-core/src/verify/orchestration.rs:388-389`, `:776`). So the human rendering
  and `--json`'s `live.rows` are exactly `collect_live`'s order.
- **`records_from_manifest` already conforms and is already asserted.** Its rustdoc promises
  *"work-global manifest order"* with the manifest record appended last
  (`crates/antseal-net/src/live/manifest.rs:163`; the function at `:178`).
  `the_builder_spans_every_file_of_a_multi_file_work` (`:565`) asserts the ids are sorted
  (`:581`, *"unit ids are the manifest-order ordinals"*) and
  `the_encrypted_manifest_record_is_appended_last` (`:585`) the manifest-last half — both since
  `R11` (`c37f778`, 2026-08-02). Outside its own test module its only caller is
  `crates/antseal-cli/tests/e2e_devnet.rs:255`.
- **Manifest order is ascending `unit_id`, by a decode invariant.**
  `crates/antseal-core/src/manifest/body.rs:27-28`: *"each unit's stored `unit_id` must equal
  its work-global manifest-order ordinal (registry §7.5 key 0)"*, enforced by
  `validate_unit_ordinals(&files)?` (`:1165`). One predicate — unit rows strictly ascending by
  `unit_id`, then the manifest row — therefore states the manifest-order promise for both
  builders.
- **What pins `collect_live` today.** Manifest-last only:
  `crates/antseal-cli/tests/verify_live_manifest.rs:237-241` asserts
  `section.rows.last()` is the manifest subject (*"the manifest record is appended after the
  units (collect_live's order)"*). Its unit order is pinned nowhere. The file's
  `linked_bundle` (`:127-133`, `shapes::multi_file()` under `Selection::all(3)`) is the shape on
  which `R90` measured `unit 1` after `unit 4`.

### 1.4 What freezes, and when

- **Tier.** The `live` and `overlay` siblings of `verify --json` are tier C (D65 §3,
  `:457-462`; `crates/antseal-cli/src/machine.rs:111`): *"Keys here may be renamed, removed or
  retyped between M3 and M4 with no version moving."* `ENVELOPE_VERSION` is `1`
  (`machine.rs:203`).
- **After `U32`, a respelling costs a version.** D65 §6 (`:627-634`) makes *"narrowing an
  enum-valued key's spelling set"* breaking, and a respelling narrows. D134 §2 R3 (2) makes tier
  C stable-additive at `U32`. So the respelling is free now and an `ENVELOPE_VERSION` bump after
  the freeze.
- **D65 says nothing about array order.** §7 (`:686-693`) rules only key order (*"Key order is
  NOT promised anywhere in the document except inside the report member"*), and `machine.rs`'s
  tier table (`:107-111`) is silent on arrays. `R90`'s question is genuinely unruled until
  this record.
- **No R18 byte moves under §2.** The labels keep their words; `verdict-wording.txt:101-102`
  stays byte-identical.

### 1.5 `U50`: the null rule's producer

- **The producer couples the three fields.** `seal --json`'s `anchors` member is the `json!`
  literal at `crates/antseal-cli/src/seal_run.rs:237-248` (`null` when no stage ran,
  `:234-236`). Each row's `ok` is `e.succeeded()`, which is `self.failure_class.is_none()`
  (`crates/antseal-cli/src/pipeline/anchors.rs:936-937`), and `from_submission` sets
  `failure_class` and `detail` from the same `failure` (`:984-985`, `:993-994`). So
  `ok ⇔ failure_class == null ⇔ detail == null` holds at the producer, not at the literal.
- **The rule is already ruled, and stated nowhere a reader of the contract looks.** D65 §6
  rider 1 (`:638-644`) and §9.2 (`:763-772`): *"`failure_class` is **always present**, `null`
  when the endpoint succeeded and a kebab-case string otherwise, and that distinction is
  promised at every tier."* `machine.rs`'s tier table covers `seal` only as *"every
  already-shipped command"* and never states this field's rule; no user doc names the key.
- **Its home is `machine.rs`.** D65 §8.1 (`:700-712`): *"`crates/antseal-cli/src/machine.rs`'s
  module doc ... Not a new file under `docs/` ... **U32 lifts it into release docs**"*.

## 2. RULING

### §2 R1 — `FetchFailureClass` serializes kebab-case (`R91` (a))

`FetchFailureClass` gets `#[serde(rename_all = "kebab-case")]`, so its wire values are
`"transport"` and `"backend-refused"`. Its doc at `orchestration.rs:258-261` is rewritten to
record this ruling at the type (`R91` Accept 1).

Reasons: it is the only `Serialize` enum on `verify`'s JSON path without kebab-case (the
ruling's text says *"of the 8"*; measured, §0: 1 of 9 in the two files, 1 of 14 under
`verify/`); one value mixes casings; every hop of the sibling vocabulary that has a consumer is
kebab-case; and nothing consumes the PascalCase form (§1.1). `rename_all` binds `Deserialize`
too, so `antseal-net`'s round trips stay self-consistent.

Refused: recording why the two classes legitimately differ (no measured reason exists; the
only stated one is `antseal-net`'s pre-move house style), and a hand-written `Serialize` that
spells through `token()` (about 40 lines to keep a second spelling path the declared pair does
not have).

### §2 R2 — `FetchFailureClass::token()` is deleted (`R91` (b))

Its one caller, `crates/antseal-net/tests/live_display_channel.rs:315`, is a distinctness
check that the serde sweep replaces. The type then has exactly `ProbeFailureClass`'s shape, the
pair its own doc tells a reader to read together (`orchestration.rs:234-239`).

Refused: keeping it beside kebab serde with a `serde == token` assertion. That leaves a
test-only `pub fn`, which `R91`'s Accept clause 2 (*"either has a production caller or does
not exist"*) forbids as written.

### §2 R3 — The rendered word is required equal, by construction (`R91` (c))

One shared constant (for example `TRANSPORT_FAILURE_LABEL`) is used by both label functions
(`wording.rs:781`, `:896`), a test asserts
`probe_failure_class_label(ProbeFailureClass::Transport) ==
live_fetch_failure_class_label(FetchFailureClass::Transport)`, and the false comment at
`crates/antseal-core/tests/verdict_wording.rs:738-744` (the ruling's text says `:739-745`;
measured, §0) is rewritten to cite this ruling. **Zero rendered bytes move**:
`verdict-wording.txt` stays byte-identical.

Reasons: `wording.rs:773-774` already asserts the equality as fact; `R79` ruled one
closed-class discipline for both boundaries; both words render in the same `verify` output.
With one constant, a reword moves the frozen live row, and a probe-only reword (an arm that
stops using the constant) reddens the equality test. Refused: documenting the equality as a
coincidence at both sites, which leaves the unfrozen probe side free to drift (§1.2).

### §2 R4 — A cross-class wire test

A test asserts that both classes' `Transport` serialize to `"transport"`. It is the second
producer for `R91`'s casing Accept: `r89_live_outcome_json.rs`'s pinned shapes cover
`FetchFailureClass`, and this test is the half that reddens if `ProbeFailureClass` alone
changes.

### §2 R5 — `verify --live`'s rows: manifest order, the manifest row last (`R90`)

`live.rows` come in work-global manifest order — ascending `unit_id`, which is a decode
invariant (`manifest/body.rs:27-28`) — with the encrypted-manifest row **last**. The sort lives
in `collect_live` (`verify_host.rs:486`; the comment at `:511` is rewritten). The order is
stated **once**, in `machine.rs`'s module doc (D65 §8.1's home), as a tier-C statement. It is
asserted:
- at `collect_live` by a **new** in-process test that asserts the row count first, then
  strictly ascending unit subjects, then the manifest row last, on `linked_bundle` /
  `shapes::multi_file()`, where `R90` measured `unit 1` after `unit 4`;
- at `records_from_manifest` by the **existing** `R11` tests (`live/manifest.rs:565`, `:585`),
  against the same predicate, not against each other (`R90` Accept).

Reasons: this is the order the doc already promises and every other rendering of units uses.
The bundle's reveal order is unbuildable for one producer (`records_from_manifest` is
manifest-shaped and has no covered/non-covered split to order by). Declaring the array
unordered fails `R90`'s Accept 1 (*"One order is stated ... both ... asserted against it"*) and
leaves the human rendering in an order no document names.

### §2 R6 — `ENVELOPE_VERSION` stays `1`; `REPORT_VERSION` is unmoved

Both member changes are tier C before `U32` (D65 §3). After `U32` the respelling would be D65
§6-breaking and the order would freeze unruled, which is why this lands now. The report member
is untouched, so `REPORT_VERSION` does not move.

### §2 R7 — `machine.rs` states `U50`'s rule for `seal --json`'s `anchors`

The same module-doc edit carries one sentence: in `seal --json`'s `anchors` member,
`failure_class` is always present, `null` exactly when the endpoint row is `ok`, and a
kebab-case string otherwise (D65 §6 rider 1). Reason: D65 §9.2 already rules the content and
§8.1 names the home; `machine.rs` states the null rule generically and never this field's
(§1.5).

## 3. Fault plants

The implementing lane owes these. Green baselines come first; each plant is judged by its
message, and every restore is followed by a `touch`.

**Green — the load-bearing half.**
- `r89_live_outcome_json::every_live_outcome_serializes_to_its_pinned_shape` (`:41`), with its
  pinned shapes moved to `"transport"` and `"backend-refused"` (`:65-71`), and
  `the_machine_member_carries_no_display_word` (`:83`), whose positive half asserts the kebab
  literal rather than the Debug name (`:93-96`).
- The new label-equality test (§2 R3) and the new cross-class wire test (§2 R4).
- The new `collect_live` order test (§2 R5): row count first, then strictly ascending unit
  subjects, then the manifest row last.
- The existing `R11` tests, unchanged: `live/manifest.rs`'s
  `the_builder_spans_every_file_of_a_multi_file_work` (`:565`) and
  `the_encrypted_manifest_record_is_appended_last` (`:585`).
- `verify_live_manifest.rs`'s manifest-last assertion (`:237-241`).
- `live_display_channel::the_serialized_outcome_carries_a_token_and_not_the_backend_string`
  (`:378`), whose `contains("Transport")` (`:395-398`) becomes `contains("\"transport\"")` —
  after which its name is literally true.
- `verdict_wording::the_wording_document_matches_the_committed_snapshot` (`:446`) and
  `every_single_sourced_needle_occurs_in_the_rendered_set` (`:850`): no byte moves, which is
  the anti-plant for *"a label changed"*.
- The `wasm32-unknown-unknown` build of `antseal-core` stays green (an attribute and a deleted
  function cannot break it; the checklist demands the build anyway).

**Red — each watched red by its message.**
- **P1.** Delete `FetchFailureClass`'s `rename_all`. Expect red in the pinned-shape test: *"the
  fetch-failure member's machine shape moved"*.
- **P2.** Set `ProbeFailureClass`'s `rename_all` to `"PascalCase"`, or drop it. Expect red in
  the cross-class wire test. P1 and P2 are the *"each producer"* plants for the casing.
- **P3.** Make the probe arm stop using the shared constant and spell `"transport error"`.
  Expect red in the label-equality test. Today nothing reddens on this plant except
  `overlay/tests.rs:402`'s `contains("transport failure")`, by accident.
- **P4.** Revert `collect_live`'s sort. Expect red in the new order test, naming the
  out-of-order subject (`unit 1` after `unit 4` on `linked_bundle`).
- **P5.** Reorder `records_from_manifest` (for example, reverse the files). Expect red at
  `live/manifest.rs:581`: *"unit ids are the manifest-order ordinals"*. P4 and P5 are the
  *"each producer"* plants for the order.
- **P6.** Move the manifest record first in `collect_live`. Expect red at
  `verify_live_manifest.rs:237-241`: *"the manifest record is appended after the units
  (collect_live's order)"*.

**`U50`'s sentence (§2 R7)** is documentation: no checker reads `machine.rs`'s module doc for
it, so its evidence is the sentence grepped back by text into the row, never a lint verdict.

Build venue: every test above runs in-process (`cargo test -p antseal-core --test
r89_live_outcome_json --test verdict_wording`, `cargo test -p antseal-net --test
live_display_channel` and `--lib live::manifest`, `cargo test -p antseal-cli --test
verify_live_manifest`). No spawned binary is needed.

## 4. What this record does NOT decide

- **`R98`** (minted with this wave's rulings; after `R91`, with `U96`, before `U32`; **not
  this wave**). `verify --live` reports a storage client antseal refused to start as
  *"transport failure"* and never names the refusal. The storage-gate, environment and
  peer-locality refusals arrive as `StorageError::Network`, which
  `crates/antseal-net/src/live.rs:168` classifies as `FetchFailureClass::Transport`, so every
  row reads *"unit N: fetch failed (transport failure) — nothing established either way"*
  beside an Inconclusive line, and the handler never consults the degraded state
  (`crates/antseal-cli/src/commands.rs:1040-1053`). D191's prefix edit cannot reach it. Whether
  the fix is a third closed class (additive under D65 §6 rider 2) or a section-level line is
  not ruled.
- **`R99`** (minted; after `R91`; **not this wave**). Four `pub const fn token()` remain with
  no production caller once §2 R2 lands: `LiveBlobOutcome` (`orchestration.rs:346`),
  `HeadlineImpact` (`overlay.rs:384`), `OverlayOutcomeClass` (`:466`) and `AggregateDelta`
  (`:579`). The house pattern — keep each as public API with a `serde == token` assertion, or
  delete all four — is ruled there, so §2 R2's deletion is not read as an inconsistency.
- **`U50`'s instrument.** The presence-only helper over the real producer (`L-CFG`, in
  `crates/antseal-cli/tests/anchor_stage.rs`, over the three in-process runs at `:242`, `:377`
  and `:485`) and the pins for the three `failure_class` spellings no test pins
  (`no-pending-attestation`, `indeterminate-commitment`, `not-granted`; `L-ANCHOR`) are ruled
  without a record. This record carries only the sentence (§2 R7).
- **Array order anywhere else in `--json`.** Only `live.rows` is ruled here; D65 stays silent
  on array order elsewhere.
- **Whether the probe word joins the frozen snapshot.** §2 R3 makes a one-sided drift a red
  test; the probe word itself stays unfrozen.
- **Whether `single_sourced()` gains a *"transport failure"* needle.** It could today with zero
  offenders (§1.2); this record rules only that the comment stops giving a false reason.
- **Whether `records_from_manifest` gets a production caller.** It keeps its witness role.
- Every build and test duration: the planning lane built nothing.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-VOCAB (round 1) — §2 R1–R7

- `crates/antseal-core/src/verify/orchestration.rs` — §2 R1 (the attribute on `:262`, the doc
  at `:258-261`) and §2 R2 (delete `token()`, `:284-291`).
- `crates/antseal-core/src/verify/wording.rs` — §2 R3: the shared constant at `:781` and
  `:896`, and doc sentences citing this ruling at both definition sites (`:773-777`,
  `:891-892`).
- `crates/antseal-core/tests/r89_live_outcome_json.rs` — the pinned shapes (`:65-71`), the
  positive half (`:93-96`), the module doc's quoted wire form (`:14-18`); §2 R4's test may live
  here or in `verdict_wording.rs`.
- `crates/antseal-core/tests/verdict_wording.rs` — the comment at `:738-744` and §2 R3's
  equality test.
- `crates/antseal-net/tests/live_display_channel.rs` — the token half of `:305-322` dropped or
  re-expressed as serde-spelling distinctness; `:395-398` asserts the kebab literal.
- `crates/antseal-net/src/live/manifest.rs` — rustdoc and test-message wording only (its order
  doc may cite this record's one home).
- `crates/antseal-cli/src/verify_host.rs` — **only `collect_live`** (`~:480-530`): the sort and
  the comment at `:511`. `endpoints_from_config` and `parse_pair` belong to `L-CFG` (D188).
- `crates/antseal-cli/tests/verify_live_manifest.rs` — §2 R5's new order test, reusing the
  file's own `linked_bundle`, preload and live-run helpers.
- `crates/antseal-cli/src/machine.rs` — **only the `//!` module-doc lines** (`~:95-160`): §2
  R5's order sentence and §2 R7's sentence. The code in that file is `L-ERR1`'s (D185).
- Not touched: `overlay.rs` (`ProbeFailureClass` is unchanged), the verifier page, the wasm
  crate, every snapshot.

### L-CFG and L-ANCHOR — `U50`'s instrument (ruled without a record)

Listed so that `U50`'s tick waits on all three parts: `L-CFG`'s helper in
`tests/anchor_stage.rs`, `L-ANCHOR`'s three spelling pins, and §2 R7's sentence.

### Orchestrator — `TODO.md`, `tasks/R.md`, `tasks/U.md`, `docs/decisions/README.md`, the ledger

- `R90` and `R91`: ticked per this record. `R90`'s locator moves (`collect_live` `:412` →
  `verify_host.rs:486`); `R91`'s `verdict_wording.rs:738-748` stands (§0).
- `U50`: ticked when all three parts have landed.
- `R98` and `R99`: the ids are minted by this wave's rulings; their register rows (open,
  `TODO.md` and `tasks/R.md`) are the orchestrator's to write. At `23f3093` neither id has a
  row (`grep -ow` over `TODO.md` and `tasks/` returns 0 for each).
- The index row and the register row.

## 6. As built — wave 38, lane L-VOCAB (recorded in place before this record was first committed)

Every verdict below was read from an exit file. All plants ran in a copy of the tree (`git archive HEAD`
plus exactly this lane's eleven files, checked by `diff -rq`), built into a private target directory
without the tree lock; the tree itself never held a fault. The lane's request for the exclusive tree lock
had timed out behind another lane's long shared hold (`docs/instrument-ledger.md`).

- **§2 R1, R2 (`R91`).** `FetchFailureClass` carries `#[serde(rename_all = "kebab-case")]`
  (`orchestration.rs:275`), and its `token()` is deleted. The type's doc records the ruling and
  the old mixed-casing value. The pinned shapes are now `{"fetch-failed":{"class":"transport"}}`
  and `{"fetch-failed":{"class":"backend-refused"}}`.
- **§2 R3.** A module-private `const TRANSPORT_FAILURE_LABEL: &str = "transport failure"`
  (`wording.rs:772`) serves both `Transport` arms (`:797`, `:919`).
  `verdict_wording.rs`'s false exclusion comment is rewritten to cite this record.
  New test `the_live_and_online_transport_labels_are_one_word`. The frozen
  `verdict-wording.txt` is byte-identical (`git diff --quiet`, exit 0).
- **§2 R4.** New test `r89_live_outcome_json::the_storage_and_online_failure_classes_share_one_wire_spelling`.
  It pins each class's `Transport` to the literal `"transport"`, not to the other class, and
  sweeps all five variants of both classes for kebab shape.
- **§2 R5 (`R90`).** `collect_live` sorts the embedded units by `unit_id` (`verify_host.rs:556`),
  and the manifest row is still pushed last.
  - New test `collect_live_emits_the_unit_rows_in_manifest_order_and_the_manifest_row_last`. It
    first asserts its own premise, that the fixture's bundle order is not ascending.
  - Against the old code it failed by message: *"unit 4 precedes unit 1 in ["unit 0", "unit 2",
    "unit 3", "unit 4", "unit 1 (raw mirror)", "unit 5", "encrypted manifest"]"*.
- **§2 R6.** `ENVELOPE_VERSION` and `REPORT_VERSION` did not move.
- **§2 R7.** `machine.rs` gains a `//!` subsection, *"Two tier-C members with a stated shape"*
  (`:164-184`), that states the `live.rows` order and the `failure_class` null rule. The null
  rule is worded as promised at every tier (D65 §6 rider 1), not as tier C.
- **Plants, every one red by message.**
  - P1 (`FetchFailureClass`'s `rename_all` removed) reddened three `r89` tests.
  - P2 (`ProbeFailureClass`'s `rename_all` removed, in the copy only) reddened the cross-class
    test.
  - P3 (the probe arm spelled `"transport error"`) reddened only the equality test, while the
    frozen snapshot stayed green: the hole §2 R3 closes. P3b (the live arm) reddened both.
  - P4 (the sort removed) reddened the order test, and P6 (the manifest record moved first)
    reddened the three R81 tests and the new one.
  - P5 (`records_from_manifest`'s files reversed) reddened R11's
    `the_builder_spans_every_file_of_a_multi_file_work`.
- **Deviations.**
  - The shared constant is private: its only callers are the two functions, and a public item
    with no outside caller is the test-only surface §2 R2 deletes.
  - `FetchFailureClass` keeps `Deserialize` (antseal-net's `PersistenceOutcome` round-trips it),
    so it has `ProbeFailureClass`'s shape except for that derive, not exactly.
  - The `R11` tests' assertion logic is unchanged, but one message now names this record.
  - `live_display_channel.rs`'s needle is `"class":"transport"`, stricter than §3's bare
    `"transport"`.
  - The `token()` distinctness check became a serde-spelling distinctness check.
- **At the lane's close.**
  - Whole `antseal-core` suite: 1 823 passed, 0 failed.
  - `antseal-net`: lib 115 passed, plus its integration tests.
  - `antseal-cli`: lib 307 and `verify_live_manifest` 5 passed.
  - wasm32 check of `antseal-core`: exit 0.
  - `clippy -D warnings` on all three crates: exit 0.
- **Left open.** antseal-net's own report types still serialize PascalCase and externally tagged
  around the now-kebab class. Nothing serializes them on a production path; the question is
  noted on `R99`, which rules the house pattern.
- **The orchestrator's acts.** `R90` and `R91` are ticked, and `U50` is ticked across its three lanes. `R99` carries the antseal-net casing note.

## Closing — this record is not consent

It changes code, tests and module documentation in the tree. Nothing in it authorises a push,
a dispatch, a deploy or any other outward act.
