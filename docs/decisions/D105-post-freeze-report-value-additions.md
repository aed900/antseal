# D105 — R69: may a new *value* enter frozen report v1, and what must exercise it

- **Status: RESOLVED — YES, a variant is a VALUE ADDITION and R20's arm is
  permitted; the lean's remedy is REFUSED, twice over, by mechanisms already
  in the tree.** `ArbitrumReceipt`'s landing was legitimate and R20's
  storage-linkage arm is legitimate on the *same* ground — but not the ground
  R12 wrote down. D29 rule 1's subject is **struct** fields; it says nothing
  about enum variants, and rule 4's *"the shape of the bytes depends only on
  the report version"* cannot mean the document's key set, because **frozen
  report v1 already violates that reading**: an anchorless bundle renders
  `"anchors":[]` and the five `AnchorResult` keys vanish. Recon's crux —
  *"nested per-blob data is not two scalars"* — **dissolves**: nested structs
  with runtime cardinality are native to v1 (`anchors`, `reveal.files`,
  `revealed_spans`), and on the axis recon did not name, JSON-type
  polymorphism, the two arms are **identical** (both enums were a single unit
  variant rendering a bare string; both become `string | object`). D29 *does*
  name R20's arm as the forbidden case — and that bullet's **other** example,
  *"R12's anchor detail"*, was measured wrong at R12 by D94 §2. The bullet's
  **rule** survives verbatim; its two 2026-07-27 guesses about undesigned
  tasks do not bind, and one of them is already known false.
  **The lean's third clause is not expensive — it is refused.** Adding a 22nd
  case to `report/verification-reports.json` hits
  `vector-freeze.sh`'s frozen append-only path, and its one exception refuses
  on its *first* check (`the case count moved (21 -> 22); a verdict event
  re-values existing cases and adds none`). A second `report` document is
  refused by a different mechanism — `check_shape_coverage` runs per document
  and demands all 13 `REQUIRED_SHAPES`. **A golden vector is the wrong
  instrument, and D29 itself named the right one**: the fixed-fixture snapshot
  in Consequences bullet 1, `EXPECTED_CANONICAL_JSON`, which is hand-built
  (which is why it can still render `AnchorState::Absent`, a state the
  pipeline no longer emits at all) and **already enumerates all seven anchor
  states in one document** — `supporting_evidence` is the single slot where
  the tree's value-space exhibit stops short.
  **The reframing finding: "moved no pinned byte" is simultaneously the proof
  that it was not a format event and the statement that nothing checks it.**
  A value addition nothing emits moves zero pins; a format event moves all 21
  and all 26. The pin count is a correct *format* signal and an uninformative
  *coverage* signal, and the tree has no second signal — which is why
  `arbitrum-receipt` shipped with nothing red and nothing wrong. R69 is a
  coverage defect wearing a format defect's clothes.
  **And R69 does not depend on A22 in any direction.** Under this ruling it
  writes neither `FROZEN.sha256` nor `INDEX.json`, so the only coupling anyone
  claimed is gone. `TODO.md:50`'s *"shares D101's ruling and should follow
  A22"* is false on both halves (D101 contains zero occurrences of "R69").
- **Date: 2026-08-09** (M2 wave 10 planning round; briefed to confirm that
  R20's arm is legal *exactly like* `ArbitrumReceipt`, that `report.rs:299`
  should say so, and that one report vector should be added. The first is
  affirmed on **different reasoning**, the second is granted with text that
  refuses to predict M3, and the third is **overturned**.)
- **Owning task: R69** (executes; its Accept rows are rewritten by §9).
  Consumed by **R20** (M3 — this record is what it will be built against),
  **Q107** (whose three-class table is short a class), **Q127** (minted here,
  §7). Register entry: the D105 row under `TODO.md` "Due M2".
- Read at `4672843`. **Nothing was executed**: this record reads and reasons
  only, per the planning brief and the two-core constraint. Everything below
  that is stated as measured was read off the file named beside it.

---

## The problem, in one sentence

A value that report v1 could not produce on the day it was frozen can now be
produced, nothing in the tree went red when that happened, and the tree has no
way to tell "this was legal" from "this was never checked" — because both look
like zero moved pins.

---

## 1. What was measured

Recon's eight findings, verified. Six confirmed, one confirmed with its
conclusion inverted, one enlarged.

| # | Recon's claim | Verdict |
| --- | --- | --- |
| 1 | R12 already fixed the receipt arm; the type doc rules it at `report.rs:478-484` | **Confirmed**, text quoted in §4 |
| 2 | The stale twin is `StorageLinkageResult`, claim text on `report.rs:299`; recorded citations stale | **Confirmed.** `tasks/R.md:734` says `:226-231`, `D94:506` says `:365-366`; both are wrong, the live line is **`:299`** |
| 3 | D29 `:126-128` names R20's arm as the forbidden case; the pre-Q14 window closed 2026-07-28 | **Confirmed** — and the bullet's *other* named example is already known false (§3.2) |
| 4 | The value-vs-field argument may not transfer; *"the R12 argument does not transfer unexamined"* is the crux | **Examined, and the crux dissolves.** §3.3. The two arms are structurally the same case on every axis D29 has, including one recon did not name |
| 5 | No committed vector renders `arbitrum-receipt`; the string appears once, at `report.rs:702` | **Confirmed**, repo-wide, zero testdata files |
| 6 | A vector costs a catalogue Case + an R30 row + a report-vector case + a freeze update | **Confirmed as to cost and wrong as to necessity in both directions.** §5.1: the catalogue Case does *not* force a report-vector case (26 shapes, 21 cases); the report-vector case is not merely costly, it is **refused** |
| 7 | `verify_bundle` → `anchor_stage` already renders one; a synthetic `ReceiptRecord` exists | **Confirmed** (`pipeline.rs:1079-1086`, `:3006-3034`, `bundle_fixtures.rs:1488-1494`) |
| 8 | R69 does not depend on A22; the coupling is mechanical (both write `FROZEN.sha256`) | **Confirmed, and the residue dissolves.** D101 has zero "R69". Under §5's ruling R69 writes no frozen file, so the two lanes do not even need serializing (§8) |

### 1.1 The two D29 rules, in full

> 1. **Struct fields serialize in declaration order** (serde derive
>    guarantee). Declaration order in
>    `crates/antseal-core/src/verify/report.rs` **is** the wire order —
>    reordering, adding, or removing a field is a report-format change.

> 4. **No conditional field presence** (`skip_serializing_if` is banned in
>    report types): every field of a given report version serializes every
>    time; absence is expressed by `null` (`Option`) or an explicit
>    `not-evaluated`/`absent` state. The shape of the bytes depends only on
>    the report version, never on runtime happenstance.

### 1.2 The report's value space today, and what pins each value

Five enums. Read off `report.rs` and the 21 committed cases:

| enum | variants | what pins each spelling | in composition? |
| --- | --- | --- | --- |
| `AnchorState` | 7 | `ALL` + wildcard-free `wire_name` + `wire_name_is_the_serialized_spelling` (`:722-732`) — **exhaustive by construction** | all 7, `verify/mod.rs:358` |
| `SignatureScheme` | 3 | one asserted by hand (`:664-667`); the other two incidentally | incidentally |
| `AnchorKind` | 2 | one asserted by hand (`:676-679`); the other incidentally | yes |
| `StorageLinkageResult` | 1 | `:668-671` | yes |
| `SupportingEvidenceResult` | 2 | `none` at `:672-675`; `arbitrum-receipt` at `:693-713`, **standalone only** | **`none` only** |

`AnchorState` is the only enum immune to a variant landing unexercised, and it
is immune for an unrelated reason — the registry-spelling parity `wire_name`
was built for. Every other enum's coverage is *incidental*: it holds because
some fixture happens to render the value. The one value no fixture happens to
render is the one that shipped invisibly. → **§7, Q127.**

### 1.3 The freeze machinery, read rather than assumed

`scripts/vector-freeze.sh`, at `#! status frozen`, is append-only **per file**:
every existing digest line must survive byte-identically (`:258-278`). The one
exception, `--update --verdict-event <Dnn>`, does not take the flag's word — it
re-derives the class from the diff against `HEAD`. Its **first** check:

```
b, a = before["expect"]["cases"], after["expect"]["cases"]
if len(b) != len(a):
    fail(f"the case count moved ({len(b)} -> {len(a)}); a verdict event re-values "
         "existing cases and adds none")
```

### 1.4 The per-document coverage rule

`check_shape_coverage` (`vectors_report.rs:287-330`) runs on **each** report
document and requires that every one of `REQUIRED_SHAPES`' 13 M0 rows appears
in *that* document, else `m0-shape-coverage`. It is enforced on wasm32 as well
as natively (`vectors_report.rs:93-94`).

### 1.5 What runs on both targets, and by which route

Two distinct mechanisms, and conflating them is how a lane picks the expensive
instrument:

- **`--lib` unit tests** run under `wasm32-unknown-unknown`
  (`scripts/wasm-tests.sh:48`, `cargo test -p antseal-core --lib --target
  wasm32-unknown-unknown`). This is **A90's established route**, adopted by
  A18 (44 rows), A21, A43 and R72 for exactly this reason. Integration targets
  under `crates/antseal-core/tests/` are separate crates and **never** execute
  there.
- **Committed vectors** reach wasm32 through `crates/wasm-bitmatch/build.rs`,
  which embeds them and byte-compares the recomputation.

`report.rs`'s tests, `verify/mod.rs`'s tests and the R30 digest table are all
`--lib`, so all three are already dual-target. `tests/report_vectors.rs` is
not, and gets its parity from the second mechanism.

---

## 2. RULING 1 — R20's storage-linkage "evaluated" arm is a **legal post-freeze VALUE ADDITION**, on reasoning that also corrects R12's

**Ruled: permitted, conditionally and decidably.** Adding a variant —
including a struct variant carrying nested per-blob results — to
`StorageLinkageResult` is a VALUE ADDITION. `REPORT_VERSION` stays `1`. The
condition is stated as a test in §2.4 and is not a matter of judgement.

### 2.1 Rule 1 does not reach an enum variant, and says so in its first word

Rule 1's subject is **`Struct` fields**, and its warrant is *"the serde derive
guarantee"* about declaration order. Enums appear in D29 exactly once, at rule
7, and only to fix their **wire spellings** as kebab-case. Neither
`ArbitrumReceipt` nor an R20 arm reorders, adds or removes a field of any
struct that existed at Q14 — `VerificationReport`'s seven fields
(`report.rs:116-146`) are untouched, and so is every nested struct's.

The tempting counter is that `block_number` and `transaction_count` *are* new
JSON keys. They are — but they are keys of a type that did not exist at the
freeze, and rule 1 is a statement about the declaration order of types that
did. Read as *"no new key may ever appear"*, rule 1 forbids R20 entirely, in
any form, forever — which no one has ever suggested and which the freeze
boundary's own report row (`docs/format/anchor-artifact-limits.md:138-147`)
contradicts by leaving *"a bump remains available for a genuine field
addition"* open.

### 2.2 Rule 4's last sentence cannot mean what it appears to mean — v1 already breaks it

*"The shape of the bytes depends only on the report version, never on runtime
happenstance"* is false of frozen report v1, on the day it froze:

- an anchorless bundle serializes `"anchors":[]` — pinned in production at
  `pipeline.rs:3098` — so `kind`, `state`, `verified_time_unix`, `source` and
  `fetch_date` are **absent from 20 of the 21 committed cases** and present in
  the 21st. That is the document's key set varying by runtime happenstance;
- `reveal.files[].raw_mirror` is `null` in one case of the pinned snapshot and
  a two-key object in another;
- `unrevealed_files` is empty or populated depending on the reveal.

A reading under which report v1 is illegal is the wrong reading. The operative
content of rule 4 is what its own body states and what its parenthetical
enforces: **`skip_serializing_if` is banned, so a given struct renders its
full declared field list on every run.** That is a per-*type* invariant. Both
arms keep it: `StorageLinkageResult` and `SupportingEvidenceResult` are
non-`Option` fields of `VerificationReport` and serialize on every run, before
and after.

### 2.3 Recon's crux, examined — and it dissolves

Recon: *"`ArbitrumReceipt` is a variant carrying two scalars in a slot that
already existed. R20's arm would carry per-blob nested results — new nested
data, not a bare unit variant."*

Three reasons the distinction is not load-bearing:

1. **Nested structs with runtime cardinality are native to frozen v1.**
   `anchors: Vec<AnchorResult>` is a list of five-field structs; `reveal.files`
   is a list of six-field structs each containing two further `Vec<UnitSpan>`.
   "Per-blob nested results" is structurally `anchors` with a different name.
   Payload complexity is not an axis D29 has.
2. **On the axis recon did not name, the two are identical.** The real change
   either arm makes is that the slot's JSON *type* becomes polymorphic. Before
   R12, `SupportingEvidenceResult` had exactly one unit variant and
   `supporting_evidence` was always the string `"none"`; after, it is
   `string | object`. `StorageLinkageResult` has exactly one unit variant today
   and `storage_linkage` is always the string `"not-evaluated"`. **This is the
   same transition, from the same starting shape.** If polymorphism is
   disqualifying, `ArbitrumReceipt` is already a breach; if it is not, R20's
   arm is clear. There is no reading on which they differ.
3. **`ArbitrumReceipt`'s two scalars are already "new nested data".** Its
   serialization is `{"arbitrum-receipt":{"block_number":…,"transaction_count":…}}`
   (`report.rs:702`) — an object inside an object, with two keys that did not
   exist at the freeze. The difference from R20 is the *number* of new keys and
   whether a `Vec` wraps them. Neither is a rule.

**Recon's judgement that the R12 argument "does not transfer unexamined" was
the right instinct and the wrong conclusion.** It does not transfer *as R12
wrote it* (§4.2 — R12's sentence is imprecise in a way that bites exactly
here), but the corrected argument transfers completely.

### 2.4 The distinguishing test — one sentence, mechanically checkable

> **A post-freeze change to the report is a VALUE ADDITION — legal, with
> `REPORT_VERSION` unchanged — if and only if no struct that report v1 could
> already serialize gains, loses or reorders a field; adding a *variant* to a
> report enum is a value addition whatever its payload, and adding a *field*
> to a frozen struct is not.**

It is checked by reading the diff's `pub struct` declarations, and it is
corroborated for free by two instruments that already exist: a FORMAT EVENT
moves **all 21** report cases and **all 26** `REPORT_DIGEST_BY_SHAPE` rows (R32
measured exactly that at `report_version` 0 → 1, D94 §2a), while a value
addition nothing yet emits moves **zero**. If a change claiming to be a value
addition moves *some* pins, it is a VERDICT EVENT as well and needs D94's
`--verdict-event` path; if it moves *all* of them, the claim is false.

Concretely, for R20: an `Evaluated { … }` variant is clear. Anything that adds
a field to `VerificationReport`, `AnchorResult`, `WorkMetadata`,
`EvidenceLayerResult`, `RevealSet`, `FileReveal`, `UnitSpan` or
`UnrevealedFilePlaceholder` is a FORMAT EVENT and costs the bump.

### 2.5 Overriding D29's named example — the argument, not the assumption

D29 `:126-128`:

> Any pre-Q14 field addition (e.g. R12's anchor detail, **R20's
> storage-linkage arm**) re-snapshots the R1 fixture — expected and cheap
> before the freeze, forbidden after it without a version bump.

The bullet's **rule** is not overridden and is not weakened: a pre-Q14 *field*
addition is forbidden post-freeze without a bump, verbatim, and §2.4 is a
statement of what counts as one. What does not bind is the parenthetical.

It contains two examples. Both are **predictions**, written 2026-07-27 about
tasks not yet designed. The first was measured, and it was wrong: D94 §2
established that *"R12 adds no field. The bullet does not reach this case, and
reading it as though it did is how a lane arrives at 'report v2'."* R12's
"anchor detail" turned out to be values in slots that already existed.

An author who guessed the shape of two future tasks and was demonstrably wrong
about the first has not thereby ruled on the second. This is the same defect
D94 found in D84 §7 and named precisely — *"a **prediction about a future
milestone**, sitting inside a block whose job is to delimit"* — recurring one
document over, and it should be recorded as such rather than deferred to
again. D29's bullet is a Consequences note, not a ruling; the ruling is §2.4.

---

## 3. RULING 2 — the exact replacement text for `report.rs:294-299`

**Ruled.** Replace the type doc's third paragraph. It must be true on the day
it lands and must not predict M3, so it states a **rule that applies if** an
arm is added, never that one will be.

Current, `crates/antseal-core/src/verify/report.rs:294-299`:

```
/// Storage-linkage-layer result slot (MVP-SPEC.md line 119), rendered
/// distinctly from the evidence layer and never gating it.
///
/// R20 (M3) adds the evaluated arm (per-blob offline address
/// recomputation results); until then the slot reports not-evaluated —
/// a pre-Q14 extension per D29.
```

Replacement:

```
/// Storage-linkage-layer result slot (MVP-SPEC.md line 119), rendered
/// distinctly from the evidence layer and never gating it.
///
/// The slot has one variant and reports not-evaluated in every report
/// emitted to date. **Not-evaluated is neither a claim nor a verdict**:
/// the stage has not run, so this says nothing in either direction about
/// where the work is stored — and nothing here ever gates the evidence
/// layer, because "storage is the product's bonus, not its proof".
///
/// # Adding an arm here is a value addition, not a field addition
///
/// This doc said the slot was "a pre-Q14 extension per D29" until
/// **D105**. Q14 executed on 2026-07-28, so it was false when read and
/// false when written down: there is no open pre-freeze window.
///
/// What is true is that the freeze does not close this enum. D29 rule 1
/// fixes the declaration order of the report's **struct** fields; a new
/// enum *variant* moves no struct's field list, and `storage_linkage`
/// serializes in every report either way (D29 rule 4). So an arm added
/// here is a VALUE ADDITION and `REPORT_VERSION` stays `1` — the same
/// class, and the same reasoning, as
/// [`SupportingEvidenceResult::ArbitrumReceipt`].
///
/// D29's Consequences bullet names "R20's storage-linkage arm" as a
/// pre-Q14 *field* addition. That was a guess about an undesigned task,
/// and the same bullet's other guess — "R12's anchor detail" — was
/// measured wrong when R12 landed (D94 §2). D105 rules the test that
/// decides it: **a report change is a value addition iff no struct
/// report v1 could already serialize gains, loses or reorders a field.**
/// An arm that instead adds a field to this or any other frozen struct
/// is a FORMAT EVENT and costs a report-version bump.
///
/// Whatever lands here must arrive with a committed assertion that
/// renders it inside a whole canonical report — D105 ruling 4; the
/// receipt arm did not, and that is the whole of why R69 exists.
```

Three properties, deliberate:

- **True on the day it lands.** Every sentence is about the slot as it is, the
  rule as it is, or a dated historical correction. Nothing asserts R20 exists.
- **No M3 prediction.** "Adding an arm here" is conditional; the
  "per-blob offline address recomputation results" gloss — which *is* a design
  claim about R20, and one not sourced to any R20 text — is deleted.
- **It carries its own obligation forward.** The last paragraph is what would
  have stopped R69 from happening, applied at the site where the next arm will
  be written.

---

## 4. RULING 3 — `ArbitrumReceipt`'s landing was legitimate; R12's *reasoning* has a flaw, and it is the one that matters for R20

**Ruled: affirmed on the format question. Two corrections, neither reversing
it.**

### 4.1 Why it was legitimate

Four independent grounds, all measured:

1. **No struct moved** (§2.4). `VerificationReport`'s seven fields and every
   nested struct's field list are byte-for-byte what Q14 froze.
2. **Zero pins moved** — 21/21 report cases and 26/26 R30 rows, which is what
   a value addition nothing emits looks like and is *not* what a format event
   looks like.
3. **`Deserialize` is derived on no report type.** Verified: zero occurrences
   in `verify/report.rs` and `verify/mod.rs`. D29 rule 9 (*"`Serialize` only
   for now… nothing parses adversarial report bytes"*) still holds, so there is
   no reader for whom an unknown variant is an error. This is the ground that
   would move first: **the day `Deserialize` is derived, §2.4 needs a second
   clause**, because a v1 reader meeting a variant minted after it was written
   fails, and that is a compatibility event a serializer-only analysis cannot
   see. → §10, revisit trigger.
4. **No release exists** (Q34 is unstarted), so no deployed consumer can break,
   and D84 line 123's promise — *"v1 reports remain verifiable"* — is untouched
   either way, since v1 reports are exactly the ones already emitted.

### 4.2 The flaw: R12's sentence proves too much, and R20 is where that bites

`report.rs:482-484`:

> Q14 froze report **v1**'s field list (D29 rule 1); this adds a *value*, not a
> field, and the slot is present in every report either way (D29 rule 4).

*"Field list"* drops rule 1's subject. Rule 1 froze the **struct** field lists
and their declaration order. Read as "the field list" — the set of keys the
report may contain — the sentence refutes itself in its own next paragraph,
because `block_number` and `transaction_count` are keys the report may now
contain and could not before.

The imprecision is harmless where R12 used it and load-bearing where R20 will:
a lane reading `:482` to decide whether an `Evaluated { blobs: Vec<…> }` arm is
legal gets *"it adds fields, so it is a field addition"* — the exact wrong
answer, from the exact sentence written to prevent it. Fixed in §9 edit 2.

### 4.3 The finding: the reassurance and the gap are the same sentence

R12's heading is **"Adding this arm moved no pinned byte"**, and it is
accurate. It is also, word for word, the statement that no pinned byte
exercises the arm. Zero moved pins is:

- **a correct format signal** — a format event moves all 21 and all 26, so zero
  is affirmative evidence the change was not one; and
- **an empty coverage signal** — an unexercised value moves zero pins too.

The two are indistinguishable by pin count, the tree has no second signal, and
R12 wrote down the first reading only. That is the whole content of R69: not
that something illegal happened, but that **the tree's only instrument here
returns the same answer for "legal" and "untested", and nobody had noticed the
question was two questions.** It is the same shape as D94's own finding — an
instrument that cannot distinguish the thing it is cited for.

---

## 5. RULING 4 — a report golden vector is **REFUSED**, and the right instrument is the one D29 named

**Ruled: no new committed vector. Extend D29's fixed-fixture snapshot.**

### 5.1 The lean's remedy is refused twice, by two different mechanisms

**Route A — a 22nd case in `testdata/vectors/v1/report/verification-reports.json`.**
That changes a frozen file's digest. `vector-freeze.sh` refuses (`:258-278`),
and the one legal exception refuses on its first check: *"the case count moved
(21 -> 22); a verdict event re-values existing cases and adds none"*. It is not
a FORMAT EVENT (no format moved) and not a FIXTURE EVENT (no existing input
moved). **There is no class for it.** This is not cost — it is a red gate with
no key. Note that the lean, D94 §11's R69 sketch (*"commit a case that actually
renders `arbitrum-receipt`"*) and R69's own Accept row all assume this route,
and none of the three checked it.

**Route B — a second `report` document.** *Adding* a file is legal forever
(`testdata/vectors/README.md`, "Add a vector" row). But
`check_shape_coverage` runs **per document** and requires all 13
`REQUIRED_SHAPES`; a receipt-only document fails `m0-shape-coverage`. To pass,
it must re-carry every M0 shape — a second copy of the 21-case work, to pin one
slot.

**Recon's cost estimate was also wrong in the permissive direction.** It
reported that minting a catalogue Case *mandates* a report-vector case. It does
not: the catalogue has **26** entries and the document has **21**, and
`check_shape_coverage` constrains only `REQUIRED_SHAPES`. So catalogue-plus-R30
is available *without* touching a frozen file — which matters, because it is
the runner-up.

### 5.2 The instrument, and it is D29's own

D29 Consequences bullet 1: *"R1 implements the report model under rules 1–9 and
ships the determinism tests (double-serialize byte-equality + **a fixed-fixture
snapshot pinning the exact bytes**)."*

That snapshot is `EXPECTED_CANONICAL_JSON` (`verify/mod.rs:358`), compared
against `fully_populated_report()` (`:113`) by `snapshot_bytes_are_stable`
(`:268-277`). Four properties make it the right home, and the third is the one
that settles it:

1. **It is hand-constructed, not pipeline-produced.** Proof: it renders
   `AnchorState::Absent`, and the pipeline emits no `absent` slot at all
   (D53 §4a; `pipeline.rs:3088`). So it can exhibit values no bundle can
   currently produce — which is exactly the job.
2. **It already enumerates all seven anchor states in one document.** It is
   *already* the tree's report-value-space exhibit; nobody labelled it that,
   and `supporting_evidence` is the single slot where it stops at the default.
3. **It pins the value in composition.** `report.rs:702` pins the arm's bytes
   *standalone*; it can never show the `"supporting_evidence":` key, the object
   sitting where a string sat, or the sibling ordering
   `anchors → supporting_evidence → reveal` that D29 rule 1 is about. Only a
   whole-report literal shows that, and no whole-report artifact in the tree —
   pinned or otherwise — has ever contained a receipt.
4. **It costs no ceremony and runs on both targets.** A `--lib` test, so
   wasm32 executes it via `scripts/wasm-tests.sh:48` (A90's route, R72's
   precedent). No `FROZEN.sha256`, no `INDEX.json`, no D87 budget, no
   `--verdict-event`.

### 5.3 The case's shape, concretely

- Add a **receipt-bearing twin** of `fully_populated_report()` in
  `crates/antseal-core/src/verify/mod.rs`'s test module — same report in every
  other respect, `supporting_evidence:
  SupportingEvidenceResult::ArbitrumReceipt { block_number, transaction_count }`.
  Do **not** mutate the existing fixture: `"supporting_evidence":"none"` in
  composition is itself worth keeping pinned, and it is the control the twin is
  differential against.
- Add a sibling `const EXPECTED_CANONICAL_JSON_WITH_RECEIPT` and a sibling
  `snapshot_bytes_are_stable`-style test.
- **Checkable prediction, so the implementer can audit the diff before
  trusting it**: the twin's bytes are the existing snapshot with
  `"supporting_evidence":"none"` (6 B) replaced by
  `"supporting_evidence":{"arbitrum-receipt":{"block_number":…,"transaction_count":…}}`
  — the value is **69 B** at the `report.rs:702` operands, so **+63 bytes** and
  **no other difference anywhere in the literal**. Any other delta means the
  twin diverged from the control in something besides the receipt: fix the
  fixture, not the constant.
- Run the twin through the existing secret-leak sweep at `verify/mod.rs:330-353`
  alongside the control, so the new value is covered by project rule 6 from the
  moment it exists rather than at the next sweep.
- **Reuse the `report.rs:702` operands** (`block_number: 271_828_182`,
  `transaction_count: 2`) rather than minting new ones, so the standalone pin
  and the composed pin move together and a future edit cannot satisfy one while
  breaking the other.

**What reddens it**: deleting the arm (compile error), renaming
`block_number`/`transaction_count`, reordering them, changing the enum's serde
representation, changing the kebab-case spelling, and moving
`supporting_evidence` relative to its siblings. That is R69's Accept row
*"deleting the arm or changing its fields reddens it"*, discharged.

### 5.4 The two legal alternatives, and why each loses

Catalogue Case `multi-file-every-anchor-kind/…` + a `REPORT_DIGEST_BY_SHAPE`
row: legal, dual-target, no frozen file. It loses on two counts. It pins an
**opaque digest** — you cannot read `arbitrum-receipt` out of it, and the
review surface a whole-report literal gives is the point. And a catalogue Case
is consumed by six iterators (`leaf_level_cover_shapes.rs:93`, `:265`;
`codec_fuzz.rs:447`, `:477`; the `by_name` census at `bundle_fixtures.rs:1891`;
R30 at `:2297`), so it is the widest blast radius of the three legal options
for the least readable result.

**Route D, and it is newly and unambiguously legal — a new vector *kind*.**
Q124's in-flight correction to `testdata/vectors/README.md` (ruling D101 §5)
rewrites the "Add a kind" row to *"a new kind is an **append** … no existing
digest moves and no existing vector is touched"*, which removes the last doubt
that a kind could be added post-freeze. A kind defines its own `inputs`/`expect`
and therefore escapes `check_shape_coverage` entirely — Route B's blocker does
not apply. It is nonetheless refused here: it costs a dispatch arm and an
executor in `test_util::vectors`, an `INDEX.json` entry and a `FROZEN.sha256`
append — which would re-couple R69 to A22 for no reason (§8) — and it touches
`crates/antseal-core/src/test_util/vectors.rs`, which another lane owns as this
is written. Minting a whole vector kind to pin one enum variant is the most
expensive of the four routes and the only one that reintroduces a dependency
this ruling otherwise removes. If R-VAL (§6) is ever ruled to require a
*retained* artifact, this is the route to reconsider — not before.

### 5.5 Stated plainly: what this ruling does not buy

The snapshot is source, not `testdata/`. It gets **no retention guarantee, no
freeze manifest line, and no `wasm-bitmatch` transcript entry** — its
dual-target parity comes from executing the same assertion on both targets,
which is A90's route and is sufficient, but it is a different mechanism from
the vectors'. If the project later rules that every report v1 value must live
in a *retained* artifact, that is a vector-append question and it belongs to
whoever mints the missing class (§7). This record does not pre-empt it.

---

## 6. RULING 5 — the missing general rule, and the class the freeze vocabulary is short

**Ruled: the rule should exist, in two halves.**

> **R-VAL.** Every value report v1 can serialize must be exercised by a
> committed assertion that renders it **inside a whole canonical report**, and
> the report's enums must be enumerable so that "every value" is a checkable
> quantity rather than a hand-maintained list.

The second half is the enforceable one, and the tree already has a working
template for it in exactly one place: `AnchorState::ALL` (a `const` array) +
`wire_name` (a wildcard-free match, so a new variant is a **compile error**) +
`wire_name_is_the_serialized_spelling` (which sweeps `ALL`). That triple is why
an eighth anchor state cannot land unexercised. Four of the five report enums
lack it (§1.2), and `SupportingEvidenceResult` is the one where the gap was
realised.

**A second, smaller gap, found while ruling §5.1 and outside R69's scope:**
D94's three-class vocabulary (FORMAT / VERDICT / FIXTURE) has **no class for
adding a case to a frozen report document**. It is not a format change, not a
re-valuation, and not a changed input — and `vector-freeze.sh` correctly
refuses it while naming three causes none of which apply. Q107 is open and owns
that table, but Q107 as written only *splits* the existing row into the three
D94 classes; it does not add a fourth. This is drift on Q107's scope, reported
rather than edited.

---

## 7. Discovered work — named, not registered

**ID claim.** `TODO.md` and `tasks/Q.md` reach **Q125**; **Q126** is minted by
D104 §7 and recorded in its index row but is **not yet in `TODO.md`**.
Therefore the next free Q id is **Q127**, and this record claims exactly that
one. (Noted, per the brief: **A112 is claimed by D104 §7 and by a second
concurrent planner** — this record uses no A id, so it does not add to that
collision.)

### Q127 — Report enums are not enumerable, so a value can land unexercised
- Milestone: M2 · Size: S · Deps: D105
- Give `SignatureScheme`, `AnchorKind`, `StorageLinkageResult` and
  `SupportingEvidenceResult` the triple `AnchorState` already has — a `const
  ALL`, a wildcard-free spelling accessor, and a sweep over `ALL` that asserts
  the serialized bytes — so a new variant is a compile error and its rendering
  is asserted from the moment it exists. `SupportingEvidenceResult` needs a
  hand-written arm for its struct variant; the point is that the sweep is
  *exhaustive*, not that it is uniform. Then state R-VAL (§6) wherever the
  report's format discipline is written, so the "in a whole canonical report"
  half has a home. **Not Q120**: Q120 is cross-surface agreement between
  `list`, `status` and `WorkRecord` on UNANCHORED; this is the report's own
  value space being a checkable set. Do not merge them.

### Drift, reported not edited (records are immutable; these are not records)
1. **`tasks/R.md:734`** cites `report.rs:226-231` and **`D94:506`** cites
   `report.rs:365-366` for the `StorageLinkageResult` claim. The live line is
   **`report.rs:299`**. D94 is a ruled record and must not be edited;
   `tasks/R.md` is R69's own entry and is corrected by §9.
2. **`TODO.md:50`** — *"Then **R69**'s vector, which shares D101's ruling and
   should follow A22 rather than race it."* Both halves false: D101 contains
   zero occurrences of "R69", and under §5 R69 writes no frozen file.
3. **D29 `:126-128`'s parenthetical** is a stale prediction whose first example
   was falsified at R12. D29 is immutable; §3's replacement text is where the
   correction lands, and §2.5 is the argument.

---

## 8. Kill criteria

This record is wrong, and must be re-opened, if any of these is observed:

1. **`Deserialize` is derived on any report type.** §4.1 ground 3 falls, and
   §2.4's test needs a compatibility clause — a v1 reader meeting a
   later-minted variant fails, which no serializer-side analysis can see.
   The likely trigger is Q4's runner or external tooling wanting structural
   comparison, which D29 rule 9 explicitly contemplates as "non-breaking".
2. **A struct that existed in report v1 at Q14 gains, loses or reorders a
   field.** Then §2.4 says FORMAT EVENT and this record authorises nothing —
   R20 in that shape needs a version bump, not D105.
3. **The receipt twin's snapshot diff is anything other than +63 bytes at the
   `supporting_evidence` value** (§5.3). The twin has diverged from the control
   in something besides the receipt, and the differential claim is void until
   it is fixed.
4. **Adding the twin moves any committed vector digest or any
   `REPORT_DIGEST_BY_SHAPE` row.** It touches no fixture the vectors or the
   catalogue use; if a pin moves, the edit reached further than §9 describes.
   Stop and find out why — do **not** re-pin.
5. **A release ships** (Q34). §4.1 ground 4 expires, and any subsequent value
   addition is a compatibility question about deployed verifiers rather than an
   internal format question.
6. **Someone finds a report consumer that branches on `supporting_evidence`
   being a JSON string.** §2.3's polymorphism argument holds only because no
   such consumer exists; R21/U30's `--json` and R22's page binding are M3 and
   unwritten, and they must be written against `string | object`.

---

## 9. Consequences — the exact edit set

| # | File | Edit | Why |
| --- | --- | --- | --- |
| 1 | `crates/antseal-core/src/verify/report.rs:294-299` | Replace the `StorageLinkageResult` type doc's third paragraph with §3's text | Ruling 2. The live false claim |
| 2 | `crates/antseal-core/src/verify/report.rs:482-484` | *"Q14 froze report **v1**'s field list (D29 rule 1)"* → *"Q14 froze the declaration order of report **v1**'s **struct** fields (D29 rule 1)"*; append *"D105 states the test both slots are ruled by, so the rule has one home rather than two paraphrases."* | Ruling 3.2. The imprecision is harmless here and wrong at R20 |
| 3 | `crates/antseal-core/src/verify/report.rs:478` | Heading *"# Adding this arm moved no pinned byte"* gains a second sentence: that zero moved pins is a correct **format** signal and an empty **coverage** signal, and the coverage is R69's twin snapshot | Ruling 3.3. The reassurance and the gap were one sentence |
| 4 | `crates/antseal-core/src/verify/mod.rs` (test module) | Receipt-bearing twin of `fully_populated_report()`; `EXPECTED_CANONICAL_JSON_WITH_RECEIPT`; its snapshot test; twin added to the leak sweep at `:330-353`. Operands reused from `report.rs:702` | Ruling 4, §5.3. The whole of R69's coverage half |
| 5 | `tasks/R.md` R69 | `Do`: replace *"Commit a vector that opts a receipt in"* with §5's ruling and the reason a vector is refused. `Accept`: *"a committed case renders the receipt arm"* → *"the D29 fixed-fixture snapshot renders `arbitrum-receipt` in composition, on native and wasm32"*. Fix the stale `report.rs:226-231` → `:299` | The Accept row as written cannot be satisfied (§5.1) |
| 6 | `tasks/R.md` R20 | Append to `Do`: an `Evaluated` **variant** is a VALUE ADDITION per D105 §2.4, `REPORT_VERSION` stays 1; a **field** on any frozen struct is a FORMAT EVENT and costs the bump. D29 `:126-128`'s naming of this arm is a superseded prediction | R20 arriving at this question a third time is precisely what R69 exists to prevent |
| 7 | `TODO.md:50` | Delete *"which shares D101's ruling and should follow A22 rather than race it"* | False on both halves (§7 drift 2) |
| 8 | `TODO.md:475` | R69 row records the ruling: value addition affirmed on corrected reasoning, vector **refused** by `vector-freeze.sh`'s case-count check and per-document M0 coverage, remedy is D29's own fixed-fixture snapshot, R69 **decoupled from A22**. Discovered Q127 | Bookkeeping |
| 9 | — | Register **Q127** (§7) and the **D105** row under "Due M2" | Bookkeeping |
| 10 | `docs/decisions/README.md` | this decision's index row — **applied 2026-08-11** under [D119](D119-decision-index-identity-and-the-index-row-sections.md) RULING 4 | The former `## Index row` section is demoted to this row; RULING 6 puts the row in the act that commits the record |

**Gate, in this order** (2-core machine — none of these is `--workspace`):
`cargo test -p antseal-core --lib` (edits 1–4 all land there; the snapshot test
is `#[cfg(test)]`, so a failure on wasm32 is a bare *"the test binary trapped"*
with no test name — `report.rs:58-65` warns about exactly this, and `--lib`
natively is the readable reproduction); then `scripts/wasm-tests.sh --check`;
then `cargo fmt` and `cargo clippy`. **`scripts/vector-freeze.sh` must report
`unchanged`** — if it does not, kill criterion 4 has fired.

**The commit message must state**, and be checkable against the diff: *value
addition, not a format event (D105 §2.4) — no struct report v1 could already
serialize gains, loses or reorders a field*; **0 vector digests moved, 0 R30
rows moved, 0 files under `testdata/` touched**; and that the twin's literal
differs from the control by exactly +63 bytes at `supporting_evidence`.

---

## 10. What this record does not decide

- **R20's design.** Whether the storage-linkage arm carries per-blob results,
  what fields they have, or whether R20 renders anything at all. This record
  rules only that an arm is *permissible* and states the test that decides any
  particular shape. R20 is M3.
- **Whether `Deserialize` should be derived on the report types.** D29 rule 9
  contemplates it as non-breaking; §8 kill criterion 1 says it changes the
  analysis. Nobody has asked, and this record does not ask.
- **The missing fourth freeze class** (§6) — adding a case to a frozen report
  document has no vocabulary and no mechanism. Reported as drift on Q107's
  scope; not designed here, and §5 deliberately routes around it rather than
  forcing it.
- **Whether every report value must eventually live in a retained
  `testdata/` artifact** (§5.5). If ruled yes, R69's snapshot is a floor and
  not a ceiling.
- **`AnchorState::Absent`'s reachability** — R70, open, and adjacent: it is the
  converse gap (a value report v1 carries that the pipeline may no longer
  produce, versus a value it produces that nothing pins). Q127's enumerability
  work would make both visible; neither is ruled here.
- **Anything about A22, the `anchor` vector kind, or `testdata/anchors/`.** D101
  owns those and does not mention R69.

---

## Outcome

R20's arm is permitted; `ArbitrumReceipt`'s landing was legitimate and its
recorded reasoning is one word short; the doc comment gets text that is true
and predicts nothing; the vector is refused by two mechanisms neither the lean
nor R69's own Accept row had read; and the instrument that closes it was named
by D29 in 2026-07-27 and has been sitting in `verify/mod.rs` rendering all
seven anchor states ever since, one slot short of the whole value space.
