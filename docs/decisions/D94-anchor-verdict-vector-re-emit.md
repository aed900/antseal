# D94 — When the M2 anchor stage changes a frozen report vector's anchor state, what happens?

- **Status: RESOLVED — RE-EMIT, and it is not report v2. The recomputed
  `"invalid"` is correct and the fixture's synthetic anchor bytes STAY. What
  moved is a *verdict*, not a *format*: report v1's `AnchorState` already
  carries all seven states, `REPORT_VERSION` stays `1`, no field is added,
  reordered or renamed, and no bundle byte changes. The tree has vocabulary
  for exactly two causes of a moved pin — "the format changed" and "the
  targets diverged" — and R12 is neither; the standing rule this record
  creates is the missing third class, the **VERDICT EVENT**, which re-emits
  under the full freeze ceremony but never bumps a version. D84's §7
  checklist row predicting report **v2** is STALE and is amended in three
  files. And the brief's premise that "two checks go red" is where the real
  finding is: a THIRD instrument — the one D84 §2, `docs/security-assumptions.md`,
  `docs/format/Q14-freeze-gate-plan.md` and `bundle_mutators.rs` all name as
  the equality that makes D84's safety argument true rather than intended —
  is **structurally unable to go red at R12**, because it observes
  `verify_bundle`'s accept/reject outcome and D84's own rule F2 guarantees
  that outcome never moves. It must not be inverted; it must be re-titled as
  the permanent F2 guard it has always actually been.**
- **Date: 2026-08-06** (M2 wave 5 planning; blocks R12, consumed by A21, A22,
  R30, Q27)
- **Owning tasks: R12** (executes the re-emit), **A21/A22** (the next two
  tasks to touch this surface), **Q27** (the format-stability policy that
  gains the three-class vocabulary). Register entry: the D94 row this record
  creates under `TODO.md` "Due M2".

---

## 1. What the brief claimed, and what the tree says

| Claim | Verdict |
| --- | --- |
| All 21 pinned report cases carry `"supporting_evidence": "none"`, so the new `ArbitrumReceipt` variant moves nothing | **Confirmed, measured.** 21/21. Case 19 (`multi-file-anchored/mixed`) is also the only case with a non-empty `anchors` array; the other 20 pin `[]` |
| D84 predicts the `absent` → `invalid` transition by name and reads as authorising it | **Confirmed.** `docs/decisions/D84-anchor-artifact-limits-permanence.md:163-165` and its rule **F3** at `:146-153` |
| D84's v2 sentence may be stale, written before D8 settled the state set | **Confirmed, and on stronger ground than the brief gives.** See §3 |
| "the anchor-state change is the whole of the diff" | **NOT ESTABLISHED.** See §6 — `first_difference` reports one difference, and `fetch_date` is a live second candidate |
| "D30 §3 (append-only rules)" is a document to read alongside D29 | **Mispointed.** There is no `docs/decisions/D30-*.md`. D30 is a register row (`TODO.md:597`) whose document is `docs/testing/error-code-contract.md`; its §3 (`:380`) is append-only for **error codes**, not for vector bytes. The vector append-only rule is `testdata/vectors/README.md` "What changes at Q14" (`:413-419`), which is a different rule with a different owner |
| Applied to the tree, R12 turns **two** checks red | **True but incomplete, and the omission is the finding.** A third instrument was designed, documented in four places and named in the Q14 gate plan as this argument's load-bearing evidence — and it will stay green. §4 |

## 2. The classification, and why it is not report v2

Two questions hide under "is this a format event?" and the tree conflates
them.

**The format** is what D29 fixes: the field set, declaration order, the
absence of conditional presence, hex encoding, kebab-case enum spellings, and
`report_version` as the first field (`docs/decisions/D29-report-byte-format.md`
rules 1–9). R12 touches none of it. `crates/antseal-core/src/verify/report.rs:72`
keeps `REPORT_VERSION = 1`. `AnchorResult`'s five fields (`:322-359`) keep
their declaration order. `AnchorState`'s seven variants (`:258-277`) keep
their spellings, and `wire_name` (`:306-316`) is a wildcard-free match that
would fail compilation if one moved.

**The verdict** is what the pinned bytes *record*: what `verify_bundle`
computes for a given bundle. R12 changes that, deliberately, by design, and
D84 §4's rule F3 is the rule it changes it under.

D29's own Consequences bullet (`:126-128`) is written about the first
category only — *"any pre-Q14 **field addition** (e.g. R12's anchor detail…)
re-snapshots the R1 fixture — expected and cheap before the freeze, forbidden
after it **without a version bump**"*. R12 adds no field. The bullet does not
reach this case, and reading it as though it did is how a lane arrives at
"report v2".

The concrete disproof of v2 is one line of code:

```
crates/antseal-core/src/verify/report.rs:282
    pub const ALL: [Self; 7] = [ Proven, ValidAtStampingCertSinceExpired,
        Attested, Pending, InternallyConsistentOnly, Invalid, Absent ];
```

Report v1 carries all seven states, `Invalid` among them, and has since the
freeze. There is no state R12 can populate that v1 does not already have. The
module's own doc comment says so in the imperative — `:320-321`: *"M0 reports
carry `Absent` state and `None` everywhere; **A18/R12 populate real data at
M2**"* — with no version bump contemplated anywhere in the type.

**Ruling 1. Re-emit `testdata/vectors/v1/report/verification-reports.json`
with `"invalid"`. `REPORT_VERSION` stays `1`. No `v2/` directory is created.**

### 2a. Re-emitting is not the same as the ceremony being waived

`testdata/vectors/v1/FROZEN.sha256:48` reads `#! status frozen`, and
`testdata/vectors/README.md:416` says a byte change post-freeze is *"refused.
A byte change is a format event needing a new format version."* That sentence
is written for a `v1/` directory whose vectors pin **format** artifacts —
manifest bytes, bundle bytes, commitments — where "the bytes moved" and "the
format moved" really are the same statement. The `report` kind broke that
identity the moment it landed: its pinned bytes are a *function of the
verifier*, which is not frozen and by design keeps changing through M2, M3
and M4.

So the ceremony applies in full (`--update`, a moved digest, a justified
commit) and the *classification* does not. That gap is the vocabulary defect
this record fixes:

**Ruling 4 — the standing rule.** A moved report pin has exactly three
possible causes, and a commit that moves one must name which:

| Class | Cause | Costs |
| --- | --- | --- |
| **FORMAT EVENT** | D29 surface moved: a field added/removed/reordered, an encoding or enum spelling changed, `REPORT_VERSION` bumped | a report-version bump; the R32 coupled-edit procedure |
| **VERDICT EVENT** | the same bundle now verifies to a different *value* in an existing field of an existing type | re-emit + `--update` + a justified commit; **no** version bump. R12 is the first |
| **FIXTURE EVENT** | the *input bundle* changed — different fixture bytes, so `bundle_sha256` moves | the largest: it moves frozen `bundle`/`manifest` vectors too. §5 |

A VERDICT EVENT is legal after the freeze; a FIXTURE EVENT over a frozen
v1 vector is not, absent its own decision. The three are told apart
mechanically, not editorially: **a VERDICT EVENT never moves `bundle_len` or
`bundle_sha256`, and a FORMAT EVENT moves every one of the 21 cases** (that
is what R32 measured when `report_version` 0 → 1 rewrote all 21 at once,
`tasks/R.md` R32). R12 moves one case and zero bundle digests.

## 3. D84's v2 sentence is stale — and its staleness has a second cause

D84 §7's second checklist row (`docs/decisions/D84-anchor-artifact-limits-permanence.md:245-251`)
says:

> M2's anchor stage will populate anchor states that report v1 does not carry
> and will therefore ship report **v2**; that is ordinary versioned evolution

The brief guesses it predates D8. Verified: **it is false for a simpler and
older reason than D8.** D84 is dated 2026-07-28 and R32 — the bump that
froze `REPORT_VERSION = 1` — landed the same day, in the same wave. The
seven-variant `AnchorState` was already in `report.rs` when D84 was written.
The row was never true; it was an assumption made without opening the file
its own §7 freezes, and D8's later "no subset at all" ruling (README index
row for D8) only makes it *doubly* untrue by closing the wire side as well.

The row's placement is its own defect: it is a **prediction about a future
milestone**, sitting inside a `FREEZE-BOUNDARY` block whose job is to
*delimit* what is frozen. Predictions do not belong there; a delimiting row
cannot go stale, and this one did within hours.

**Ruling 4a. Amend it.** The amendment is a **three-file byte-identical
edit** — `scripts/check-traceability.py --freeze-boundary` compares D84 §7's
blockquote against `tasks/Q.md:180-210` and
`docs/format/anchor-artifact-limits.md:110-140` (the latter's copy is at
`:133-139`; `tasks/Q.md`'s row is ticked `- [x]`, which the check tolerates
post-Q49). The exact replacement text is §9.

## 4. The finding: the third instrument cannot go red, and four documents say it will

`docs/decisions/D84-...:88-94` states, as the load-bearing evidence for its
whole line-123 safety argument:

> This is asserted on disk, **as an equality, not an intention**.
> `crates/antseal-core/tests/verify_fuzz.rs::m0_anchor_artifacts_are_inert_until_r12_wires_the_anchor_stage`
> — a test **written to go red when R12 lands**, with the instruction to
> invert it

The test (`crates/antseal-core/tests/verify_fuzz.rs:353-372`) takes the
`valid-multi-file-anchored` seed bundle, locates the literal
`b"fixture .ots artifact"`, flips each of its 21 bytes in turn, and asserts:

```
assert_eq!(drive(&mutated), Outcome::Verified,
    "an OTS artifact byte became verdict-bearing. If R12 has landed, this
     test has done its job: invert it, …");
```

`Outcome` has exactly two variants (`crates/antseal-core/src/test_util/bundle_mutators.rs:438-446`)
and `drive` (`:471-476`) is:

```
match verify_bundle(bytes, &VerifyOptions::new()) {
    Ok(_) => Outcome::Verified,
    Err(err) => Outcome::Rejected(err.code()),
}
```

The report is **discarded** (`Ok(_)`). So the test measures one bit: did the
bundle verify? And D84's own rule **F2** (`:146` region, *"never fails bundle
decoding, never fails the evidence layer … never changes the manifest
verdict"*) guarantees that bit never moves — at M2 or ever. That guarantee is
already demonstrated by the brief's own evidence: the R9 vector *regenerated*
a report for case 19, and a report only exists for a bundle that passed
(D27 §4, restated in D86's index row). `verify_bundle` returns `Ok`.

Flipping a byte inside 21 bytes of ASCII that were never a parseable `.ots`
yields 21 bytes of ASCII that are still not a parseable `.ots` — `invalid`
before, `invalid` after, `Ok` both times. **The test stays green through
R12, and would stay green through any correct implementation of it.**

The claim propagates to five sites, none of which check it:

1. `docs/decisions/D84-anchor-artifact-limits-permanence.md:88-94` — the source
2. `docs/format/anchor-artifact-limits.md:89-94` — A27's hand-made mirror
3. `docs/security-assumptions.md:459-465` — *"that one is a moving boundary, so the test that pins it is written to go red when R12 lands, with the instruction to invert it"*
4. `docs/format/Q14-freeze-gate-plan.md:111` — row N1's evidence column: *"The last one is the row's own load-bearing evidence: it pins, **as an equality**, that M0 renders every anchor `absent` and no verdict depends on artifact internals"*
5. `crates/antseal-core/src/test_util/bundle_mutators.rs:288-304` — `GraftAnchors`, *"the section-level twin … written to go red at the same moment"* (same `drive`, same blindness)

Site 4 is the sharpest: it is the Q14 gate's recorded evidence, and it
overstates by exactly one word. The test pins that no anchor byte changes the
**bundle's accept/reject outcome**. It does not pin that no **verdict**
depends on artifact internals — nothing in the tree pins that, and nothing
ever did.

This is, structurally, D84's own "correction to the correction" recurring:
normative prose about a mechanism, mirrored by hand into places no lint
reaches, asserting a property the mechanism does not have.

### 4a. What to do with it — do NOT invert it

Two propositions were conflated:

- **P1** — *no anchor byte changes the bundle's accept/reject outcome.* True
  at M0, **true forever** under F2. This is what the test measures.
- **P2** — *no verdict depends on anchor artifact internals.* True at M0
  only; R12 ends it. **Nothing measures P2.**

Inverting the test would assert `Rejected` after a byte flip, which F2
forbids — R12 would be implemented wrongly to satisfy it. Asserting a
*changed report state* instead is unsatisfiable too: with synthetic bytes,
every flip yields `invalid` either way.

**Ruling 4b.** Keep the test, keep its assertion, **re-title it** as the
permanent F2 guard it has always been (F2 currently has no other mechanism),
and delete the "invert it" instruction from all four prose sites and the
`GraftAnchors` doc. P2's successor is A21 rows 1–2 (wrong-digest `.ots`/TSA
→ `invalid`), which are red-capable because they run against A25's **real**
material where a flipped byte genuinely moves `proven` → `invalid`. Task
**R67**.

## 5. Is `"invalid"` right — or should the fixture get real bytes?

`"invalid"` is right, on three independent grounds, and the synthetic bytes
must stay.

**5a. D84 F3 mandates it.** *"Not `absent` (the artifact is present), and not
`internally-consistent-only` (that state means well-formed-but-unanchored; an
artifact we refused to finish reading is not known to be well-formed)."* An
artifact we could not begin reading is a fortiori not known to be well-formed.
This also matches D53/D56's partition principle — `invalid` iff the artifact
makes a claim the verifier can refute from material it already trusts; a
21-byte string with no OTS magic header refutes itself.

**5b. R12's own Accept already says the seven states come from elsewhere.**
`tasks/R.md:149` — *"Bundles carrying each of the 7 states produce reports
with that state populated (**fixtures from A**)"*. R6's shape catalogue is
the **report byte-format** catalogue; its job is to cover structural report
shapes, and `multi-file-anchored/mixed` exists to pin *a populated anchor
array* against *an empty one*, which it still does. It was never the place
the state machine gets documented. The place for that is the **`anchor`
vector kind already reserved for M2** (`testdata/vectors/README.md:206-207`,
an explicit Q4 accept that it needs no envelope change), landed by A22 — and
adding a vector is legal forever (`:415`, *"additions stay legal forever"*).

**5c. Swapping in real bytes is a FIXTURE EVENT with a large blast radius,
for zero gain.** The synthetic bytes at
`crates/antseal-core/src/test_util/bundle_fixtures.rs:1419-1445` are not only
in the report vector. `AnchorSet::OneOtsTwoTsa` is the `"anchors":
"one-ots-two-tsa"` case of the **frozen** `bundle/bundle.json`, whose
`bundle_bytes` are the v1 `.sealproof` format's committed evidence. Changing
them would move:

- `bundle_bytes` in `testdata/vectors/v1/bundle/bundle.json` (frozen, and a
  genuine format-vector rewrite),
- its `diagnostic` sidecar, hence F14's Python cross-check,
- `bundle_len` **and** `bundle_sha256` in report case 19,
- the `valid-multi-file-anchored` seed-corpus entry and the byte offsets
  `verify_fuzz.rs:360-361` locates by literal.

R6's fixture comment already anticipated this and scoped it correctly
(`:1411-1415`): *"Every artifact byte string here is a schema-opaque
placeholder … What the shapes exercise is the section structure."*

**Ruling 2. `"invalid"` stands; the fixture keeps its synthetic bytes; the
meaningful anchor documentation is A22's appended `anchor` kind, not a
rewrite of R6's.** The re-emitted case then documents something true and
worth pinning: *an unparseable artifact costs its own anchor and nothing
else* — which is F2 and F3 observed end-to-end, and the only committed
evidence for either.

## 6. What the brief did not establish: the diff is not known to be three fields

`vector_report_document_regenerates` reports **the first** difference
(`crates/antseal-core/tests/report_vectors.rs:191`, `first_difference(…)`).
`cases[19].report.anchors[0].state` being first proves nothing about
`anchors[1..]`, `fetch_date`, or `source`.

`fetch_date` is a live candidate. R12's `Do` says *"store the resulting
state, verified time, and **metadata** in the report's anchor slots"*
(`tasks/R.md:147`), the report field exists and is documented as
*"sealer-recorded metadata … verbatim string form"* (`report.rs:355-358`),
and the fixture's two TSA anchors are constructed **with** a fetch date
(`bundle_fixtures.rs:1433`, `:1440` — `FIXTURE_CLAIMED_TIME: u64 =
1_767_225_600`). If R12 populates it, case 19 grows by far more than the
three bytes a pure state change costs.

That is not a re-emit detail; it is a **separate unruled question** — may an
`invalid` anchor render sealer-recorded metadata, when registry §6.1 treats
sealer-written anchor fields as distrusted and D8 removed the TSA `source`
string from v1 on exactly that ground? D94 does not rule it, because the
brief did not surface it and no measurement here settles it.

**Ruling 2a.** The predicted diff for a state-only change is: case 19's
`report_len` **1141 → 1144** (`"absent"` → `"invalid"` × 3), `report_json`
and `report` changed, everything else on all 21 cases byte-identical. **If
`fetch_date` or `source` populate, the orchestrator STOPS and rules that
question before re-emitting** — a frozen vector must not be the place a
metadata-rendering policy is decided by default.

## 7. The R30 in-tree pin — same ruling, lesser ceremony, and it is a *measurement*

`REPORT_DIGEST_BY_SHAPE` (`crates/antseal-core/src/test_util/bundle_fixtures.rs:2184-2290`)
sits in a source file. It is covered by neither `scripts/vector-freeze.sh`
(which reads `testdata/vectors/v1/*.json`) nor `scripts/format-freeze.sh`
(which covers `registry-v1.json` and `registry-v1.md` only). There is no
manifest, no digest line, no `--update`.

**Ruling 3. Same classification (VERDICT EVENT, re-pin, no version bump);
lesser ceremony (the sanctioned ignored emitter + review); and one obligation
the vector side does not carry — the re-pin is a falsification test.**

The R30 table has 26 rows and R12 may move **exactly one**:
`("multi-file-anchored/mixed", "90d663bd64a988b2453d9f736e5bc740fc093a28d3115fb111160c09617e5b2d")`
(`:2283-2285`) — the only catalogue shape with anchors. **If a second row
moves, D84 rule F2 has been breached and R12 is wrong. Fix R12; do not
re-pin.** No other mechanism in the tree tests F2's blast radius over the
whole shape catalogue, and this one is free.

The R30 assertion message (`:2366-2371`) enumerates the same two causes the
vector message does — *"the report byte format changed … or this target
diverged from the other"* — and R12 is neither. Both messages need the third
class. Task **R68**.

## 8. Measured vs. assumed

**Measured on the tree at `edbb4d6`:**

- 21/21 pinned report cases carry `"supporting_evidence": "none"`; case 19 is
  the only one with a non-empty `anchors` array, pinning three `"absent"`.
- `REPORT_VERSION = 1` (`report.rs:72`); `AnchorState::ALL` has 7 variants
  including `Invalid` (`:282-290`); `wire_name` is exhaustive (`:306-316`).
- `Outcome` has 2 variants; `drive` discards the report (`bundle_mutators.rs:438-476`).
- The inertness test asserts only `Outcome::Verified` (`verify_fuzz.rs:353-372`).
- The fixture's `.ots` is `b"fixture .ots artifact"` (`bundle_fixtures.rs:1423`).
- `#! status frozen` (`FROZEN.sha256:48`); the report vector's digest is
  `aa0b99d1…` (`:115`); 13 files frozen in `v1/`.
- `bundle/bundle.json` has exactly one `"anchors": "one-ots-two-tsa"` case.
- `docs/decisions/D30-*.md` does not exist; D30 is `docs/testing/error-code-contract.md`.
- The v2 sentence is inside the `FREEZE-BOUNDARY` block, mirrored in
  `tasks/Q.md:202-208` and `docs/format/anchor-artifact-limits.md:133-139`.

**Assumed, and flagged as such:**

- That R12's held-aside patch returns `Ok` from `verify_bundle` for case 19.
  Inferred from the brief's own evidence (a report was regenerated), not read
  — the patch was not in the tree.
- That the diff is confined to `state`. **Explicitly not established** (§6).
- That `check-traceability.py --freeze-boundary` still tolerates the `- [x]`
  tick post-Q49. Recorded in `tasks/Q.md:922`; the orchestrator must run the
  lint after the §9 edit rather than trust this.
- **Not run**: no emitter, no `--update`, no `cargo test`. This record reads
  and reasons only, per the planning brief.

## 9. Amendments (orchestrator applies at source)
- `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

### 9a. D84 §7 second row — three files, byte-identical, one commit

Replace, in `docs/decisions/D84-anchor-artifact-limits-permanence.md:245-251`
(inside the §7 blockquote, so each line keeps its `> ` prefix),
`tasks/Q.md:202-208` (keeping its `- [x]` tick) and
`docs/format/anchor-artifact-limits.md:133-139`:

```
- [ ] **Report-version evolution is not blocked by this freeze.** The Q14
  freeze fixes report **v1** (`REPORT_VERSION = 1`, per R32 and D29 §8).
  D29 records that adding fields after the freeze requires a version bump,
  not that no bump may occur. M2's anchor stage populates anchor states that
  report v1 **already carries** — `AnchorState::ALL` is all seven at the
  freeze — so R12 moves recomputed verdicts, not format surface, and
  `REPORT_VERSION` stays 1 (**D94**: a VERDICT EVENT re-emits the frozen
  vector under the full ceremony and bumps nothing). A bump remains
  available for a genuine field addition; line 123's promise is that v1
  reports remain verifiable, not that v1 is the last version.
```

Then run `python3 scripts/check-traceability.py --freeze-boundary`; it must
be green before the commit. Record the amendment in D84's dated-corrections
section, noting the placement defect: a *predictive* sentence was placed
inside a block whose job is to *delimit*, and it went stale within hours of
being written.

### 9b. The "written to go red" claim — four prose sites plus one doc comment

At `docs/decisions/D84-...:88-94`, `docs/format/anchor-artifact-limits.md:89-94`,
`docs/security-assumptions.md:459-465`, `docs/format/Q14-freeze-gate-plan.md:111`
and `crates/antseal-core/src/test_util/bundle_mutators.rs:288-304`: the test
pins that **no anchor byte changes the bundle's accept/reject outcome** —
which rule F2 makes permanent — not that no verdict depends on artifact
internals. Delete "written to go red when R12 lands" and "invert it"; state
instead that the test becomes the standing F2 regression guard, and that P2's
successor is A21 rows 1–2. Owned by **R67**, which must land in the same
commit as R12 or immediately after it.

### 9c. `tasks/R.md` R12

1. **`Do` gains the re-emit obligation.** It currently does not mention a
   frozen vector at all, so a lane executing R12 meets two red pinned
   assertions with no instruction. Append: *"Landing this stage changes one
   recomputed anchor state in the frozen R9 report vector and one row of the
   in-tree R30 digest table. That is a **VERDICT EVENT**, not a format event
   (D94): re-emit and re-pin under §10's procedure, `REPORT_VERSION` stays 1,
   and no `v2/` directory is created. Exactly one of 21 report cases and
   exactly one of 26 R30 rows may move; a second is an F2 breach to fix, not
   to re-pin. Do **not** invert
   `m0_anchor_artifacts_are_inert_until_r12_wires_the_anchor_stage` (D94 §4)."*
2. **Accept gains the F2 row that D84 Consequences item 6 asked for on
   2026-07-28 and that was never applied** — verified absent from
   `tasks/R.md:148-151` today: *"An over-limit or unparseable artifact yields
   a decodable bundle with a verified manifest and only its own anchor
   `invalid`; `bundle_len`/`bundle_sha256` unchanged across all 21 report
   vector cases."*
3. **Accept gains the metadata gate** (§6): *"If `fetch_date` or `source`
   populate on an `invalid` anchor, stop and get a ruling before re-emitting."*

### 9d. `tasks/A.md` A22

Append to `Do`: *"These vectors are an **append**, legal after the freeze
forever (`testdata/vectors/README.md:415`) — never a re-emit of R9's
document, whose anchored case is deliberately synthetic (D94 §5). Reconcile
the home first: A22's Accept says `testdata/anchors/` while
`testdata/vectors/README.md:206-207` reserves an `anchor` **kind** under
`testdata/vectors/v1/`; two homes for one artifact class (**Q109**)."*
Append to `Do`: *"A21 rows 1–2 are the red-capable successor to the retired
M0 anchor-inertness equality (D94 §4b); they are the first instruments in the
tree that can observe an anchor byte changing a verdict."*

## 10. The re-emit procedure (orchestrator, in this order)

0. Apply R12. Confirm `cargo test -p antseal-core` fails in **exactly** the
   two named places and nowhere else.
1. **Edit the prose first.** `crates/antseal-core/tests/report_vectors.rs:136-138`
   — the `pins` sentence reads *"each an absent M0 slot"* and becomes a lie
   at R12. It lives in `inputs`, which
   `vector_report_document_regenerates` never compares; the only check is
   `vector_report_emitter_case_list_matches_the_committed_document`
   (`:284-308`), which compares the file against **the same const**, so a
   stale sentence is green on both sides forever. Replace with e.g. *"the
   populated anchor section: one OTS and two TSA artifacts, each a synthetic
   placeholder the M2 anchor stage cannot parse, so each renders `invalid`
   (D84 F3; real material is A22's `anchor` kind)"*. → **Q108**.
2. **Emit**: `cargo test -p antseal-core --features test-util --test report_vectors -- --ignored emit_report_vector_document`
3. **AUDIT THE DIFF BEFORE ANYTHING ELSE.** Required: `bundle_len`,
   `bundle_sha256`, `revealed_unit_ids` byte-identical on all 21; cases 0–18
   and 20 byte-identical; case 19 changed only in `report`, `report_json`,
   `report_len`; `report_len` 1141 → 1144. **STOP** if `fetch_date` or
   `source` populated (§6 / Ruling 2a), or if any `bundle_sha256` moved
   (that is a FIXTURE EVENT and is not authorised here).
4. **Re-pin R30**: `cargo test -p antseal-core --features test-util --lib -- --ignored emit_r30_report_digest_table --nocapture`,
   paste into `REPORT_DIGEST_BY_SHAPE`. **Exactly one row may move** —
   `multi-file-anchored/mixed`, from `90d663bd64a988b2…`. A second moving row
   means R12 breached F2: fix R12, re-run from step 2.
5. **`./scripts/vector-freeze.sh --update` — REQUIRED.** Exactly one digest
   line moves: `report/verification-reports.json`, from `aa0b99d1d29e56e1…`
   (`FROZEN.sha256:115`). `INDEX.json` is untouched (no new vector, no new
   kind, no pending migration). Do **not** run `scripts/format-freeze.sh
   --update` — the registry does not move.
6. `cargo test -p antseal-core vector_` — runner, freeze and index together.
7. `./scripts/wasm-bitmatch.sh` — the vector is embedded by
   `crates/wasm-bitmatch/build.rs`; native and wasm32 must stay byte-identical.
   The +3 bytes are far inside D87's `v1` budget (590 280 B of 2 MiB).
8. Apply §9a and run `python3 scripts/check-traceability.py --freeze-boundary`.
9. Gate: `cargo fmt`, `cargo clippy`, full suite, wasm32 build.

**The commit message must state, and be checkable against the diff:**

- the classification and its authority — *VERDICT EVENT, not a format event
  (D94 §2); `REPORT_VERSION` stays 1 because report v1's `AnchorState`
  already carries all seven states (`verify/report.rs:282-290`)*;
- the rule the new value comes from — *D84 §4 rule F3: an artifact the
  verifier will not finish reading renders `invalid`, not `absent`, not
  `internally-consistent-only`*;
- the four measurements, as numbers: **1 of 21 report cases moved; 1 of 26
  R30 rows moved; 1 of 13 freeze digests moved; 0 bundle digests moved** —
  the last being the sentence that distinguishes this from a format event;
- that `report_len` moved 1141 → 1144 and why (three `"absent"` → `"invalid"`).

## 11. Discovered work

### R67 — Retire the M0 anchor-inertness equality; re-title it as the F2 guard
- Milestone: M2 · Size: S · Deps: R12
- The test cannot go red at R12 (§4) and four documents plus one doc comment
  say it will. Re-title
  `m0_anchor_artifacts_are_inert_until_r12_wires_the_anchor_stage` to name
  what it measures (D84 rule F2: anchor bytes never move the bundle's
  accept/reject outcome), keep the assertion unchanged, and correct the five
  sites in §9b. Accept: the F2 guard is green post-R12 with a name that
  claims only what it proves; no site still says "invert it"; the Q14 gate
  plan's row N1 evidence column no longer claims the equality covers verdicts.

### R68 — Give the two report-pin assertion messages the third cause
- Milestone: M2 · Size: XS · Deps: R12
- `crates/antseal-core/tests/report_vectors.rs:186-190` and
  `crates/antseal-core/src/test_util/bundle_fixtures.rs:2366-2371` each
  enumerate two causes for a moved pin; R12 is a third (§2a). Both messages
  must name FORMAT / VERDICT / FIXTURE and say which ceremony each costs, so
  the next lane is not told a verdict change is a format event by the very
  assertion that catches it.

### R69 — `SupportingEvidenceResult::ArbitrumReceipt` lands post-freeze with no vector and a stale doc comment
- Milestone: M2 · Size: S · Deps: R12
- `crates/antseal-core/src/verify/report.rs:365-366` says the receipt arm is
  *"a pre-Q14 extension per D29"* — Q14 executed on 2026-07-28, so R12 adds
  a **post-freeze** variant to a serialized enum. D94 does not reach it (no
  pinned case exercises it, so nothing went red), and that is precisely the
  problem: a new value enters report v1's value space **with no golden vector
  and no red test**. Decide whether adding a variant nothing emits is inert
  (D29 rule 9: `Serialize` only, nothing parses report bytes) or a format
  event, correct the doc comment, and commit a case that actually renders
  `arbitrum-receipt` — the `every-kind` bundle shape already carries a
  receipt and is not in R9's document.

### R70 — Is `AnchorState::Absent` reachable after R12?
- Milestone: M2 · Size: XS · Deps: R12
- D84 F3 forbids `absent` for a present artifact, and a bundle with no
  anchors emits an empty array rather than an `absent` slot. If no path
  produces it, report v1 carries a state nothing emits, R9's structural
  coverage claim (*"some case yields an empty anchor list, some other a
  populated one"*, `testdata/vectors/README.md:186`) needs restating, and
  `error_universe.rs:193`'s "no `AnchorState`" note may need a companion.
  Either document the surviving producer or record the state as
  format-retained-but-unreachable — never silently.

### Q107 — Add the three-class event vocabulary to the freeze policy
- Milestone: M2 · Size: S · Deps: D94; Q27
- `testdata/vectors/README.md:413-419`'s "What changes at Q14" table has one
  row for "change a vector's bytes" and one verdict for it. Split it into
  FORMAT / VERDICT / FIXTURE per §2a, with the mechanical discriminator
  (`bundle_sha256` moved? how many of 21 cases moved?), and carry the same
  text into Q27's format-stability policy. Without this, the next lane reads
  `:416` literally and mints report v2.

### Q108 — A vector's `pins` prose is compared only against its own emitter
- Milestone: M2 · Size: S · Deps: Q4
- `vector_report_emitter_case_list_matches_the_committed_document`
  (`report_vectors.rs:284-308`) compares the committed `inputs.cases[].pins`
  against the `CASES` const that generated them — both sides move together
  or neither does, so a sentence that becomes false (as
  `report_vectors.rs:137`'s does at R12) stays green forever in a **frozen**
  file. Decide: bind `pins` to something falsifiable, or record explicitly
  that vector prose is unchecked and must be reviewed by hand at every
  re-emit. Same shape as the `INDEX.json` `pins` field.

### Q109 — A22's anchor vectors have two specified homes
- Milestone: M2 · Size: XS · Deps: A22 (must resolve before A22 starts)
- `tasks/A.md:272` puts them under `testdata/anchors/`;
  `testdata/vectors/README.md:206-207` reserves an `anchor` **kind** under
  `testdata/vectors/v<n>/` with the envelope, the runner, `FROZEN.sha256`,
  `INDEX.json` and the wasm bit-match already wired for it. Only the second
  gets retention, freeze and native↔WASM parity for free — ~~which are three of
  A22's four Accept rows~~. Pick one before A22 builds against the other.

  — **Corrected 2026-08-11 by [D103](D103-upgraded-ots-vector-provenance.md)
  §7.2 RULING 6a, under [D117](D117-resolved-decision-corrections.md)
  §2.3 (b)**; see "Correction — §11's Q109 bullet miscounts A22's Accept rows,
  2026-08-11" below. The count is **dropped, not restated** — A22's Accept is
  numbered (D103 §7.1) so that nobody counts it again — and the corrected
  citation-by-number lives in that section and nowhere else (D117 §2.3 (c)).
  **Q109's ruling stands**: D101 RULING 1 picked Home B, and the error runs in
  the direction that strengthens the case for it. **`Q109` is not renumbered**
  (D117 RULING 4).

### Q110 — Sweep for prose that predicts a test will fail at a future task
- Milestone: M2 · Size: M · Deps: Q64
- The defect in §4 is a class: a document asserts that a named test will go
  red at a named future task, nothing binds the claim, and the task arrives
  to find the instrument blind. Q64 already owes a lint over D84's F1–F4
  block; extend the sweep to every *"written to go red"* / *"will fail
  when"* / *"invert it"* claim in `docs/` and in doc comments, and for each
  either bind it to a real assertion or delete it. Start from the five sites
  in §9b — they are one claim, copied.

## 11a. Dated corrections — what executing this record measured (2026-08-06)

R12 landed the same day this record was written. Four of its claims did not
survive the execution, and they are corrected here rather than in the reader's
head.

1. **§4's "nothing measures P2" was too strong.** This record concluded that
   no instrument in the tree observed whether a verdict depends on artifact
   internals, and named A21 rows 1–2 as the first that would.
   `tests/anchor_aggregate.rs::vector_every_anchor_kind_bundle_is_all_absent_and_unanchored_at_m1`
   reads report **states** rather than the accept/reject bit, and went red at
   R12 exactly as an M0-inertness claim should. The §4 finding stands for the
   instrument it was about; the generalisation does not. **R71.**
2. **§10 step 0's "exactly two red places" was five.** The two named, plus the
   vector runner reaching the same document through a second binary, plus a
   doc-pointer lint catching a line-wrapped identifier **inside the held-aside
   R12 patch**, plus item 1. And **two more went red after step 2** rather than
   before it — `anchor_verdict_report_freeze.rs` reads the committed document,
   not a recomputed report, so the emit is what reddens it. Both named the
   wrong cause, and one is the **sixth** copy of D84 §7's stale report-v2
   claim, in a **fourth** file that §9a's three-file amendment does not reach.
   **R75.**
3. **§10 step 5 called `./scripts/vector-freeze.sh --update` REQUIRED, and the
   script refused it.** Ruling 4 says the three classes are told apart
   mechanically, not editorially — but the only mechanism in the tree
   implemented the two-class world the ruling replaced. Fixed by teaching the
   script the class as a **checked** flag that re-derives the classification
   from the diff rather than trusting an assertion. **Q114.**
4. **§6's unresolved question was resolved, and its lean was overturned.** The
   STOP fired on `fetch_date` alone; `source` is `null` on all three slots
   because both `invalid` arms pass `None`. **D95** rules RENDER,
   unconditionally and with no state gate — §6's reading of registry §6.1 as
   an authority for suppression does not survive: §6.1's rule is *do not
   consume, MAY display as a sealer-asserted claim*, and it says it about
   `anchor_status`, the sealer's own competing verdict claim.

What did survive, unchanged: Ruling 1 (re-emit, not report v2), Ruling 2
(`"invalid"` is correct and the synthetic bytes stay), Ruling 2a's byte
prediction for the state half (+3), Ruling 3's "exactly one of 26 R30 rows may
move" — which passed and is the only test of F2's blast radius the tree has —
and Ruling 4's three-class vocabulary, which is now enforced as well as
written.

## 12. Residual risks and revisit triggers

- **The re-emit is authorised on an unread patch.** R12's implementation was
  held aside and this record reasons from the brief's reported failure
  output. If the patch's diff exceeds §6's prediction, the ruling on
  classification still holds but Ruling 2a's stop applies. Trigger: any
  populated `fetch_date`/`source`.
- **`multi-file-anchored/mixed` now pins a degenerate verdict forever.** The
  case documents "an unparseable placeholder costs its own anchor and nothing
  else" — true and load-bearing for F2/F3, but it means R9's document never
  exhibits `proven`, `pending` or `attested`. That is A22's job by design;
  the risk is A22 not landing and M2 exiting with no committed evidence of a
  successful anchor. Trigger: A22 slipping past the M2 exit checklist.
- **The VERDICT EVENT class is a door.** It says a frozen vector's bytes may
  move without a version bump when the verifier legitimately changes its
  mind. That is correct and unavoidable — the verifier is not frozen — but it
  is quotable. The containment is the mechanical discriminator in §2a
  (`bundle_sha256` unmoved, and a count of moved cases), not the adjective.
  Trigger: any commit claiming VERDICT EVENT that moves more than one case
  without naming the additional cause.
- **A21's rows are now the only planned instrument for P2.** If A21 slips or
  its rows are built against synthetic material, the tree returns to having
  *no* mechanism asserting that anchor internals are verdict-bearing — the
  same blindness, one milestone later. Trigger: any A21 row whose fixture is
  not from A25.

---
## Correction — §11's Q109 bullet miscounts A22's Accept rows, 2026-08-11

**The sentence, quoted verbatim, from §11's `### Q109` bullet** — cited
everywhere else as `D94:554-555`; this correction cites it by section, per
D117 RULING 6:

> Only the second gets retention, freeze and native↔WASM parity for free —
> which are three of A22's four Accept rows.

**Disposition: STRIKE, and the sentence stays standing (D117 §2.3 (b)).** §11
is this record's discovered-work list, and the bullet's instruction — *"Pick
one before A22 builds against the other"* — was executed on 2026-08-07, when
D101 RULING 1 picked Home B. No lane will act on it; the sentence's value is
the record of what this record believed on 2026-08-06. Because the count is
**dropped** rather than restated, there is no scalar to carry inline
(D117 §2.3 (c)) and the strike is the whole of the edit at the site.

**(1) The original figure.** *"three of A22's four Accept rows"*, in §11's
`### Q109` bullet.

**(2) The new figure: none — the count is dropped.** D101 §2.2's own fallback,
*"or delete the count — a count that has been wrong in three places at once is
not load-bearing enough to keep"*, taken by D103 RULING 6: *"the defect class
is counting and the fix is to make counting unnecessary."*

**(3) The predicate, and the commands.** A22's `Accept` rows, counted at two
epochs (D117 RULING 5's epoch rule — a count over a mutable corpus is
meaningless without the commit it was taken at):

```
$ git show a053272:tasks/A.md | awk '/^### A22 /,/^### A23 /' \
    | sed -n '/^- Accept:/,/^- Notes:/p' | grep -c '^  - '
3
$ awk '/^### A22 /,/^### A23 /' tasks/A.md | grep -c '^  - \*\*[0-9]\.\*\*'
4
```

`a053272` is the commit that created this record (2026-08-06), so the first
figure is what A22 read on the day the sentence was written. The second is
today's, after D103 §7.1 replaced the `Accept` with four **numbered** rows.

**(4) Which defect: WRONG WHEN WRITTEN, not gone stale.** A22 had **three**
`Accept` rows on 2026-08-06 and this record said four. The mechanism is the one
D101 §2.2 measured: the old row 1 — *"Vectors committed under
`testdata/anchors/`; retained forever in CI per format-stability policy (Q
wiring)."* — is a home clause and a retention clause joined by a semicolon, so
counting clauses gives four where counting rows gives three. D53 had already
recorded the same expansion on A21, before this record was written.

**(5) The citation by number, which is what replaces the count — and it is not
the pair D103 §7.2 prescribes.** RULING 6a's instruction is *"the D94 sentence
becomes 'which are A22 Accept rows 1 and 2'"*. **That pair is the pre-§7.1
numbering and does not survive §7.1's own renumber.** Against the `Accept` as
D103 §7.1 wrote it, the three properties this sentence names are supplied by
**rows 2 and 3**:

| property named in the sentence | the row that supplies it, per D103 §7.1 |
| --- | --- |
| retention | **2.** *"Frozen and retained … retained forever per Q6's per-version retention policy"* |
| freeze | **2.** — the same row, *"Frozen and retained"* |
| native↔WASM parity | **3.** *"Native and wasm runs produce byte-identical `recomputed_digest` for every vector"* |

Row **1** is the home row — the *subject* of *"only the second"*, not one of
the properties it supplies. It names all three properties, but only in its
*"Not `testdata/anchors/`, which … carries no freeze, no retention rule and no
wasm parity lane"* clause, which is what the refused home lacks; a reader who
counts that as a supplying row re-derives the wrong pair. Row **4** is the M2
exit checklist. Under the three-row `Accept` RULING 6a was reading from —
retention inside row 1, parity in row 2, freeze in neither — *"rows 1 and 2"*
was correct, which is why it was written. **The corrected reading is therefore
`which are A22 Accept rows 2 and 3`.** RULING 6a's disposition is applied in
full; its example text is not, and the reason is recorded here rather than
propagated silently. Whether D103 §7.2's own text takes a correction is D103's
to make, not this record's (D117 §2.3 (e)).

**A second defect D101 §2.2 found in this sentence has since cured itself.**
§2.2's item 2 — *"all three sources name 'freeze' as an A22 Accept property,
and no A22 Accept row mentions freeze"* — was true on 2026-08-07 and is false
today: D103 §7.1's row 2 is *"Frozen and retained"*. The sentence's *"retention,
freeze"* is now exactly one `Accept` row. Only the count was ever wrong, and
only the count is struck.

**(6) Does the conclusion survive? Yes, and slightly strengthened.** The
bullet's claim is that only the reserved `anchor` **kind** supplies retention,
freeze and wasm parity without new machinery, and that A22 must pick a home
before it builds. D101 RULING 1 picked Home B on five committed sources
against one, and D103 §7.1's `Accept` now asks for the freeze the old `Accept`
never did. Every error above runs in the direction that strengthens the
bullet.

**Authority, and who executed it.** `Q187`, under D117 RULING 1 and §5.4,
discharging two orders that were issued and never ran:

- **D101.** The order is the closing sentence of **§2.3** — *"And amend
  `tasks/Q.md:1373`, `TODO.md:529` and `D94:554-555` to 'three of A22's three
  Accept rows', or delete the count …"* — with this record's site tabulated in
  **§2.2** and the edit repeated in **§10**'s edit set, whose `§` column
  attributes it to §2.2. D117 §1.10 and `TODO.md`'s `Q187` row both cite it as
  *"D101 §2.2 / §7"*: **§7 is *"Ruling 6 — the artifact bytes"* and carries no
  such order**, and §2.2 carries the diagnosis and the table of sites but not
  the imperative.
- **D103 §7.2 RULING 6a**, which re-issued it with the disposition applied
  above, and repeated it in **§12**'s edit set.

Executed by the `Q187` lane of M2 wave 15, which re-measured every figure here.

**Separability (D117 §2.1 (c)).** This correction lands in a commit distinct
from `a053272`, which created this record, and from `5f758de`, which executed
it.

**Which rulings stand (D117 §2.2, required content 4).** All of this record's.
The corrected sentence is in §11, the discovered-work list; no ruling rests on
it. Rulings 1–4, §2a's three-class vocabulary and §4's finding about the third
instrument are untouched by the count.

**Identifier discipline (D117 RULING 4).** `Q109` is not renumbered, and
neither is §11. The sites that cite this bullet are: D101's front matter
(`Corrects:`), its §2.2 table and its §10 edit set; D103 §7.2 and its §12 edit
set; D117 §1.10, §5.4, §7 and §8 (iii); `tasks/Q.md`'s `Q109` and `Q187`
entries; and `TODO.md`'s `Q109` and `Q187` rows. **Every one of them cites it
as `D94:554-555` or `D94:555`.** This correction mints no successor line
number for them (D117 RULING 6); the durable handle is §11's `### Q109`
bullet.
