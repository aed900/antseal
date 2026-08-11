# D95 — May a refuted anchor render sealer-recorded metadata?

- **Status: RESOLVED — RENDER, unconditionally, with no state gate.**
  `AnchorResult::fetch_date` is rendered in every state that emits a slot,
  `invalid` included, as the **decimal POSIX-seconds** form of the wire
  `uint` (`u64::to_string()` — no separator, no timezone, no date form).
  That spelling is **format-permanent for report v1**: it is the same
  spelling `claimed_time_informational_only` froze at Q14, over the same
  kind of value, and in case 19 over the *numerically same* value. The
  `source` half of the question **was never open** — D53 §4 rules it, and it
  is measured moot for the vector that forced the STOP. The honesty
  obligation this creates is discharged by a **label**, owned by R18, never
  by conditional presence: a state-gated field would publish the false
  implicature that a visible `fetch_date` had been corroborated by the state
  it sits under, when the field is unverifiable in **every** state. Rider
  (c) converts that safety argument from inspection into an equality
  (**R72**).
- **Date: 2026-08-06** (M2 wave 6; unblocks R12's re-emit, consumed by R17,
  R18, R23, A21, A22)
- **Owning tasks: R12** (executes the re-emit under this ruling), **R18**
  (owns the label), **R72/R73/R74** (the discovered work below). Register
  entry: the D95 row under `TODO.md` "Due M2".
- **Method**: two independent planners, each charged with the opposite side
  and briefed to overturn the register's own lean. The planner assigned
  SUPPRESS reported **against its own charge**. Both computed the predicted
  re-emit by hand; one predicted the post-R12 R30 digest as
  `e450be73…ff8e`, which the machine then produced byte-for-byte.

---
- `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

## 1. Why this decision exists at all

D94 §6 / Ruling 2a ordered a **STOP**: if the R12 re-emit populated
`fetch_date` or `source` on an `invalid` anchor, the orchestrator must rule
the question before re-emitting, because *"a frozen vector must not be the
place a metadata-rendering policy is decided by default"*.

**Measured, on the applied patch:** the STOP fires, and it fires on
`fetch_date` alone.

`crates/antseal-core/src/anchor/verdicts.rs:1059` binds
`let fetch_date = Some(view.fetch_date().to_string());` **before** T1/T2, and
the T1/T2 early return — the arm an unparseable token takes — carries it into
`AnchorVerdict::invalid` while passing `None` for `source`, under the comment
*"no source at all: nothing was parsed far enough to claim one."*

The arithmetic closes exactly, which is how we know nothing else moved:

| slot | kind | `state` | `source` | `fetch_date` | Δ bytes |
| --- | --- | --- | --- | --- | --- |
| 0 | `ots` | `absent` → `invalid` | `null` | `null` (no D79 upgrade group to hold one) | +1 |
| 1 | `tsa` | `absent` → `invalid` | `null` | `null` → `"1767225600"` | +1 +8 |
| 2 | `tsa` | `absent` → `invalid` | `null` | `null` → `"1767225600"` | +1 +8 |

`report_len` **1141 → 1160**, and the R30 canonical report for
`multi-file-anchored/mixed` measured **1160 B** on the failing assertion —
+19, every byte accounted for. `source` is `null` six times out of six, so
**case 19 cannot exercise the `source` question at all.**

The OTS slot renders no `fetch_date` under any ruling, by *availability*, not
by rule: registry §7.9 key 3 is `req` for TSA, while the OTS counterpart lives
in §7.8's all-or-nothing D79 upgrade group and this fixture has none. **Do not
read case 19's asymmetry as a kind inconsistency to fix** — `verdicts.rs:681`
applies the identical policy on the OTS side.

## 2. The ruling, and the argument that decides it

`fetch_date` is sealer-written and bound by nothing **in every state**. The
bundle is unsigned (registry §7.6.1); `anchor_digest` covers the manifest
envelope, and the anchor sections are bundle keys, outside it. And the one
available cross-check is not merely unperformed but **normatively
prohibited**: D59 §6(a) forbids comparing a token's `genTime` against a
capture clock *"in any direction — not `gen_time <= fetch_date`, not a skew
window, not a warning"*, off a measurement of a dev machine 129 s slow that
would have rejected every real FreeTSA token in `testdata/anchors/`.

So the field's trustworthiness **does not vary with the state**. A rule of the
form *hide it on `invalid`, show it on `proven`* would therefore encode a
verification distinction that does not exist, and publish it to every
downstream consumer as: *a `fetch_date` you can see has been vouched for by
the state it sits under.* It has not been, and cannot be.

The inversion is sharper. The only benefit anyone can name for the `proven`
case — a human eyeballing `fetch_date` against `verified_time_unix` — **is
itself the inference D59 §6(a) prohibits.** If adjacency is the harm, then
rendering the field next to a *verified* time is the more dangerous
adjacency, not the less. Suppression-on-`invalid` removes the value from
precisely the slot where it is least likely to be misread as corroborated,
and leaves it where it is most likely to be.

**Ruling 1. Render `fetch_date` in every state that emits a slot. No state
condition. The rendering is `u64::to_string()` — decimal POSIX seconds — and
that spelling is format-permanent for report v1.**

### 2a. The precedent is already frozen in the report's own bytes

The decisive evidence is inside case 19 itself. Its frozen `report_json`
contains:

```
"claimed_time_informational_only":"1767225600"
```

A sealer-recorded wire `uint` (registry §7.2), never verified by anything,
rendered as a decimal-seconds JSON string, **unconditionally in all 21 cases**
— and in case 19 it is *numerically the same value* as the `fetch_date` under
dispute, because both come from `FIXTURE_CLAIMED_TIME = 1_767_225_600`.
Emitted by `crates/antseal-core/src/verify/pipeline.rs` as
`Some(body.claimed_time().to_string())`; documented at
`crates/antseal-core/src/verify/report.rs:171-178` as *"Informational only —
never verified, never headline-eligible. The field name carries the marker
into the serialized bytes so no consumer can miss it."*

So the project's settled technique for an unverified sealer-recorded time in
the report is **render + label**, it was frozen at Q14, and D95 applies it
unchanged. `AnchorResult` is not a special jurisdiction; it is the one struct
where the label is a *sibling field* (`state`) rather than a name suffix.

Nor would `fetch_date` be the weakest claim in the report. `WorkMetadata`'s
`title` and `app_version` are sealer-written and render with **no** trust
caveat at all, under a struct doc that calls the group *"Work-level metadata
as verified from the bundle"* — which over-claims for three of its five
children (**R73**).

### 2b. `null` is not the neutral choice it looks like

Registry §7.9 key 3 is **`req`**: *"always known at seal, hence required where
the OTS counterpart is optional."* Every TSA artifact in every valid v1 bundle
has a `fetch_date`. A report rendering `"fetch_date":null` on a TSA slot
therefore asserts something that **cannot be true of any bundle that reached
the anchor stage** — it would be lying about the bundle's shape in order to
protect the reader from a number.

The datum also discriminates two failures a triager must tell apart. Under
this ruling case 19 reads: *the sealer records receiving a `TimeStampResp` at
1767225600, and what it stored is not a `TimeStampResp`* — a capture-path
defect, timestamped. Under suppression it reads *this is not a token*, which
is indistinguishable from a bundle hand-assembled with no capture ever
performed. A product whose thesis is *preserve the evidence, label its
weight* does not delete evidence for being weak.

### 2c. What does **not** decide it

Recorded so nobody re-runs these:

- **D29 does not forbid suppression.** Rule 4 bans `skip_serializing_if` and
  requires the key to serialize every time, with *"absence expressed by
  `null`"*; `verified_time_unix` is already a state-conditioned `null`. A
  conditional `fetch_date` would have been legal, and cheap — one line inside
  `AnchorVerdict::invalid`, which already forces `AnchorSource::Claimed` and
  so would make the rule unforgeable by any caller. **Suppression loses on
  meaning, not on mechanism or cost.**
- **There is no spec line requiring the render.** `fetch date` appears in
  MVP-SPEC.md at exactly lines 108 and 114, both describing *bundle content*.
  Lines 127–137 are the verdict taxonomy and the headline rule and never
  mention it. The doc comment claiming otherwise is mispointed (§4, **R73**).
  This ruling stands on §6.1's display permission, the frozen `claimed_time`
  precedent, D53 §4 and forensics — not on a mandate, because there isn't one.
- **Registry §6.1 is not the authority for suppression that D94 §6 read into
  it.** Its rule is *do not consume; MAY display as a sealer-asserted claim*,
  and it says that about **`anchor_status`** — the sealer's own competing
  verdict claim, the most dangerous field in the section, the one set to
  `proven` on all three of case 19's garbage artifacts. If §6.1 permits
  displaying *that*, it cannot forbid displaying a capture instant.

## 3. `source` is not this decision's

D53 §4's "What each state carries" table already rules it: a *claimed*
identity on `internally-consistent-only` and `invalid`, *rendered as claimed*.
It is mechanized — `AnchorSource::{Verified, Claimed}` with constructors that
choose the variant from the state, pinned by
`source_verification_kind_is_chosen_by_the_state` — and restated in the
imperative at `report.rs`'s `source` doc. Suppressing an *identity* is the
strictly more dangerous move (it is the value MVP-SPEC line 137's headline
template names in parentheses) and the project already ruled it permissively.

**Ruling 2. D95 does not reopen D53 §4.** A ruling that suppressed a *date*
on `invalid` while D53 authorises an *identity* there would be incoherent.
D53 §4's table has no `fetch_date` column — that silence is the gap D95
fills, and D94 §6 was right to call the STOP; it simply read the silence as a
lean.

## 4. The label is owed, and is currently undischarged **and unreachable**

RENDER without the label takes half of §2a's precedent. Worse, the tree's
existing "render as claimed" obligation is stated four times and mechanized
nowhere:

`crates/antseal-core/src/anchor/model.rs:963` collapses the discriminant —
`source: self.source.as_ref().map(|s| s.identity().to_owned())`, and
`identity()` maps `Verified(s) | Claimed(s) => s`. The report field is a bare
`Option<String>`; both serialize identically. Repo-wide, `is_verified` has
**three** hits — its own definition and two tests. And R22 hands the verifier
page *only the report's serialized bytes*, so **the page is structurally
incapable of honouring "MUST render as such."**

The pin that appears to cover this does not: `model.rs`'s byte-exact
`invalid`-slot assertion reads `"source":"claimed-tsa"`, and `claimed-tsa` is
the *fixture's own identity string*, not a marker. It demonstrates marking
while demonstrating nothing.

**Ruling 3.** The honesty obligation is discharged by R18's authoritative
wording set, which must gain a `fetch_date` row, and — per R22's own text —
by R18 embedding final display strings in the report, which discharges it at
M3 **without** a version bump. Recorded as **R74**. Until R18 lands, the
label is the sibling `state` field and nothing else, and this record says so
rather than implying more.

## 5. The three riders

- **(a) R18 owns the label and must be told.** A `fetch_date` row: rendered
  subordinate to the state, labelled sealer-recorded and not verified, in the
  `claimed_time` register of MVP-SPEC line 137. **R74.**
- **(b) The report is a machine format; pages format it.** `"1767225600"` is
  what a renderer receives. Recorded here so no page author invents a date
  format and no future lane reads the raw integer as a display decision.
- **(c) Make the non-branching guarantee an equality, not an inspection.**
  Nothing in `crates/antseal-core/src/anchor/` branches on `fetch_date`
  today — its only appearances are two `.to_string()` captures and an
  accessor. That is true by inspection, and inspection is what D94 §4 just
  finished catching out. The analogue of D59 §7's
  `nonce_presence_does_not_move_the_verdict` is red-capable: **two bundles
  identical but for `fetch_date` produce `AnchorResult`s equal in every field
  except `fetch_date` itself.** An implementer who adds D59 §6(a)'s forbidden
  comparison turns it red immediately. **R72 — and this is the measure that
  makes Ruling 1 safe.**

## 6. Two further instruments that go red, in a file D94 never opened

D94 §4's finding was that a *third* instrument could not go red. There are
two more that **do**, and they were invisible at step 0 because both read the
**committed** vector document rather than a recomputed report — so they go red
at step 2, after the emit, not before it. Both fail with a **wrong cause**:

1. `tests/anchor_verdict_report_freeze.rs::the_pinned_report_vectors_still_carry_only_absent_anchor_slots`
   asserts `state == "absent"` with the message *"a pinned vector gained a
   non-absent anchor slot — **that is a REPORT_VERSION event**, not a lane
   change."* D94 Ruling 1 overruled exactly that: it is a VERDICT EVENT and
   `REPORT_VERSION` stays 1. This is a **sixth copy** of the stale-v2 claim,
   in a **fourth** file, which D94 §9a's three-file byte-identical amendment
   does not reach.
2. `…::no_non_absent_state_or_diagnostic_appears_in_the_pinned_bytes` scans
   for the six non-`absent` spellings and then guards its own vacuity on
   `saw_absent`. After the re-emit, case 19's slots are `invalid` and the
   other 20 pin `"anchors":[]`, so **no pinned report contains
   `"state":"absent"` at all** and the guard fires with *"the needle shape is
   wrong and the six assertions above are vacuous."* The needle shape is
   correct; `absent` has legitimately left the file, exactly as D53 §4a
   predicted. An implementer following that message would weaken the guard.

**Ruling 4.** Both are re-authored by R12 in the same commit, to assert the
post-R12 truth with messages naming the right cause. The file's purpose
survives intact — it is A39's mechanization of D53 §6's hand measurement, and
D53 §6's real invariant is *`AnchorResult` has exactly five fields and the
diagnostic never reaches the report*, which R12 does not touch. **R75.**

## 7. Measured vs. assumed

**Measured on the tree with R12 applied (branch `m2w6-r12`):**

- `cargo test -p antseal-core --features test-util --no-fail-fast --tests`:
  **five** red, not D94 step 0's predicted two — the R30 pin, the frozen R9
  document, the vector runner reaching the same document, a doc-pointer lint
  catching a line-wrapped identifier **inside the R12 patch**, and
  `anchor_aggregate.rs`'s M1 all-`absent` row.
- R30's canonical report for `multi-file-anchored/mixed` is **1160 B**;
  measured digest `e450be73…ff8e`, matching a planner's hand computation.
- Case 19's frozen bytes decode to 1141 B with three `absent` slots, all
  metadata `null`, and `"claimed_time_informational_only":"1767225600"`.
- `verdicts.rs:1059` precedes T1/T2; `:681` gates the OTS date on `upgrade`;
  `model.rs`'s `to_anchor_result` copies both fields for every slot-emitting
  state and drops the `AnchorSource` discriminant.
- `is_verified`: 3 repo-wide hits, all definition-or-test. `fetch date` in
  MVP-SPEC.md: lines 108 and 114 only.
- Registry §6.1's non-consumption rule; §7.9 key 3 `req`; §7.8's three
  non-rules; §7.10 key 1 *"Display-only: unverified in v1"*. D53 §4's table.
  D59 §6(a) and its 129 s measurement. D29 rules 1–9.

**Assumed, and flagged:**

- That no *other* R30 row moves. R12's own Accept makes a second mover an F2
  breach; verified at re-pin time, not here.
- That the 20 other report cases move no byte. `first_difference` reports one
  difference, so this is closed by the step-3 diff audit, not by this record.
- The confidence in Ruling 1 is high but is judgement: both planners agree,
  and the one charged with the opposite side conceded on a specific argument
  it could not answer (§2). That is strong evidence, not proof.

## 8. Discovered work

### R72 — `fetch_date` never moves any other field of a verdict
- Milestone: M2 · Size: S · Deps: R12 (D95 rider c)
- Two bundles identical but for `fetch_date` must produce `AnchorResult`s
  equal in every field except `fetch_date`. Red-capable against D59 §6(a)'s
  forbidden comparison. Model: `nonce_presence_does_not_move_the_verdict`.

### R73 — The report's sealer-claim surface is documented inconsistently
- Milestone: M2 · Size: S · Deps: D95
- `report.rs`'s `fetch_date` doc cites *"MVP-SPEC.md line 127+"* for a
  rendering requirement that passage does not contain (lines 108/114 do, as
  bundle content). `WorkMetadata`'s doc calls the group *"as verified from the
  bundle"* while three of its five children are sealer claims — `title` and
  `app_version` carry no caveat at all, and `app_version`'s *"informational
  only"* note exists one layer down in `manifest/body.rs` and never reaches
  the report. Also: `model.rs`'s byte-exact `invalid`-slot pin uses
  `"fetch_date":"2026-08-02"`, a **shape the emitter can never produce**.
  Make the one committed example agree with the one real producer, and give
  each sealer-recorded report field the same caveat.

### R74 — R18 gains the `fetch_date` label row (D95 rider a)
- Milestone: M3 · Size: S · Deps: R18; D95
- The obligation Ruling 3 creates, plus the finding that
  `AnchorSource::Verified`/`Claimed` is discarded at the report boundary and
  R22's page cannot recover it. Decide between a sixth `AnchorResult` field
  (a version bump; D53 §6 forbids it casually) and R18 embedding final display
  strings, which `tasks/R.md` R22 already says the page receives — so the
  obligation is dischargeable at M3 with no version bump.

### R75 — Re-author `anchor_verdict_report_freeze.rs` for the post-R12 truth
- Milestone: M2 · Size: S · Deps: R12 (D95 §6)
- Both tests, both messages. The `absent` assertions become `invalid`; the
  two TSA slots gain the rendered `fetch_date`; `NON_ABSENT_STATES` exempts
  `invalid`; the `saw_absent` anti-vacuity guard needs a witness that still
  exists (`"anchors":[]` survives for its sibling). The stale *"that is a
  REPORT_VERSION event"* message is the sixth copy of D84 §7's v2 claim and
  is corrected here.

## 9. Residual risks and revisit triggers

- **The label is owed and not yet paid.** Until R18 lands, a rendered
  `fetch_date` is labelled only by its sibling `state`. Trigger: R18 shipping
  without a `fetch_date` row, or R22 shipping a page that renders the raw
  integer.
- **"Render + label" is quotable without its second half.** The containment
  is R72's equality and R74's row, not the adjective. Trigger: any new
  sealer-recorded field entering the report without a caveat in its own doc.
- **This ruling makes case 19 the tree's only committed evidence for F2/F3
  end to end** — an unparseable artifact costs its own anchor and nothing
  else. Trigger: A22 slipping, leaving M2 with no committed evidence of a
  *successful* anchor.
- **The `source` question is closed for case 19 but not exercised anywhere.**
  No committed vector renders a claimed source. Trigger: A22's `anchor` kind
  landing without one.
