# D56 — The OTS trigger for `internally-consistent-only`, and the complete OTS state mapping

- **Status: RESOLVED — the conflict the register alleges is REAL and its line
  numbers are right, but its resolution is half an answer. Read literally,
  MVP-SPEC.md:133 assigns `internally-consistent-only` to an OTS anchor that
  *"does not … match online"*, while lines 108 and 168 assign `invalid` to
  exactly that input; **108/168 win**. But deleting line 133's OTS clause
  would make the state unreachable for OTS, and it is not: its real OTS
  trigger is **an `.ots` whose ops commit `anchor_digest` but whose every
  branch ends in an op or attestation the verifier cannot evaluate** (A11's
  *"typed unverifiable results"*) — which is line 133's own definition,
  *"cryptographically well-formed but not independently anchored"*, word for
  word. Line 133 is corrected in its **parenthetical trigger**, not in its
  definition. Two things the spec never states are decided here: `--online`
  attempted but the endpoints unreachable **or disagreeing** leaves the state
  at `attested` — absence of evidence is not a mismatch, and a cryptographic
  verdict must never move with network weather; and because A13 makes the
  **merged multi-attestation `.ots` the normal artifact** while line 108 is
  written for a single-attestation one, the per-branch precedence is
  **best-evidence-wins**: a refuted branch never demotes a confirmed or
  pending one, because the `.sealproof` bundle is unsigned and refutation-wins
  would hand any relay a downgrade-to-`invalid` primitive. Zero frozen report
  bytes change.**
- **Date: 2026-08-02** (M2 planning round; blocks A11, A12, A18, A21, R18, Q18)
- **Owning tasks: A18** (the state machine), **A11/A12** (the checks it
  consumes), **A21/Q18** (the rows), **R18** (the wording). Register entry:
  `TODO.md:568` — *"Reconcile spec lines 133 vs 108/168 on the OTS
  `internally-consistent-only` trigger (mismatch → `invalid`; align R
  wording) (A18/A21/R18 — 'A-OD4')"*.

---

## Context — was there a conflict at all?

The brief for this round warned that the entry was written on 2026-07-27,
that the spec has been revised since, and that a decision entry inventing a
conflict is itself a finding. It is not one here. All three of the register's
line numbers are still correct, verified by `grep -n` on 2026-08-02:

```
$ grep -n "does not chain to a pinned root" MVP-SPEC.md
133:- `internally-consistent-only` — a well-formed token/attestation that does not chain to a pinned root (TSA) or match online (OTS): cryptographically well-formed but not independently anchored; never headline-eligible.

$ grep -n "forged Bitcoin attestation/header" MVP-SPEC.md
108:  … A header that fails the online match, or an `.ots` whose ops don't commit `anchor_digest`, is the `forged Bitcoin attestation/header` tamper case (`invalid`). …

$ grep -n "forged Bitcoin header that fails" MVP-SPEC.md
168:  … **(M2)** anchor rows: … **forged Bitcoin header that fails the `--online` block match** (→ `invalid`); …
```

Two of the three read on the same input — *the online check was performed and
it did not match* — and they name different states. **The conflict is real.**

What the register got wrong is the size of the question. "Mismatch →
`invalid`" resolves the collision and leaves three larger holes: whether
`internally-consistent-only` is reachable for OTS **at all** (§3), what
happens when the online check is *attempted and produces nothing* (§4), and
what happens in the **merged, multi-attestation `.ots`** that A13's ≥2-calendar
policy makes the ordinary artifact and that line 108 does not describe (§5).
Those are where this decision does its work.

---

## 1. Exactly where the two lines disagree, and why 108/168 win

Line 133's OTS clause has one reading and it is the colliding one. *"Does not
match online"* is a statement about a comparison that **ran and failed** —
the same event lines 108 and 168 call *"fails the online match"*. There is no
construal on which the two assign the same state.

108/168 win, on four independent grounds:

1. **Specificity.** Line 133 is a one-line gloss in the taxonomy list. Line
   108 is the Anchoring section's normative paragraph on OTS, and it states
   the outcome as part of a worked threat argument (the self-referential
   proof-of-work of a lone header, the wholesale-forged-bundle attack, the
   deliberate online gate). Line 168 then repeats it in the tamper matrix.
   Two normative statements against one gloss.
2. **It is the only reading under which line 131 has content.** Line 131 —
   *"`attested` — upgraded OTS, header embedded, **not** headline-eligible
   offline; `--online` promotes it to `proven`"* — already owns the *offline*
   upgraded case. If line 133 also owned "not confirmed online", `attested`
   and `internally-consistent-only` would name the same artifact.
3. **The tamper matrix is already committed to it.**
   `testdata/tamper/MATRIX.json` pre-registers `anchor-forged-header` with
   `"outcome_kind": "verdict", "expected": "invalid", "why": "Spec-stated
   outcome (→ `invalid`)"`. Changing it would be a row edit, and row expected
   outcomes are never edited (`docs/testing/error-code-contract.md` §6).
4. **Under D53's partition principle it is the right answer anyway.** A
   fetched-and-agreed block header that differs from the embedded one is a
   **refutation** from trusted material. That is `Invalid` by definition:
   *`invalid` iff the artifact makes a claim the verifier can refute from
   material it already trusts.*

---

## 2. But `internally-consistent-only` is not thereby unreachable for OTS

The register's fix — "mismatch → `invalid`" — read as a deletion of line 133's
OTS clause, would leave the state TSA-only. That would be wrong, and it would
be an *unfalsifiable* kind of wrong: nothing in the tree tests for the
reachability of a state from a given artifact kind, so the loss would be
invisible until someone asked why A18's exhaustive-reachability test (A18
Accept: *"every one of the seven states reachable from a concrete fixture"*)
had a TSA fixture for a state whose definition says *"token/attestation"*.

The reachable OTS trigger is A11's own escape hatch. `tasks/A.md` A11 `Do`:

> Unknown ops/attestation types surface as **typed unverifiable results**,
> never crashes — and per **F3**, unknown is *not* over-limit, so that path
> keeps its own treatment and is not governed by a limit.

A11 defines the class and explicitly declines to say what state it produces.
It produces this one. An `.ots` whose stamped digest **is** `anchor_digest`
(so the artifact is about this seal) but whose every root-to-leaf branch ends
in an attestation type the verifier does not implement — or traverses an op
it cannot execute — is *"cryptographically well-formed but not independently
anchored"*: line 133's definition, unedited.

This is not hypothetical. The OpenTimestamps attestation registry is
open-ended and carries an explicit unknown-attestation catch-all holding
opaque bytes; Litecoin and Ethereum calendars exist. An `.ots` merged from a
calendar antseal does not implement is exactly this shape, and **the
alternatives are both wrong**: `Invalid` would accuse an honest artifact of
forgery, and `Pending` would tell the user to run `status --upgrade`, which
will never help.

**Ruling: line 133's definition stands; its parenthetical trigger for OTS is
corrected** from *"or match online (OTS)"* to the unevaluable-attestation
case. §11 gives the replacement text.

---

## 3. The `--online`-attempted-but-nothing-came-back case

MVP-SPEC.md:137 fixes the precondition — *"Online mode: **two pinned default
endpoints per source, results must agree**"* — and `tasks/A.md` A16 makes the
distinction typed in the network layer: *"typed outcomes distinguishing
endpoint-unavailable (advisory/retryable) from disagreement (alarming — a
lying endpoint)"*. Neither says what the **anchor state** becomes. Three
candidates, and the wrong two are the tempting ones.

**Ruling: the state is `Attested`, unchanged from the offline evaluation, in
both the unreachable and the disagreeing case.**

- **Not `InternallyConsistentOnly`.** It is a strictly *less* informative
  label than `attested` — it discards the attested height, the embedded
  header and the fetch date, which A12 verified offline and which R18 renders
  — and it would make the *cryptographic* verdict a function of network
  weather: the same bundle, same bytes, would render differently on a flaky
  connection. MVP-SPEC.md:137 requires the opposite, that online results are
  *"an advisory overlay **distinct from** the offline cryptographic verdict"*.
- **Not `Invalid`.** Nothing was refuted (D53's principle P). A lying or
  absent endpoint is evidence about the endpoint, not about the artifact.
- **`Attested` is exactly right**, because `attested` already *means*
  "well-formed, evidence embedded, no independently proven time offline" —
  which is precisely the epistemic position of a verifier whose online probe
  returned nothing.

**The consequence is an API constraint on A2, and it is the enforcement
mechanism**: at the `antseal-core` boundary there is **no "attempted and
failed" variant**. `evaluate_anchors` receives online evidence as

```rust
/// The agreed result of the must-agree esplora pair (A16) for one block
/// height. Constructible with no network access; core never fetches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnlineBlockResult {
    /// Both endpoints returned this byte-identical 80-byte header.
    Header([u8; 80]),
    /// Both endpoints agreed there is no block at this height.
    NoSuchBlock,
}

/// Online evidence for a whole verification, keyed by block height.
/// `BTreeMap` rather than `HashMap` for the same determinism reason D29
/// gives the report: iteration order must not vary between runs or between
/// native and wasm32.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OnlineEvidence {
    pub blocks: std::collections::BTreeMap<u64, OnlineBlockResult>,
}
```

(`std::`, not `alloc::` — `antseal-core` is **not** `#![no_std]`; it is
WASM-safe by dependency discipline, and the crate already uses
`std::collections::BTreeMap` in `verify/error.rs`. Written out because the
"WASM-safe core" framing invites the wrong import.)

An unreachable or disagreeing pair is represented by **the absence of the
entry**, so the "network weather changes the verdict" defect is not
prevented by discipline — it is unrepresentable. `antseal-anchor` keeps A16's
richer typed outcome for the overlay; it simply has nothing to hand core.

`NoSuchBlock` is a separate ruling and is the hole this section found: two
endpoints *agreeing* that height H does not exist is agreed evidence
refuting the artifact's claim, and it must be `Invalid` (rule O7), not a
missing entry. Collapsing it into "no evidence" would let an `.ots` claiming
a block beyond the chain tip render `attested` for ever.

---

## 4. The merged `.ots`, and why refutation must not win

MVP-SPEC.md:108's sentence — *"A header that fails the online match … is the
`forged Bitcoin attestation/header` tamper case (`invalid`)"* — is written
about **a header**, in a paragraph that speaks of "an upgraded OTS anchor" in
the singular. But `tasks/A.md` A13 builds *"a merged pending `.ots`"* across
≥2 calendars, and A14 does *"upgrade polling + attestation merge"*. **The
ordinary artifact carries several branches, at several different upgrade
stages, and the spec never says what the artifact's single `AnchorState` is
when they disagree.** `AnchorResult` is one slot per artifact, so the question
cannot be dodged.

The candidate rules are refutation-wins (any refuted branch makes the anchor
`Invalid`) and best-evidence-wins (the anchor's state is the strongest any
branch independently justifies; refutations classify only when nothing better
exists).

**Ruling: best-evidence-wins.** The argument is about who can edit the
artifact:

- The `.sealproof` bundle is **unsigned**. Only the manifest is signed; the
  anchor artifacts live in bundle maps (`docs/format/registry-v1.md` §7.8,
  §7.9), and §8 records that even **duplicate anchor artifacts are legal v1,
  deliberately**. Any relay holding a bundle can append a branch or a whole
  second `.ots`.
- Under refutation-wins, appending one garbage Bitcoin branch to an honest
  `.ots` turns its anchor `invalid` — a **downgrade-to-forgery-accusation
  primitive**, exercisable by anyone who forwards a bundle, against a sealer
  who did nothing wrong.
- Under best-evidence-wins, the same append gains the attacker nothing. The
  ceiling it can reach on its own is `attested`, which requires only mining a
  minimal-difficulty header with the right merkle root — and `attested` is
  **already** designed to be forgeable-but-not-headline-eligible offline
  (line 108: *"a forged header can never produce an offline headline time"*).
  Reaching `proven` still requires an online-agreed header, which cannot be
  forged.

So best-evidence-wins costs nothing the design was not already paying, and
refutation-wins buys a censorship vector. This also lands D56 on the **same
meta-rule as D53** (`C1/C2` beat `C3–C5`: a junk intermediate never demotes a
good chain), which is a consistency check both decisions had to pass.

**The price, stated rather than hidden:** a refuted branch alongside a
confirmed one no longer shows up in the anchor state. It must not vanish. A18
therefore emits a wording-free **suppressed-anomaly** list per anchor (task
**A39**), R18 renders it in the advisory overlay (task **R61**), and — because
report v1 is frozen and `AnchorResult` has no field for it (§7) — the page
cannot show it until a `report_version: 2`. Recorded as a residual risk.

**And a trap for A21**, which follows directly: the `anchor-forged-header`
row's fixture must be an `.ots` whose **only** branch is the forged Bitcoin
one. Building it by forging the header of a real *merged* `.ots` — the
obvious move, since that is what A25 records — leaves the sibling pending
branches in place, so rule O5 fires first and the row renders **`pending`**,
not `invalid`. The row would then fail, correctly, and the temptation would
be to blame the rule.

---

## 5. The complete OTS mapping — `evaluate_anchors`'s decision order

**Branch model.** Executing an `.ots` yields, for each root-to-leaf path,
either `Branch::Evaluable { commitment: [u8; 32], attestation }` with
`attestation ∈ { Pending { calendar }, Bitcoin { height } }`, or
`Branch::Unevaluable` — an unknown op anywhere on the path, or an unknown
attestation type at the leaf (A11's typed unverifiable result). Per-branch
helpers, with `u` the artifact's D79 upgrade group
(`block_height`, `block_header`, `fetch_date`; free-standing per D79 and
all-or-nothing by construction):

```rust
// A12's offline check. `merkle_root_of` reads bytes 36..68 of the 80-byte
// header; the byte order between the OTS-derived commitment and the header
// field is A12's empirical pin against A25's real upgraded fixture.
fn header_commits(b: &Branch, u: &OtsUpgrade) -> bool {
    b.attestation == Bitcoin { height: u.block_height }
        && merkle_root_of(&u.block_header) == b.commitment
}
```

Let `bitcoin` be the Bitcoin-attested evaluable branches, `pending` the
pending ones, and `online = evidence.blocks.get(&u.block_height)`.

```text
O0.  artifact absent for this slot                     ->  AnchorState::Absent

O1.  A11's anchor-stage limits exceeded, or the `.ots`
     codec rejects the bytes                           ->  AnchorState::Invalid
                                                           code: A11's limit / codec code (F1-F3)

O2.  artifact.stamped_digest != *anchor_digest         ->  AnchorState::Invalid
                                                           code "anchor-ots-digest-mismatch"

     --- best-evidence-first from here (§4) ---

O3.  upgrade.is_some()
       && bitcoin.iter().any(|b| header_commits(b, u))
       && online == Some(Header(h)) && h == u.block_header
                                                       ->  AnchorState::Proven               [H]
                                                           verified_time_unix = Some(nTime(h))

O4.  upgrade.is_some()
       && bitcoin.iter().any(|b| header_commits(b, u)) ->  AnchorState::Attested
                                                           verified_time_unix = None

O5.  !pending.is_empty()                               ->  AnchorState::Pending
                                                           verified_time_unix = None

     --- nothing confirms; now classify the refutations ---

O6.  upgrade.is_some() && online == Some(Header(h))
       && h != u.block_header                          ->  AnchorState::Invalid
                                                           code "anchor-ots-online-header-mismatch"

O7.  upgrade.is_some() && online == Some(NoSuchBlock)  ->  AnchorState::Invalid
                                                           code "anchor-ots-online-block-absent"

O8.  upgrade.is_some()
       && !bitcoin.iter().any(|b| header_commits(b, u))->  AnchorState::Invalid
                                                           code "anchor-ots-header-uncommitted"

O9.  otherwise                                         ->  AnchorState::InternallyConsistentOnly
                                                           verified_time_unix = None
```

> **Clarified 2026-08-02 by [D91](D91-anchor-error-code-namespace.md) §6.4.**
> O2 names an outcome, not a second check. D58 §10.2 makes `anchor_digest` a
> required parameter of `parse_ots`, so the comparison happens at §10.3 step 5
> inside the parser — deliberately, since a post-parse check would let a
> wrong-digest `.ots` amplify work — and `OtsArtifact` therefore has no
> `stamped_digest` field to read. O1 always claims this input; its code for it
> is `anchor-ots-digest-mismatch`, which is what O2 says. Do **not** add a
> `stamped_digest` field to make O2 literally executable.

**On O8's name and breadth.** The registry makes the D79 upgrade group
**singular** — keys 2–4 of one artifact
(`docs/format/registry-v1.md` §7.8) — so an `.ots` carrying Bitcoin
attestations at two heights has an embedded header for at most one of them.
O8's predicate is therefore *"the embedded header is not committed by the
ops"*, which is why the code is `anchor-ots-header-uncommitted` and not the
narrower "root mismatch" A12's prose uses. It subsumes three shapes that
would otherwise need three codes, and the name is accurate for all three:
the recorded height has a Bitcoin branch whose ops-derived root disagrees
(A12's case); the recorded height has **no** Bitcoin branch at all; and the
artifact carries an upgrade group with no evaluable Bitcoin attestation
whatsoever. §7.8 makes the third representable on purpose — *"an artifact
recording `status = pending` while carrying height + header is well-formed
v1"* — so it is reachable, not theoretical.

**And the converse shape, which falls to O9.** A Bitcoin-attested branch
with **no** upgrade group (the sealer stripped keys 2–4, or a relay did — the
bundle is unsigned, and D79 deliberately decoupled the group's presence from
`status`) satisfies none of O3/O4/O6/O7/O8, all of which are guarded on
`upgrade.is_some()`. It falls to O9 → `InternallyConsistentOnly`, and that is
correct rather than an oversight: MVP-SPEC.md:108 defines `attested` as *"ops
commit `anchor_digest` to the merkle root of Bitcoin block H (**header
embedded**)"*, so without the header there is nothing to be `attested`
about, and line 133's definition fits exactly. Verifying such a branch from
online evidence alone — fetching H and comparing its merkle root to the
branch commitment, without any embedded header — would be strictly stronger
and is **deliberately not v1**: line 108 defines `--online` as checking *the
embedded header*, and adding a second promotion route is a spec change, not
an implementation choice. Recorded as a v1.1 candidate in §12.

**First match wins, in exactly this order.** Every guard is an existential
over the branch set, so the outcome is invariant under branch order — the same
permutation-invariance D53 §3 requires of candidate paths, and pinned by the
same kind of property test.

Three details in the rules that are rulings, not restatements:

- **O3 requires `header_commits` *and* the online match.** An online-agreed
  header alone proves nothing about *this* seal: an attacker can embed a real,
  fetchable block header whose merkle root has no relation to the ops. The
  conjunction is what makes `merkle_root_of(fetched_header) == b.commitment`
  true transitively, which is the property that actually matters.
- **`verified_time_unix` for `Proven` is `nTime` of the *online-agreed*
  header** (bytes 68..72), never of the embedded one. Reading the embedded
  header's timestamp would reinstate exactly the offline forgeable time that
  the online gate exists to prevent, and would do so *invisibly*, since the
  two headers are equal on every honest bundle. §9 tests it.
- **`Attested` carries `verified_time_unix = None`, always.** Same reason.
  MVP-SPEC.md:131 makes `attested` non-headline-eligible, and
  `aggregate_anchors` already drops times on ineligible slots — so a populated
  time here would be invisible to every existing test.

`O9` absorbs both the all-unevaluable case (§2) and the degenerate
zero-attestation `.ots`. Merging them mints no code for a shape that proves
nothing either way; A11 may instead reject a zero-attestation file at parse
(→ O1), and **either is safe** because both outcomes are non-headline-eligible
and neither is `Pending` — which is the property §9 tests, rather than the
choice.

### The seven inputs the brief enumerates, resolved

| Input | State | Rule |
| --- | --- | --- |
| ops don't commit `anchor_digest` | `Invalid` (`anchor-ots-digest-mismatch`) | O2 |
| pending, no Bitcoin attestation yet | `Pending` | O5 |
| upgraded with header, offline | `Attested` | O4 |
| upgraded with header, `--online` match | `Proven` [H], time = `nTime(h)` | O3 |
| upgraded with header, `--online` mismatch | `Invalid` (`anchor-ots-online-header-mismatch`) | O6 |
| `--online` attempted, endpoints unreachable or disagreeing | `Attested` | O4 (no evidence entry exists — §3) |
| unknown op / unknown attestation type | `InternallyConsistentOnly` **if it is all there is**; otherwise it contributes nothing and the best evaluable branch decides | O9, or O3–O8 |

The last row is the one a careless implementation gets wrong in the visible
direction: treating "an unknown attestation is present" as itself a trigger
demotes a perfectly good pending `.ots` merged from one supported and one
unsupported calendar. §9 tests it.

### Every overlapping pair, and its winner

| Both hold | Winner | Why |
| --- | --- | --- |
| O2 and any of O3–O9 | **O2** | The artifact is about a different document; no branch can attest to this seal. |
| O1 and any of O2–O9 | **O1** | F3 — an artifact we refused to finish reading is not known to be well-formed. |
| O3 and O6 (one branch online-confirmed, another online-mismatched) | **O3** | Best-evidence-wins (§4). The confirmed branch's proof is unaffected by a branch anyone could have appended. |
| O3/O4 and O8 (a committing branch and a non-committing one) | **O3/O4** | Same. |
| O4 and O5 (partially-upgraded merge: one calendar upgraded, one still pending) | **O4** | The **normal** post-partial-upgrade artifact. `attested` is the stronger true statement and carries the height/header evidence. |
| O5 and O6/O7/O8 (a pending branch and a forged Bitcoin one) | **O5 — `Pending`** | Best-evidence-wins. The cheapest laundering append is a pending attestation, so this pair is the one an attacker actually reaches; it gains nothing, since `pending` proves no time either. **This is the pair that makes the A21 fixture trap in §4 real.** |
| O5 and O9 (a pending branch and an unevaluable one) | **O5** | An unevaluable branch is not evidence; it must not demote a pending anchor. |
| O3/O4 and O9 | **O3/O4** | Same. |
| O6 and O7 | **O6** | Cannot both hold for one height (`Header` and `NoSuchBlock` are exclusive); ordered so multi-branch artifacts at different heights are deterministic. |
| O7 and O8 | **O7** | Agreed online refutation is stronger evidence than the offline structural one, and names the more specific defect. |

---

## 6. Report-format impact: **zero bytes**

Identical measurement to D53 §6, and it covers both decisions:
`testdata/vectors/v1/report/verification-reports.json` carries 21 cases at
`report_version: 1`; exactly **one** has a non-empty `anchors` array, holding
**3** slots all in state `absent`; the strings `"proven"`, `"attested"`,
`"pending"`, `"internally-consistent-only"`, `"invalid"` and
`"valid-at-stamping-cert-since-expired"` occur **0** times. No state is
minted, renamed or respelled, so registry assertion **C10**
(`crates/antseal-core/tests/format_registry_freeze.rs`,
`report_anchor_state_matches_the_wire_anchor_status`) continues to pass
unchanged, and `REPORT_VERSION` does not move.

The same constraint as D53 §6 keeps it true and is repeated because it is the
one an implementer will trip over: **the four `anchor-ots-*` codes and the
A39 suppressed-anomaly list MUST NOT enter `VerificationReport`.**
`AnchorResult` has five fields and report v1 is frozen (D29/R32; Q14). They
live in A18's `AnchorVerdicts`; R12 projects and drops them. This is D86's
ruling applied to the anchor domain.

---

## 7. Error codes minted

Four, all new, all pairwise distinct, none colliding with the 194 codes in
`testdata/error-codes/v1/CODES.txt` (measured: zero existing codes carry the
`anchor-` prefix).

| Code | Fires at | Meaning |
| --- | --- | --- |
| `anchor-ots-digest-mismatch` | O2 | The `.ots` stamped digest is not this seal's `anchor_digest`. |
| `anchor-ots-online-header-mismatch` | O6 | The agreed fetched header for the attested height differs from the embedded one. |
| `anchor-ots-online-block-absent` | O7 | Both endpoints agreed there is no block at the attested height. |
| `anchor-ots-header-uncommitted` | O8 | The embedded header is not committed by the ops — its merkle root disagrees with the branch commitment (A12's check), or the recorded height has no Bitcoin attestation, or the artifact carries an upgrade group with no evaluable Bitcoin attestation at all. One code, because the predicate is one (§5). |

All four depend on the `anchor-` prefix row that
`docs/testing/error-code-contract.md` §2 **does not have** — see D53 §7 and
task A38. That defect blocks A5 and A11 equally.

---

## 8. Tamper rows this decision binds

The eight-row enumeration, the count defect behind "seven", and the verbatim
`MATRIX.json` edits are in **D53 §8** (one place, because the two decisions
share the row set). D56 binds three of the eight:

| # | `row_id` | `ExpectedOutcome` | Rule |
| --- | --- | --- | --- |
| 1 | `anchor-ots-digest-mismatch` | `ErrorCode("anchor-ots-digest-mismatch")` | O2 |
| 4 | `anchor-forged-header` | `VerdictState("invalid")` | O6 — **fixture must be single-branch** (§4) |
| 5 | `anchor-attested-not-headline` | `VerdictState("attested")` | O4 — the positive control |

Row 4 is the single claimant of the `verdict:invalid` key; every other row
rendering `Invalid` pins a code instead (D53 §8). Row 5 is a *positive*
control, so its exercise function must return
`ActualOutcome::VerdictState("attested")` — **not** `ActualOutcome::Accepted`,
whose doc comment (`crates/antseal-core/src/test_util/tamper.rs`) correctly
calls acceptance *"always a failure"* for a mutation row.

`anchor-ots-online-block-absent` and `anchor-ots-header-uncommitted` get no
row: line 168 names neither, and both would be `project_added[]` entries. A12's
Accept already requires the O8 case as a named test (*"root-mismatched header
→ distinct `invalid` error"*). O7 gets a named test here (§9). If A21 later
wants either as a row, `project_added[]` is the mechanism and the codes are
already distinct.

---

## 9. The tests that must exist, and what makes each fail

Location: `crates/antseal-core/src/anchor/ots.rs` (unit) and
`crates/antseal-core/tests/anchor_ots_states.rs` (integration over A25's
recorded pending and upgraded fixtures). All run native **and**
`wasm32-unknown-unknown`.

| Test | Claim | **What makes it fail** |
| --- | --- | --- |
| `a_pending_ots_is_pending` | O5 | Baseline; a fixture that is not a valid pending `.ots` makes every row below vacuous (the R7 rule). |
| `an_upgraded_ots_is_attested_offline` | O4 | An implementation promoting on the embedded header alone — the exact hole the online gate exists to close. |
| `an_attested_anchor_never_carries_a_verified_time` | §5 | Reading `nTime` from the **embedded** header. `aggregate_anchors` drops times on ineligible slots, so **only this test can see it.** |
| `an_attested_anchor_is_never_headline_eligible` | line 108/131; `MATRIX.json` row `anchor-attested-not-headline` | Adding `Attested` to `headline_eligible` — already guarded by `exactly_the_two_spec_h_states_are_headline_eligible`, asserted here at the anchor level too. |
| `matching_online_evidence_promotes_attested_to_proven` | O3 | Online evidence not threaded into the state machine at all. |
| `the_proven_time_is_the_online_headers_ntime_not_the_embedded_ones` | §5 | Reading `nTime` from the embedded header. Requires a fixture whose two headers **differ in `nTime` alone while both commit the ops root** — a fixture built by copying the real header would pass vacuously. |
| `online_evidence_that_does_not_commit_the_ops_root_does_not_promote` | O3's conjunction | Checking only `h == u.block_header` and skipping `header_commits`; the artifact would reach `Proven` on a real block unrelated to the seal. |
| `a_mismatched_online_header_is_invalid` | O6 | The register's losing option (`internally-consistent-only`); also `MATRIX.json` row `anchor-forged-header`. |
| `agreed_absence_of_the_block_is_invalid` | O7 | Collapsing `NoSuchBlock` into "no evidence" — the artifact would render `attested` for ever on a claimed height beyond the chain tip. |
| `an_embedded_header_for_an_unattested_height_is_invalid` | O8, second shape | An O8 predicate written as "the root disagrees" rather than "the header is not committed": with **no** Bitcoin branch at the recorded height there is no root to disagree, and the artifact would fall through to O9 and render `internally-consistent-only`. |
| `an_upgrade_group_over_a_pending_only_ots_is_pending_not_invalid` | O5 over O8 | Reordering O8 above O5. `docs/format/registry-v1.md` §7.8 makes this artifact **well-formed v1 by decision**, and it is the shape a sealer produces mid-upgrade; rendering it `invalid` would accuse an honest bundle. |
| `a_bitcoin_branch_without_an_upgrade_group_is_internally_consistent_only` | The converse shape (§5) | Promoting to `attested` on the ops alone, with no embedded header — which is the offline forgeable time the online gate exists to prevent, reached by a *different* route than the one line 108 closes. |
| `absent_online_evidence_leaves_the_state_at_attested` | §3 | An `OnlineEvidence` type with an "attempted and failed" variant, or a state machine branching on one. |
| `unreachable_and_disagreeing_endpoints_are_indistinguishable_to_core` | §3's API constraint | Any core-side type able to tell them apart; the test constructs both `antseal-anchor` outcomes and asserts they produce the identical core input. |
| `an_all_unknown_attestation_ots_is_internally_consistent_only` | O9 / §2 | Mapping unknown attestations to `Invalid` (accuses an honest artifact) or to `Pending` (offers `status --upgrade`, which can never help). **This is the only test that proves the state is OTS-reachable at all.** |
| `an_unknown_attestation_does_not_demote_a_pending_ots` | O5 over O9 | Treating the *presence* of an unknown attestation as the trigger. A naive implementation passes the row above and fails only here. |
| `a_pending_branch_is_not_demoted_by_a_forged_bitcoin_branch` | O5 over O6/O8 — §4 | Refutation-wins. Under it, any relay could downgrade an honest anchor to `invalid` by appending one branch to the **unsigned** bundle. |
| `a_confirmed_branch_is_not_demoted_by_a_mismatching_one` | O3 over O6 | Same, at the top of the lattice. |
| `a_partially_upgraded_merge_is_attested_not_pending` | O4 over O5 | Order-of-branches dependence; the normal post-partial-upgrade artifact would render `pending` half the time. |
| `the_state_is_invariant_under_permutation_of_branches` (proptest, seeded) | §5's existential form | Any "first branch wins" implementation. It passes every fixture above and fails only here. |
| `a_zero_attestation_ots_is_never_pending_or_headline_eligible` | O9 / O1 | Either treatment is legal; this pins that both are safe, so the choice never becomes load-bearing. |
| `a_wrong_digest_ots_is_invalid_regardless_of_its_attestations` | O2 over everything | Checking the stamped digest *after* the branches; a `.ots` for someone else's seal, carrying a genuine online-confirmable Bitcoin attestation, would render `proven`. **This is the worst reachable defect in the file.** |
| `every_ots_code_is_pairwise_distinct_and_anchor_prefixed` | §7 | A copy-pasted code, or one minted under `bundle-` (forbidden by error-contract §2). |

---

## 10. Discovered work

Shared block with D53; this document uses **A38, A39, R61, Q76** (full task
entries in the planner's task file). None are unique to D56:

- **A38** — the missing `anchor-` prefix row + A-domain exemplar enumerator.
  **Blocks A11**, which mints `anchor-ots-digest-mismatch`.
- **A39** — the per-anchor suppressed-anomaly list that keeps
  best-evidence-wins (§4) from silently discarding a refutation.
- **R61** — R18 renders it, and pins the CLI/page asymmetry §6 creates.
- **Q76** — the `MATRIX.json` edits (D53 §8), before A21 starts.

---

## 11. Corrections to existing prose (orchestrator applies at source)

1. **MVP-SPEC.md:133 — the correction this decision is named for.** Replace

   > `internally-consistent-only` — a well-formed token/attestation that does
   > not chain to a pinned root (TSA) or match online (OTS): cryptographically
   > well-formed but not independently anchored; never headline-eligible.

   with

   > `internally-consistent-only` — a well-formed token/attestation that is
   > not independently anchored: a TSA token that does not chain to a pinned
   > root, or an `.ots` whose ops commit `anchor_digest` but whose every
   > attestation is of a type this verifier cannot evaluate; cryptographically
   > well-formed but not independently anchored; never headline-eligible. An
   > OTS anchor that *fails* an online match is `invalid` (line 108), and one
   > whose online match could not be performed stays `attested` (line 131).

   The clause *"or match online (OTS)"* is the whole of the D56 conflict, and
   the replacement also closes the two silences §3 and §4 found.

2. **MVP-SPEC.md:108** — the sentence *"A header that fails the online match,
   or an `.ots` whose ops don't commit `anchor_digest`, is the `forged Bitcoin
   attestation/header` tamper case (`invalid`)"* is written for a
   single-attestation artifact, while A13/A14 make the merged multi-attestation
   `.ots` the norm. Append: *"In a merged `.ots` the anchor's state is the
   strongest any single branch independently justifies; a refuted branch never
   demotes a confirmed or pending one (D56 §4)."*

3. **`tasks/A.md` A11 `Do`** — *"Unknown ops/attestation types surface as typed
   unverifiable results"* names the class and assigns it no state. Add: *"→
   they contribute no evidence; an artifact whose every branch is unevaluable
   renders `internally-consistent-only` (D56 rule O9), and a single unevaluable
   branch never demotes an evaluable one."*

4. **`tasks/A.md` A12 `Do`** — *"on match, the state is `attested`"* omits the
   `verified_time_unix = None` rule, which is the invariant no existing test
   can see. Add it, with the reason.

5. **`tasks/A.md` A18 `Do`** — the OTS half reads *"`invalid` (online header
   mismatch, or ops not committing `anchor_digest`)"* and lists no OTS route
   to `internally-consistent-only`, so an implementer following A18 alone
   would ship the state as TSA-only and A18's own *"every one of the seven
   states reachable from a concrete fixture"* Accept would be discharged with
   a TSA fixture. Add rule O9.

6. **`tasks/A.md` A16 `Accept`** — the typed unavailable/disagreement outcomes
   are consumed by *"R's M3 endpoint-disagreement case"*; add that **neither
   ever reaches `antseal-core`**, since `OnlineEvidence` has no failure
   variant by decision (§3).

7. **`tasks/A.md` A2 `Do`** — *"`OnlineEvidence` input structs (agreed esplora
   header result; Arbitrum RPC result)"* must gain the `NoSuchBlock` arm
   (§3); without it the O7 refutation is unrepresentable.

8. Shared with D53 §11: the missing `anchor-` prefix row, `TODO.md`'s *"all 7
   anchor tamper rows"* (there are eight), and the registry §8 anchor-
   independence obligation that no task carries.

---

## 12. Residual risks and revisit triggers

- **The page cannot render suppressed anomalies or diagnostic codes** (§6).
  Trigger: any `report_version` bump — carry an `anomalies` field with it.
- **Bitcoin `nTime` is a loose bound.** Consensus permits a header timestamp
  up to ~2 h ahead of median-time-past, so a `proven` OTS time can overstate
  by hours. MVP-SPEC.md:108 fixes the rule (*"reads its timestamp"*) and :137's
  >48 h divergence flag absorbs the error; recorded because the product's
  claim is *"existed no later than"* and the caveat belongs in R18's wording.
  Trigger: any tightening of the divergence window below 48 h.
- **A stripped upgrade group costs an anchor its `attested` state** (§5's
  converse shape). A relay can delete keys 2–4 from an unsigned bundle and
  drop a genuine upgraded anchor to `internally-consistent-only`. This is a
  *degradation*, not a false statement, and it cannot manufacture a headline
  time — but it is the one place where best-evidence-wins does not fully
  neutralise the unsigned bundle, because the deleted evidence is the
  evidence. The v1.1 fix is the online-only promotion route (fetch H, compare
  its merkle root to the branch commitment, no embedded header needed), which
  needs no new format surface. Trigger: any spec revision to line 108's
  definition of what `--online` checks.
- **`internally-consistent-only` for OTS depends on A11's unknown-type
  surfacing actually working** (D58 decides `opentimestamps` 0.2.0's
  viability). If D58 lands a vendored codec that *errors* on unknown
  attestations instead of surfacing them, O9 becomes unreachable and the
  §9 test `an_all_unknown_attestation_ots_is_internally_consistent_only`
  fails — which is the intended way to find out. Trigger: D58 choosing the
  vendor/fork fallback.

---

## Index row (orchestrator applies at merge)

| [D56](D56-ots-internally-consistent-trigger.md) | OTS trigger for `internally-consistent-only` — the alleged conflict is **real** (line 133 says the state, 108/168 say `invalid`, on the same input) and the register's line numbers are right, but its fix is half an answer: **108/168 win**, *and* the state stays OTS-reachable, because its true trigger is an `.ots` whose ops commit `anchor_digest` but whose every branch is an **unevaluable op/attestation type** (A11's "typed unverifiable results") — line 133's own definition, unedited. Line 133's *parenthetical* is corrected, not its definition. Two spec silences closed: `--online` attempted but endpoints **unreachable or disagreeing** stays **`attested`** (enforced structurally — `OnlineEvidence` has no failure variant, only `Header`/`NoSuchBlock` keyed by height, so "network weather changes the cryptographic verdict" is unrepresentable), and because A13/A14 make the **merged multi-branch `.ots`** normal while line 108 addresses a single one, per-branch precedence is **best-evidence-wins**: refutation-wins would hand any relay a downgrade-to-`invalid` primitive over the **unsigned** bundle, while best-evidence-wins concedes nothing (the forgeable ceiling is `attested`, already non-headline-eligible by design). Complete 10-rule order O0–O9 with every overlapping pair adjudicated; `anchor-ots-online-block-absent` is a new refutation the spec never named. Four `anchor-ots-*` codes minted; zero frozen report bytes change | RESOLVED | 2026-08-02 |
