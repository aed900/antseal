# D96 — How Q8's tests-of-the-test survive the pending set emptying

- **Status: RESOLVED**
- **Date: 2026-08-06** — status block normalised to the house
  `- **Status:` / `- **Date:` form on 2026-08-11, executing
  [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5
  step 2. The original front matter read `- **Status**: Resolved 2026-08-06`
  and carried no `- **Date` line; the status word and the date are unchanged,
  and nothing else in this record is touched.
- **Owner**: Q8 / Q18 / A21
- **Minted**: mid-execution, by A21's lane, from a blocker the task brief did
  not name
- **Supersedes**: nothing. **Amends**: the `A_PENDING_CASE` doc comment
  (`tamper_completeness/mod.rs`) and `testdata/tamper/README.md`'s
  *"they are what keeps the mechanism live"* paragraph.

## The problem, in one sentence

A21 closes the last eight `pending` cases in `testdata/tamper/MATRIX.json`,
and nine of Q8's own tests-of-the-test work by reaching into the **committed**
registry and mutating a live `pending` block — so the task that completes the
M2 matrix is the task that breaks the instrument measuring it.

## What was measured

Both halves of this were measured, not argued.

**The failure set.** A planner extracted the checker (`mod.rs:74-1596`) into a
standalone crate depending only on `serde_json`, replacing exactly three
things: the `TamperRow` import (struct-identical stub), the two baked-in paths
(env vars), and `live_rows()`'s `super::all_rows()` (regenerated from the
registry's own claimed ids, which `check_text` proves is the same set). The
model reproduces **all 17 committed fixtures passing** against today's
`MATRIX.json`. Against a post-A21 registry — eight `pending` blocks replaced
by `rows`, eight ids added to the live set — **8 of 17 fixtures break, in
three distinct ways**:

| Fixture | Post-A21 behaviour |
| --- | --- |
| `…_no_coverage_and_no_pending_marker` | `.remove("pending")` is a **no-op** on a case that now has `rows`; the registry passes and `expect_red` panics |
| `…_green_on_a_case_discharged_by_a_recorded_non_row` | two states at once **plus** an orphaned live row — two failures, neither the one it tests |
| `…_by_an_unrecorded_non_row` | needle miss: the two-state rule fires before the dispatch, so the rule under test never runs |
| `…_in_two_states_at_once` | **red on the wrong rule** — reports `["rows","non_row"]`, needle wants `["pending","non_row"]` |
| `…_colliding_with_an_implemented_one` | **panic** at `.expect("pending object")` |
| `…_two_pending_rows_collide_without_a_note` | **red on the wrong rule**; the cross-distinctness walk skips a claimant that is now `rows` |
| `…_reserving_a_live_row_id` | **panic** |
| `…_without_a_task_id` | **panic** |
| `…_on_an_unknown_field` | **survives** — `only_keys` runs before the state dispatch |

**The two dangerous ones are not the panics.** Two fixtures stay *red on a
rule they were not written to test*. A maintainer bisecting a red lane sees a
red test with a plausible message, and the cheapest repair is a needle edit —
which leaves the collision rule and the pending-arity rule permanently
untested while the suite reads green. The borrowed design produces that
outcome by construction.

## The three routes, and why two are dead

Two planners were briefed on **opposite** charges, each told to report against
its own charge if the evidence went the other way. The one charged with
*keeping the real registrations* **rejected its own charge**.

**(a) Re-anchor onto another real pending case — structurally impossible, not
merely inconvenient.** A `pending` block lives on a *case*, a case lives under
a *family*, and every family's `spec_quote` must be a literal substring of
MVP-SPEC.md line 168 in its own milestone's half (`mod.rs:500-506`), with the
milestone restricted to M0 or M2 (`:494-498`). M0's pending set is empty and
**must stay empty — that is Q14's gate condition**. Every M2 clause on line
168 is A21's. So after A21 there is no pending case to borrow and none can be
created:

- **A81/Q92's O7 row does not supply one.** It is a `project_added[]` entry,
  whose schema has no `pending` key (`:608`) and which fails unless the row
  already exists (`:624-629`) — and it lands *after* A21.
- **O7 could not be a case even if wanted.** Line 168 does not name it; that
  is D93 §12's stated reason for using `project_added` at all.
- **No M3/M4 case is registrable** without changing both the checker and the
  spec line.

**(b) Hold one row back so its case stays pending — mechanically possible,
fails on three grounds.** It breaks A21's Accept (*"one test per row"*, eight
rows) and the M2 gate's *"all 8 anchor tamper rows implemented + registered"*;
the most tempting candidate (`ber-where-der-required`) is the one with the
*strongest* evidence it should land now (A5's code and the BER fixtures are
committed, and its deferral reason is recorded as stale); and it inverts the
dependency — Q14's gate **defines success as pending being empty**, so a
fixture requiring a non-empty pending set is a fixture requiring the project
never to finish.

**(c) Synthesize — the ruling.**

## Ruling

**The tests-of-the-test synthesize the pending case they need, by appending
one synthetic case to the parsed value. They do not borrow, and they do not
disturb any committed case.**

```rust
/// Install a synthetic **pending** spec case in the parsed registry and
/// return a mutable handle to it.
fn synthetic_pending_case<'a>(root: &'a mut Value, case_id: &str) -> &'a mut Value
```

Four properties, each measured rather than assumed:

1. **An appended *case* is invisible to every pin.** `check_text` pins
   *family* counts but **never asserts a case count**; `EXPECTED_M2_CASES` is
   checked in `assert_m2_anchor_set_is_armed`, a `pub fn` no fixture calls. A
   synthetic *family* would break both count pins and need a real
   `spec_quote`; a synthetic *root* would break the section's stated contract
   (*"takes the COMMITTED registry, breaks exactly one thing"*). One appended
   case keeps that contract intact.
2. **Converting a real implemented case is refused.** Removing `rows` orphans
   the live row and emits ``implemented row `…` is in NO registry entry`` —
   fatal for the green fixture, noise for the reds. This is the measured
   defect in the "synthesize the state, borrow the identity" hybrid, and the
   reason it was not taken.
3. **Every needle stays verbatim.** The rewrite changes where the pending
   block comes from, not what is asserted.
4. **`task: "Z99"`** — `is_task_id` accepts uppercase-letter-plus-digits, and
   `tasks/` holds A, C, F, G, P, Q, R, S, U only, so Z is unambiguously
   fictional. This is *stricter* than what the file does today: the surviving
   `…_stale_pending_marker` fixture already synthesizes a whole `pending`
   block using the **real** task id `"R7"`.

### The D81 precedent governs, and the file already practises it

`…_two_pending_rows_collide_without_a_note` records, verbatim:

> **Synthesized rather than borrowed from the registry.** … D81 resolved that
> pair … so there is no longer any collision to borrow, and a test that
> depended on one would have to be deleted **or kept alive by leaving a
> collision in place**. Building the pair here instead makes the rule
> **permanently testable and independent of what the matrix happens to
> contain.**

Substitute "pending case" for "collision" and it is this decision. *"Kept
alive by leaving a collision in place"* is route (b), named and rejected one
state down. Flagged honestly: the paragraph's literal subject is collisions,
so this is precedent by reasoning, not by scope.

### What the "real registration" was actually buying

The counter-argument is `A_PENDING_CASE`'s own doc: *"the M2 markers are real
registrations rather than props."* Taken in context its load-bearing clause is
the preceding one — *"the rules under test are milestone-agnostic"* — and the
sentence asserts that the **new** borrowed case is as good as the **old** one.
It is an equivalence claim about the M0→M2 re-anchor, not a standing rule.

Of the three things a real registration bought:

- **A true premise about the shipped artifact** — post-A21 this has *no
  referent*. The prop replaces nothing, not something.
- **A drift canary** — the one genuine loss, and already delivered by
  `completeness_committed_registry_is_green`, which runs the whole check over
  the committed file. Restored in stronger form below.
- **Proof the `pending` mechanism is not dead code** — a fact about the
  registry, not the fixtures. Once nothing is pending it is unexercised by
  production data whatever the fixtures do; keeping the *rule* testable in the
  interim is verbatim what the D81 paragraph prescribes.

The doc comment concedes the coupling is a liability in its own next
paragraph: every fixture *"**overwrites** `expected` or replaces the whole
`pending` block, so none of them depends on its committed value"*, followed by
a recorded near-miss (*"Until Q76 that value was `null` … a fixture resting on
it would have had to be rewritten"*). Borrowing buys the block's **existence**,
never its content — and existence is exactly what A21 removes. Measured
history: `A_PENDING_CASE` has been forcibly re-pointed **twice** in ten days
(F15, Q76) and `SECOND_CLAIMANT` once. A21 would be the third and the last
possible one.

## Riders

**(a) `expect_only_red`, adopted in the same commit.** `expect_red` matches
its needle against the rendered *list*, so a synthesized block broken in a
second, unnoticed way could be carried by that other failure. Measured: every
rewritten red fixture emits **exactly one** failure, so pinning that costs
nothing.

```rust
#[track_caller]
fn expect_only_red(root: &Value, needle: &str)   // failures.len() == 1 && contains(needle)
```

This is the rider that closes the one residual the borrowed design genuinely
covered — a future decision adding a mandatory `pending` key would otherwise
leave the fixtures passing against an obsolete shape. It is **strictly
stronger** than what borrowing had. It cannot be applied globally:
`…_red_on_a_deleted_family` orphans that family's rows by design.

**(b) The M2 arming assertion must not degenerate.** Both planners found this
independently, and it is the more important of the two riders.
`assert_m2_anchor_set_is_armed` computes its arming check, its printing loop
and its unminted check **all** by iterating `m2_pending`. With the pending set
empty it iterates nothing and the whole function collapses to
`assert_eq!(m2_cases, 8)` — which is precisely the *"complete but comparing
nothing"* failure its own doc was written to prevent, reappearing one level
up. Deleting the `EXPECTED_M2_UNMINTED` entry without noticing this is the
edit A21 would otherwise be tempted to make, and `EXPECTED_M2_UNMINTED`'s own
doc warns that *"the list must never silently empty."*

**Ruling: the M2 half stays armed by following the cases into their live
state.** Once nothing is pending, the assertion checks that all eight M2 cases
are discharged by **live rows** whose outcome keys are the eight pinned ones,
and prints those keys as before. The scaffold becomes a permanent check
instead of a vacuous one, and the print — *"what lets a reader see which eight
outcomes the M2 milestone is buying"* — keeps working after the thing it read
from is gone.

**(c) The synthesized collision must claim an unclaimed key.** The collision
fixture's committed key is `verdict:internally-consistent-only`; post-A21 the
live row `anchor-untrusted-root` claims it, so a naive synthesis would also
trip *"is ALREADY claimed by implemented row"* and pass for a muddied reason.
Deriving each synthetic key from its `case_id` makes the collision deliberate
and the key unclaimable by any minted code.

## Amendment, 2026-08-06 — a **third** instrument, found by running the gate

Both riders were written from what two planners found by reading. The gate
found a third, in a file **neither planner opened**:
`tests/anchor_code_namespace.rs::no_matrix_row_expects_a_code_under_a_closed_prefix`
(**A41**, D91 §6.1's ruling checked against the committed artifacts).

It walks `MATRIX.json` collecting every `"expected"` string and sweeps them
for the closed `ots-`/`tsa-` prefixes. **Every one of those cells lived inside
a `pending` block**, so after A21 the walk found zero — and the test went red,
correctly, on its own anti-vacuity control: *"the walk did not reach D91
§9.1's own filled cell … so it could not have seen a violation either."*

That is rider (b)'s shape exactly — a check computed from a set A21 was about
to empty — and the fix is rider (b)'s fix: **follow the codes to where they
now live.** A row's expected code is authoritative in the row itself, so the
sweep now unions the registry's remaining cells (there may be pending cases
again one day) with every live row's `ErrorCode`. Verdict states stay
excluded: `ots-`/`tsa-` are closed as *error-code* prefixes only.

**The general lesson, recorded because three is a pattern and not a
coincidence:** the pending set was not one instrument's input, it was a
*shared* one, and its emptying is a **milestone event** rather than a local
edit. Three separate checks read it — the fixtures (§ruling), the arming
assertion (rider (b)), and this prefix sweep — and only the first was
reachable by grepping for the constant the fixtures used. The reliable finder
was not analysis but **running the gate**, which is why the count moved from
two to three after the code was written.

Its own anti-vacuity control is what made this cheap: the test refused to
report green on a sweep that could no longer see anything, and said so in one
sentence. A version asserting only *"no violations found"* would have gone
green forever the moment A21 landed.

## Residual risks and revisit triggers

- **Schema drift** on the `pending` block — closed by rider (a); without it,
  moderate rather than closed.
- **`families.last_mut()`** panics on an empty array; unreachable while the
  17 + 6 family counts hold, and the `expect` message names the condition.
- **Reader confusion** — nine synthetic cases could read as registry content
  in a failure dump. Mitigated by both the `what` and `why` strings leading
  with `synthetic:`.
- **Revisit if** a future milestone ever registers a pending case again (it
  would need a spec-line change *and* a checker change): the synthesized
  fixtures stay correct, so this is a trigger to re-read, not to revert.

## Discovered work

- **Q115** — the wasm32 lane emits `unused import: error::all_code_exemplars`
  (`anchor/ots/mod.rs:70`) and nothing fails on it: the lane runs `cargo test`,
  not clippy, so warnings are invisible there. Pre-existing, unrelated to A21.
