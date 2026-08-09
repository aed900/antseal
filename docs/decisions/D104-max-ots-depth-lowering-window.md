# D104 — A109: does the `MAX_OTS_DEPTH` lowering window exist, and should it be used

- **Status: RESOLVED — the window EXISTS and A109's expiry clock is correctly
  filed; the lowering is refused, and refused on a stronger ground than
  D102's. Both sides of the brief are overturned.** Recon's lean — *"§5a
  governs, the window never existed, A109 is misfiled"* — fails on
  **provenance**: the Update rule recon reads as D102's late unlogged addition
  is **A27's, commit `1620543`, 2026-07-28**, the same day D84 resolved, and it
  is a **registry-keeping procedure, not a permission**. It says what a
  lowering *costs* and what the table must *record*; it never says *when* one
  is allowed. F4 sentence 1 says when, and sentence 3's *"format-version
  event"* characterisation **presupposes** the harm sentence 2 names — a
  release that accepted a bundle a lowered limit would now reject — which D84
  §2 and §3 spend two sections proving cannot exist before M2 ships. Calling a
  pre-release lowering a format-version event would contradict D84 §3, the
  load-bearing half of D84's own ruling. **But D102 is wrong in the other
  direction**: its *"lowering is available today **at no cost**"* (§5) is
  refuted by the same unqualified sentence recon cited. A lowering today still
  spends §5's Update-rule ceremony and kills the registry's `lowered: never`
  cell permanently. The window is open; it was never free.
  **On the merits the option is not declined — it is EMPTY.** Because the
  allocation is `next_power_of_two(MAX_OTS_DEPTH) × size_of::<Frame>()`, every
  cap in **(512, 1 024]** reserves **exactly the same bytes on every target**,
  so a lowering inside that band buys **zero bytes** while accepting strictly
  fewer artifacts. The first value that saves anything is **512** — and the
  tree's own committed margin discipline (`ots/tests.rs:280`, *"every measured
  quantity is far under its cap; that is what the F4 margins claim, asserted
  rather than trusted"*) demands `MAX_OTS_DEPTH ≥ 8 × deepest real artifact`,
  which is **≥ 680**. **The admissible band and the cost-effective band are
  disjoint.** Since every admissible cap costs the identical 40 960 B, **1 024
  weakly dominates every other admissible value** — it is the cost-minimal
  admissible cap, not a generous guess. **This conclusion is invariant to the
  depth-85 dispute**: it holds at 85, at 73, and at the discredited 67
  (floor 536 > 512). It would change only if the deepest real artifact were
  ≤ 64, and every artifact in the tree measures 12, 67, 70, 73, 83 or 85.
  **A109's paragraph is wrong in all four of its load-bearing numbers** and is
  restated rather than merely closed: 40 960 B is the x86-64 figure, and the
  browser tab it invokes as the constrained venue costs **24 576 B** and is the
  **cheapest** place this parser runs (`limits.rs:155-157`, which already says
  so); "depth 67" is a third-party crate's test constant A48 exists to retire;
  the margin is not 15.28×; and the option's cost is a rejection threshold, not
  bookkeeping bytes. **Three defects fall out, none of them A109's to fix**:
  D102's §5a insertion **captured two A27 paragraphs under a banner reading
  "Added 2026-08-07 by D102"** — a provenance corruption that already produced
  one measured error, recon's finding 1, inside this planning round; the
  **margin column is the only numeric column in §5 that no test cross-checks**,
  which is exactly how A109 came to reason from it; and **§6 Changelog has
  taken zero entries across seven document-changing commits** while §5's Update
  rule routes F4's *"has this ever been lowered?"* auditability through it.
- **Date: 2026-08-09** (M2 wave 10 planning round; briefed to confirm that the
  window does not exist, and the window does exist)
- **Owning tasks: A109** (the ruling; closed by it), **A11** (the constant, which
  does not move), **A48** (the re-measurement and the registry cells), **A63**
  (the artifact A48 measures), **A106** (the two prose defects on this file),
  **A27** (the document, historically — its Update rule is vindicated as a
  procedure and mis-attributed by structure)
- **Amends**: **D102 §5** — the *"available today at no cost"* clause, and
  **kill criterion 6, which this record ANSWERS** (no released build verified
  real anchors before 2026-08-07; three independent confirmations, §1.5);
  **D102 §8**'s claim that the alloc test binary *"runs on wasm32 wherever that
  lane already runs the crate's tests"* (`D102:517-519`), which is **false** —
  `scripts/wasm-tests.sh` runs `cargo test -p antseal-core --lib`;
  **D58 §9.2's D102 note** (`D58:773-779`), which carries the same "one
  irreversible move… at no cost" framing; **`tasks/A.md` A48's `Do`**
  (`:791`), whose *"every margin is ≥ 15×"* is falsified by the depth row;
  **`docs/format/anchor-artifact-limits.md` §5a** (heading scope) and its
  `MAX_OTS_DEPTH` row. **Supersedes**: nothing. **Binds against**: D84 F1–F4,
  D10 rows 8/16/17, D58 §9.2/§9.3/§10.3 rule 6, D102, D26 §2, Q14, Q27, Q64.

---

## The problem, in one sentence

A109 says a window to lower `MAX_OTS_DEPTH` is open and expiring, and cites
four numbers to argue the lowering is worth making: every one of the four is
wrong, and the window is real anyway.

---

## 1. What was measured

Everything below was read at `4672843` with the working tree carrying Q125's
uncommitted lane. No production code was written, no constant moved, and
**no `cargo` run was needed** — §2.2 records precisely why the ruling does not
turn on the one figure that is not gate-verified.

### 1.1 The two texts, in full, and the third nobody cited

Three statements of F4 exist in the tree, and the brief cites only two.

| # | site | text on monotonicity | drift-checked? |
| --- | --- | --- | --- |
| 1 | `D84:162-169` = `anchor-artifact-limits.md:56-63` | *"**Monotonicity after M2's first release.** Once a released build verifies real anchors… **raised, never lowered**… Any lowering is a format-version event…"* | **no** — hand copy, Q64 |
| 2 | `D84:244-245` = `anchor-artifact-limits.md:127-128` = `tasks/Q.md:192` | *"limits may **afterwards** be raised, never lowered"* | **yes** — `check-traceability.py --freeze-boundary` |
| 3 | `anchor-artifact-limits.md:331-338` | *"`lowered` starts at `never`… changing it away from `never` is a **format-version event** requiring the full freeze procedure (Q27, mirroring Q14) and a dated note in §6 saying which release lowered it and why"* | no |

Site 2 is the one inside the v1 freeze, the one Q14's checklist quotes, and
the **only** copy a lint compares across files — and it drops the release
condition entirely, saying *"afterwards"* with no antecedent but "set at M2".
Neither D102 nor recon cites it. It is the strongest textual case for the
unconditional reading, and §2.1 explains why it still loses.

### 1.2 The provenance of site 3 — recon's finding 1 is wrong at the source

Recon states that `:331-337` was *"added 2026-08-07 by the D102 lane"*.
Measured:

```
$ git log -S'Update rule' --oneline -- docs/format/anchor-artifact-limits.md
1620543 A27: the anchor-artifact limit contract — F1–F4 frozen, the numbers deliberately absent
```

One commit, **2026-07-28** — A27's creating commit, the same day D84 resolved.
`git show 1620543:…` renders the paragraph byte-identically to today's
`:331-338`. What the D102 lane added (`6f69e1a`) is the **`### 5a.` heading and
the ~50 lines under it**, inserted *above* A27's two closing paragraphs. The
insertion point means the Update rule and the `Rows A28 must add on day one`
paragraph (`:340-341`) now sit **inside a section whose second line reads
"Added 2026-08-07 by [D102] (task A100)"**.

This is not a quibble about a date. It is a **provenance corruption with a
measured victim**: a careful read-only recon lane, working from the rendered
document, concluded that a rule written by the task D84 chartered to record F4
was written ten days later by an unrelated lane, and built its central finding
on that. The document produced the error. §5 rules the repair and its owner.

### 1.3 The structural cost, by target, derived rather than quoted

`OTS_FRAME_BYTES` and `OTS_ATTESTATION_BYTES` are `size_of` (`limits.rs:149`,
`:158`), so the cost is a function of pointer width. `Frame` is
`Option<Vec<u8>> + 2×u32 + bool`: 24+8+1 → 40 on 64-bit, 12+8+1 → 24 on 32-bit.
Both figures agree with the measured values `limits.rs:143` and `:153` record.

| | `walk.rest` | `attestations` | total | % of `MAX_OTS_BYTES` |
| --- | --- | --- | --- | --- |
| x86-64 | 1 024 × 40 = **40 960 B** | 256 × 48 = 12 288 B | **53 248 B** | 5.08 % |
| **wasm32** | 1 024 × 24 = **24 576 B** | 256 × 32 = 8 192 B | **32 768 B** | 3.13 % |

**A109 applies the x86-64 number to the wasm32 venue.** Its sentence is *"40 960 B
of work-stack bookkeeping in a parser that runs in a browser tab"*; the browser
tab's work stack is **24 576 B**, and `limits.rs:155-157` states the
consequence outright — *"the browser tab, which is the tightest ceiling this
parser runs under, is also the **cheapest place it runs**"*. The one venue
A109 invokes to make the cost sound alarming is the venue where it is 40 %
lower.

Scale, from the same freeze: `MAX_OTS_BYTES` = 1 MiB **per artifact**,
`MAX_OTS_ANCHOR_COUNT` = 256 artifacts per bundle, `MAX_BUNDLE_BYTES` =
268 435 456 B. The browser tab's 24 576 B of parser bookkeeping is **0.009 %**
of the bundle this verifier has already committed to holding.

Clause (c)'s ceiling is also target-dependent, and nothing in the tree says so:
the largest admissible power of two is **16 384 on x86-64** and **32 768 on
wasm32** (`P×24 + 8 192 ≤ 1 048 576` admits 32 768). D102 §3.2's table, quoted
into `limits.rs:195-197` and into the registry at `:320-321`, states the
x86-64 row as universal. The conclusion is safe — the `const` assert fires on
the strictest target and CI builds both — but the statement is not qualified,
and this project reddened `wasm32-core-tests` on precisely this confusion one
commit ago (`873a1cf`).

### 1.4 The real artifact's depth, and what is and is not gate-verified

`ots/tests.rs:250` and `:267` commit two shape measurements: `merged-A.ots` at
depth 12, `rust-opentimestamps-LARGE_TEST.ots` at depth 67. A read-only Python
port of `parse.rs::walk` reproduces **both exactly**, and then reports the
project's own six 2026-08-03 upgrade fragments:

| artifact | bytes | depth | ops | atts |
| --- | --- | --- | --- | --- |
| `merged-A.ots` (pre-upgrade) | 664 | 12 | 34 | 3 |
| `upgraded/A-alice.upgrade` | 1 000 | 67 | 67 | 1 |
| `upgraded/A-bob.upgrade` | 1 036 | 70 | 70 | 1 |
| `upgraded/A-catallaxy.upgrade` | 1 105 | 73 | 73 | 1 |
| **merged-A + all three, spliced** | **3 808** | **85** | **244** | **6** |
| merged-B + all three, spliced | 3 773 | 83 | 242 | 6 |

The splice is `file[..offset] ‖ 0xff ‖ body ‖ file[offset..]`, read line by line
against `container.rs:252-268`, at the offset `locate_pending` returns (the
`0x00` attestation tag byte, `container.rs:200-243`). The structural fact this
exposes is worth more than the number: **depth is not a property of the
calendar's proof, it is the attachment depth plus the fragment depth.** The
deepest fragment is 73; the artifact a verifier parses is 85, because
catallaxy's pending attestation hangs at depth 12 in our own merged file.
Adding calendars adds width, not depth — but a longer Bitcoin merkle path or a
larger calendar aggregation round adds depth, and both are set by third
parties and trend upward with block transaction count and calendar traffic.

**Not gate-verified.** The 85 is a planning-round measurement, and this record
deliberately does **not** write it into the registry (§4). **The lowering
ruling does not turn on it** — §2.2 shows the ruling is identical at 85, 73 and
67, and would move only below 64. That is why no `cargo` run was made.

### 1.5 No release has occurred — three independent confirmations

Every crate is `version = "0.0.0"` (eight `Cargo.toml`s). The only tags are
`format-v1-freeze` and `pre-trailer-strip-949dd9d`, neither a release. Q30
(signing keys) and Q31 (release workflow, versioning scheme) are unbuilt. And
independently of this record's reasoning, **D97 §1.3 already ruled on the same
fact for a different constant** — *"no build has shipped, so the first release
is at v2"*. **D102 kill criterion 6 is hereby answered in the negative.**

### 1.6 What a lowering costs in the tree, measured

Sites that move with the constant, in descending order of how load-bearing they
are:

| site | what it is | breaks below |
| --- | --- | --- |
| `ots/tests.rs:280` | `shape.max_depth <= MAX_OTS_DEPTH / 8` over each real fixture — *"what the F4 margins claim, asserted rather than trusted"* | **680** (once measured at 85); 536 at the old 67 |
| `tests/anchor_ots_alloc.rs:383-384` | `assert_eq!(at_cap.len(), 1_145)` — hand-written, and 1 145 = 65 header + `MAX_OTS_DEPTH` + 56 | **any** change |
| `ots/tests.rs:939-944` | `vec![0x08; 1_025]`, the `+1` rejection witness | **any** change |
| `limits.rs:399` | `("MAX_OTS_DEPTH", 1_103)`, *"deliberately hand-transcribed rather than computed"* | **any** change |
| `tests/anchor_ots_alloc.rs:399-402` | `open_fork_spine(128)` must reach depth 128 | **128** |
| `ots/tests.rs:1186-1197` | `parser_is_iterative_at_max_depth` — D58 §11's 256 KiB-stack witness | see below |
| prose | `limits.rs:87`, `:195-197`; `D102:213-225`; `docs/testing/fuzzing.md:75`; registry `:222` (the last cross-checked by `ots_limits_match_the_f4_registry`, `limits.rs:264-278`) | any |

**There is no lowering that keeps every assertion green with no test edit** —
the `1_145` literal moves first, on any change at all.

The iterative-parser witness deserves a number rather than a shrug. D58 §3.5
measured the rejected recursive crate at **1 048 576 B for a 255-op chain in
debug** and 163 840 B in release, so on a 256 KiB thread stack it aborts above
≈ **64** ops in debug and ≈ **408** in release. At 1 024 the witness kills a
recursive reimplementation in **both** profiles. At 512 it still kills it in
both. At 256 or 128 it kills it only in debug — which is the profile CI runs
(`ci.yml`'s `test` job is `cargo test --workspace --locked`, and D58 §11 records there is no release test lane anywhere), so
the practical witness survives a deep cut while its **profile-independence**
does not. Recon's finding 9 is real but graded, and the grade matters: this is
the exact test `D102:596-600` names as the thing that would have flipped
D102's own ruling.

The same lowering also **loosens** clause (c)'s headroom guard
(`anchor_ots_alloc.rs:493-503`), which asserts `last_green >= MAX_OTS_DEPTH * 4`
— a floor measured *relative to the constant*, so shrinking the constant moves
the tripwire further from firing. That guard exists to detect D102 kill
criterion 4 (clause (c) blocking a raise that is independently necessary), and
lowering blunts it.

---

## 2. RULING 1 — the window exists; sentence 1 governs *when*, sentence 3 and §5 govern *what it costs*

**There is no conflict to resolve. Recon manufactured one by reading a
procedure as a permission.**

### 2.1 Why sentence 1 governs the permission question

Four grounds, in ascending order of strength.

1. **The heading.** F4 is titled *"Monotonicity after M2's first release."*
   A rule whose own title carries the condition does not shed it in its third
   sentence.
2. **Sentence 2 is the harm model and it names a release.** *"Raising cannot
   reject a bundle a past release accepted; lowering can."* The harm requires
   a past release that rendered a verdict depending on artifact internals.
   D84 §2 spends three numbered paragraphs establishing that none exists and
   none can before M2 — the M0 verifier never opened an artifact, M1 ships
   `--no-anchor`, and the first `.ots` and the limits arrive in the same
   milestone. The condition is not a date someone picked; it is the exact
   statement of when the harm becomes possible.
3. **Sentence 3's characterisation presupposes the harm.** *"Any lowering is a
   format-version event"* is only coherent where lowering can break format
   compatibility. Applied before first release it contradicts **D84 §3** —
   *"the numeric limits are **not** format surface"*, which is the load-bearing
   half of D84's whole ruling and the reason no exception to MVP-SPEC.md line
   123 was written. Reading sentence 3 as an independent unconditional rule
   requires D84 to contradict its own §3 in its own §4.
4. **Site 3 is a registry procedure, not a permission.** `:331-338` opens
   *"One row per artifact-internal limit… added when the limit is first set,
   never deleted"* and closes *"the history stays readable, so 'has this ever
   been lowered?' is answerable from the tree"*. Every clause is about **what
   the table must contain**. It answers "what does a lowering cost and what
   gets recorded", never "when may one happen". Its author had transcribed
   F4's release-conditioned heading three sections earlier in the same commit;
   an author who read F4 as unconditional would not have carried that heading.

**On site 2**, the drift-checked freeze-boundary copy. It is a **parenthetical
summary** of F1–F4 — *"(limits are evaluated only in the anchor stage; an
over-limit artifact fails that anchor alone as `invalid`; limits may afterwards
be raised, never lowered)"* — compressing three rules into three clauses. A
summary that loses a qualifier does not overrule the rule it summarises, and
this is the same block D84's own "correction to the correction" identifies as
having propagated one error across five sites. It is evidence that the
condition is easy to lose, not evidence that it was never there.

**Ruling.** F4 sentence 1 governs the permission. **The window to lower
`MAX_OTS_DEPTH` is open today and closes at the first release that verifies
real anchors** — Q31's first tagged build carrying the M2 anchor stage.
A109's `⏳ EXPIRES AT FIRST RELEASE` is **correctly filed**, and its dependency
`before Q30/Q31` is the right dependency.

### 2.2 But D102's "at no cost" is refuted, by recon's own citation

D102 §5 reads: *"F4 has not yet engaged and lowering is available **today at no
cost** and never again."* Sentence 3 and site 3 are unqualified about **cost**
even though they are conditioned about **permission**, and they attach to any
lowering that is actually made:

- The `lowered` cell stops reading `never`, **permanently and visibly**, in the
  one table whose stated purpose is answering *"has this ever been lowered?"*.
  D102 §5's own third bullet counts that cell as a thing worth keeping.
- §6 owes a dated note.
- Q27/Q14's freeze procedure is named by both sites for *any* lowering, and
  nothing in either text scopes that naming to the post-release case.

So the honest statement, replacing D102's, is: **the window is open, and it was
never free.** That correction matters more than it looks, because "free" is
what makes an expiring option feel obligatory to exercise — and it is the
premise A109 inherited.

---

## 3. RULING 2 — `MAX_OTS_DEPTH` stays at 1 024, because no admissible lowering exists

Not declined on balance. **Empty.**

### 3.1 Every cap in (512, 1 024] costs exactly the same

`OTS_STRUCTURAL_WORK_STACK_BYTES = next_power_of_two(MAX_OTS_DEPTH) ×
OTS_FRAME_BYTES` (`limits.rs:166-167`), and `next_power_of_two(d) = 1 024` for
every `d` in `[513, 1024]`. The model is not an approximation of the
allocation — `Vec` doubles from capacity 4, so a parser that admits depth 681
still grows `rest` to capacity 1 024 before it refuses.

The fuzz-side exemption behaves identically: `ots_structural_alloc_bytes(L)`
uses `L.min(MAX_OTS_DEPTH).next_power_of_two()` (`limits.rs:222-228`), and for
every input length `L` that expression is unchanged when the cap moves within
`(512, 1 024]`.

> **Lowering to any value in (512, 1 024] changes not one reserved byte, on any
> target, for any input — and rejects artifacts the current cap accepts.** It
> is a strict loss.

The first value that saves anything is **512**: 20 480 B back on x86-64,
**12 288 B in the browser**. Twelve kilobytes, against a 256 MiB bundle cap.

### 3.2 The tree's own margin discipline puts the floor at 680

`ots/tests.rs:276-286` asserts, over each real fixture, that every measured
quantity is `≤ cap / 8`, with the comment *"that is what the F4 margins claim,
asserted rather than trusted"*. It is the only place the margin column becomes
operational. Against the deepest real artifact it demands
`MAX_OTS_DEPTH ≥ 8 × 85 = 680`.

**The bands are disjoint.** Admissible: `[680, 1 024]`. Buys a byte:
`≤ 512`. To lower at all you must first weaken the *"no honest artifact comes
close"* discipline — which is the premise A109 argues **from**. The option
defeats its own justification.

### 3.3 Invariance — why this does not turn on the depth-85 figure

| deepest real artifact | 8× floor | ≤ 512 admissible? |
| --- | --- | --- |
| 85 (spliced, §1.4) | 680 | no |
| 73 (deepest fragment) | 584 | no |
| **67** (the discredited third-party fixture A109 cites) | **536** | **no** |
| 64 | 512 | yes — the first value at which the ruling would move |

Every artifact in the tree measures 12, 67, 70, 73, 83 or 85 — every floor
from 536 upward. The ruling is invariant across all of them, **including the
wrong one**.

### 3.4 1 024 is not generous — it is optimal

Because cost is `next_pow2(cap)`, every admissible cap in `[680, 1 024]`
reserves the identical 40 960 B, and 1 024 accepts the most. **1 024 weakly
dominates every other admissible value**, and it is the smallest power of two
at or above the floor. The corroborating derivation: D58 §9.2 puts the deepest
honest *branch* at ~110–134 ops; §1.4 shows a merged artifact adds its
attachment depth, giving ~122–146; 8× that is 976–1 168, and 1 024 sits inside
that band. By the same standard D58 applied to `MAX_OTS_OPS` (*"4 096 is 4.6×"*
the structural ceiling), depth's 7.0× is the **more** conservative of the two.

The cap looked generous only because it was being compared against a
third-party crate's 2017 test constant.

### 3.5 The trade recon names, stated plainly

A lower cap **strengthens** the allocation bound and **weakens** the
iterative-parser witness (§1.6) and clause (c)'s headroom tripwire. That trade
is real, and this record does not need to price it, because the strengthening
side is **zero bytes** for every lowering the margin discipline permits. A
trade with nothing on one side is not a trade.

**Ruling. `MAX_OTS_DEPTH` remains `1_024`. No production constant changes.**
The margin this buys against the real spliced artifact at depth 85 is
**12.05×** (`1024/85`); against the deepest single upgrade fragment, 14.03×;
against the pre-upgrade merged file, 85.33×.

---

## 4. RULING 3 — the depth-67 citation and the 15.28× margin: A48's, with A63 supplying the artifact

Findings 3 and 5 are defects whichever way §3 had gone, and **A109 must not
absorb them.**

**Owner: A48**, unambiguously and already registered. Its `Do` (`tasks/A.md:781-792`)
names this exact work — re-measure the bootstrapped rows *"with
`anchor::ots::parse_ots_measured` — which exists so this is a call rather than
a second parser"* — and its Accept row reads *"The four `measured against`
cells name an A25 fixture and no crate."* **A63** owns producing the artifact
(assemble the real upgraded `.ots` from the six committed 2026-08-03
responses). **A106** already flags the citation at `:221-226`. **A22 owns none
of it**, and neither does A25 — `tasks/A.md:316` records that three documents
mis-charge A25 with A48's work.

What this record supplies, so A48 does not re-derive it:

1. The `MAX_OTS_DEPTH` row's `measured against` cell must name **A63's
   artifact** and its depth, and the `margin` cell must be recomputed. If the
   depth is 85 it reads **12.05×**, not 15.28×.
2. **A48's own `Do` is falsified in the same edit.** `tasks/A.md:791` justifies
   leaving the values alone with *"(F4 forbids lowering, **every margin is
   ≥ 15×**)"*. Against the real artifact the depth row is **12.05×**. The
   conclusion survives — §3 refuses the lowering on far better grounds — but
   the stated reason does not, and a task entry that carries a false
   parenthetical is how the next lane inherits it. Ops, for the record, moves
   40.96× → **16.79×** (244 ops) and attestations 64.00× → 42.67× (6).
3. **This record deliberately writes no number into the registry.** The
   registry's own rule is that every `measured against` figure *"is produced by
   the parser itself"* (`:262-263`). A planning round's Python is not that
   parser, however faithfully it reproduces two committed measurements. A48
   measures; D104 rules what the cell must **say**.
4. The margin cell must state **which artifact** it is a margin against. The
   table currently holds two candidate fixtures and the reader cannot tell
   which a bare `15.28x` refers to — which is how A109's author took a
   third-party number for *"the real mainnet proof"*.

**And a new requirement, because §3.2 changed the column's status.** The margin
was descriptive before D102; `ots/tests.rs:280` and clause (c)'s headroom guard
have made it operational. Yet **the margin column is the only numeric column in
§5 that nothing cross-checks**: `ots_limits_match_the_f4_registry`
(`limits.rs:264-278`) pins the *value* cell, and
`the_structural_cost_column_states_the_derivation_and_its_value` (`:295-324`)
pins the *structural-cost* cells. Nothing pins margin. That is the mechanism by
which A109 reasoned from the single unverified cell in an otherwise
cross-checked table. **Registered, not absorbed — see §7.**

---

## 5. RULING 4 — §6's changelog gap is not repaired here, and it is larger than finding 7 states

Recon reports that §6 *"stops at 2026-07-28 and records no D102 edit at all"*.
Measured, the gap is total:

```
$ git log --oneline 1620543..HEAD -- docs/format/anchor-artifact-limits.md | wc -l
7
```

**Seven document-changing commits since creation, zero §6 entries.** §6 is not
missing an entry; it has never been used. That is worse than an omission,
because **§5's Update rule routes F4's auditability through it** — *"a dated
note in §6 saying which release lowered it and why"* is the evidence step that
makes *"has this ever been lowered?"* answerable, and it depends on a section
with a 100 % miss rate.

**Not repaired here.** A109 rules a limit; this is document machinery, and the
repair is not seven retrospective entries — a changelog written by lanes that
did not make the edits is fabricated provenance, which this project refuses
elsewhere. The durable repair is a lint of the `--freeze-boundary` shape, or
deleting §6 and moving the lowering note into the `lowered` cell itself.
**Registered as Q126** (§7). It is not A106's — A106 is scoped to two
provenance citations — and it is not Q64's, which is the F1–F4 lint.

**One clause of it is A109's**, because it conditions the window §2 just
opened: **a future lowering may not be recorded into an inert §6.** Whoever
exercises the window closes Q126 first, or the ceremony §5's Update rule
prescribes produces an entry in a section nothing maintains.

---

## 6. RULING 5 — yes, the wasm32 asymmetry goes in the registry, and it is A106's

Five grounds.

1. **The registry is where the argument for lowering was made, and it cannot be
   checked there.** A109's case is *"40 960 B in a browser tab"*. The registry
   cell says `40 960 B … (40 B, x86-64)` — correct, and target-qualified — but
   a reader cannot learn from it that the other target is **24 576 B**, still
   less that the qualifier points the *opposite* way from the argument. The
   fact that guts A109 lives in `limits.rs:155-157` and nowhere the registry
   reader will look.
2. **This project has already paid for the identical omission, one commit ago.**
   `873a1cf`: `size_of::<x509_cert::Certificate>()` is 376 on wasm32 against
   512 on x86-64, two new DER equality rows asserted the 64-bit literals
   unconditionally, and `wasm32-core-tests` went red. Its own commit message
   states the `.ots` half's fact for the DER half — *"the browser tab, the
   tightest ceiling this parser actually runs under, is the target with the
   most headroom rather than the least"*. The `.ots` side has the same fact and
   the registry does not say it.
3. **The wasm32 figures are asserted by nothing, which clause (a) forbids.**
   `the_structural_cost_column_states_the_derivation_and_its_value` checks byte
   counts only under `size_of::<usize>() == 8`; `tests/anchor_ots_alloc.rs` —
   clause (b)'s equalities *and* the clause-(c) headroom guard — is an
   **integration** test, and `scripts/wasm-tests.sh` runs
   `cargo test -p antseal-core --lib`. So 24 576 / 8 192 / 32 768 exist only as
   hand-written doc prose, which is exactly *"a number typed by hand is a
   number that survives a raise"*. **`D102:517-519` is wrong** to say the test
   binary *"runs on wasm32 wherever that lane already runs the crate's tests"*.
4. **Clause (c)'s ceiling is target-dependent** (§1.3): 16 384 native, 32 768
   wasm32. The registry `:320-321` and `limits.rs:195-197` state the native row
   as universal.
5. It is two cells and one sentence.

**Ruling.** The two numeric `structural cost` cells carry the wasm32 figure
beside the x86-64 one; §5a gains one sentence stating the direction — the
browser is the cheapest venue, not the tightest — and the headroom line is
target-qualified. Because clause (a) forbids adding a fourth unchecked number,
the same edit gives `the_structural_cost_column_states_the_derivation_and_its_value`
a 32-bit arm asserting the wasm32 cells, mirroring the split `caps.rs` adopted
at `873a1cf`.

**Owner: A106**, whose class this is — *"this file says something that misleads
a careful reader"* — and which is already `after A48`, so it lands after the
row is re-measured. The `§5a` heading capture (§1.2) is the same owner and the
same edit: end §5a before `**Update rule.**`, or re-title it so A27's two
paragraphs are not filed under a D102 banner. **A106 grows from XS to S** and
gains the 32-bit test arm; if the orchestrator prefers the test edit sit with
code, it rides A48. Q125's in-flight lane closes the *venue* half (a gate that
runs the wasm32 tests); this ruling is about the *record*, and neither
substitutes for the other.

---

## 7. Discovered work — named, not registered

*(A-domain is at A111, Q-domain at Q125; the orchestrator allocates.)*

- **A112** (XS) — the F4 registry's `margin` column is cross-checked by
  nothing, while `ots/tests.rs:280` and clause (c)'s headroom guard have made
  it operational; pin it the way the value and structural-cost cells are pinned.
- **Q126** (S) — `docs/format/anchor-artifact-limits.md` §6 has taken zero
  entries across seven document-changing commits while §5's Update rule routes
  F4's *"has this ever been lowered?"* auditability through it; either enforce
  it with a `--freeze-boundary`-shaped lint or delete it and move the lowering
  note into the `lowered` cell.

---

## 8. Kill criteria

This record is wrong, and must be reopened, if any of these is measured:

1. **The deepest real artifact measures ≤ 64.** §3.3's invariance table
   collapses, 512 becomes admissible, and the lowering must be re-argued on the
   20 480 B / 12 288 B it would then buy. A48's `parse_ots_measured` run over
   A63's artifact is exactly this test.
2. **`walk.rest` is found not to grow by doubling from capacity 4** — a
   `RawVec` policy change on the pinned toolchain. §3.1's "every cap in
   (512, 1 024] costs the same" is a property of that growth policy, and D102
   §8 already anticipates the toolchain bump as the venue where it would
   surface.
3. **A released build is found to have verified real anchors before
   2026-08-09.** §2.1's window closes retroactively; §3's refusal is unchanged,
   but §2.2's correction to D102 would then be moot and this record must not
   stand claiming an option was open if it was not. Inherited from D102 kill
   criterion 6, which §1.5 answers.
4. **`ots/tests.rs:280`'s `/8` is deliberately weakened by a later record.**
   §3.2's floor is derived from it. Weakening it is legitimate work, but it
   re-opens the lowering question and must say so.
5. **A calendar topology change pushes a real artifact past `1 024 / 8 = 128`.**
   Then the *raise* question opens under clause (c) — which is the clause
   working. Headroom to 16 384 (x86-64) is measured and available.
6. **The Python's splice is found to disagree with `merge_upgrade`.** §1.4's 85
   would move. §3.3 makes the ruling survive it, but §4's registry cell would
   need a different number — which is precisely why §4 declines to write one.

---

## 9. Consequences — the exact edit set

| file | edit | § |
| --- | --- | --- |
| `TODO.md` A109 | closed as RULED; the paragraph's four wrong numbers restated (40 960 → 24 576 in the venue it names; "depth 67" → A63's artifact; the window is open but never free; the option is empty, not declined) | 2, 3 |
| `docs/decisions/D102-parser-structural-allocation-cost.md` §5 | *"available today at no cost"* → the ceremony §5's Update rule prescribes and the permanent loss of `lowered: never` | 2.2 |
| `D102` kill criterion 6 | marked **answered** — no released build verified real anchors before 2026-08-09 | 1.5 |
| `D102` §8, `:517-519` | the alloc test binary does **not** run on wasm32; `scripts/wasm-tests.sh` is `--lib` | 6 |
| `docs/decisions/D58-opentimestamps-viability.md:775-776` | same "one irreversible move… at no cost" framing as D102 §5 | 2.2 |
| `tasks/A.md` A48 `Do` `:791` | *"every margin is ≥ 15×"* → the measured margins, depth included | 4 |
| `docs/format/anchor-artifact-limits.md:222` | `measured against` names A63's artifact and its depth; `margin` recomputed | 4 |
| `docs/format/anchor-artifact-limits.md:276-338` | §5a ends before `**Update rule.**` — A27's two paragraphs stop being filed under a D102 banner | 1.2, 6 |
| `docs/format/anchor-artifact-limits.md` §5a + the two numeric cost cells | wasm32 figures beside x86-64; one sentence on the direction; headroom line target-qualified | 6 |
| `crates/antseal-core/src/anchor/ots/limits.rs:195-197` | the headroom table is x86-64's; wasm32's last green is 32 768 | 1.3, 6 |
| `crates/antseal-core/src/anchor/ots/limits.rs:295-324` | a 32-bit arm asserting the wasm32 cells, mirroring `caps.rs` at `873a1cf` | 6 |

**Zero constants move. Zero wire bytes. Zero format-version events. Zero
vectors, digests or error codes touched. `MAX_OTS_DEPTH` is `1_024` before and
after.**

---

## 10. What this record does not decide

- **Whether the real spliced artifact is depth 85.** §1.4 measures it and §3.3
  makes the ruling independent of it. **A48** measures it with
  `parse_ots_measured` against **A63**'s artifact; this record writes no
  number into the registry.
- **Whether `MAX_OTS_DEPTH` should be *raised*.** Raising is always available
  under F4 and never expires, and clause (c) measures the ceiling at 16 384.
  §3.4 notes that 1 024 sits at, not above, the 8× line against D58 §9.2's
  derived honest ceiling — a live observation, not a proposal.
- **The other seven F4 rows' lowering windows.** Every one is open on the same
  reading and closes at the same moment. §3's arithmetic is `MAX_OTS_DEPTH`'s
  alone; the `next_pow2` step argument transfers to `MAX_OTS_ATTESTATIONS` and
  to nothing else, because only those two bound containers.
- **The DER half.** `MAX_CHAIN_CERTS`, `MAX_CHAIN_CERT_BYTES` and
  `MAX_SIGNED_ATTRS` have no registry rows at all (**A110**), so they have no
  cells for §4 or §6 to correct. Their lowering windows are open on the same
  reading and nobody has asked.
- **Whether the wasm32 tests should run in the local gate.** **Q125**, in
  flight in the working tree. §6 rules the record, not the venue.
- **A100.** Closed. §1.3 restates its measured numbers; it re-opens nothing.

---

## Outcome

**RESOLVED, 2026-08-09.** The window is **open** — F4 sentence 1's release
condition governs the permission, because sentence 2 is the harm model and
sentence 3's *"format-version event"* would contradict D84 §3 if applied before
a release exists; the Update rule recon read as an unconditional prohibition is
**A27's registry procedure from 2026-07-28**, mis-attributed to D102 by a
heading inserted above it, and it prices a lowering without permitting or
forbidding one. **D102's *"at no cost"* is refuted in the same breath**: the
ceremony and the permanent loss of `lowered: never` are unqualified. On the
merits the option is **empty, not declined** — `next_pow2` makes every cap in
`(512, 1 024]` cost identical bytes, the tree's own 8× margin discipline puts
the floor at 680, the bands are disjoint, and 1 024 weakly dominates every
admissible value. The conclusion holds at depth 85, 73 and the discredited 67.
**`MAX_OTS_DEPTH` stays 1 024 and nothing in `limits.rs` moves.** A109's four
load-bearing numbers are each wrong — most sharply the one that invokes the
browser tab as the constrained venue when the browser tab costs **24 576 B**
and is the cheapest place this parser runs. The registry's depth-67 provenance
and 15.28× margin are **A48's** to re-measure against **A63's** artifact, with
A48's own *"every margin is ≥ 15×"* falsified in the same edit; the §5a heading
capture and the wasm32 asymmetry are **A106's**; §6's total changelog silence
across seven commits is **Q126's**, and it conditions any future exercise of
the window this record leaves open.

---

## Index row (orchestrator applies at merge)

| [D104](D104-max-ots-depth-lowering-window.md) | A109 — does the `MAX_OTS_DEPTH` lowering window exist, and should it be used — **it exists, and the lowering is empty rather than declined.** Both sides of the brief are overturned. Recon's *"§5a governs, the window never existed"* fails on **provenance**: the Update rule at `:331-338` is **A27's, commit `1620543`, 2026-07-28**, not the D102 lane's — D102's §5a heading was inserted *above* it and now files two A27 paragraphs under a banner reading "Added 2026-08-07 by D102", a corruption that **already produced one measured error, recon's own finding 1**. And it is a **procedure, not a permission**: it prices a lowering and never permits or forbids one. F4 sentence 1 governs *when* — sentence 2 is the harm model and names a release, and sentence 3's *"format-version event"* would contradict **D84 §3** (*"not format surface"*) if applied before any release exists. A third statement neither the brief nor D102 cites — the **drift-checked** freeze-boundary copy at `:127-128`, *"raised, never lowered"* with no condition — is a parenthetical summary and loses. **But D102 is wrong the other way**: *"available today at no cost"* is refuted by the same unqualified sentence, since a lowering still spends Q27's ceremony and kills `lowered: never` forever. **On the merits the option is EMPTY.** Cost is `next_power_of_two(MAX_OTS_DEPTH) × size_of::<Frame>()`, so **every cap in (512, 1 024] reserves identical bytes on every target** and rejects more artifacts — a strict loss; the first value that saves anything is 512, and the tree's own margin discipline (`ots/tests.rs:280`, *"asserted rather than trusted"*) demands ≥ **680**. **Disjoint bands**, so **1 024 weakly dominates every admissible value** and is the cost-minimal admissible cap, not a generous guess. **Invariant to the depth dispute** — holds at 85, 73 and the discredited 67 (floor 536 > 512); would move only below 64, and every artifact in the tree is 12/67/70/73/83/85. **A109's four load-bearing numbers are all wrong**: 40 960 B is x86-64's, and the browser tab it invokes as the constrained venue costs **24 576 B** and is the **cheapest** place the parser runs (`limits.rs:155-157` already says so, total 32 768 B wasm32 vs 53 248 B native); "depth 67" is a third-party crate's 2017 test constant A48 exists to retire, while the project's own fragments are 67/70/73 and the **spliced artifact a verifier parses is 85** — depth is attachment depth **plus** fragment depth, a structural fact nobody had written down; the margin is 12.05×, not 15.28×; and the cost is a rejection threshold, not bytes. Three defects fall out, **none absorbed**: the margin column is the **only numeric column in §5 no test cross-checks** (→ **A112**) — exactly how A109 came to reason from it; **§6 has taken zero entries across seven document-changing commits** while §5's Update rule routes F4's auditability through it (→ **Q126**, and it conditions any future lowering); and the wasm32 figures are asserted by nothing because `scripts/wasm-tests.sh` is `--lib`, so **`D102:517-519` is false** and clause (a)'s *"a number typed by hand survives a raise"* is being violated one file over from where it is written — the same confusion that reddened `wasm32-core-tests` at `873a1cf` one commit ago. Re-measurement is **A48's** (artifact from **A63**), with A48's own *"every margin is ≥ 15×"* falsified by the depth row; the §5a capture and the wasm32 cells are **A106's**. **Zero constants move** | RESOLVED (A48/A63/A106 execute; A112/Q126 registered) | 2026-08-09 |
