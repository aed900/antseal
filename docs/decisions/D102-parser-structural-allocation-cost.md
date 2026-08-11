# D102 — A100: which allocation rule governs the `.ots` parser's work stack

- **Status: RESOLVED — NEITHER of the two rules A100 names, because the
  allocation A100 is about is neither of the two things they govern.** The
  measured peak is not the op executor's running value and not a clamped
  container: it is `walk.rest`, the parser's iterative work stack
  (`parse.rs:437`), whose growth is **count-bounded** by `MAX_OTS_DEPTH` and
  not length-bounded by anything. D10 §4's clamp rule — imported into this
  parser verbatim by D58 §10.3 rule 4 — is a rule about **length headers**,
  and this site has no length header. There is a third class, it has never
  been written down, and A100 is the first thing to touch it.
  **Recon's lean is confirmed in shape and overturned in every load-bearing
  particular.** A compile-time structural bound is right; a compile-time
  structural bound **alone** is precisely the rubber stamp
  `docs/testing/fuzzing.md` §4 warns about, because it moves with the limit it
  is derived from and would stay green through the exact raise the objection
  names. The ruling therefore has **two** clauses, and the second one is new
  red that does not exist in the tree today. **This is a decision, not a
  task-level fix** (§2) — it amends D58 §10.3's normative rule set, and it
  attaches a precondition to **F4**, which D84 §7 puts inside the v1 freeze.
  **The option the brief asked me to take most seriously — bound the work
  stack by the input — is measured dead** (§4.3): its arithmetic is off by a
  factor of 40, the "~L/2 frames" premise is wrong (a frame costs **one** op
  byte, not two), and no reachable parser change makes the 1× rule true.
  **`MAX_OTS_DEPTH` is not lowered** (§5), though the window in which lowering
  is legal is measured to be open **now** and closing. **A100's Accept row 2
  is unsatisfiable and is replaced** (§7): the committed reproducer is
  measured at **245 B, sha1 `08df86ba…`**, not the 248 B / `b5aec24c…` the
  record claims — four base64 characters lost in transcription — and it
  reaches a **different terminal error** than the record implies.
- **Date: 2026-08-07** (M2 wave 9 planning round; briefed to overturn the
  lean, and the strongest finding is the one recon flagged for verification)
- **Owning tasks: A100** (the ruling), **A11** (the parser), **A23** (both
  fuzz targets), **A5** (the DER half, §6), **Q9** (`docs/testing/fuzzing.md`),
  **F30** (whose constant is being scoped, not weakened)
- **Amends**: **D58 §10.3** — adds rule 6 and scopes rule 4; **D58 §9.2**'s
  `MAX_OTS_DEPTH` derivation sentence, which asserted a cost it never
  computed; **`docs/format/anchor-artifact-limits.md` §5** — every F4 row
  gains a structural-cost column and a raise precondition; **A100's Accept
  rows 2 and 3**; **`docs/testing/fuzzing.md` §4 step 3**, by *exception with
  a named test*, not by amendment (§3.3). **Supersedes**: nothing.
  **Binds against**: D10 §4, D26 §2, D58, D61, D84 F1–F4, F30.

## Context

`fuzz-smoke` has been red on `anchor_ots` for four consecutive CI runs
(31086210534, 31127730409, 31128531727, 31167014974), on four different
inputs — 248, 744, 988 and 638 bytes — every one below 1 024 B and every one
peaking at **exactly 5 120 B** while the relative cap moved four times
(4 344 / 4 840 / 5 084 / 4 734 B). A100 records that pattern accurately and
draws the right negative conclusion from it: *"a rule whose verdict on
identical allocator behaviour depends on the input's length is the wrong
shape of rule for this parser."* It then names two candidates for what is
allocating, and **both are wrong.**

Everything numeric below was measured in this planning round on a counting
global allocator against the crate at `09a81c2`, x86-64, release profile.

## 1. What is actually allocating, and the number nobody has seen

### 1.1 It is the work stack, and `MAX_OTS_DEPTH` is its only bound

`Frame` (`parse.rs:218-229`) is `Option<Vec<u8>>` + two `u32` + a `bool` =
**40 bytes** (measured). `walk.rest: Vec<Frame>` starts empty and is grown one
`push` at a time at `parse.rs:437`. Rust's `RawVec` allocates capacity 4 for a
40-byte element and doubles, so the single-allocation ladder is

```
160  320  640  1280  2560  5120  10240  20480  40960
```

The **65th push** crosses 64 → 128 and allocates `128 × 40 = 5 120 B`. That
is the constant A100 measured four times and could not explain. Its
explanation is that `rest.len()` is exactly the current node's depth — the
stack holds the root-to-current path and `complete_top` pops on completion —
so

> **`walk.rest` reaches `MAX_OTS_DEPTH` entries, and nothing else bounds it.**

`MAX_OTS_DEPTH = 1_024` (`limits.rs:64`). `1_024 × 40 = **40 960 B**.`

### 1.2 The tree already builds that input, and asserts it is fine

`crates/antseal-core/src/anchor/ots/tests.rs:1186-1201`
(`parser_is_iterative_at_max_depth`) constructs a 1 024-op chain and asserts
it **parses successfully**. It is green today. Measured:

| input | len | shape | peak single | total | guard cap (`len + 4096`) | guard |
| --- | --- | --- | --- | --- | --- | --- |
| **`parser_is_iterative_at_max_depth`** | **1 145** | depth 1 024, 1 att | **40 960** | 114 829 | 5 241 | **FAIL 7.82×** |
| chain, 63 ops | 156 | depth 63 | 2 560 | 7 249 | 4 252 | pass |
| chain, 64 ops | 157 | depth 64 | 2 560 | 7 281 | 4 253 | pass |
| chain, **65 ops** | 158 | depth 65 | **5 120** | 12 433 | 4 254 | **FAIL** |
| chain, 65 ops, short URI | **142** | depth 65 | 5 120 | 12 417 | 4 238 | **FAIL** |
| chain, 129 ops | 222 | depth 129 | 10 240 | 24 721 | 4 318 | **FAIL** |
| **mainnet `LARGE_TEST.ots`** | **1 768** | depth 67, 100 ops, 4 atts | **5 120** | 15 520 | 5 864 | **pass** |
| open-fork spine, n=128 | 1 869 | depth 128, **129 atts** | **12 288** | 42 849 | 5 965 | **FAIL** |
| open-fork spine, n=1023 | 14 399 | `too-many-attestations` | 40 960 | 147 360 | 18 495 | **FAIL** |
| A100's committed blob | 245 | `unknown-op` | 5 120 | 10 112 | 4 341 | **FAIL** |

Three readings, in ascending order of importance.

1. **A legal artifact costs 40 960 B of bookkeeping from 1 145 B of input.**
   That is **35.77× the input** and **7.82× the guard's cap** — on bytes a
   counterparty supplied, in a parser that ships to a browser tab. Recon
   quoted "~7.8× amplification"; the two ratios are different numbers and both
   belong in the record.
2. **The real mainnet artifact allocates *exactly* the same 5 120 B as all
   four CI failures**, and passes for one reason only: 1 768 > 1 024. This is
   no longer an inference from four points on a line. It is the same
   allocation, measured, on the honest artifact and on the hostile ones, with
   the verdict decided by input length and nothing else. A100's suspicion is
   **confirmed as a measurement.**
3. **The smallest violator is 142 B, not 248 B.** libFuzzer minimises for
   crash preservation, not size, so all four CI inputs are far above the real
   boundary. Any future triage that starts from the 248 B blob starts three
   layers away from the cause.

### 1.3 The second site is real and has never fired

`attestations: Vec<OtsAttestation>` (`parse.rs:332`, pushed at `:384`) is
count-bounded by `MAX_OTS_ATTESTATIONS = 256`, element **48 B** (measured), so
`256 × 48 = **12 288 B**`. Reachable: the n=128 open-fork spine above peaks at
12 288 B — the attestation Vec, not the work stack — from 1 869 B of input.
It has never been the reported peak in CI because the work stack usually wins
first. It is the same defect and it must be ruled at the same time, or the
next fuzz red re-opens all of this under a different constant.

### 1.4 Recon's two negative findings, verified

- **The executor is not the violator.** `exec::apply` (`exec.rs:118-135`)
  returns `Ok(None)` for an indeterminate value and computes SHA-256 into a
  32-byte array otherwise; `alloc_checked`'s `would_be = value_len +
  operand_len` with the operand **borrowed from the reader**, so it already
  satisfies `len + 32`. Every op in the reproducer path is skipped or
  32-byte. **Tightening `MAX_OTS_VALUE_BYTES` changes nothing**, and A100's
  `Do` — *"should use a budget bounded by `MAX_OTS_VALUE_BYTES`"* — would have
  produced a 32 768 B budget that fixes nothing and hides the D58 §3.2 class
  (§4.2). Option (B) is **refuted**.
- **`len × 1 + 4096` is the harness's invention, not D10's text.** D10 §4
  (`D10-parser-caps.md:287-291`) says *"Every pre-allocation is clamped to
  `min(claimed_length, remaining_input)`"*, justified by *"every element of a
  definite-length array costs at least one wire byte"*. `SLACK = 4096` and
  `MAX_CLAMPED_ELEMENT_BYTES = 1` (`fuzz/src/lib.rs:95, 135`) carry **F30**
  provenance about the CBOR codec.

## 2. Why this is a decision and not a task-level fix

Recon says task-level. That is wrong for three independent reasons, any one
of which is sufficient.

1. **It writes a rule D10 §4 does not contain and D58 §10.3 does not
   contain.** §3 below is normative for every count-bounded container in the
   anchor stage — `.ots` today, DER at A5 (§6) — and normative text lives in
   a decision, not in a task entry that no future reader greps.
2. **It attaches a precondition to F4.** Clause (c) of §3.1 makes a raise of a
   count limit conditional on its structural cost. F4 is inside the v1 freeze
   (D84 §7's checklist row, verbatim). Adding an operating condition to a
   frozen rule is a registry event by D84's own construction, and D84 §4
   requires *"every limit's value and every change"* to be answerable from the
   tree.
3. **It rules on whether lowering `MAX_OTS_DEPTH` is legal** (§5). That is
   squarely a D84 §4 F4 question and cannot be settled in a task entry.

The task-level half — editing the two fuzz targets and adding a test binary —
is real work and belongs to A23/A11. It is downstream of this document, not a
substitute for it.

## 3. The ruling

### 3.1 The third rule (D58 §10.3 gains rule 6, verbatim)

> **6. A container bounded by a *count limit* is not governed by the clamp
> rule, and its cost must be derived, bounded and asserted.** Rule 4's clamp
> discipline governs allocations driven by a **length header** in the input.
> A container whose length is bounded instead by one of §9.1's count limits —
> `walk.rest` by `MAX_OTS_DEPTH`, `attestations` by `MAX_OTS_ATTESTATIONS` —
> has no claimed length to clamp against and is governed by this rule
> instead. Its **structural allocation cost** is
>
> ```text
> next_power_of_two(LIMIT) × size_of::<Element>()
> ```
>
> summed over every such container live in one parse. That cost must be:
>
> - **(a) derived in code from the limit constants and `size_of`, never
>   written as a literal.** A number typed by hand is a number that survives
>   a raise.
> - **(b) asserted at equality against the measured peak**, on the pinned
>   stable toolchain, for at least one input that reaches each limit and for
>   the real A25 artifact.
> - **(c) `≤ MAX_OTS_BYTES`.** A raise under F4 that breaks this is refused
>   until it is argued on memory rather than on "it only costs a `Vec`
>   entry".

Rule 4 is unchanged in content and gains one scoping clause: *"…applies
unchanged **to every allocation driven by a length header**. Count-bounded
containers are rule 6's."*

### 3.2 Why clause (c) is `MAX_OTS_BYTES` and not a new number

This is the part that answers the objection, and it costs **zero new
constants**. `MAX_OTS_BYTES = 1_048_576` (D10 row 16) is already frozen v1
format surface, already the size of artifact this verifier commits to
holding, and D58 §9's opening paragraph already requires this module to
consume it *"by name … not redefined, restated or shadowed"*. Structural
bookkeeping that stays under the artifact's own frozen byte cap adds at most
a constant factor to a commitment already made. Measured against it:

| container | limit | element | structural cost | % of `MAX_OTS_BYTES` |
| --- | --- | --- | --- | --- |
| `walk.rest` | `MAX_OTS_DEPTH` 1 024 | `Frame` 40 B | 40 960 B | 3.91 % |
| `attestations` | `MAX_OTS_ATTESTATIONS` 256 | `OtsAttestation` 48 B | 12 288 B | 1.17 % |
| **total** | | | **53 248 B** | **5.08 %** |

And the headroom clause (c) leaves, which is the number a future raiser needs:

| hypothetical `MAX_OTS_DEPTH` | structural cost | clause (c) |
| --- | --- | --- |
| 1 024 (today) | 53 248 B | green |
| 4 096 (4×) | 176 128 B | green |
| **16 384 (16×)** | **667 648 B** | **green — the last one** |
| 32 768 | 1 323 008 B | **RED** |
| **65 536** — the objection's own number | **2 633 728 B (2.51×)** | **RED** |

**The objection's scenario goes red.** A future raise to 65 536 on the
"it's just a `Vec` entry" sentence fails clause (c) by 2.5×, and — see
§3.4 — it fails it at **compile time**, not in a lane someone can rerun.
That is the new red this ruling adds, and it does not exist in the tree
today in any form.

### 3.3 What the fuzz target asserts instead

The peak assertion at `anchor_ots.rs:71` becomes

```text
peak_single ≤ max( len × 1 + SLACK , structural(len) )

structural(L) = next_pow2(min(L, MAX_OTS_DEPTH))        × size_of::<Frame>()
              + next_pow2(min(L, MAX_OTS_ATTESTATIONS)) × size_of::<OtsAttestation>()
```

Three properties make this a scoping of the guard rather than a widening of
it, and the third is the one that matters:

1. **The exemption is a function of the input**, not a constant. `min(L, …)`
   is sound because **every frame costs at least one op byte** — a bare
   `0x08` — so `rest.len() ≤ ops ≤ L`. An input that never goes deep gets
   almost no exemption. `structural(80) = 11 264 B`; `structural(1 145) =
   53 248 B`.
2. **The 1× clamp claim survives everywhere it was ever true.** `MAX_CLAMPED_-
   ELEMENT_BYTES = 1` is untouched, and F30's finding is untouched. What
   changes is that it stops being applied to a site it was never about.
3. **Both D58 crashers stay fully visible.** A regression reintroducing
   `vec![0; attacker_varint]` at the 80-byte §3.1 input allocates far past
   `max(4 176, 11 264)` → red. A regression reintroducing the unbounded
   hexlify chain at the 102-byte §3.2 input → red. Even a regression capped at
   `MAX_OTS_VALUE_BYTES = 32 768` is red at both lengths. **The class this
   target exists for is not weakened.**

**The honest cost, stated rather than buried.** At an 80-byte input the
window in which a hostile allocation can hide widens from 4 176 B to
11 264 B — about 7 KB. That is the minimum widening consistent with what the
parser structurally is, and closing it further needs **per-site attribution**,
which a `#[global_allocator]` cannot give. Registered as a follow-up (§9),
not required now.

**On `docs/testing/fuzzing.md` §4 step 3.** The policy is *"a panic or an
allocation-budget violation is a parser bug. Fix the parser."* I do **not**
amend it, and I do not accept that this is an exception granted to the party
the guard caught. Step 3 presupposes that the budget states a property the
parser is supposed to have. `MAX_CLAMPED_ELEMENT_BYTES`' own doc comment says
which property: *"Bytes of `Vec` capacity one clamped **element** costs"*,
justified by *"One input byte buys at most one reserved byte."* For
`walk.rest`, one input byte buys **forty**, by arithmetic, on legal input,
and no parser change alters that (§4.3). The work stack is **not a member of
the class the constant is about.** Applying it there was not a decision
anyone made; it is `assert_within_budget`'s default argument reaching a call
site nobody checked when A23 added a second target. That is a harness defect
under §4 **step 2**'s own words — *"the finding is in the harness, not the
parser — say so in the fix"* — reached by a route step 2 did not anticipate,
because the input **does** reproduce on the stable toolchain.

The discipline that keeps this from being a rubber stamp is that the fix must
leave the guard **strictly stronger somewhere**, not merely weaker here. It
does, in three places: clause (c) is a new red that does not exist today; the
exemption is tight and input-derived, so a *new* allocation site in the parser
is red on its first input; and `parser_is_iterative_at_max_depth` — green and
silent about 40 960 B today — acquires an assertion it does not carry.

### 3.4 Clause (c) is a `const` assertion, not a test

```text
const _: () = assert!(OTS_STRUCTURAL_ALLOC_BYTES <= MAX_OTS_BYTES, "...");
```

in `limits.rs`. In-tree precedent, and the same reasoning verbatim:
`fuzz_entry.rs:144-147` guards the start-digest offset with a `const` assert
because *"the build stops here rather than the target quietly losing its
coverage."* A raise that breaks clause (c) then fails **`cargo build`** — on
every lane, on wasm32, for every contributor, with no lane to rerun and no
budget to adjust. That is unignorable in a way no test is.

## 4. The options, and what killed each

### 4.1 (A) A compile-time structural bound, as a task, no D-number — *recon's lean*

**Overturned as stated, adopted as half of §3.** Right that the bound must be
derived; wrong that derivation is sufficient and wrong that it is task-level.
A bound derived from `MAX_OTS_DEPTH` **moves when `MAX_OTS_DEPTH` moves**, so
the objection's 65 536 scenario stays green under (A) alone and nothing red
ever says so. Clause (c) is what recon's lean was missing, and clause (c) is
an F4 precondition, which is what makes this a decision (§2).

### 4.2 (B) Tighten the executor — *refuted, verified*

§1.4. The executor allocates 32 bytes on the reproducer path and already
satisfies `len + 32`. A budget of `MAX_OTS_VALUE_BYTES = 32 768` would not
only fail to fix the work stack — it would be a **flat 32 KB constant
exemption** that hides the entire D58 §3.1/§3.2 class the target was built to
catch. It is the worst option on the table and it is the one A100's `Do`
currently leans toward. A100's `Do` must be corrected in the same edit.

### 4.3 (E-as-briefed) Bound the work stack by the input — *measured dead*

The brief asked me to take this most seriously: *"a `.ots` of length L cannot
honestly need more than ~L/2 frames, since each frame costs at least one op
byte."* The premise is arithmetically wrong in two ways.

- **A frame costs one byte, not two.** A bare `0x08` is one wire byte and one
  frame. So the honest relation is `frames ≤ L`, not `L/2`. Measured:
  `parser_is_iterative_at_max_depth` is 1 145 B and reaches 1 024 frames —
  0.89 frames per byte. An L/2 rule would **reject a legal artifact the tree
  already asserts must parse**.
- **`frames ≤ L` does not give `bytes ≤ L`.** It gives `bytes ≤ 40 L`. The 1×
  rule is not "make the parser honest about frames"; it is "make a frame cost
  one byte", and a frame cannot cost one byte.

I then tested the one parser change that *would* collapse the depth case — a
tail-call elimination, replacing the top frame in place when `is_last_child`
rather than pushing, since a last child's parent is never resumed. It is
sound, and it takes the 1 024-deep chain to O(1). **It does not save the
rule.** An open-fork spine `ff 08 ff 08 …` leaves every ancestor genuinely
open, so no replacement is legal; measured, n=1023 reaches the same 40 960 B
from 14 399 B, and n=128 reaches 12 288 B from 1 869 B on the *attestation*
Vec, which the optimisation does not touch at all. Best case it converts a
40× amplification into a 20× one. **No reachable parser change makes the 1×
rule true.** Option (E) as briefed is closed; the tail-call elimination is
registered separately (§9) on its own merits, not as an A100 fix.

### 4.4 (C) Exempt the target

Kills invariant #3 of `anchor_ots.rs`'s own module docs — *"no allocation
beyond the F11 budget … the assertion that would have caught D58 §3.1
directly"* — and leaves the D58 crashers guarded only by three unit tests
over three fixed inputs. Rejected outright.

### 4.5 (D-variants) Change the allocation

`Vec::with_capacity(MAX_OTS_DEPTH)` up front makes every honest 664 B
artifact allocate 40 KB — worse in the common case, better in none. Shrinking
`Frame` is real but bounded: `Option<Vec<u8>>` is 24 of the 40 bytes and is
load-bearing (D58 §9.4's indeterminate-value path). Boxing it would trade one
allocation for a thousand. Lowering `MAX_OTS_DEPTH` is §5.

## 5. `MAX_OTS_DEPTH` is not lowered — and the window is open now

Two things must be said in order, because the second is the one that expires.

**Is lowering legal?** D84 F4 reads *"Once a released build verifies real
anchors, artifact-internal limits may be **raised, never lowered**."* The
monotonicity is scoped to **after M2's first release**. If no build has been
released that verifies real anchors, F4 has not yet engaged and lowering is
available **today at no cost** and never again. This record does not need to
answer whether the window is open, because it declines the option on the
merits — but **anyone who later wishes it had been lowered must answer that
question first, and the answer gets harder every day.** Recording it is the
point.

**Should it be lowered?** No.

- D58 §9.2's structural derivation gives ~110–134 for the deepest honest
  branch. 256 would be ~2× that — inside the range where a real calendar
  topology change costs a format event. D84 §6's own guidance, quoted from
  D10, is *"guessing high is free, guessing low is a compatibility break."*
- The cost being bought back is **30 720 B**. Forty kilobytes was never the
  problem; the problem was that nothing measured it and nothing bounded its
  growth. §3 fixes both without spending the one irreversible move the freeze
  allows.
- The F4 registry row's `lowered: never` stays true, and `docs/format/anchor-
  artifact-limits.md` keeps its cleanest property.

**But D58 §9.2's sentence is wrong and must be corrected.** It reads *"depth
costs a `Vec` entry, not a stack frame — which is why it can be generous"*.
The clause is true and the inference is not: a `Vec` entry is 40 bytes,
nobody costed it, and the limit was set at 1 024 on the strength of a cost
nobody computed. The correction is one sentence and the measured number
(§3.2's table), so the next raiser inherits an arithmetic fact rather than a
reassurance.

## 6. `anchor_token.rs:71` — the same rule, applied before it goes red

The DER target uses the same entry point and the same default budget. It has
never gone red. **That is not evidence**, and A100 is the standing proof:
`anchor_ots` was green until its **first remote execution**, which found the
disagreement in 3 140 execs.

The DER path has the same class of site, verified:

- `tsa.rs:389-414` `chain_certificates` — `Vec::with_capacity(count)` **after**
  `count > MAX_CHAIN_CERTS` is rejected. Textbook count-bounded: `8 ×
  size_of::<Certificate>()` plus `8 × 24 B` for the DER copies.
- `chain.rs:669` `PathBuilder::new` — `Vec::with_capacity(supplied.len() + 1)`,
  bounded by `MAX_CHAIN_CERTS = 8` plus `MAX_INTERMEDIATE_COUNT = 16`.

**The only difference between the two targets is that one count limit is
1 024 and the other is 8.** Three orders of magnitude, not a difference in
kind — and `MAX_CHAIN_CERTS` is raise-only under F4 exactly as
`MAX_OTS_DEPTH` is.

**Ruling.** Rule 6 is written at the **anchor-stage** level, not the `.ots`
level, and `anchor_token.rs` takes the same treatment in the same change:
derive its structural cost from `MAX_CHAIN_CERTS`, `MAX_INTERMEDIATE_COUNT`
and `MAX_SIGNED_ATTRS`; assert it at equality; guard it with the same `const`
clause (c) against `MAX_TSA_TOKEN_BYTES` (D10 row 17, also 1 MiB). If the
derivation comes out **small enough to fit inside `SLACK`**, that is a
measured finding and it is committed **as an equality assertion**, because
that assertion is what goes red the day someone adds a container or raises a
count — which is the day it matters. An unmeasured "it's fine" is what this
whole record is about.

## 7. The record defect: A100's reproducer

**Measured.** The base64 block at `tasks/A.md:1077-1081` is **328 characters**
across five lines (80/80/80/80/8), decoding to **245 bytes**, sha1
`08df86ba508f949f93f45c9b478b4397000f6c06`, sha256 `c6d7636f…`. The record at
`:1075` claims **248 bytes**, sha1 `b5aec24c28e280a39dfba4027c750954fac646c3`.
248 bytes requires 332 base64 characters. **Exactly four characters were lost
in transcription**, and nothing in the tree can regenerate the bytes the
record names.

**A100's Accept row 2 — *"the committed reproducer below is a regression case
that is red before the ruling lands and green after"* — is unsatisfiable as
written**, and the ruling that replaces it must state one nuance the next
reader will otherwise get wrong: the 245-byte blob **does** still violate the
budget (peak 5 120 B, measured) but terminates at
**`anchor-ots-unknown-op`**, a different path than any of the four CI inputs
is known to take. So the row is **unverifiable, not dead**, and *"it still
reproduces, so the record is fine"* is the wrong conclusion — we cannot know
what the recorded 248-byte input did, and never will.

**Ruling — what replaces it.** `docs/testing/fuzzing.md` §4 step 4 already
prefers a **generated** witness over a hand-transcribed blob. Apply it:

1. **The regression cases are generated, not transcribed**, by the same
   `anchor::testing::ots_writer` the suite already owns. The primary witness
   is the **142-byte, 65-op chain** of §1.2 — the minimal structural
   witness of the boundary, red at depth 65 and green at 64, whose
   construction *states its own cause*. It is a better witness than any of
   the four CI inputs, and it is two lines against the existing writer.
2. **The four CI inputs are retained as what they are** — run ids, lengths,
   and the measured peak, in A100's entry. Not as bytes.
3. **The blob is deleted from `tasks/A.md`.** Standing rule, general beyond
   this record: **reproducer bytes are never carried in prose.** A base64
   block in Markdown has no checksum anything verifies, and this one was
   wrong in both its length and its digest for a full wave while three CI
   runs cited it. Bytes that must be retained go to `testdata/` under the Q7
   procedure with a manifest digest — fuzzing.md §4 step 4's other arm.
4. **A100's Accept row 3** (*"if the executor is tightened, a real `.ots` from
   `testdata/anchors/A25-bootstrap/` still parses"*) is kept and
   **strengthened**: the executor is not tightened (§4.2), so the row becomes
   the equality assertion of §8 row 4 over `rust-opentimestamps-LARGE_TEST.ots`
   — which must not merely parse but must cost exactly 5 120 B.

## 8. The exact regression test

Recon's suggestion — stable toolchain, counting allocator, no nightly, no
cargo-fuzz, no network — is **confirmed**, with one structural constraint
recon did not name and `parser_caps_alloc.rs` already learned the hard way: a
`#[global_allocator]` is process-wide and `cargo test` runs a binary's tests
on parallel threads, so **it must be its own test binary with one test in
it**, or the peak is flaky. New file
`crates/antseal-core/tests/anchor_ots_alloc.rs`, `#![allow(unsafe_code)]`
carrying the same four documented invariants as `parser_caps_alloc.rs` §"The
`unsafe_code` exception".

Assertions, **at equality** (D26 §2's shape — see below):

| # | input | source | measured peak | asserted |
| --- | --- | --- | --- | --- |
| 1 | 65-op chain, 142 B | generated | 5 120 | `== next_pow2(65) × size_of::<Frame>()`; and 64 ops `== 2 560` |
| 2 | 1 024-op chain, 1 145 B | generated (the `tests.rs:1186` body) | 40 960 | `== OTS_STRUCTURAL_WORK_STACK_BYTES` |
| 3 | open-fork spine n=128, 1 869 B | generated | 12 288 | `== next_pow2(129) × size_of::<OtsAttestation>()` — the attestation site |
| 4 | `rust-opentimestamps-LARGE_TEST.ots`, 1 768 B | committed A25 fixture | 5 120 | `== next_pow2(67) × size_of::<Frame>()` — the real artifact's real cost |
| 5 | clause (c) | — | — | `const` assert in `limits.rs` (§3.4), **not** a test |

**Why equality and not `≤`.** D26 §2 is the precedent and the argument is
already written there: G18 asked for a bound of the form `C₁·⌈log₂ n⌉` and
D26 **overturned the shape**, replacing the fudge constant with exact closed
forms asserted at equality, because *"that number — not a `C₁` — is what
'O(log n) memory' means in this codebase."* Same move, same reason. An
inequality goes green forever after a raise; an equality goes red the moment
the structure changes, in either direction, including a change nobody
intended.

**The one place equality must *not* go**, and this is deliberate: the **fuzz
target keeps the inequality** of §3.3. `Vec` growth from capacity 4 by
doubling is a `RawVec` implementation detail, not a language guarantee. An
equality in a nightly-toolchain lane would flake on a growth-policy change,
and **a flaky guard gets switched off** — which is the failure mode this
entire record exists to prevent. The unit test may assert equality because
the workspace pins stable `=1.92.0` exactly (D4), so a growth-policy change
arrives as a reviewed toolchain bump with a red test attached, which is the
correct venue for it.

No new CI context. The test binary rides `cargo test --workspace` (ci.yml's
`test` job) and runs on wasm32 wherever that lane already runs the crate's
tests; clause (c) rides every build there is.

## 9. Consequences and open actions

*(No task IDs minted here — the orchestrator allocates at bookkeeping.)*

1. **A11/A23 (M2, blocking `fuzz-smoke` green):** implement §3 — rule 6's
   derived constants in `limits.rs`, the `const` clause (c), the §3.3 budget
   in both anchor targets, and §8's test binary.
2. **A100's entry is corrected, not just closed**: its `Do` currently leans
   toward option (B), which §4.2 refutes; its Accept row 2 is replaced per §7;
   the blob is deleted; the four CI inputs stay as run ids.
3. **D58 is amended** — §10.3 gains rule 6 and rule 4 gains its scoping
   clause; §9.2's `MAX_OTS_DEPTH` sentence is corrected per §5.
4. **`docs/format/anchor-artifact-limits.md` §5** — every F4 row gains a
   `structural cost` column and the clause (c) precondition. **Note the D84
   trap**: the F1–F4 block in that file is a **hand-made copy outside the
   `--freeze-boundary` lint's markers** (D84's "correction to the correction",
   registered as Q64). Editing F4's neighbourhood without extending that lint
   repeats the exact failure D84 documented, one wave later.
5. **`docs/testing/fuzzing.md`** — §1's "What is asserted per input" gains the
   count-bounded exemption and a pointer here; §4 step 3 is **not** amended,
   it gains a cross-reference to §3.3's argument.
6. **A5 (M2)** — §6's DER derivation and its equality assertion, in the same
   change, before the target goes red rather than after.
7. **Registered for the F domain (unnumbered):** F30's clamp fix bounds the
   *initial* `with_capacity`, but a container whose real element count exceeds
   `remaining / size_of::<T>()` grows past that bound by doubling. Whether any
   CBOR container is reachable in that state is **unmeasured here** and out of
   this record's scope. It is the same question one layer down and it should
   be measured, not assumed.
8. **Registered (unnumbered), on its own merits and not as an A100 fix:** the
   §4.3 tail-call elimination of last-child pushes. It takes the honest
   deep-chain case from 40 960 B to O(1) and costs nothing at runtime. It does
   **not** change any verdict, any limit, or `shape.max_depth`, so
   `parser_is_iterative_at_max_depth` stays green unchanged — which is
   precisely why it must be argued separately rather than smuggled in here.
9. **Registered (unnumbered):** per-site allocation attribution, to close
   §3.3's 7 KB residual window. Needs instrumentation on the two `Vec`s
   rather than a global allocator.
10. `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

## 10. Kill criteria

This record is wrong, and must be reopened, if any of these is measured:

1. **The peak is not the work stack.** Falsified by a counting-allocator run
   showing a peak that is not a member of `{40 × 2ᵏ} ∪ {48 × 2ᵏ}` on any input
   reaching the current caps. §8 rows 1–4 are exactly this test.
2. **`rest.len()` is not the current depth.** The whole derivation of
   `40 960` rests on it. A fork/completion path that leaves a completed
   ancestor on the stack breaks clause (a) and the number is wrong in the
   unsafe direction.
3. **`structural(len)` hides a real finding.** If any input is found that
   allocates hostilely inside the exemption window, §3.3's inequality is too
   loose and action 9 becomes mandatory rather than registered.
4. **Clause (c) blocks a raise that is independently necessary.** If a real
   calendar topology ever needs depth > 16 384, clause (c) fires and must be
   re-argued on memory. That is the clause working, not failing — but the
   re-argument is a decision, not a constant edit.
5. **`size_of::<Frame>()` or `size_of::<OtsAttestation>()` moves** on a
   supported target and the derived cost is not recomputed from `size_of`.
   Clause (a) exists to make this impossible; if a literal ever appears,
   clause (a) has been violated.
6. **A released build is found to have verified real anchors before this
   date**, which would close §5's lowering window retroactively and make that
   section's "available today" claim false. It changes no ruling here — the
   option is declined either way — but the record must not stand claiming an
   option was open if it was not.

## 11. What would have changed my mind

Stated in advance, so this is falsifiable rather than merely argued:

1. **Had the peak been length-driven**, recon's premise would have collapsed
   and this would be a parser bug under fuzzing.md §4 step 3 with no
   exception needed. The mainnet artifact allocating **the identical 5 120 B**
   as all four failures is what killed that.
2. **Had `parser_is_iterative_at_max_depth` been red, or absent**, I would
   have ruled the 40 960 B case hostile and lowered `MAX_OTS_DEPTH` — a legal
   move today (§5) and the cleanest one. It is green, and it is the tree's own
   assertion that a 1 024-deep chain **must** parse. You cannot call an input
   hostile that your own test requires you to accept.
3. **Had `frames ≤ L/2` been true**, option (E) would have been right, the
   guard's relative rule would have been correct, and the parser would have
   been the thing that changed — satisfying fuzzing.md's policy instead of
   scoping it. It is `frames ≤ L`, measured at 0.89 frames/byte, and 40 bytes
   per frame is not negotiable.
4. **Had the tail-call elimination bounded the fork case**, I would have
   ruled (D) — fix the allocation, keep the 1× rule, no new normative text,
   no decision needed. The open-fork spine at 40 960 B from 14 399 B is what
   killed it.
5. **Had clause (c) had no candidate ceiling**, I would have accepted recon's
   task-level lean under protest, because a ceiling invented in this document
   would be exactly the fudge factor D26 §2 refused to write. `MAX_OTS_BYTES`
   being already frozen, already the verifier's committed working set, and
   already required to be consumed by name is what made the second clause
   possible — and the second clause is the whole reason this is a decision.

## Outcome

**RESOLVED, 2026-08-07.** Neither rule in A100's problem statement governs
the allocation A100 found. `walk.rest` is a **count-bounded** container, D10
§4's clamp is a **length-header** rule, and the third class has never been
written down. It is now: D58 §10.3 rule 6 — derived cost (a), equality
assertion (b), and `≤ MAX_OTS_BYTES` (c), the last as a `const` assert so a
raise that breaks it fails the build. The fuzz budget is **scoped, not
widened**: the exemption is a function of the input, the 1× clamp claim is
untouched everywhere it was ever true, and both D58 crashers stay fully
visible. `MAX_OTS_DEPTH` stays at 1 024 and D58 §9.2's uncomputed cost
sentence is corrected. `anchor_token.rs` takes the same derivation now, while
it is still green. A100's committed reproducer is measured at 245 B / sha1
`08df86ba…` against a record claiming 248 B / `b5aec24c…`, its Accept row is
unsatisfiable, and it is replaced by a **generated 142-byte** witness under
a standing rule that reproducer bytes never live in prose again.
