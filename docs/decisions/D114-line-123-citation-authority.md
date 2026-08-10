# D114 — Q148: which of the tree's 189 line-123 citations are actually wrong, what each one's authority is, and why the lint for them cannot exist

- **Status: RESOLVED — the defect is real and the row's arithmetic is wrong in
  both directions. The sweep finds 189 citation sites, not nine.** Ten of them
  are defective, not nine. **One of the row's nine is not a defect at all** —
  `format_registry_freeze.rs:1017` already names Q14 for permanence and cites
  line 123 only for the compatibility break, which is precisely the shape Q132
  prescribed; it is a class (b) and must be left byte-identical. **Two sites the
  row never named are defective**, and the second one changes the wave: the
  misquotation is in **`docs/format/registry-v1.md`'s §0 freeze blockquote** —
  inside the SHA-256-pinned normative document a third-party verifier
  implements from, and therefore **unreachable by Q132's fix**. Its disposition
  is D108's landed errata instrument, not an edit. So the wave is **9 prose
  edits + 1 erratum entry**, not "nine more sites, same fix as Q132".
  **The row's `Do` is wrong about the vector family in one place**: the
  authority is not uniformly "Q6's own act" — Q6's `Do` imposes the append-only
  byte pin, but the `#! status frozen` flip is **Q14's**, and
  `vector_freeze.rs:437` is an assertion about `status`, so at that one site the
  authority the row wants substituted is already the one the site names.
  **The row's Notes premise is false**: it says `vector-freeze.sh:8` "cites line
  167 correctly for retention in the same breath as line 123 wrongly", so "a
  reader sees two citations side by side with no signal that only one is right".
  Both are right for retention — **line 123 states retention itself**, in its own
  second clause. Line 123 is wrong there only for the *byte pin*, which is a
  third claim in the same sentence.
  **The instrument is REFUSED, on three independent measurements**, the last of
  which is structural rather than a tuning problem: a prose lint over this class
  is red on the corrected text, because the corrected text must say *"this is
  **not** under line 123"* and a regex cannot read negation. The strictest
  usable variant is already red at two sites **Q132 made correct last wave**, and
  red at one of this wave's own proposed replacement blocks; the variant narrow
  enough to avoid that is **green at 6 of the 9 fixable sites this row exists to
  fix**. What lands instead is one entry in an existing, tested gate.
- **Date: 2026-08-10** (M2 wave 12/13 planning round; briefed to confirm "nine
  more sites, same fix", and rules that the count, one classification, one
  authority claim and one Notes premise are each wrong, and that the fix has a
  second half Q132's shape cannot reach)
- **Owning task: Q148** (its `Problem`, `Do`, `Accept` and `Notes` are all
  amended by this document). **Consumes**: Q132 (the four sites it fixed and the
  two it deliberately left), Q14 (the wire-registry freeze act), Q6 (the vector
  freeze act), Q27 (the change procedure), D25 (the Unicode-table retention
  architecture), D104 §1.5 (nothing released), D108 §3/R4 (the errata
  instrument and why frozen bytes are not edited), D111 (why prose comparison
  over the registry is refused).
- **Amends**: `tasks/Q.md` Q148 (`:1766-1769`); `TODO.md`'s Q148 row (`:585`).
  **Will amend on execution**: `crates/antseal-core/tests/format_registry_freeze.rs`,
  `crates/antseal-core/src/manifest/registry.rs`,
  `crates/antseal-core/src/bundle/registry.rs`,
  `crates/antseal-core/tests/vector_freeze.rs` (two blocks),
  `crates/antseal-core/src/canon/unicode.rs` (two blocks),
  `scripts/vector-freeze.sh`, `CHANGELOG.md`,
  `docs/format/frozen-registry-errata.md` (one new entry, and §0's framing).
  **Supersedes**: nothing.
  **Binds against**: `docs/format/FROZEN.sha256` and
  `testdata/vectors/v1/FROZEN.sha256` (neither may move a digest line);
  the `format-v1-freeze` tag at `d3345e1`; `format_freeze.rs`'s
  `every_erratum_quotes_its_frozen_sentence_verbatim`;
  `format_registry_freeze.rs`'s section D (*"Do not add a prose comparison
  here"*); `scripts/check-traceability.py`'s `DECISION_SCAN` / `TASK_SCAN` and
  its refusal of `registry-v1.{md,json}:<line>` citations; `doc_pointer_liveness.rs`'s
  two recognition rules.

---

## The question, in a paragraph

Q132 closed four sites in the *format*-freeze machinery that cited
`MVP-SPEC.md` line 123 as the authority for byte-immutability, when line 123
states a **compatibility** rule conditioned on *released* and D104 §1.5
measures with three independent confirmations that nothing has been released.
Its closing note filed Q148 for "at least six more" sites, and Q148's row grew
that to nine and asserted they are the same defect wanting the same fix. The
question this document answers is not whether the defect is real — it is, and
Q132's argument for why it matters transfers unchanged — but **which sites are
actually defective, what the correct authority is at each one, whether the fix
Q132 used is even available at all of them, and whether a class that has now
drifted twice earns a mechanical guard**. Every one of those four sub-questions
has an answer the row does not have, and one of them (the second) turns out to
be the reason this wave is not a repeat of the last one.

---

## 1. What was measured

Read from the working tree at `5fbc48d` plus wave 12's uncommitted work, on
2026-08-10, which is what "today" means throughout. Every figure below came
from a script I wrote and ran over `git ls-files`; none is quoted from the row
or from the orchestrator's brief. The scripts are in the session scratchpad and
are reproducible from the definitions given in §1.3 and §4.1.

### 1.1 The two spec lines, quoted exactly

`MVP-SPEC.md` has **never been modified** since the initial commit `01cdc83`
(`git log -- MVP-SPEC.md` returns one commit), so today's line numbers are the
line numbers every citation in the tree was written against. Nothing pins that
fact — see §7.

**Line 123**, byte-exact:

> `**Format stability (normative)**: every released manifest/bundle format version remains verifiable by all future CLI and page releases; per-version golden vectors are retained in CI indefinitely; the hosted page supports all released versions.`

**Line 167**, byte-exact:

> `- **(M0)** Unit/property tests per crate; committed golden vectors so the WASM build must bit-match native verification; empty-anchor and per-version vectors retained in CI forever.`

Three separate claims live in line 123, and the whole of this row turns on
keeping them apart:

1. **Compatibility**, conditioned on *released* — "every **released** …
   remains verifiable by all future CLI and page releases".
2. **Retention** — "per-version golden vectors are retained in CI
   indefinitely". Unconditioned.
3. **Page coverage** — "the hosted page supports all released versions".
   Conditioned on *released*.

**There is no fourth claim, and byte-immutability is not any of the three.**
Clause 1 forbids a *future* release from failing to verify a *past released*
artifact. It says nothing about whether a document in this repository may be
edited today, and with nothing released it currently binds nothing at all.

### 1.2 The sweep: 189 citation sites, not nine

Over all tracked files, matching `MVP-SPEC.md line 123`, `MVP-SPEC.md:123`,
`spec line 123`, `line 123`, `line-123`:

| scope | citation sites |
| --- | --- |
| whole tracked tree | **189** |
| `check_decisions()`'s `DECISION_SCAN` (`crates`, `docs/format`, `docs/testing`; `.rs .md .json .py`) | 51 |
| `check_task_citations()`'s `TASK_SCAN` (adds `scripts/`, `.sh .mjs`) | 56 |

**Of those 189, ten are defective.** The other 179 are either correct
citations of clauses 1–3, or neutral `- Spec:` pointer lines in `tasks/*.md`
that name the section without making a claim. That ratio is the single most
important number in this document, and §4 is where it becomes a ruling: any
guard for this class has to find 10 needles in 189 pieces of prose that all
look alike to a matcher.

### 1.3 The defect predicate, stated once

A site is **defective** iff it attributes to line 123 a claim line 123 does
not make. Two shapes occur, and both are in scope:

- **(a-i) authority misattribution** — byte-immutability, "a format-version
  event", "not an edit", "never removed or altered" is sourced to line 123.
  This is Q132's shape.
- **(a-ii) condition substitution** — line 123's promise is restated with its
  `released` condition replaced by a condition this project has met, most often
  *frozen*. `frozen` ≠ `released`; nothing is released (D104 §1.5). This shape
  is not in Q132's record and the row does not name it; it is the same defect
  arriving through the antecedent instead of through the citation.

A site is **class (b), correct**, iff it cites line 123 for clause 1, 2 or 3
and either carries the condition word or is a claim the clause genuinely
supports. A site is **class (c), neutral**, iff it is a `- Spec:` pointer or a
section reference that asserts nothing.

**Retention citations of line 123 are class (b), not defects.** This is where
the row goes wrong in §1.7 and it is worth being explicit: clause 2 is
unconditioned and says exactly "per-version golden vectors are retained in CI
indefinitely", so `testdata/vectors/README.md:5`'s near-verbatim quotation of
it is a *model* citation, not a defect.

### 1.4 One of the row's nine is a correct citation

`crates/antseal-core/tests/format_registry_freeze.rs:1015-1018` reads:

```rust
/// The caps are format-permanent (they freeze at Q14 with the rest of v1: a
/// receiver that rejects a bundle a sealer produced is a compatibility break,
/// MVP-SPEC.md line 123), so a silent drift between the two would be
/// unrecoverable rather than merely untidy.
```

Read the parenthetical in order. Permanence is sourced to **"they freeze at
Q14"**. Line 123 is attached to **"a receiver that rejects a bundle a sealer
produced is a compatibility break"** — which is clause 1 stated in the
verifier's own vocabulary, and correct. This is the exact structure Q132's
Accept demanded (*"every citation of the byte-immutability rule names Q14, and
line 123 is cited only for compatibility"*), written before Q132 existed.

It is the same standard by which Q132 left `format_freeze.rs:35` and `:160`
alone: `:35` cites line 123 for why a v2 lands *beside* v1 rather than
replacing it, quoting "every released version stays verifiable forever"; `:160`
cites it for why deleting a frozen document's normative text is never legal.
Both are clause 1. `:1017` belongs with them.

**A lane that "fixes" `:1017` would be reverting a correct citation into an
inconsistent one.** It is class (b) and must come out of the wave
byte-identical.

### 1.5 Two defective sites the row never named

**`docs/format/registry-v1.md`, §0's freeze blockquote (line 8).** The
document that *is* format v1:

```
> **FROZEN — v1. This document is normative.** It froze at the Q14
> `format-v1-freeze` gate (M0 Definitions sign-off) and is signed off by
> **D8** (`docs/decisions/D8-wire-registry-final.md`). Every key
> assignment, type, presence rule, byte length, enum value, tuple shape and
> reserved range below is **format-permanent**: changing one is a
> format-version event, not an edit (MVP-SPEC.md line 123; the procedure is
> Q27's).
```

This is class (a-i) in its purest form, in the **most-read normative sentence
the project has**, two lines after the blockquote itself names Q14 as the
freezing act. It is also **the one instance Q132's fix cannot reach**: every
byte of `registry-v1.md` is pinned by `docs/format/FROZEN.sha256`, and D108
settled that the in-band re-bless — real, and spent once at `622f5fe` — is
priced at a **tag event** now that `format-v1-freeze` exists, a
repository-identity act and not a lane's. The argument is restated for exactly
this situation at `docs/format/frozen-registry-errata.md` §2.1, which exists
because "the next lane to meet it will reach for the edit before it reaches for
the decision record". §3.4 rules its disposition.

**`CHANGELOG.md:10-11`** — class (a-ii), and the only externally-facing
instance in the tree:

```
**Format versions are the load-bearing entries.** A format version, once
frozen, is verifiable forever (MVP-SPEC.md line 123). Entries under a
```

*Frozen* is substituted for *released*. The file's own first paragraph
(`:5-6`) says "Before it there were no releases and no external consumers",
so the sentence contradicts its own page four lines later.

### 1.6 The retention premise of Q148's Notes is false

Q148's Notes (`tasks/Q.md:1769`) argue the vector-freeze half is "the worse of
the two, because `vector-freeze.sh:8` cites line 167 **correctly** for the
retention rule in the same breath as line 123 wrongly for immutability, so a
reader sees two citations side by side with no signal that only one is right."

The header is:

```sh
# Contract (MVP-SPEC.md line 123 format stability, line 167 "per-version
# vectors retained in CI forever"; tasks/Q.md Q6): each
# `testdata/vectors/v<n>/FROZEN.sha256` pins the exact bytes of every
# committed vector of that format version AND is the must-exist list, …
```

Line 123's **clause 2** states retention in almost the same words as line 167.
So of the two citations sitting side by side, **both are right for retention**,
and line 123 is wrong only for the *third* claim in that sentence — the byte
pin — which neither line states. The reader's real problem is not "two
citations, one wrong"; it is **one citation doing three jobs and being right at
two of them**, which is harder to see and is why the fix must split the header
rather than delete a citation from it (§2, S5).

### 1.7 Authority per family, verified from the rows and entries

- **Wire registry and its mirrors — Q14.** Confirmed; unchanged from Q132.
- **Golden vectors — Q6 for the byte pin, Q14 for the status.** Q6's `Do`
  (`tasks/Q.md:68`) reads *"Implement the **append-only guarantee**: a
  per-version `FROZEN.sha256` manifest of frozen vector files; a CI job
  recomputes hashes and fails on any modification or deletion of a frozen
  entry, while allowing additions."* That is byte-immutability, imposed by Q6.
  But Q6's Accept defers the gate — *"Must-exist list … enforced before the M0
  freeze tag (Q14)"* — and the manifest header says `status frozen` **(set by
  Q14)**, which `vector_freeze.rs:16` restates as *"Q14's gate condition is
  zero pending"*. So the row's blanket *"whose authority is Q6's own act"* is
  right at `vector-freeze.sh:8` and `vector_freeze.rs:10`, and **imprecise at
  `vector_freeze.rs:437`**, which asserts on `Status::Frozen` and therefore
  already names its own authority correctly. At `:437` only the trailing
  line-123 clause is wrong.
- **Unicode tables — Q14's freeze of registry §7.3 key 3, with D25 as the
  design record.** The row leaves this open (*"whatever act froze the Unicode
  tables"*) and the answer is not Q6 and not line 123. Registry §7.3 key 3
  (`unicode_version`) records `v1 value set = {"unicode-17.0.0"} (D25)`, and
  that row froze at Q14 with the rest of the registry; the mirror carries the
  same in its `unicode_version` entry with `"status": "frozen-v1"`. The
  *mechanism* keeping the table itself present is `Cargo.toml`'s exact pin
  `unicode-normalization = "=0.1.25"` plus the module's own test asserting the
  crate's `UNICODE_VERSION == (17, 0, 0)`. What line 123 correctly supplies is
  the *reason* retention matters once a bundle ships — which is why one half of
  `unicode.rs:15-18` is a correct citation and the sentence after it is not
  (§2, S8).

### 1.8 The class (b) exemplars — what a lane must not touch

Named so the implementing lane can recognise the correct shape and stop:

| site | why it is correct |
| --- | --- |
| `crates/antseal-core/src/format.rs:9-30` | **The derivation, written out.** Quotes line 123 verbatim including "released", then derives three obligations. Q132's Accept explicitly permits this alternative (*"or the derivation from line 123 is written out where it is claimed"*). Obligation 1 says "**A released** version's byte behaviour never changes." |
| `crates/antseal-core/src/codec/caps.rs:86-88` | Names Q14 for permanence, line 123 for the compatibility break, quotes "released version". |
| `crates/wasm-bitmatch/build.rs:24-25` | "Q6 retains every released version forever (MVP-SPEC.md line 123)" — mechanism to Q6, promise to line 123, condition quoted. |
| `crates/antseal-core/tests/format_registry_freeze.rs:1015-1018` | §1.4. |
| `crates/antseal-core/tests/format_freeze.rs:35`, `:160` | Q132's two deliberate leaves. |
| `crates/antseal-core/src/manifest/error.rs:526` | "Per the line-123 stability contract a **released** version is decodable forever." |
| `crates/antseal-core/src/anchor/ots/exec.rs:23-26` | "It never rejects an artifact a past release accepted, so it is compatible with MVP-SPEC.md line 123." |
| `crates/antseal-core/tests/vector_index.rs:212-219` | Retention (clause 2); the preceding comment says "a **released** version is never dropped". |
| `testdata/README.md:49-52` | Quotes clause 1 *and* line 167. The model citation in the tree. |
| `testdata/vectors/README.md:5`, `:402`, `:458` | Clause 2 near-verbatim; retention; and "line 123's promise is that v1 reports stay **verifiable**". |
| `docs/testing/cross-check.md:305-306` | Clause 2 — "for the same reason the golden vectors are retained forever". |
| `Cargo.toml:209-211` | "every **shipped** table is retained forever" — carries its own condition; correct derivation of clause 1. |
| `crates/antseal-core/src/manifest/body.rs:1265`, `bundle/schema.rs:1789` | "the structural half of MVP-SPEC.md line 123" — obligations 1/2 of `format.rs`'s written-out derivation, one module over. |
| `docs/format/registry-v1.md` §0 second paragraph, §7.6 key 0, §9 and §14's *"A released version is decodable forever (line 123)"*; `registry-v1.json`'s `direction` and `released_versions_decodable_forever` | Frozen **and correct**. Clause 1 in the illegal-direction form, several quoting "released" outright. No erratum is owed for any of them, which is why §3.4 lands **one** erratum and not two — unlike D108, whose claim was duplicated across both surfaces, this one is not: the mirror's `change_procedure` field names **Q27** and cites no spec line at all. |

---

## 2. The site table — the whole deliverable

Ten defective sites. Nine are edits; the tenth is §3.4's erratum. Every `old`
block below was extracted byte-exactly from the working tree with
`repr()`-level fidelity and every `new` block was written against it; both are
**verbatim** and the implementing lane should not re-derive anything.

Line widths in the `new` blocks are held to the ≤ 78 columns each file already
uses. None introduces a backticked `snake_case` token with ≥ 4 underscores or a
`tests/*.rs` path, so `doc_pointer_liveness.rs`'s two recognition rules are
untouched. None cites `registry-v1.md`/`.json` by line number, so
`check-traceability.py` check 3 stays green; §7.3 key 3 is cited **by section**,
per that check's own instruction. Every task id used (Q6, Q14, Q27, Q132, Q148)
and decision id (D25, D104, D108) resolves to a row and a record.

---

### S1 — `crates/antseal-core/tests/format_registry_freeze.rs:6-8` · class **(a-i)** · authority **Q14**

**old** (lines 6-8):

```rust
//! gate (D8 §12). The registry is now **frozen**: every number, name and
//! rule it records is format-permanent, and changing one is a
//! format-version event (MVP-SPEC.md line 123), not an edit.
```

**new**:

```rust
//! gate (D8 §12). The registry is now **frozen**: every number, name and
//! rule it records is format-permanent, and changing one is a
//! format-version event, not an edit. The authority for that is **Q14's own
//! freeze act** (procedure Q27), not MVP-SPEC.md line 123 (**Q148**): line
//! 123 is the *compatibility* rule and is conditioned on *released* — D104
//! §1.5 measures with three independent confirmations that nothing has been
//! released — so citing it as the source of immutability hands a reader a
//! conditional whose condition is false today. Q14 is deliberately stronger;
//! line 123 is what the freeze protects once a version ships.
```

### S2 — `crates/antseal-core/tests/format_registry_freeze.rs:1017` · class **(b)** · **NO CHANGE**

See §1.4. The row lists this among its nine; it is not a defect. Leave it
byte-identical and record in the row's close that it was inspected and cleared.

### S3 — `crates/antseal-core/src/manifest/registry.rs:16-17` · class **(a-i)**, mild · authority **Q14**

**old**:

```rust
//! is the point: after the Q14 `format-v1-freeze` gate, either change is a
//! format-version event (MVP-SPEC.md line 123).
```

**new**:

```rust
//! is the point: after the Q14 `format-v1-freeze` gate, either change is a
//! format-version event under **Q14's own freeze act** (procedure Q27) — not
//! under MVP-SPEC.md line 123, which is the *released*-conditioned
//! compatibility rule the freeze protects once a version ships (**Q148**).
```

The row calls this and S4 "mildest — they name Q14 first", and that is right as
far as it goes: the *sentence* is temporally anchored to Q14 correctly, and only
the parenthetical is misdirected. The fix is therefore one clause, not a
rewrite, and deliberately shorter than S1's — a nine-line authority note in a
per-key module doc would bury the key bands it exists to introduce.

### S4 — `crates/antseal-core/src/bundle/registry.rs:17-18` · class **(a-i)**, mild · authority **Q14**

**old**:

```rust
//! which is the point: after the Q14 `format-v1-freeze` gate, either change
//! is a format-version event (MVP-SPEC.md line 123).
```

**new**:

```rust
//! which is the point: after the Q14 `format-v1-freeze` gate, either change
//! is a format-version event under **Q14's own freeze act** (procedure Q27) —
//! not under MVP-SPEC.md line 123, which is the *released*-conditioned
//! compatibility rule the freeze protects once a version ships (**Q148**).
```

### S5 — `scripts/vector-freeze.sh:8-13` · class **(a-i)** · authority **Q6's byte pin, executed at Q14**

The header does three jobs in one sentence (§1.6). The replacement splits them
and adds the authority block in the same shape `scripts/format-freeze.sh:14-25`
already carries, so the two sibling lanes read alike.

**old** (lines 8-13):

```sh
# Contract (MVP-SPEC.md line 123 format stability, line 167 "per-version
# vectors retained in CI forever"; tasks/Q.md Q6): each
# `testdata/vectors/v<n>/FROZEN.sha256` pins the exact bytes of every
# committed vector of that format version AND is the must-exist list, so a
# deleted vector file — which the Q4 runner structurally cannot notice,
# since it only executes files it finds — turns this lane red.
```

**new**:

```sh
# Contract (the byte pin is Q6's own act, executed at Q14; tasks/Q.md Q6):
# each `testdata/vectors/v<n>/FROZEN.sha256` pins the exact bytes of every
# committed vector of that format version AND is the must-exist list, so a
# deleted vector file — which the Q4 runner structurally cannot notice,
# since it only executes files it finds — turns this lane red.
#
# Retention — per version, indefinite — IS spec, and BOTH lines state it:
# MVP-SPEC.md line 123 ("per-version golden vectors are retained in CI
# indefinitely") and line 167 ("empty-anchor and per-version vectors retained
# in CI forever"). Neither states the byte pin.
#
# ── Authority: what makes a byte change illegal (Q148) ─────────────────────
#
# Q6's freeze manifest, flipped to `#! status frozen` at Q14 — NOT MVP-SPEC.md
# line 123. Line 123's first clause is the *compatibility* rule: "every
# RELEASED manifest/bundle format version remains verifiable by all future CLI
# and page releases", and D104 §1.5 measures with three independent
# confirmations that nothing has been released. Cited as the source of
# byte-immutability it is a conditional whose condition is false today, so a
# reader who checks it may conclude the freeze is soft — the inference D108 §3
# spends a section refusing. Q6/Q14 impose a STRONGER, self-imposed discipline
# than line 123 requires; line 123 is what it protects once a version ships.
```

### S6 — `crates/antseal-core/tests/vector_freeze.rs:9-10` · class **(a-i)** · authority **Q6, flipped at Q14**

**old**:

```rust
//! 1. **the frozen bytes** — a SHA-256 per committed vector file, so a
//!    modification turns CI red (MVP-SPEC.md line 123, format stability);
```

**new**:

```rust
//! 1. **the frozen bytes** — a SHA-256 per committed vector file, so a
//!    modification turns CI red. The authority is **Q6's freeze manifest**,
//!    flipped to `#! status frozen` at Q14 — not MVP-SPEC.md line 123, which
//!    is the *released*-conditioned compatibility rule (**Q148**);
```

Note that this module's item 3 and its "Retention is **per version,
indefinite**" paragraph are already correct and cite nothing wrongly; they are
not part of the edit.

### S7 — `crates/antseal-core/tests/vector_freeze.rs:436-437` · class **(a-i)**, dropped-condition · authority **Q14 (already named)**

The site already names its own authority (§1.7). Only the trailing clause is
defective, and it is defective in the a-ii direction as well: it asserts
unconditionally what line 123 conditions on release.

**old**:

```rust
        "v1 is `{:?}`; the format-v1 freeze (Q14) set it to `frozen` on 2026-07-28 \
         and nothing since may relax it — line 123 makes v1 verifiable forever",
```

**new**:

```rust
        "v1 is `{:?}`; the format-v1 freeze (Q14) set it to `frozen` on 2026-07-28 \
         and nothing since may relax it. The authority is Q14's own act, not \
         MVP-SPEC.md line 123, which promises verifiability for RELEASED \
         versions and nothing has been released (D104 §1.5)",
```

This is an `assert_eq!` message, so the change is failure text only and no
assertion, count or behaviour moves.

### S8 — `crates/antseal-core/src/canon/unicode.rs:15-18` · **half (b), half (a-i)** · authority **Q14's freeze of registry §7.3 key 3**

The first sentence is a *correct* derivation of clause 1 — it even carries its
own condition word, "ever shipped". The second sentence is the defect. Do not
delete the line-123 citation here; re-scope it.

**old**:

```rust
//! - Future Unicode versions are **added** to this registry; every table
//!   ever shipped is **retained forever** under the format-stability policy
//!   (spec line 123). Removing, renaming, or altering a registered entry is
//!   a format break.
```

**new**:

```rust
//! - Future Unicode versions are **added** to this registry; every table
//!   ever shipped is **retained forever**, because a released bundle that
//!   records that version must stay verifiable (MVP-SPEC.md line 123 — the
//!   correct, *released*-conditioned use of it). Removing, renaming, or
//!   altering a registered entry is a format break under **Q14's freeze of
//!   registry §7.3 key 3**, whose v1 value set is `{"unicode-17.0.0"}` (D25)
//!   and is format-permanent — not under line 123 (**Q148**).
```

### S9 — `crates/antseal-core/src/canon/unicode.rs:62-63` · class **(a-i)** · authority **Q14's freeze of registry §7.3 key 3**

**old**:

```rust
/// One variant per retained table, forever (format-stability policy,
/// MVP-SPEC.md line 123). Each variant names its exact data source.
```

**new**:

```rust
/// One variant per retained table, forever: registry §7.3 key 3's v1 value
/// set froze at Q14 (D25), so a shipped table can never be removed or
/// renamed. MVP-SPEC.md line 123 is the *released*-conditioned compatibility
/// rule that discipline protects, not its source (**Q148**). Each variant
/// names its exact data source.
```

### S10 — `CHANGELOG.md:10-11` · class **(a-ii)** · the row missed this one

**old**:

```
**Format versions are the load-bearing entries.** A format version, once
frozen, is verifiable forever (MVP-SPEC.md line 123). Entries under a
```

**new**:

```
**Format versions are the load-bearing entries.** A format version, once
frozen, is byte-permanent under the act that froze it — **Q14** for the wire
registry, **Q6/Q14** for the golden vectors — and once *released* it stays
verifiable by every future release (MVP-SPEC.md line 123, which is
conditioned on *released*; nothing has been released yet, D104 §1.5).
Entries under a
```

`CHANGELOG.md` sits outside `DECISION_SCAN` and `TASK_SCAN`, so nothing lints
its citations either way — which is exactly why it drifted and why it is worth
the one sentence.

### S11 — `docs/format/registry-v1.md` §0 freeze blockquote · class **(a-i)** · **FROZEN — erratum, not an edit**

Disposition in §3.4. No byte of `registry-v1.md` is touched.

---

## 3. The frozen-bytes verification protocol

Four of the nine edits sit in or beside freeze machinery, and the tenth reads
against frozen bytes. Q132 proved "zero frozen bytes moved" four ways; this
wave must repeat all four **plus two more**, because it touches the *vector*
freeze that Q132 did not and adds an errata entry that Q132 did not.

### 3.1 What is actually at risk — measured, not assumed

**Nothing in S1–S10 is a freeze input.** Established by reading the manifests:

- `docs/format/FROZEN.sha256` pins exactly two paths — `registry-v1.json` and
  `registry-v1.md`. No Rust file, no script, and not itself.
- `testdata/vectors/v1/FROZEN.sha256` pins fourteen `*.json` vector files.
  Its own header states that `README.md` and the `*.py` generators are
  **deliberately not frozen**; no `.rs` or `.sh` file is in it.
- `scripts/vector-freeze.sh` and `crates/antseal-core/tests/vector_freeze.rs`
  are the *checkers*. `crates/antseal-core/src/manifest/registry.rs`,
  `src/bundle/registry.rs` and `src/canon/unicode.rs` are code that the
  registry is compared *against*, by value — `format_registry_freeze.rs`'s
  D-family reads `type`, `presence`, `rule` and `tier` fields, never doc-comment
  prose.
- **Wave 12's D111 checks do not read prose.** `format_registry_freeze.rs`'s
  section D is explicit: the two surfaces' prose "is compared to nothing, in
  either direction, **by design**", and it closes with *"Do not add a prose
  comparison here."* Editing a doc comment cannot trip it.
- Q132's own precedent for the header class is live in the working tree: its
  edit to `docs/format/FROZEN.sha256` added ten comment lines above the `#!`
  directives and **changed no digest line**. `--update` preserves `^#` lines
  verbatim and regenerates only the digest block, so header prose is
  idempotent under it.

So the expected result is that all six checks below pass trivially. **Run them
anyway** — that is the whole point of the protocol, and A21's lesson is that
the reader you did not grep for is the one that breaks.

### 3.2 The six checks

1. **No digest line differs**, both manifests:
   `git diff -- docs/format/FROZEN.sha256 testdata/vectors/v1/FROZEN.sha256 | grep -E '^[+-][0-9a-f]{64}'`
   must print nothing. (Neither manifest should be touched at all by this wave;
   this catches an accidental `--update`.)
2. **Both registry surfaces and all fourteen vectors are byte-identical**:
   `git diff --exit-code -- docs/format/registry-v1.md docs/format/registry-v1.json 'testdata/vectors/v1/**/*.json'`
3. **The independent layer agrees**, sharing no code with antseal:
   `(cd docs/format && grep -v '^#' FROZEN.sha256 | grep -v '^$' | sha256sum -c -)` and the
   same in `testdata/vectors/v1`. Baseline captured today: **2 OK, 14 OK.**
4. **The tag is unmoved**: `git rev-parse format-v1-freeze^{commit}` must print
   `d3345e1622bf4ae8d90d5d02b9e80317c73b7683`. (Note it is an *annotated* tag —
   `git rev-parse format-v1-freeze` alone yields the tag object `5b72bb0`; the
   `^{commit}` peel is required, and Q132's record of `d3345e1` is the commit.)
5. **A reconstruction of what `--update` would emit is byte-identical to the
   live file**, both lanes: run `scripts/format-freeze.sh --update` and
   `scripts/vector-freeze.sh --update`, then `git diff --exit-code` over both
   manifests. This is Q132's fourth proof and is the one that catches a header
   edit that would not survive regeneration.
6. **Both halves of both lanes, not just the check half**:
   `scripts/format-freeze.sh` **and** `scripts/format-freeze.sh --self-test`,
   `scripts/vector-freeze.sh` **and** `scripts/vector-freeze.sh --self-test`.
   The half that selects a fixture is not the half that checks it, and CI runs
   them as separate steps.

### 3.3 The errata gate, additionally

`cargo test --test format_freeze` must pass with the new entry — in particular
`every_erratum_quotes_its_frozen_sentence_verbatim`, whose match is a **raw
byte substring search** against the frozen file. The quotation in §3.4 was
verified today against `docs/format/registry-v1.md`: it occurs **exactly once**
and is 73 bytes.

### 3.4 The ruling on the frozen site: one erratum, in the gate D108 already built

`registry-v1.md`'s §0 parenthetical gets an entry in
`docs/format/frozen-registry-errata.md`. This is not a new instrument — it is
the instrument D108 R4 landed and tested, and its whole design goal was a
correction "reachable only from outside" for a document that "cannot point at
anything". A misdirected citation in the first normative sentence of the
format is squarely what it is for, and pinning it to the sentence means a
future registry version that fixes the parenthetical turns the note **red**
rather than leaving it stale.

**Entry**, verbatim, to be appended to §1:

```markdown
### registry-v1.md — §0's freeze blockquote, the authority parenthetical

- file: `registry-v1.md`
- quotes: `format-version event, not an edit (MVP-SPEC.md line 123; the procedure is`
- scope: the **rule** is exactly right and unconditional — a byte change to
  this document IS a format-version event. Only the **citation** is wrong.
  Byte-immutability is imposed by **Q14's own freeze act**, which this same
  blockquote names two lines above; `MVP-SPEC.md` line 123 is the
  *compatibility* rule and is conditioned on *released*, and D104 §1.5 measures
  with three independent confirmations that nothing has been released.
- queued for: the next registry version (Q148)

A reader who follows this citation finds a conditional whose condition is false
today, and the available inference — *the freeze is soft* — is the one D108 §3
spends a section refusing. The direction of the misreading is the **opposite**
of this file's other two entries: those are sentences that will be read to claim
more than they claim; this one will be read to claim **less**. The rule stands
at full strength on Q14's authority whatever line 123 says.

The mirror needs no companion entry. `registry-v1.json`'s `change_procedure`
field states the same rule and cites **Q27** and no spec line, and its
`direction` field cites line 123 for the relax/tighten rule, which is clause 1
and correct. This is the one place the two surfaces do **not** diverge, which is
why D108 needed two entries here and Q148 needs one.
```

**One consequence the implementing lane must handle rather than skip**: the
errata file's §0 defines an erratum as a note about a sentence that "will be
read to claim **more** than it claims". This entry is the under-read case. §0 is
prose in an **unfrozen** file, so widening it is legal and cheap; the lane
should extend that sentence to cover both directions rather than land an entry
that contradicts the file's own definition of an entry. Nothing mechanical
objects — `parse_errata` requires only `- file:`, `- quotes:` and a non-empty
`- scope:` — which is precisely why the prose has to be fixed by hand.

---

## 4. The instrument question

Q148 has now drifted twice: Q132 fixed four sites and nine more were standing
the same day. That is the profile of a class that drifts again, and it is a
real argument for a guard. It loses anyway, on measurement.

### 4.1 The candidates, and what each costs

All figures are over the 189 citation sites, with a ±1-line window around each
citation to catch a claim wrapped across lines, comment markers stripped. Three
vocabularies and one condition test, stated exactly because the numbers move if
they are loosened:

- `COND` = `\breleased\b|\brelease[sd]\b|\bship(?:s|ped)\b`
- `IMM`, the byte-immutability vocabulary = `format-version event|byte change|not
  an edit|never an edit|never removed or altered|Removing, renaming, or
  altering|format-permanent`
- `BROAD`, the naive stability net = `IMM` plus `immutab|frozen|freeze|forever|
  stability|removing|renaming|deleting|byte-identical|unchanged`
- `STRICT` = `format-version event`

| variant | rule | RED today (whole tree) | RED in `TASK_SCAN` |
| --- | --- | --- | --- |
| **V1** | every line-123 citation must carry a `COND` word | **129 / 189** | 35 / 56 |
| **V2** | `BROAD` in window and no `COND` | 89 | 22 |
| **V3** | `STRICT` in window, no exceptions | 17 | 6 |
| **V4** | `IMM` in window and no `COND` | 12 | 6 |
| **V5** | V4, and the window does not name `Q14`/`Q6`/`freeze act` | 5 | 3 |

**V1 is unusable**: it reddens **68 %** of the tree's citations, nearly all of
them correct prose or `- Spec:` pointers. **V2 is worse than useless**: 89 red
for at most 10 real defects is an ≈89 % false-positive rate. An allowlist at either size
is a rule nobody believes — the standard `doc_pointer_liveness.rs` already sets
for this repo, in its own words: *"a rule with false positives gets an
allowlist, and an allowlist that grows is a rule nobody believes."*

**V2 and V3 are red at correct text.** V3 reddens
`crates/antseal-core/tests/format_freeze.rs:171` — text **Q132 landed last wave
and this document classifies as correct**. V2 reddens `docs/testing/cross-check.md:306`,
a clause-2 retention citation.

**V4 is red at Q132's own exemplar.** It reddens `scripts/format-freeze.sh:193`
— the `::error::` line whose entire content is *"line 123 is the compatibility
rule this protects, not its source."* The check cannot tell that sentence from
the defect it was written to correct.

**V5 avoids that, and pays by missing the row.** In `TASK_SCAN` it reddens
three: `format_registry_freeze.rs:8` (genuine, S1), `registry-v1.json:17` (a
window artifact — the `format-version event` is in the *next* JSON field, and
`:17` itself is correct), and `registry-v1.md:8` (genuine, and **unfixable**).
It is **green at S3, S4, S5, S6, S7, S8 and S9** — seven of the nine fixable
sites, including the whole Q6 vector family and both Unicode sites; S10 sits
outside `TASK_SCAN` altogether, which makes eight of nine unreachable one way
or the other. Even after a perfect fix it cannot reach green without a
permanent allowlist entry for the frozen document.

### 4.2 The structural refutation: a regex cannot read negation

The three results above are not tuning failures; they are one failure with
three faces. **The corrected form of this defect necessarily contains both the
immutability vocabulary and the line-123 citation in the same breath**, because
what the correction *says* is "this is **not** under line 123, it is under
Q14". Any matcher keyed on co-occurrence is therefore red on the fix by
construction.

The proof is on this document's own output. Running V4 over the nine
replacement blocks in §2 — text this document asserts is correct — **S8 goes
RED**, at the clause `and is format-permanent — not under line 123 (**Q148**)`.
The word "not" is the entire difference and the check cannot see it. Together
with `format-freeze.sh:193` and `format_freeze.rs:171` that is **three
independent instances of a candidate check reddening on text that is right**,
one of them produced by the fix this very document specifies.

This is the same shape as wave 12's refusal under D111, where a closed-vocabulary
prose check was measured *"green on its own motivating case"*; here the polarity
is inverted — red on its own corrected case — and the conclusion is the same.

### 4.3 Ruling: no lint. Prose plus one errata entry.

**No new automated check over citing prose lands in this wave, and none should
land later without overturning §4.2 with a measurement.** What lands is:

- the nine prose corrections of §2, which are *self-describing*: each now names
  its authority in its own sentence, so the next reader does not have to hold
  Q132's argument in their head to see why the citation reads as it does;
- one entry in `frozen-registry-errata.md`, which is **not a new instrument** —
  it is a row in a gate that already exists, is already tested by
  `every_erratum_quotes_its_frozen_sentence_verbatim`, and already goes red on
  drift. The class's one genuinely unfixable member ends up under mechanical
  guard, which is more than a lint would have achieved for it: a lint could only
  have reported it forever.

Two things that are *not* the reason for the refusal, so nobody re-opens it on
the wrong grounds. It is not cost — a check is thirty lines in
`check-traceability.py`, whose `TASK_SCAN` already reaches every file in §2.
And it is not that the class is unimportant — it has drifted twice and D108 §3
had to spend a section on the inference it enables. It is that **every
formulation measured is wrong at the sites that are right**, and a lane that
ships a lint which reddens on correct text has moved the defect from the prose
into the gate.

### 4.4 What would change this ruling

A check whose predicate is not co-occurrence. Concretely, one that keys on
**line 123 being the *nearest* authority token in the sentence** — i.e. parses
which claim the citation is attached to rather than which words are nearby.
That is a parser, not a regex, and it is its own task with its own measurement.
Nothing in this wave should attempt it.

---

## 5. Riders — normative, cite by number

- **R1** — `format_registry_freeze.rs:1017` is class (b). It is inspected,
  cleared and left byte-identical; the row's close must say so, so the next
  sweep does not re-open it.
- **R2** — The line-123 citation is **re-scoped, never deleted**, at S5 and S8.
  Line 123 genuinely states retention (clause 2) and genuinely underwrites
  Unicode-table retention once a bundle ships; deleting it there would trade
  one wrong citation for one missing one.
- **R3** — No file in `crates/` or `scripts/` may cite `registry-v1.md` or
  `registry-v1.json` by line number; §7.3 key 3 is cited **by section**
  throughout §2. `check-traceability.py` check 3 rejects the line form.
- **R4** — No frozen byte moves. §3.2's six checks are run and their outputs
  recorded in the row's close, as Q132 recorded its four.
- **R5** — The errata file's §0 is widened to admit the under-read direction in
  the **same commit** as the entry (§3.4). An entry that contradicts its own
  file's definition of an entry is the drift this row is about.
- **R6** — **No behaviour change and no test added.** S1–S10 are doc comments,
  shell comments, one `assert_eq!` message and one changelog sentence. The
  test count must come out of this wave unchanged; if it moves, something was
  done that this document did not specify.
- **R7** — `seal-core` must still compile for `wasm32-unknown-unknown` after
  S3, S4, S8 and S9, which are `src/` doc comments in that crate. Doc-only, so
  this is a formality — run it anyway.

---

## 6. Discovered work — named, not registered

Described in a sentence each; the orchestrator assigns ids at bookkeeping.

1. **Nothing pins `MVP-SPEC.md`'s line numbering, and 189 citations depend on
   it.** The spec has never been edited since `01cdc83`, so every `line N`
   citation in the tree is correct by historical accident rather than by
   construction; a single inserted line above 123 silently rots all of them.
   The tree already contains the instrument shape — `anchor/model.rs`'s
   `spec_line_points_at_the_states_own_definition` reads `MVP-SPEC.md`, indexes
   a line number and asserts its content, gated `#[cfg(not(target_arch =
   "wasm32"))]` — so extending it to a small register of load-bearing lines
   (123, 167, 121, 137, 168) is cheap. **This is deliberately not folded into
   Q148**: it is green today and would fail the "red on a real site, green
   after" bar this wave held its own instrument to. It is a guard against the
   *recurrence vector*, not against the defect, and it deserves to be argued on
   its own terms.
2. **`check-traceability.py`'s three scan scopes disagree about what a
   "citation site" is, and the gap is where this defect lives.**
   `DECISION_SCAN` omits `scripts/`; `TASK_SCAN` includes it; neither reaches
   root files. `CHANGELOG.md` — the one externally-facing document in the
   project — is swept by nothing, which is why S10 drifted unobserved and would
   have kept drifting.
3. **The `frozen-registry-errata.md` §0 definition is narrower than its own
   gate.** §0 defines an erratum as an over-read note; the parser enforces only
   three fields and admits any direction. R5 fixes the instance; the general
   question of what an erratum may record is worth one sentence somewhere
   normative before a third kind arrives.
4. **`testdata/tamper/MATRIX.json:700` cites line 123 for a claim about
   *forward* compatibility** — why a v1 verifier meeting a v2 bundle must render
   "newer antseal" rather than "corrupt". Line 123 binds future releases to past
   versions, not past releases to future ones. It is arguably class (c) and it
   is one `"why"` string in a frozen-adjacent fixture; left out of Q148's scope
   deliberately, but somebody should decide rather than inherit it.
5. **Q6's row and entry do not agree on who freezes.** The entry's `Do` imposes
   the append-only byte pin and its `Accept` defers enforcement to Q14, while
   the row's summary reads as though Q6 did both. §1.7 resolves it for this
   wave; the split authority is a fact about the vector freeze that three
   separate sites now have to restate because no single row states it.
6. **The tag peel is a trap that has been stepped in once.**
   `git rev-parse format-v1-freeze` returns the annotated tag object
   (`5b72bb0`), not the commit (`d3345e1`), and every record in the project
   quotes the commit. Any future "the tag is unmoved" check must peel with
   `^{commit}` or it will compare the wrong two hashes and pass.


---

## Amendment — the erratum landed as a corrected clause, not verbatim, 2026-08-10

**Recorded, not applied. The body above is byte-unchanged**, per D115 §3.7 and
`Q122`; this is D84's appended-correction mechanism, not a body edit.

**§3.4's specified erratum text was wrong about its own subject and the
implementing lane corrected it in flight, saying so.** The block prescribed for
`frozen-registry-errata.md` described Q14 as named *"two lines above"* the
quoted sentence; lane B measured the offset as five and landed a corrected
clause instead — the entry now reads *"Byte-immutability is imposed by **Q14's
own freeze act**, which this same blockquote names in its own first sentence"*.
The substitution is deliberate and is the right call: an erratum whose own
positional claim is wrong is the defect this document exists to refuse, one
document over.

**This record has no `Index row (orchestrator applies at merge)` section**,
which its three siblings from this wave all carry. Its register line was
composed at wave 13's bookkeeping from §4.3's ruling, §5's riders and §1's
measurements, and is therefore the bookkeeping lane's summary of this document
rather than its author's own proposed line. A reader comparing the register
against the record should know which.

**§7 bullet 2 is stale in its first two clauses.** It reads *"`DECISION_SCAN`
omits `scripts/`; `TASK_SCAN` includes it; neither reaches root files."* Both
constants were **deleted** on 2026-08-10 by `Q133`, which collapsed them into
`CITATION_SCAN`/`CITATION_SUFFIXES`/`CITATION_SCAN_SELF`. **The third clause —
the load-bearing one — is still true**, re-verified against the post-`Q133`
tree: the scan roots are subdirectory names and `rglob` from `ROOT/<sub>` never
reaches `ROOT/CHANGELOG.md`. Registered as `Q176`; that this record was
falsified in its mechanism by a rename landing in the same wave is `Q151`.

**Nothing in §2's site table, §3's protocol or §4's refusal is affected.**
