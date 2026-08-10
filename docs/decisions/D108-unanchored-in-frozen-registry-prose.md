# D108 — Q129: a fourth sense of UNANCHORED, in frozen normative text

- **Status: RESOLVED — the frozen bytes are NOT edited; the correction lands at
  every editable site, the four senses get one normative home, and the
  in-place edit is queued as an erratum against the next registry version.**
  The register's lean — *annotate or retire the word at `registry-v1.md:664`* —
  is **refused**, because both of its arms and recon's rejected "correct" arm
  are the **same act**: a byte change to a frozen registry. Recon's freeze
  analysis is **wrong in the direction that matters**: it reports *"there is no
  bless flag; re-pinning in place requires hand-editing `FROZEN.sha256`"*.
  There **is** an in-band re-bless — flip `#! status frozen` → `pre-freeze`,
  `--update`, flip back, inside one commit, which `format_freeze.rs:189-192`
  forces by reddening a committed `pre-freeze` — and it has been **used once,
  on the record, for exactly this class of change**: `622f5fe`, which corrected
  §14's overstated D-family claim and re-blessed the digest with the reason in
  the commit message. So the edit is not blocked by a missing mechanism. It is
  blocked by **the limit that commit set for itself**: *"done in one commit
  with the reason stated, **before any tag exists**."* `format-v1-freeze` now
  exists (`d3345e1`), so a byte change today is not one sentence — it is a **tag
  event**, and that is a repository-identity act, not a lane's. Weighed against
  a **gloss in a `len/shape` cell that no parser reads and that the registry's
  own `:459-462` already defers past** — it points its reader at MVP-SPEC.md
  line 137 **by name** for verdict vocabulary — the trade fails. And recon's
  strongest premise is **inverted**: *"no test reads that prose"* is not a
  licence, it is the reason the digest exists. Every mechanical fact in
  registry-v1 is pinned twice, by `format_registry_freeze.rs` and by SHA-256;
  the **only** content the digest alone covers is the prose, so *"no assertion
  reaches these bytes"* and *"the freeze is the sole thing covering these
  bytes"* are one sentence, and it argues for the freeze. Meanwhile the
  highest-value site is **free**: `schema.rs:1449-1450` is unfrozen rustdoc, is
  where an implementer of this codebase actually reads, and is edited here. And
  the separation the ruling protects turns out to be **already asserted and
  unattributed**: `verdicts/tests.rs:1862-1896` builds a bundle with a
  **non-empty** `ots_anchors` holding one `pending` OTS and asserts
  `is_unanchored()` — so a rewrite of sense (c) into sense (d) goes red today,
  inside a test named for identity counting that cites none of this.
- **Date: 2026-08-09** (M2 wave 10 planning round; briefed to annotate the
  frozen line, and the frozen line is left alone)
- **Owning tasks: Q129** (the ruling; closed by it), **Q120** (the three-sense
  net this completes), **F8/F4** (the registry and its freeze), **A18/A15**
  (the two code senses)
- **Amends**: **`docs/decisions/D98-status-anchor-state-vocabulary.md` rider
  3c** (`:421-431`) — extended from three senses to four, and given the
  layer/scope column that makes the fourth legible; **`tasks/Q.md` Q129's
  Accept** (`:1573`), whose both arms require editing frozen bytes;
  **`TODO.md`'s Q129 row**; **`crates/antseal-core/src/bundle/schema.rs:1449-1450`**;
  **`crates/antseal-core/src/anchor/verdicts/tests.rs:1862-1896`** (the
  unattributed separation). **Supersedes**: nothing. **Binds against**: D78
  (`registry-v1.md:115-124`), D98 rider 3c, D30, Q14, Q27, Q50, MVP-SPEC.md
  lines 121/123/137, `622f5fe`.

---

## The problem, in one sentence

`registry-v1.md:664` says *"an UNANCHORED bundle is **both** anchor arrays
empty"*, which is false as a biconditional against MVP-SPEC.md line 137 — and
the sentence is inside a SHA-256-pinned file whose own freeze manifest says a
byte change is a format-version event.

---

## 1. What was measured

Read from the tree at `a68d9ea`. No `cargo` command was run (§7).

### 1.1 The sentence, and the exact shape of its falsity

`docs/format/registry-v1.md:664`, the `len/shape` cell of §7.6 key 3:

> `OTS artifacts (§7.8); an UNANCHORED bundle is **both** anchor arrays empty`

`MVP-SPEC.md:137` defines the word as **zero headline-eligible anchors**, and
names the counterexample in the same sentence:

> *"Zero headline-eligible anchors → loud 'UNANCHORED — integrity and signature
> only, no provable time'. … It arises only for `--force-degraded`/`--no-anchor`
> seals, **or a bundle carrying only a `pending`/`attested` OTS**"*

A bundle carrying one `pending` OTS is spec-UNANCHORED with `ots_anchors`
**non-empty**. So `:664` read as a biconditional is false; read as *"both arrays
empty ⇒ UNANCHORED"* it is true and weak; read as a local definition it is
coherent and collides with the word two layers up.

**What the cell is actually doing is true.** Its job is to justify
`req, may be empty` — an empty anchor array is a well-formed bundle, not a
schema error. That statement is correct and is the content. The word UNANCHORED
is decorative, and it is decoration borrowed from a vocabulary that means
something else. This is **D98 rider 3c's disease, in the one place Q120's
mechanism could not reach** (`tasks/Q.md:1512`: *"a frozen document is outside
it"*).

### 1.2 Four senses, and three sites for the fourth

| sense | predicate | site |
| --- | --- | --- |
| (a) | the `--no-anchor` **shaping flag** recorded at seal | `crates/antseal-cli/src/listing.rs:283` (`WorkRow.unanchored`) |
| (b) | **no anchor records at all** | `crates/antseal-anchor/src/ots/engine.rs:661` (`NagState::Unanchored`, doc `:649-660`) |
| (c) | **zero headline-eligible anchors** — the spec's | `MVP-SPEC.md:137`; `crates/antseal-core/src/verify/aggregate.rs:83-91` (`is_unanchored`); `crates/antseal-cli/src/status.rs:442-456` |
| (d) | **both bundle anchor arrays empty** | `docs/format/registry-v1.md:664`; `docs/format/registry-v1.json:356`; `crates/antseal-core/src/bundle/schema.rs:1449-1450` |

Senses (a)–(c) each carry a doc comment naming the other two and citing D98
rider 3c — that is Q120's landed work. **Sense (d) names nobody and is named by
nobody**, and it has three sites, **two of them SHA-256-pinned**.

**The row does not mention the `.json`.** `registry-v1.json:356`'s `notes` field
reads *"ots_anchor elements; an UNANCHORED bundle is both anchor arrays empty.
Anchor kind is positional — this key IS the OTS kind"*. That is **not** a
verbatim copy: no bold, and a second clause the `.md` does not have. So the
project holds **two independently worded copies of one claim**, and §1.6
measures that nothing compares them.

### 1.3 The registry structurally cannot state sense (c) — so "correct it" is a tier violation

D78, ratified, at `registry-v1.md:115-124`:

> *"**bundle schema validation never consults the embedded manifest.** … Any
> rule needing both sides is therefore **[R]**, not a schema error. … a bundle
> that is *well-formed but inconsistent with its manifest* must report a verify
> code, never a schema code, so 'malformed bundle' and 'lying sealer' never
> render alike."*

The cell sits in a table whose rows are tier **[P]** — *"decidable from the
**one entry** being decoded"* (`:111`). Headline-eligibility is not [P] and is
not [X]: it is a per-anchor cryptographic verdict computed layers up
(`aggregate.rs:83-91` counts it from `AnchorVerdict::is_headline_eligible()`).
The registry says so twice in its own voice:

- `:459-460` — *"**No v1 parse rule and no v1 verdict may read this field.** A
  verifier derives its own per-anchor state (sealer-as-adversary, line 121) and
  MAY display the recorded value only as a *sealer-asserted claim*, with the
  discipline **MVP-SPEC.md line 137** already prescribes…"*
- `:923` — *"an under-anchored bundle is a *verdict*, not a parse error."*

**So recon is right that "correct it to state the spec's predicate" trades a
scoped-name defect for a D78 tier violation** — and there is a second finding in
the same lines: **the registry already points its reader at MVP-SPEC.md line 137
by name, four hundred lines earlier, as the authority for exactly this
vocabulary.** A reader who takes `:664`'s gloss for a verdict rule is
contradicting the document they are reading. That does not make `:664` harmless;
it bounds the harm, and §3 weighs it.

### 1.4 The freeze mechanics — recon is wrong about the mechanism and right about the cost

| fact | where |
| --- | --- |
| both files are pinned | `docs/format/FROZEN.sha256:59-60` |
| under `#! status frozen`, `--update` **refuses** to modify or drop an entry, quoting MVP-SPEC.md line 123 and Q27 | `scripts/format-freeze.sh:170-183` |
| **but `pre-freeze` permits a re-bless, in band and by design** — *"While `#! status pre-freeze` an entry may be re-blessed as a recorded, justified change; under `#! status frozen` …"* | `crates/antseal-core/tests/format_freeze.rs:30-31` |
| and a **committed** `pre-freeze` is red — *"still calls itself pre-freeze permits a silent re-bless"* — so the flip cannot survive a commit | `format_freeze.rs:189-192`, test at `:368-380` |
| nothing pins `FROZEN.sha256`'s own bytes | grep over `crates/`, `scripts/`, `.github/` |

**So recon's *"there is no bless flag; re-pinning in place requires hand-editing
`FROZEN.sha256`"* is false.** The status directive **is** the bless flag, the
Rust test forces the flip to be transient, and the whole operation lands as one
reviewable commit carrying one changed digest line and one changed document.

**And it has been done, once, for this exact class of change.** `622f5fe`
(2026-07-28), *after* the freeze commit `1f0b363`:

> *"**The Q50 digest is re-blessed once, deliberately and on the record.** It was
> computed before (1) was found, so the frozen manifest refused `--update`,
> exactly as designed — the refusal is quoted in this lane's report. The
> re-bless is a status flip to `pre-freeze`, an update, and a flip back, done in
> one commit with the reason stated, **before any tag exists**. Recorded rather
> than silent because the mechanism's whole value is that a change to a frozen
> document is visible; a maintainer reading this history sees **one** re-bless
> with a reason, which is the shape the contract intends."*

Two things follow, and they point opposite ways.

1. **The precedent exists and its class is close to ours.** What `622f5fe`
   corrected was §14's claim that the freeze test asserts *"§2's fixed-length
   table matches `scalars[]`"* — an **overstatement about the project's own
   assertions**. Its own stated principle: *"a substring match on the prose would
   pin editorial wording rather than format facts"*, and *"an overstatement in
   the normative text is the one thing not to freeze."*
2. **The commit drew its own boundary, and we are past it.** *"before any tag
   exists."* `format-v1-freeze` → `d3345e1`, and `622f5fe` is an ancestor of it
   (verified). A byte change today makes the tag name a registry the tree does
   not have — which is the harm `d3345e1`'s own subject line was written to
   prevent (*"anchor the freeze report to the tag, not to a rewritten hash"*).

### 1.5 What a prose edit would and would not redden

| fact | where |
| --- | --- |
| the §7.x table check compares `cells[0]`, `cells[1]`, `cells[3]` only, and asserts `cells.len() == 5` | `crates/antseal-core/tests/format_registry_freeze.rs:1824-1836` |
| **`cells[4]` — the `len/shape` cell — is never compared to anything** | same |
| so a prose edit inside `cells[4]` is not a code event **provided it introduces no `|`** | derived |
| the `.json` `notes` field is likewise uncompared: the mirror check reads structured fields, and the only `notes` reference is §6.2's `sig_alg` **header** | `format_registry_freeze.rs:1914-1919` |

Recon's claim is confirmed. **§3.2 rules on what follows from it, and it is not
what recon inferred.**

### 1.6 Nothing cross-checks the two copies of the sentence

`format_registry_freeze.rs`'s D-family compares the document's mechanical tables
against the JSON mirror in both directions — keys, names, presence, reserved
slots, bands, enums, scalars, arities, caps. **The `.md`'s `len/shape` prose and
the `.json`'s `notes` prose are compared to nothing, in either direction.** So
the two independently worded copies of §1.2's sentence can drift without a
signal, and one has already acquired a clause the other lacks.

Whether that gap is in scope is ruled at §5 and described at §9.

### 1.7 The separation Q129 protects is already asserted — and unattributed

`crates/antseal-core/src/anchor/verdicts/tests.rs:1862-1896`, inside
`a_lone_proven_ots_establishes_one_identity`, builds four bundles and asserts
`distinct_verified_identities() == 0 ⟺ aggregate().is_unanchored()` over all
four. One of them is:

```rust
let pending_only = [ots_anchor(MERGED_A, None)];
let unanchored = evaluate_anchors(&AnchorArtifacts::from_parts(&pending_only, &[], None), …);
```

— a **non-empty** `ots_anchors` array whose aggregate is `is_unanchored()`.
Rewrite `is_unanchored()` as sense (d) (`ots.is_empty() && tsa.is_empty()`) and
that row goes **red today**, in a test named for identity counting, whose doc
comment cites D92 §9 T4 and nothing about UNANCHORED's four senses.

**So the collapse Q129 fears is already guarded and the guard does not know what
it is guarding.** That is the difference between coverage and a claim, and it
changes the instrument section from *"write a test"* to *"name the one you
have"*.

---

## 2. The options, and what kills each

### (a) Correct `:664` to state the spec's predicate — killed by D78

§1.3. Headline-eligibility is a [R]-tier verdict; the cell is [P]. Stating it
there would put a rule the schema layer must not evaluate into the schema
layer's own table, and would contradict `:459-460` and `:923` in the same
document. Recon is right, and this kill is independent of the freeze.

### (b) Annotate in place — *"name which of the four senses it means"* — the lean

### (c) Retire the word in place — keep the shape fact, drop `UNANCHORED`

**(b) and (c) are the same act as (a): a byte change to a frozen registry.** The
freeze does not grade edits by how small they are. §3.1 rules the principle and
§3.2 kills the "no parser reads it" argument that both arms rest on. What
survives from (b) and (c) is their *content*, which §3.3 lands at every site that
is not frozen.

### (d) A format-version event — cut a `registry-v2` pair for this sentence

Refused as disproportionate, and recorded because it is Q27's literal
instruction. Q27's procedure exists for changes that alter what a v1 decoder must
do; this alters nothing a decoder does. Cutting v2 for a gloss would also spend
the one thing the reserved-slot discipline is meant to conserve — MVP-SPEC.md's
*"prefer reserved slots over breaking changes"* — on a defect with no wire
consequence.

**But it is not refused forever.** §4 R4 queues the correction so that whenever a
v2 pair is cut for a real reason, the sentence is fixed in the same act at zero
marginal cost.

### (e) Leave the frozen bytes; correct every editable site; one normative home; queue the rest — **the ruling**

---

## 3. Ruling

### 3.1 The principle: what would license an in-place edit, stated so it cannot be stretched

**An in-place byte change to a frozen registry entry requires all three of the
following. `:664` clears C1, fails C2, and therefore never reaches C3.**

**C1 — nothing that is format surface moves.** No key, type, presence, rule,
length, tier, status, enum value, cap, error code or reserved slot; no change to
any row's cell count; nothing that any needle in `format_registry_freeze.rs` or
`format_freeze.rs` reads. Concretely today: not `cells[0]`, `cells[1]` or
`cells[3]` of any §7.x row, and no new `|`.

**C2 — the sentence is false *about this project's own machinery*, not merely
misleading about vocabulary.** It claims an assertion that does not exist, a
constant that is not the constant, a code that is not minted, or a guarantee the
tree does not provide. `622f5fe` is the one precedent and is exactly this class:
§14 claimed the freeze test made a row-comparison it does not make. **A statement
that is true at its own layer and borrows a word used differently elsewhere is
not in this class.**

*Why C2 and not "is it wrong?".* The freeze's value is that a reviewer can trust
what the document says about what is guaranteed. A false claim about the
project's own assertions attacks that directly and cannot be corrected anywhere
else, because the claim is *about this document*. A vocabulary collision has
other channels — the code, the spec, the decision record — and §3.3 uses them.

**C3 — the re-bless is in-band and the tag is settled in the same act.** The
mechanism is `#! status frozen` → `pre-freeze` → `--update` → `frozen`, inside
one commit whose message states the reason (`format_freeze.rs:189-192` makes a
committed `pre-freeze` red). **And**, because `format-v1-freeze` now exists and
`622f5fe` conditioned its own legitimacy on being *before any tag*: the tag is
re-pointed or superseded in the same act, so `format-v1-freeze` never names a
registry the tree does not have.

**C3 is what makes the price legible: an in-place edit is not one sentence, it
is a tag event** — and re-pointing a published tag is a repository-identity act,
which is §8's business and not a lane's.

### 3.2 The "no parser reads it" argument is refused, and refused structurally

Every mechanical fact in registry-v1 is pinned **twice**: once by
`format_registry_freeze.rs`'s cell and mirror comparisons, once by the SHA-256.
The **only** content the digest alone covers is the prose. So *"no assertion
reaches these bytes"* and *"the freeze is the sole thing covering these bytes"*
are the same sentence — and it is an argument **for** the freeze.

A rule that licensed edits wherever no assertion reaches would license editing
exactly the surface the freeze exists to hold, and would leave the digest
guarding only what is already guarded twice. `FROZEN.sha256:12-23` says this in
its own words about the D10 caps: a coordinated edit that keeps two files
agreeing *"passes the entire suite, forever"*, and the manifest exists because
**consistency is not a pin**. Prose has no consistency check at all, which makes
it more dependent on the pin, not less.

### 3.3 The three sites

| site | frozen? | ruling |
| --- | --- | --- |
| `docs/format/registry-v1.md:664` | **yes** | **untouched.** Recorded as an erratum (R4) and queued for the next registry version |
| `docs/format/registry-v1.json:356` | **yes** | **untouched.** Recorded as a **separate** erratum entry, because its wording is not the `.md`'s (§1.2) and a reader who consults the mirror meets a second, independently worded copy |
| `crates/antseal-core/src/bundle/schema.rs:1449-1450` | no | **edited now** (R1). It is the site an implementer of this codebase reads, it is free, and leaving it is the only avoidable half of the defect |

**Q129's Accept is amended** (R5): both of its arms — *"states the spec's
predicate"* and *"names which of the four senses it means"* — require editing
frozen bytes, and it was written without knowing that the re-bless mechanism is
in-band but tag-bounded, or that `622f5fe` had already drawn the tag line.

---

## 4. Riders — normative, cite by number

### R1 — `schema.rs:1449-1450`, exactly

The word is **retired**, not annotated, because the surrounding rustdoc is a
schema-layer document and sense (c) has no business being nameable there. The
shape fact is stated and the vocabulary is deferred:

```rust
/// OTS anchor artifacts. **Empty is legal**: a bundle with no anchors at all
/// is well-formed, not a schema error.
///
/// Deliberately **not** spelled "UNANCHORED". That word is MVP-SPEC.md line
/// 137's and it means *zero headline-eligible anchors* — a bundle carrying
/// one `pending` OTS is UNANCHORED with this array **non-empty**. Layer 1
/// cannot decide it (D78; registry §7.6 is tier [P], *"decidable from the one
/// entry being decoded"*), and the registry says so itself: *"an
/// under-anchored bundle is a verdict, not a parse error"* (§7.9). Four
/// senses of the word share this codebase — D98 rider 3c, extended by D108.
pub ots_anchors: Vec<OtsAnchor>,
/// TSA anchor artifacts; empty is legal, on the same terms.
pub tsa_anchors: Vec<TsaAnchor>,
```

### R2 — The single normative home is D98 rider 3c, extended to four

**Not a new document.** Rider 3c is where the prohibition already lives, it is
what all three code sites already cite by name, and Q120's landed test cites it.
A fifth place to look is how a taxonomy acquires a fifth entry nobody reconciles.

Rider 3c gains the fourth row and a **layer** column, because the fourth sense is
what it is:

| # | predicate | layer / subject | authority |
| --- | --- | --- | --- |
| (a) | the `--no-anchor` shaping flag | a **vault work**, at seal time | `listing.rs:283` |
| (b) | no anchor records at all | a **vault work**, now | `engine.rs:649-661` |
| (c) | zero **headline-eligible** anchors | a **verdict** over a bundle or a work | `MVP-SPEC.md:137`; `aggregate.rs:83-91` |
| (d) | both anchor arrays empty | the **CBOR shape** of a `.sealproof`, tier [P] | `registry-v1.md:664` (**frozen**); `registry-v1.json:356` (**frozen**); `schema.rs:1449` |

And it gains the sentence that makes (d) legible rather than merely listed:

> *(d) is not a competing definition; it is a true layer-1 shape fact that
> borrowed the word. Its two normative sites are frozen and cannot be corrected
> before the next registry version — D108 §3 rules the in-place edit refused and
> §8 records the maintainer's alternative. (c) and (d) are the pair most likely
> to collapse, because both are about a bundle; `verdicts/tests.rs:1862-1896` is
> the row that goes red if they do.*

**Rider 3c is not renumbered** — it stays 3c with four rows, so every existing
citation (`listing.rs:280`, `engine.rs:655`, `status_command.rs`, Q120, Q129)
keeps resolving.

### R3 — The three editable senses each name the fourth

One line each, completing the net Q120 built. Leaving two of four incomplete is
how a cross-reference net rots.

- **`aggregate.rs:83-91` — mandatory.** It is sense (c) and it lives in the same
  universe as (d); this is the collapse R2 names. Add: *"and **not** registry
  §7.6 key 3's *both anchor arrays empty*, which is a layer-1 CBOR shape fact
  (tier [P]) and cannot decide this — a bundle with one `pending` OTS is
  UNANCHORED here with that array non-empty."*
- **`engine.rs:649-660`** and **`listing.rs:278-282`** — one clause each,
  extending the existing *"not X and not Y"* sentences to *"and not Z"*, with the
  note that (d) is about a `.sealproof`, not about a work, so it can never be the
  answer at either of those sites.

### R4 — The erratum file, and why it is a file rather than a decision record

**`docs/format/frozen-registry-errata.md`** — new, unfrozen, two entries today.

**Why a file.** The frozen document **cannot point at anything**: every byte of
it is pinned, §14 included. So a correction is reachable only from outside, and
the reachable-from-outside places are the code (R1/R3), the decision record
(this one) and `ls docs/format/`. A file sitting beside `registry-v1.md` is the
only one of those a lane cutting `registry-v2` will pass without being told to.

**Why that exact name.** Not `registry-v1-errata.md`: `must_be_frozen`
(`format_freeze.rs:86-98`) collects `registry-v<digits>.{md,json}` only, so that
name would not be *required* to be frozen — but the manifest's `EntryPolicy`
(`required_name_prefix: "registry-v"`, `freeze_manifest/mod.rs:262-276`) would
**accept** it as an entry, so a future lane could freeze it by accident. A name
outside the prefix cannot be added to the manifest at all: the parser rejects it
with a message naming the policy. Choose the name that makes the mistake
impossible rather than merely unlikely.

**What an erratum is, stated in the file's own header so it cannot become a
second source of truth:**

> An erratum is a **reading note, never an amendment**. The frozen bytes govern
> the format; nothing here changes what a v1 decoder does, and no erratum may
> state, weaken or extend a rule. An entry says only: *this sentence, verbatim,
> in this frozen file, will be read to claim more than it claims — here is its
> scope.* Every entry is queued for correction in the next registry version and
> is deleted when that version lands.

**Entry shape**, three fields the checker reads (file, verbatim quotation,
scope note) plus free prose:

```
### registry-v1.md — §7.6 key 3 `ots_anchors`
- file: `registry-v1.md`
- quotes: `an UNANCHORED bundle is **both** anchor arrays empty`
- scope: sense (d) of four (D98 rider 3c). True as a layer-1 shape fact and
  **false as a biconditional** against MVP-SPEC.md line 137, which the registry
  itself names as the authority for this vocabulary at §7.8 (`:459-460`). The
  cell's actual claim — an empty anchor array is well-formed — is correct.
- queued for: registry-v2 (D108 §3.3)
```

The second entry is the same for `registry-v1.json`'s `notes` field, quoting
**its** wording, which is not the `.md`'s.

### R5 — Q129's Accept, amended with its reason

Replace:

> *"the registry line either states the spec's predicate **or** names which of
> the four senses it means; the decision is recorded with its freeze cost either
> way."*

with:

> *"The four senses are enumerated in one normative home (D98 rider 3c,
> extended). Every **editable** site of the word names its sense and points
> there. The two frozen sites are left byte-identical and recorded as errata with
> their scope, queued for the next registry version — and a test proves each
> erratum still quotes its frozen sentence verbatim, so a stale erratum is red
> rather than quiet. The freeze cost of the alternative is recorded (D108 §3.1
> C1–C3, §8)."*

**The reason the original could not stand:** both of its arms are byte changes to
a frozen file. It was written by the Q120 lane on the day it discovered the site
(`tasks/Q.md:1512`), and its Notes correctly price the act as *"a
**format-freeze event**, not a drive-by edit"* — it simply did not have §1.4's
measurement that the price is now a **tag** event, nor `622f5fe`'s self-imposed
boundary.

### R6 — The instrument is a rename and a citation, not a new test

§1.7. `a_lone_proven_ots_establishes_one_identity`
(`verdicts/tests.rs:1848-1900`) already reddens against the (c)→(d) collapse. It
gets:

- the local binding `unanchored` renamed to `pending_only_unanchored`, so the
  name says *non-empty array, still UNANCHORED*;
- three doc lines naming what the four-bundle sweep separates, citing D98 rider
  3c and D108 R2, so the next lane learns **why** it went red rather than
  re-blessing it.

**No new test.** Writing a second differential over the same four bundles would
be duplicate coverage with a better name, and this project's answer to
unattributed coverage is attribution.

---

## 5. Edit set

| file | edit | rider |
| --- | --- | --- |
| `docs/format/registry-v1.md` | **NO CHANGE.** Byte-identical. Recorded as an edit-set row so a lane cannot read the absence as an oversight | §3.3 |
| `docs/format/registry-v1.json` | **NO CHANGE.** Byte-identical | §3.3 |
| `docs/format/FROZEN.sha256` | **NO CHANGE.** No re-pin, no status flip | §3.1 |
| `docs/format/frozen-registry-errata.md` | **new**, unfrozen; header per R4; two entries (`registry-v1.md` §7.6 key 3, `registry-v1.json` key 3 `notes`) | R4 |
| `crates/antseal-core/src/bundle/schema.rs:1449-1450` | rustdoc replaced per R1; `tsa_anchors`' one-liner extended | R1 |
| `crates/antseal-core/src/verify/aggregate.rs:83-91` | one clause naming sense (d) and why it cannot decide (c) | R3 |
| `crates/antseal-anchor/src/ots/engine.rs:649-660` | one clause: *"and not registry §7.6 key 3's both-arrays-empty, which is about a `.sealproof`, not a work"* | R3 |
| `crates/antseal-cli/src/listing.rs:278-282` | the same clause | R3 |
| `crates/antseal-core/src/anchor/verdicts/tests.rs:1862-1896` | binding renamed `pending_only_unanchored`; three doc lines naming the separation and citing D98 rider 3c / D108 R2 | R6 |
| `crates/antseal-core/tests/format_freeze.rs` | the erratum checker + its red case (§6) | §6 |
| `docs/decisions/D98-status-anchor-state-vocabulary.md:421-431` | rider 3c extended to four rows with a **layer** column and R2's closing sentence; **not renumbered** | R2 |
| `tasks/Q.md` Q129 | Accept replaced per R5; Notes gain §1.4's correction (the re-bless is in-band, has one precedent, and is now tag-bounded) | R5 |
| `TODO.md` Q129 row | follows `tasks/Q.md` | R5 |

**Zero frozen bytes move. Zero wire bytes. Zero constants. Zero vectors,
digests, error codes or report bytes. No format-version event, and no tag.**

---

## 6. Instruments

**`every_erratum_quotes_its_frozen_sentence_verbatim`**, in
`crates/antseal-core/tests/format_freeze.rs` — the file that already owns the
frozen-registry gate, its manifest parser and its scratch-directory harness
(`scratch_dir`, `expect_red`).

For each erratum entry:

1. the named file **is one of the manifest's frozen entries** — an erratum
   against an unfrozen file is a way to smuggle a note into policy, and is
   refused by name;
2. the `quotes:` string is **byte-present** in that file.

Plus anti-vacuity: **at least one entry**, asserted, so an emptied errata file
cannot render the test silently green.

**Red arm**, in the existing `expect_red` style: a scratch `docs/format` whose
errata file quotes a sentence the document does not contain. Run before the green
verdict is trusted.

**What this test is really for, and it is worth stating.** It couples the erratum
to the frozen bytes in **both** directions. If anyone ever re-blesses `:664`
under §8's option B, the quotation stops matching and the test goes red —
forcing the erratum to be retired in the same commit rather than surviving as a
note about a sentence that no longer exists. A stale erratum is exactly the
"prose rots" failure `format_registry_freeze.rs:30` was written to catch one
layer over.

---

## 7. What this does not do

- **It does not change what any v1 decoder does.** No parse rule, no presence
  rule, no tier, no code. `ots_anchors` is `req, may be empty` before and after.
- **It does not correct `:664`.** The sentence stays false as a biconditional
  until registry-v2, and R4 is the record that this was chosen rather than
  missed.
- **It does not touch `FROZEN.sha256`, the freeze scripts, or any tag.**
- **It does not reopen D78** or propose any [P]→[R] movement. §1.3 is a reason
  the correction cannot be made *there*, not a complaint about the tier.
- **It does not close the `.md`↔`.json` prose gap** (§1.6). That is a new row
  (§9), and `622f5fe` §1 already ruled against the naive form of it.
- **It does not extend Q120's cross-surface test to a fourth column.** It
  structurally cannot: Q120's vehicle is a **vault of works** and sense (d) is a
  property of a `.sealproof`. Recorded so a lane does not attempt it and conclude
  the test is broken. The (c)/(d) separation has its own guard, and R6 names it.
- **It does not run `cargo`.** §1.5's and §1.7's claims are reads of committed
  test bodies. The implementing lane confirms §1.7 by planting
  `is_unanchored() = ots.is_empty() && tsa.is_empty()` and watching
  `a_lone_proven_ots_establishes_one_identity` go red — **worth doing once**,
  because R6 replaces a new test with a claim about an existing one and the claim
  should be demonstrated before it is documented.

---

## 8. Open for the maintainer

**The call: leave two frozen sentences wrong-in-scope until registry-v2, or
spend a re-bless plus a tag event now.** §3 recommends the first; the second is
not unavailable, and the choice belongs to whoever owns the repository's
published tags.

**Option A — the recommendation (§3, §5).** Frozen bytes untouched; the
correction lands at every editable site; four senses get one home; two errata are
queued and pinned to the frozen text by a test. **Cost:** two sentences in
frozen documents keep saying something a reader may over-read, bounded by
`:459-460`'s own deferral to MVP-SPEC.md line 137, and by the fact that the
sentence's operative claim (an empty anchor array is well-formed) is true.
**Residual risk:** a third-party verifier author reading only registry-v1
carries sense (d) into a rendering decision. Nothing in the tree can prevent that
before v2.

**Option B — re-bless now.** The act, precisely: edit the `len/shape` cell and
the `notes` field so the word is retired (`an empty pair of anchor arrays is a
well-formed bundle` — never "corrected to state the spec's predicate", which
§2(a) kills on D78); flip `#! status frozen` → `pre-freeze`; run
`scripts/format-freeze.sh --update`; flip back; commit once with the reason,
mirroring `622f5fe`'s message shape. Then — the part that is not a lane's —
**re-point or supersede `format-v1-freeze`**, because `622f5fe` conditioned its
own precedent on being *before any tag* and the tag now exists (`d3345e1`).
**Cost:** the project's second-ever re-bless, spent on a gloss; a moved or
duplicated published tag; and the precedent that a frozen registry's prose is
editable when no assertion reads it — which §3.2 argues is the argument that
unfreezes the document. **Benefit:** two sentences stop being wrong-in-scope
roughly one milestone earlier than v2.

**If Option B is chosen**, three things must hold or the act is worse than the
defect: the edit introduces **no `|`** and touches no cell but `cells[4]` /
`notes` (§1.5); `frozen-registry-errata.md`'s entries are **deleted in the same
commit** and §6's test proves it; and the commit message states C1–C3 explicitly,
because the next lane will cite this act and not this record.

---

## 9. Discovered work — described, not numbered

*(The wave owner allocates and registers.)*

**(i) The `.md` and `.json` carry two independently worded copies of one claim,
and nothing compares them.** — M2 · S · deps: F4, Q129, D108 §1.6.
`format_registry_freeze.rs`'s D-family compares every mechanical table against
the mirror in both directions; the `.md`'s `len/shape` cells and the `.json`'s
`notes` fields are compared to nothing. §7.6 key 3 is the measured instance — the
`.json` carries a clause the `.md` does not — and there are fourteen maps'
worth of the same shape. **Scope it carefully or it will fail:** `622f5fe` §1
already ruled against the naive form, *"a substring match on the prose would pin
editorial wording rather than format facts"*, and that ruling is right. The
tractable version is a **closed vocabulary check** — a short list of load-bearing
words (`UNANCHORED`, `reserved`, `may be empty`, tier letters `[P]`/`[X]`/`[R]`)
which, appearing in one side's prose for a key, must appear in the other's — so
the check pins **terms**, not wording. **Not Q129**: Q129 is one word at one key;
this is a structural gap across fourteen maps, and folding it in would give
Q129 an Accept it cannot discharge without a new instrument. Accept: the two
prose surfaces cannot diverge on a load-bearing term without a red test, **or**
the reason a prose cross-check must not exist is recorded at
`format_registry_freeze.rs`'s D-family with `622f5fe` §1's argument, so the next
lane does not re-derive it.

**(ii) `MVP-SPEC.md:123` is cited by the freeze machinery as a byte-immutability
rule and does not say that.** — M2 · XS · deps: Q27, Q14.
`scripts/format-freeze.sh:179-181` and `FROZEN.sha256:48-52` both cite line 123
for *"a byte change to a frozen entry is a format-version event"*. Line 123 reads
*"every **released** manifest/bundle format version remains verifiable by all
future CLI and page releases…"* — a **compatibility** rule, conditioned on
*released*, and D104 §1.5 measures with three independent confirmations that
nothing has been released. The freeze is a **stronger, self-imposed** discipline
than line 123 requires, and it should be cited as Q14's own act rather than as a
derivation from a line that would not currently bind. Recorded because a reader
who checks the citation finds a conditional and may conclude the freeze is soft —
which is the argument D108 §3 spends a section refusing. Accept: both citations
name Q14 as the authority for byte-immutability and line 123 as the compatibility
rule the freeze protects, or the derivation is written out where it is claimed.

---

## Outcome

**RESOLVED, 2026-08-09.** The frozen bytes are **not edited**, and the lean is
refused because *annotate*, *retire* and *correct* are one act: a byte change to
a frozen registry. Recon's freeze analysis is wrong on the mechanism — there
**is** an in-band re-bless (`#! status frozen` → `pre-freeze` → `--update` →
back, one commit; `format_freeze.rs:189-192` reddens a committed `pre-freeze`),
and it has been used once, **for exactly this class**, by `622f5fe`, which
corrected §14's overstated claim about the project's own assertions. But that
commit **drew its own line — *"before any tag exists"*** — and
`format-v1-freeze` (`d3345e1`) now does, so a byte change today is a **tag
event**, not a sentence. Weighed against a gloss in a `len/shape` cell that no
parser reads and that the registry's own `:459-460` already defers past — naming
MVP-SPEC.md line 137 as the authority for this very vocabulary — the trade
fails. And recon's premise is **inverted**: *"no test reads that prose"* is not a
licence but the reason the digest exists, because every mechanical fact is pinned
twice and **prose is the only content the digest alone covers**. "Correct it" is
independently dead on **D78**: headline-eligibility is an [R]-tier verdict and
the cell is [P]. So the correction goes everywhere else — `schema.rs:1449` (free,
and the site an implementer of this codebase reads) retires the word; **D98 rider
3c is extended from three senses to four** with a *layer* column, not
renumbered, so every existing citation still resolves; the three editable senses
each name the fourth; and both frozen sites are recorded in a new
**`docs/format/frozen-registry-errata.md`** — named outside the `registry-v` prefix
so the manifest parser cannot accept it — whose every entry is pinned to its
frozen sentence by a test, so a re-bless later makes the erratum red rather than
stale. **Q129's Accept is amended**, because both of its arms required editing
frozen bytes. **No new test was needed for the separation itself**:
`verdicts/tests.rs:1862-1896` already builds a **non-empty** `ots_anchors` holding
one `pending` OTS and asserts `is_unanchored()`, so the (c)→(d) collapse is red
today — inside a test named for identity counting that cites none of this, which
is coverage without a claim, and R6 makes it a claim. **Zero frozen bytes move;
no tag; no format-version event.** The maintainer's call — leave two sentences
wrong-in-scope until v2, or spend a re-bless plus a tag event now — is §8, with
the exact procedure and the exact price of each.

---

## Index row (orchestrator applies at merge)

| [D108](D108-unanchored-in-frozen-registry-prose.md) | Q129 — a fourth sense of UNANCHORED in frozen normative text — **the frozen bytes are NOT edited; the correction lands at every editable site and the in-place edit is queued as an erratum.** The lean (*annotate or retire the word at `registry-v1.md:664`*) is refused because annotate, retire and correct are **one act**: a byte change to a SHA-256-pinned registry. **Recon's freeze analysis is wrong on the mechanism**: it reports *"there is no bless flag; re-pinning requires hand-editing `FROZEN.sha256`"*. There **is** an in-band re-bless — `#! status frozen` → `pre-freeze` → `--update` → back, inside one commit, which `format_freeze.rs:189-192` forces to be transient by reddening a committed `pre-freeze` — **and it has been used once, for exactly this class**: `622f5fe` corrected §14's overstated claim about the project's own assertions and re-blessed with the reason in the message. But that commit **set its own limit — *"done in one commit with the reason stated, before any tag exists"*** — and `format-v1-freeze` (`d3345e1`) now exists, so a byte change today is a **tag event**, a repository-identity act and not a lane's. Weighed against a gloss in a `len/shape` cell that no parser reads and that the registry's **own `:459-460` already defers past**, naming MVP-SPEC.md line 137 by name as the authority for this vocabulary, the trade fails. **Recon's strongest premise is inverted**: *"no test reads that prose"* is not a licence — every mechanical fact in registry-v1 is pinned **twice** (cell comparisons **and** the digest), so **prose is the only content the digest alone covers**, and *"no assertion reaches these bytes"* is the same sentence as *"the freeze is all that covers them"*. `FROZEN.sha256:12-23` says it in its own words: **consistency is not a pin**. *"Correct it to the spec's predicate"* is independently dead on **D78** — headline-eligibility is an [R]-tier verdict and §7.6 is tier **[P]**, *"decidable from the one entry being decoded"*. Ruling: `schema.rs:1449` (unfrozen, and the site an implementer of this codebase reads) **retires** the word and states the shape fact; **D98 rider 3c is extended from three senses to four** with a *layer* column and is **not renumbered**, so every existing citation resolves; the three editable senses each name the fourth; both frozen sites are recorded in a new **`docs/format/frozen-registry-errata.md`** — deliberately named **outside** the `registry-v` prefix, because `EntryPolicy` would otherwise **accept** it into the manifest — whose every entry is pinned to its frozen sentence by a test, so a later re-bless turns a stale erratum **red** instead of quiet. **The row understates the site count and the divergence**: `registry-v1.json:356` carries the same claim in **different words** (no bold, plus a clause the `.md` lacks), and **nothing compares the two prose surfaces in either direction** — a new row, scoped as a **closed-vocabulary** check because `622f5fe` §1 already ruled against pinning prose 1:1. **No new test was needed for the separation**: `verdicts/tests.rs:1862-1896` already builds a **non-empty** `ots_anchors` holding one `pending` OTS and asserts `is_unanchored()`, so rewriting sense (c) as sense (d) goes **red today** — in a test named for identity counting that cites none of this. Coverage without a claim; R6 makes it a claim by renaming the binding and citing the rider, rather than writing a duplicate. **Q129's Accept is amended** — both arms required frozen bytes. Also found: **`MVP-SPEC.md:123` is cited by the freeze machinery as byte-immutability and does not say that** (it is a *released*-conditioned compatibility rule, and D104 §1.5 measures that nothing has been released), so the freeze should cite **Q14's own act**. **Zero frozen bytes, zero wire bytes, no tag, no format-version event.** §8 puts the alternative — re-bless plus a tag event — to the maintainer with its exact procedure and price | RESOLVED (Q129 executes; §8 open) | 2026-08-09 |
