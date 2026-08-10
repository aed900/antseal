# D111 — Q131: does a prose cross-check between the registry's two surfaces exist, and what does it compare?

- **Status: RESOLVED — the prose⟷prose closed-vocabulary check specified by
  Q131 is REFUSED, and four strictly mechanical document⟷mirror checks land in
  its place. All four are GREEN on the tree as it stands, so no frozen byte
  moves, no erratum is needed and no tag event is triggered.** The register's
  lean — *"add a closed-vocabulary cross-check to the D-family … `UNANCHORED`,
  `reserved`, `may be empty`, the tier letters `[P]`/`[X]`/`[R]`"* — is
  refused on **measurement, not on principle**, and it fails in the two ways
  that matter most. **(1) It is green at its own motivating instance.**
  `UNANCHORED` occurs in the prose of **both** surfaces at registry §7.6 key 3
  and **nowhere else in either**, so a term-presence check over that key is
  satisfied by construction: the divergence Q131 was minted to catch — the
  mirror dropping the emphasis and adding *"Anchor kind is positional — this
  key IS the OTS kind"* — is not a vocabulary event and the proposed check
  would never see it. **(2) It is red at roughly thirty sites that are not
  defects.** The tier letters are **md-only at 25 occurrences** measured
  against the mirror's `notes`; `may be empty` is absent from the `.md`
  `len/shape` prose at **7** of the 8 sites where the mirror carries it; and
  `reserved` splits 1 md-only / 1 json-only. A check with zero recall on its
  own case and ~30 false positives is not a scoped instrument, it is a broken
  one. **The root cause is that the two cells are not the same field.** The
  `.md`'s `len/shape` cell is a *merge* — byte length, shape pointer, tier
  tags, conditions and prose in one cell — while the mirror splits those
  across `length`, `type`, `rule`, `tier` and `notes`; **66 of 68 pairs differ
  literally**, and at 12 scalar keys the `.md` cell is a bare `32`/`16`
  against an **empty** `notes`. That is `622f5fe` §1's finding exactly, at a
  second table: *"the two are not row-comparable."* **But the measurement also
  found the real gap, and it is mechanical rather than prose.** The mirror
  carries **`type`, `presence`, `rule` and `tier`** as structured fields;
  D108 §3.1 C1 names all four as **format surface**; and `grep` over `crates/`
  returns **zero** readers of `tier` and `rule` anywhere in the tree. The
  `.md`'s **`type` column — `cells[2]` — is read by no test in the D-family
  either**, a fact Q131 does not mention, and it agrees with the mirror at
  **68 of 68**. So three of the four terms Q131 wanted to hunt for in prose
  are **already structured data on one side**, and comparing the `.md` cell to
  *that* is a mechanical document⟷mirror assertion in the D-family's existing
  idiom — not a substring match on wording, and therefore not what `622f5fe`
  §1 forbids. **And the motivating instance is already covered**: D108 R4's
  `every_erratum_quotes_its_frozen_sentence_verbatim` pins **both** copies of
  the §7.6 key 3 sentence byte-for-byte, on both sides, so that specific
  divergence is already red-on-drift — just not comparatively.
- **Date: 2026-08-10** (M2 wave 12 planning round; briefed to build the
  closed-vocabulary prose check, and the closed-vocabulary prose check is
  refused)
- **Owning tasks: Q131** (the ruling; closed by it), **F4** (the registry and
  its freeze), **Q14/Q27** (the freeze discipline)
- **Amends**: **`tasks/Q.md` Q131's `Do`** (its proposed vocabulary is refused
  term by term at §1.4) and **`TODO.md`'s Q131 row**. **Supersedes**: nothing.
  **Binds against**: **D108** §3.1 (C1–C3, the in-place-edit licence), §3.2
  (the "no parser reads it" refusal), R4 (the errata mechanism); **`622f5fe`
  §1**; **D78** (tier discipline); Q14, Q27.

---

## The problem, in one sentence

Q131 asserts that the D-family compares the two surfaces' prose to nothing and
proposes a closed-vocabulary prose check to close the gap; this decision
re-measures both halves and finds the first true, the second unworkable, and a
better instrument sitting unused in the mirror's own structured fields.

---

## 1. What was measured

Every figure below is from this lane's own measurement against the tree at
`5fbc48d`, not from Q131's prose. The extraction re-implements
`format_registry_freeze.rs`'s own `table_under` / `table_row` parser so that
what is measured is what the test would see.

### 1.1 The D-family, in full — confirmed, and Q131 understates it

The D-family is **four** tests, at `crates/antseal-core/tests/format_registry_freeze.rs:1803–2063`:

| test | reads from the document | compares to |
| --- | --- | --- |
| `the_document_map_tables_match_the_mirror` | `cells[0]`, `cells[1]`, `cells[3]` | `fields[].key`, `fields[].name`, `reserved[]` |
| `the_document_enum_tables_match_the_mirror` | §6.1 `c[0]`,`c[1]`; §6.2 `c[0]`,`c[1]`; §6.3 `c[0]`,`c[1]` | `enums[]` |
| `the_document_scalar_table_matches_the_mirror` | §2 `c[0]` only | `scalars[].length` |
| `the_document_cap_table_matches_the_mirror` | §11 `c[0]`,`c[1]`,`c[3]` | `caps.entries[]` |

**Q131's claim is confirmed**: `the_document_map_tables_match_the_mirror`
asserts `cells.len() == 5` and reads indices 0, 1 and 3, so `cells[4]` — the
`len/shape` prose — is never read, and no other test in the family reads it.
The mirror's `notes` is likewise unread: its only occurrence in the whole file
is inside §6.2's *header string* `"| value | algorithm | pubkey | signature | notes |"`.

**And Q131 understates the gap by one whole column.** `cells[2]` — the
**type** column — is also read by nothing, in any test, in either direction.
Q131 never mentions it. Nor is `cells[3]`'s *value* compared: it is consumed
only as the boolean `presence.contains("reserved")`, so `req` vs `opt` reaches
no assertion. The same holds for §6.2's `pubkey`/`signature`/`notes` columns,
§2's `fields`/`source` columns and §11's `applies to` column.

Baseline, run before anything else:

```
cargo test -p antseal-core --test format_registry_freeze
→ ok. 24 passed; 0 failed
```

### 1.2 The count, and the shape of the surface

| measurement | value |
| --- | --- |
| registered maps in the mirror | **14** (matches `sections_checked == 14`) |
| fields across all 14 maps | **68** |
| fields whose mirror `notes` is non-empty | **61** |
| `.md` rows matched to a mirror field by (section, key) | **68 of 68** — no orphan on either side |

So Q131's *"fourteen maps' worth"* is right about maps and silent about the
unit that matters: the comparison unit is the **key**, and there are **68** of
them.

### 1.3 The two cells are not the same field — 66 of 68 differ

Comparing `.md` `cells[4]` against mirror `notes` verbatim, key by key:

| | count |
| --- | --- |
| pairs compared | 68 |
| **literally different** | **66** |
| identical | 2 |

The 66 are not 66 defects. They are 66 instances of a **structural**
mismatch, in three recurring shapes:

1. **The `.md` cell holds a length where the mirror holds nothing.** At
   registry §7.2 key 2, §7.3 keys 0/1/2/5, §7.5 key 4 and others — twelve
   scalar keys — the `.md` cell is the bare string `32` or `16` and the
   mirror's `notes` is `""`, because the mirror carries the number in its own
   `length` field. Comparing these two cells compares a number to an empty
   string.
2. **The `.md` cell holds a section pointer where the mirror holds a type
   name.** registry §7.3 key 4: `.md` `§7.4`, mirror `canon_descriptor`.
   registry §7.4 key 0: `.md` `` `descriptor_kind` (§6.3) ``, mirror
   `enum descriptor_kind`.
3. **The mirror's `notes` is a long-form rationale and the `.md`'s is a
   gloss.** registry §7.2 key 3 (`title`): the `.md` cell is 125 characters,
   the mirror's `notes` is 566 and carries the D8 §2 derivation, the
   foreclosure argument and the disclosure warning. The `.md` states the
   fact; the mirror states the fact and why it was decided.

None of these is drift. All three are the two surfaces doing **different
jobs** — which is precisely why no equality and no substring relation holds
between them.

### 1.4 Q131's proposed vocabulary, measured term by term

Symmetric term-presence over the 68 pairs, emphasis-stripped and
case-insensitive (`cells[4]` against mirror `notes`):

| term | md-only | json-only | both | neither | verdict |
| --- | --- | --- | --- | --- | --- |
| `UNANCHORED` | 0 | 0 | **1** | 67 | **green at the only site it exists** — certifies nothing |
| `reserved` | 1 | 1 | 1 | 65 | **2 red**, both editorial |
| `may be empty` | 0 | 0 | 2 | 66 | green, but see below — the mirror has **8** |
| `[P]` | **10** | 0 | 0 | 58 | **10 red** |
| `[X]` | **6** | 0 | 1 | 61 | **6 red** |
| `[R]` | **9** | 0 | 0 | 59 | **9 red** |

**Every one of the six terms fails, and for four distinct reasons.**

**`UNANCHORED` — the decisive one.** It occurs in the prose of both surfaces
at registry §7.6 key 3 and nowhere else in either. A rule *"if present in one,
must be present in the other"* is therefore **satisfied at every one of the 68
keys, today and after any wording drift that keeps the word**. The measured
divergence at that key is that the mirror **drops the `**` emphasis** and
**adds the clause** *"Anchor kind is positional — this key IS the OTS kind"*.
Neither is a term event. **Q131's proposed check does not detect Q131's
motivating instance.** That single fact is enough to refuse it.

**The tier letters — 25 occurrences, all one-directional.** The `.md` tags
tiers inline at registry §7.3 key 6, §7.6 keys 6–9, §7.8 key 3, §7.11 keys
0–4, §7.12 keys 0–3, §7.13 keys 0/2 and §7.14 keys 0–2. The mirror's `notes`
carries a tier letter at **one** site. This is not drift: the mirror does not
put tiers in prose because **it has a `tier` field** (§1.6). A symmetric prose
check reddens 25 times for a fact the mirror states better elsewhere.

**`may be empty` — the vocabulary is in the wrong cell.** Two prose hits, but
the mirror carries `rule: "may be empty"` at **8** keys, and the `.md`
expresses the same fact in its **presence** cell as `req, may be empty` — also
8, also exactly those 8 (§1.6). Hunting for the phrase in `cells[4]` misses
the place both surfaces actually state it.

**`reserved` — already pinned, twice over.** The two divergent sites are
registry §7.14 key 1, where the `.md` speculates that *"a future `raw_salt`
would take a reserved slot of this map"*, and registry §7.10 key 2, where the
mirror notes that v1.1 content is *"promoted into reserved key 3"*. Both are
editorial cross-references. The **format fact** about reserved slots and bands
is already asserted in both directions by
`the_document_map_tables_match_the_mirror` (`doc_named`/`mirror_named`,
`doc_bands`/`mirror_bands`). Adding a prose term would double-count a pinned
fact and redden on commentary.

**Aggregate: the proposed check is red at ~30 of 68 keys on a clean tree and
green on the one case it was built for.**

### 1.5 `622f5fe` §1, read in full — it says what Q131 quotes, and it is narrower than Q131 assumes

`git show 622f5fe` §1, verbatim:

> *"**§14 overstated one assertion.** It said "§2's fixed-length table matches
> `scalars[]`"; what the freeze test asserts is the **set of lengths**, both
> directions. §2 groups fields by byte length and names them in prose while
> `scalars[]` names them by role with synthetic keys (`salt16`, `commit32`,
> `hash32`), so the two are not row-comparable and a substring match on the
> prose would pin editorial wording rather than format facts."*

Q131's quotation is **accurate**. But the argument's structure is conditional,
and Q131 treats it as absolute:

- The ruling's premise is *"the two are **not row-comparable**"* — §2 keys by
  length, `scalars[]` keys by role. The substring conclusion **follows from
  that premise**; it is not an independent axiom against reading prose.
- The narrowing is restated at `format_registry_freeze.rs:2001–2009`, which
  gives the concrete failure mode: *"it fails on 'every GGM cover seed' vs
  `seed32`'s 'GGM cover seeds' while catching nothing real."* That is a
  **wording** collision between two differently-keyed tables.

**So a closed-vocabulary form does not escape it — it renames it.** §1.4
measures the same failure at a larger scale: `[P]` in the `.md` against no
`[P]` in the mirror's `notes` is exactly *"every GGM cover seed" vs "GGM cover
seeds"*, 25 times over. Q131's hope that closing the vocabulary escapes
`622f5fe` §1 is **disproved by measurement**, not by argument.

**What *does* escape it** is finding a pair of cells that **are** row-
comparable. §1.6 finds four.

### 1.6 What the mirror actually carries — four structured fields, none of them pinned

`maps[].fields[]` has these keys:

```
key, name, type, presence, rule, length, tier, status, notes
```

`key`, `name` and `status` are pinned. `length` is pinned via `scalars[]`.
**`type`, `presence`, `rule` and `tier` are pinned by nothing** —
`grep -rn '"tier"' crates/ --include=*.rs` returns **zero hits**, as does the
same grep for `"rule"` inside `format_registry_freeze.rs`. And D108 §3.1 C1
names all four as format surface, in its own words: *"No key, **type**,
**presence**, **rule**, length, **tier**, status, enum value, cap, error code
or reserved slot."*

Measured against the `.md`'s own columns:

| relation | measured | result |
| --- | --- | --- |
| `.md` `cells[2]` (unticked) vs mirror `type` | 68 pairs | **68/68 identical, 0 mismatches** |
| `.md` `cells[3]` normalised vs mirror `presence` | 68 pairs | **58 `req`→`required`, 10 `opt`→`optional`, 0 mismatches** |
| `.md` `cells[3]` contains `may be empty` ⟺ mirror `rule == "may be empty"` | 68 pairs | **8 vs 8, symmetric difference EMPTY** |
| mirror `tier` ∈ `.md` `cells[4]`'s `[PXR]` tags, where both present | 19 pairs | **19/19 contained, 0 violations** |

The `type` vocabulary is closed at five values — `bstr` (25), `uint` (20),
`array` (14), `map` (5), `tstr` (4). The presence vocabulary is closed at two.

**These are row-comparable, they are format facts, and they are green today.**
That is the instrument Q131 was reaching for and did not find, because it
looked for the terms in the mirror's *prose* instead of in its *fields*.

### 1.7 The tier relation is containment, not equality — and that is a fact about the surfaces

Naive equality between the `.md`'s tier tags and the mirror's `tier` field
**mismatches at 27 of 68**, and every mismatch has one of three benign causes:

1. **The `.md` annotates selectively; the mirror annotates exhaustively.** 21
   keys have no `[PXR]` tag in the `.md` and a `tier` in the mirror. The `.md`
   tags a tier where it is load-bearing or surprising.
2. **The `.md`'s tags are per-clause; the mirror's `tier` is per-field.** At
   registry §7.11 key 3 the cell carries `[P]`, `[R]` **and** `[X]` because
   the cell discusses three conditions; the mirror's `tier` is `P`. Different
   granularity — `622f5fe` §1's non-row-comparability, again.
3. **One mirror field puts its tier in the wrong slot.** At registry §7.3 key
   6 the `.md` says `[P]` and the mirror's `tier` is **null**, while its
   `rule` carries the literal string `at least one kind=normal unit [P] (D77)`.
   The tier letter is present, in the neighbouring field. Recorded at §9 —
   it is a mirror-internal inconsistency, in a frozen file, and not this
   lane's to touch.

Under **containment** — *where the `.md` tags any tier and the mirror declares
one, the mirror's tier must be among the `.md`'s tags* — the relation holds at
**19 of 19**. That is the true statement, and the true statement is the one
that gets asserted.

---

## 2. The options, and what kills each

### (a) Q131's symmetric closed-vocabulary prose check, as written — the lean

**Killed twice over by §1.4.** It is **green at registry §7.6 key 3**, its own
motivating instance, because `UNANCHORED` is present on both sides; and it is
**red at ~30 keys** that hold no defect. Zero recall on the target, ~30 false
positives. There is no threshold or ordering of the six terms that fixes both.

### (b) The same check, one-directional (`.md` ⇒ `.json` only)

**Killed by direction.** The 25 tier occurrences are **all** md-only, so the
`.md`⇒`.json` direction is the *worst* one: it reddens 25 times immediately.
The reverse direction (`.json`⇒`.md`) is green today but asserts almost
nothing — the mirror's prose carries `UNANCHORED` once, `reserved` once and no
tier letters at all, so a mirror-side vocabulary is 2 terms over 68 keys. It
would pass forever.

### (c) Narrow the vocabulary to what is green today — `UNANCHORED` and `may be empty` only

**Killed by vacuity, and it is the trap the brief names.** `UNANCHORED` is
green because it is present on both sides at one key; `may be empty` in prose
is green at 2 keys. A three-key check over 68 that cannot fail on any
plausible drift is a test that certifies nothing while reading as coverage.
Worse: it would be **red-proof against its own motivating divergence**, so
landing it would close Q131 with a green test and an untouched defect.

### (d) Full equality between `cells[4]` and `notes`

**Killed by §1.3.** 66 of 68 differ, twelve of them comparing a bare `32` to
`""`. It would require rewriting the mirror's prose to match the document's —
a **byte change to two frozen files**, which is D108 §3.1's C3 tag event, and
the brief forbids proposing it.

### (e) A registered erratum-style exemption pinning the current divergences

**Killed as unnecessary, on measurement.** This was the brief's contingency
*if* the check went red on the current tree. §1.6 measures that the ruled
check is **green at 68/68, 68/68, 8=8 and 19/19**, so there is nothing to
exempt. Manufacturing an exemption for a green check would install a
permanent allow-list that future real divergences could hide inside.

### (f) Refuse and record, with nothing landing — the bare refusal

**Killed by the brief's own standard, and correctly:** *"a refusal that does
not say what detects the next divergence is not a ruling, it is a shrug."*
§1.6 shows something real is available; refusing to land it would leave four
format-surface fields — `type`, `presence`, `rule`, `tier` — pinned by nothing
but a SHA-256.

### (g) Refuse the prose check on the record; land the four mechanical checks — **the ruling**

Takes Q131's Accept clause 2 for the prose half (the D-family records why a
prose cross-check must not exist, carrying `622f5fe` §1) **and** discharges
its spirit with an instrument that actually reddens on drift. §3.

---

## 3. Ruling

### 3.1 The principle: what makes a document⟷mirror comparison assertable

**A cell of the document may be compared to the mirror when, and only when,
the two sides are keyed the same way.** `622f5fe` §1 is the statement of this
rule, not an exception to it: §2 keys by length and `scalars[]` keys by role,
so the comparison was narrowed to the one thing both key on — the set of
lengths. The same test applied here:

- `cells[2]` ⟷ `type`: both keyed by (map, key), both a closed 5-value
  vocabulary. **Comparable.**
- `cells[3]` ⟷ `presence`: both keyed by (map, key), both a closed 2-value
  vocabulary after a **stated, total** normalisation. **Comparable.**
- `cells[3]`'s emptiness clause ⟷ `rule`: both keyed by (map, key), one exact
  string. **Comparable, as set equality.**
- `cells[4]`'s tier tags ⟷ `tier`: keyed the same, but **per-clause against
  per-field**. **Comparable only as containment**, and that is what is
  asserted.
- `cells[4]` prose ⟷ `notes` prose: keyed the same, but the `.md` cell merges
  length+shape+tier+condition+gloss while the mirror splits them across five
  fields. **Not comparable.** This is `622f5fe` §1's case, and it is refused.

### 3.2 RULING

> **RULING**
>
> **1. The prose⟷prose cross-check is REFUSED, permanently, and the refusal is
> recorded at the D-family.** No test in this project may compare
> `registry-v1.md`'s `len/shape` cells to `registry-v1.json`'s `notes` fields
> — not as equality, not as substring, and **not as a closed vocabulary**.
> Q131's Accept clause 2 is taken. The verbatim comment block is R1.
>
> **2. Four mechanical document⟷mirror checks land in the D-family**, over the
> **same 68 (map, key) pairs** the existing `the_document_map_tables_match_the_mirror`
> already walks: **type** (R2), **presence** (R3), **the may-be-empty rule**
> (R4), **tier containment** (R5).
>
> **3. All four are GREEN on the tree at `5fbc48d`** — measured 68/68, 68/68,
> 8=8, 19/19. They land as plain green tests.
>
> **4. NO frozen byte moves.** `registry-v1.md`, `registry-v1.json` and
> `FROZEN.sha256` are untouched; `format-v1-freeze` is unmoved; no erratum
> entry is added; no re-bless, no tag event. D108 §3.1's C1–C3 are never
> reached, because nothing in the frozen files is edited.
>
> **5. The closed vocabularies are the mechanical ones, enumerated literally
> at R2–R5**, not the prose ones Q131 proposed. Each of Q131's six terms is
> refused with its measurement at §1.4.

### 3.3 Why this is not the thing `622f5fe` §1 forbids

`622f5fe` §1 forbids *"a substring match on the prose"* between two
differently-keyed tables. R2–R5 perform **no substring match on prose**:

- R2 and R3 compare **closed enumerations** — 5 values and 2 values — between
  identically-keyed rows.
- R4 compares **set membership** of a single exact rule string, keyed by
  (map, key), in both directions.
- R5 is the only one that reads `cells[4]`, and it reads **only** the regular
  expression `\[([PXR])\]` from it — three literal bracket tokens, never the
  surrounding words. Rewrite every word of that cell and R5 does not move.

The control arm at §6 proves this rather than asserting it: rewriting the
prose of registry §7.6 key 3 must leave all four green.

---

## 4. Riders — normative, cite by number

### R1 — The refusal comment block, verbatim

Lands in `crates/antseal-core/tests/format_registry_freeze.rs`, immediately
after `the_document_map_tables_match_the_mirror` ends and before R2's test.
**Verbatim, no paraphrase:**

```rust
// ---------------------------------------------------------------------------
// D — why the two surfaces' PROSE is compared to nothing, and what is
//     compared instead (D111; Q131's Accept clause 2)
// ---------------------------------------------------------------------------
//
// `registry-v1.md`'s `len/shape` cell (`cells[4]`) and `registry-v1.json`'s
// `notes` field state overlapping facts in independent words, and **nothing
// in this project compares them, in either direction, by design**.
//
// `622f5fe` §1 ruled the naive form out and the ruling stands:
//
//     "§2 groups fields by byte length and names them in prose while
//      `scalars[]` names them by role with synthetic keys (`salt16`,
//      `commit32`, `hash32`), so the two are not row-comparable and a
//      substring match on the prose would pin editorial wording rather
//      than format facts."
//
// D111 measured whether a CLOSED VOCABULARY escapes that ruling. It does
// not — it renames it. Over the 68 (map, key) pairs, symmetric and
// emphasis-stripped:
//
//   * `UNANCHORED` occurs in BOTH surfaces' prose at registry §7.6 key 3
//     and nowhere else in either, so a term-presence rule is satisfied at
//     all 68 keys by construction — INCLUDING at the one key whose two
//     copies actually diverge. The check is green on its own motivating
//     case.
//   * the tier letters `[P]`/`[X]`/`[R]` are md-only at 25 occurrences,
//     because the mirror does not put tiers in prose: it has a `tier`
//     field. A symmetric check reddens 25 times for zero defects.
//   * `may be empty` appears in the mirror's `rule` field at 8 keys and in
//     the `.md`'s PRESENCE cell at the same 8 — not in `cells[4]` at all.
//   * `reserved` splits 1/1 on editorial cross-references, while the
//     reserved FACT is already pinned both ways by
//     `the_document_map_tables_match_the_mirror`.
//
// Root cause: the two cells are not the same field. The `.md` cell merges
// byte length, shape pointer, tier tags, conditions and gloss; the mirror
// splits those across `length`, `type`, `rule`, `tier` and `notes`. 66 of
// 68 pairs differ literally, and at 12 scalar keys the `.md` cell is a bare
// `32`/`16` against an EMPTY `notes`. Not comparable.
//
// WHAT COVERS THE GAP INSTEAD — this is the operative half of the refusal:
//
//   1. The four assertions below pin the mirror's `type`, `presence`,
//      `rule` and `tier` against the document's own columns. D108 §3.1 C1
//      names all four as format surface, and before D111 NOTHING in
//      `crates/` read `tier` or `rule` at all.
//   2. `format_freeze.rs`'s `every_erratum_quotes_its_frozen_sentence_verbatim`
//      (D108 R4) pins the full text of any prose sentence known to be
//      over-read — BOTH copies of registry §7.6 key 3's sentence are
//      entries there today, byte-for-byte, one per surface.
//   3. `FROZEN.sha256` covers every remaining prose byte. D108 §3.2: the
//      prose is the ONLY content the digest alone covers, which is an
//      argument for the digest and not against it.
//
// Do not add a prose comparison here. If a future divergence matters, it
// is an erratum entry (2) or a registry-version event, never a substring
// match.
```

### R2 — `the_document_type_column_matches_the_mirror`

**Closed vocabulary (5, literal):** `bstr`, `uint`, `tstr`, `array`, `map`.

| term | why load-bearing | why the list closes here |
| --- | --- | --- |
| `bstr` | the CBOR major type a decoder branches on; 25 keys | |
| `uint` | ditto; 20 keys | |
| `tstr` | ditto; 4 keys | |
| `array` | ditto; 14 keys | |
| `map` | ditto; 5 keys | the registry is **frozen**, so the set of types across all 68 keys is format-permanent; a sixth spelling is a format-version event, and the assertion should catch it |

**Semantics.** Per (map, key), for all 68 pairs.
`unticked(cells[2]).trim()` must **equal** `fields[].type`, byte-for-byte.
**Case-sensitive.** **No emphasis stripping** — a `**bstr**` in either surface
must fail, because the type column is data and carries no emphasis today.
**Symmetric by construction**: the pairing is (map, key), and a key present in
one surface and absent from the other is already a hard failure of
`the_document_map_tables_match_the_mirror`, which compares the full
`(key, name)` vectors; R2 additionally panics with the (map, key) named if
its lookup misses, so it can never silently skip a pair.
**Anti-vacuity:** assert `pairs_compared == 68`, **and** assert the observed
type multiset is exactly `{bstr:25, uint:20, array:14, map:5, tstr:4}`.

### R3 — `the_document_presence_column_matches_the_mirror`

**Closed vocabulary (2, literal):** `required`, `optional`.

| term | why load-bearing | why closed |
| --- | --- | --- |
| `required` | a decoder rejects a manifest/bundle missing it; 58 keys | the mirror's `presence` takes no third value across all 68 keys, and the registry is frozen |
| `optional` | absence is legal; 10 keys | |

**Semantics.** Per (map, key), for all 68 pairs. Normalise the `.md` cell:
strip `**` and `*` and backticks, `trim`, `to_lowercase`. Then:

- begins with `req` ⇒ canonical `required`
- begins with `opt` ⇒ canonical `optional`
- **anything else is a hard panic naming (map, key) and the raw cell** — the
  normalisation is total or the test fails; there is no silent skip.

The canonical value must equal `fields[].presence`. **Case-insensitive on the
`.md` side only** (the lowercase is part of the stated normalisation); the
mirror side is compared **case-sensitively** against the two literals.
Emphasis **is** stripped here, because the `.md` genuinely writes
`**opt — biconditional, [R]: …**`.
**Anti-vacuity:** assert `required_seen == 58` **and** `optional_seen == 10`
**and** their sum `== 68`. Two independent floors, so a normalisation bug that
collapses every cell to one branch reddens.

### R4 — `the_document_may_be_empty_rule_matches_the_mirror`

**Closed vocabulary (1, literal):** `may be empty`.

Load-bearing because it is the difference between *"a bundle with no anchors
is UNANCHORED"* and *"a bundle with no anchors is a parse error"* — registry
§7.6 keys 3/4 and 6–9 turn on it, and it is the one term of Q131's six that
survives measurement. The list closes at one because it is the only value of
`rule` that recurs as a bare closed phrase; every other `rule` value is a
per-key condition or a prose rationale (measured: `upgrade_group` ×3, six
distinct `present iff …` conditions, and two multi-sentence D75/D8 rationales),
none of which is a vocabulary.

**Semantics.** Build two sets of (map, key):

- `from_document` = pairs whose **normalised presence cell** (R3's exact
  normalisation) **contains** the substring `may be empty`.
- `from_mirror` = pairs whose `fields[].rule`, trimmed and lowercased, **equals**
  `may be empty` exactly.

Assert `from_document == from_mirror` — **set equality, symmetric**, so a
drop on either side reddens and the failure message prints both
one-sided differences by (map, key).
**Anti-vacuity:** assert `from_document.len() == 8`.

### R5 — `the_document_tier_tags_are_consistent_with_the_mirror`

**Closed vocabulary (3, literal):** `P`, `X`, `R` — matched only inside square
brackets, as `[P]`, `[X]`, `[R]`.

| term | why load-bearing | why closed |
| --- | --- | --- |
| `P` | D78's tier discipline: decidable from the one entry being decoded | `validation_tiers.tiers[]` in the mirror declares exactly these three, and it is frozen |
| `X` | decidable from the whole container | |
| `R` | post-decode, needs bundle+manifest or crypto | |

**Semantics.** Per (map, key), for all 68 pairs:

- `md_tags` = the set of letters matched by `\[([PXR])\]` over the **raw**
  `cells[4]`. No emphasis stripping (the tags are literal), **case-sensitive**
  — a lowercase `[p]` is not a tier tag and must not satisfy this check.
- **A bare `P` in either surface never satisfies `[P]`.** The brackets are
  required on the `.md` side; the mirror side is the bare `tier` field and is
  compared as an exact one-character string.
- If `md_tags` is non-empty **and** `fields[].tier` is a string: assert
  `md_tags.contains(tier)`. **One-directional containment, deliberately** —
  §1.7 measures that the `.md` tags per clause and the mirror per field, so
  equality is false at 27 sites for three benign reasons, and containment is
  the true statement.
- If `md_tags` is empty, or `tier` is null: **no assertion**, and the pair is
  counted into `skipped`.

**Anti-vacuity — this rider needs it most, since it is the only guarded one:**
assert `both_present == 19` exactly (not `> 0`). A regex that stops matching,
a mirror that nulls its tiers, or a document whose tags are reformatted all
drive this count off 19 and redden **even though every surviving comparison
passes**. Additionally assert `both_present + skipped == 68`.

The one `.md`-tags-with-null-`tier` pair (registry §7.3 key 6) falls into
`skipped` by the guard; §9 records why.

### R6 — Placement and shared helper

All four tests sit **contiguously**, in the order R2, R3, R4, R5, immediately
after `the_document_map_tables_match_the_mirror` (which currently ends at
`format_registry_freeze.rs:1883`) and immediately before the doc comment of
`the_document_enum_tables_match_the_mirror` (currently `:1885`). R1's comment
block precedes R2.

They share one private helper, added just above R1:

```rust
/// Every (map, key) pair of §7.x, as (map name, doc row cells, mirror field).
/// Panics naming the pair if a documented key has no mirror field or the
/// reverse — a silent skip is the one failure mode these assertions cannot
/// tolerate.
fn map_rows_against_the_mirror(doc: &str, root: &Value)
    -> Vec<(String, u64, Vec<&str>, &Value)>
```

It reuses the existing `table_under`, `table_row`, `unticked`, `map_entry` and
`get_*` helpers unchanged, and uses the mirror's own `doc_section` pointer to
locate each table — the same discipline
`the_document_map_tables_match_the_mirror`'s doc comment already states, so no
fifteenth copy of the map⟷section mapping is introduced.
**No existing test is modified.** In particular
`the_document_map_tables_match_the_mirror` keeps its `cells.len() == 5`
assertion and its indices 0/1/3; R2–R5 are additive.

---

## 5. Edit set

| file | change |
| --- | --- |
| `crates/antseal-core/tests/format_registry_freeze.rs` | R1's comment block, R6's helper, R2–R5's four tests, inserted at R6's position. **Nothing else in the file is touched.** |
| `crates/antseal-core/tests/format_registry_freeze.rs` module docs (§ "D — document ⟷ mirror", currently `:1725-1733`) | append one sentence naming the four new assertions and pointing at R1's block for the prose refusal |
| `docs/format/registry-v1.md` | **untouched** |
| `docs/format/registry-v1.json` | **untouched** |
| `docs/format/FROZEN.sha256` | **untouched** |
| `docs/format/frozen-registry-errata.md` | **untouched** — no entry is added; §2(e) |
| `TODO.md`, `tasks/Q.md` | orchestrator's, at bookkeeping |

Expected suite count: `format_registry_freeze` **24 → 28**.

---

## 6. Instruments — planted-fault arms

Every arm is a **transient working-tree perturbation**, run and reverted, never
committed — the same method D108 R4's erratum pin was shown red by. **Post-
condition for the whole set, asserted before the lane's commit:**
`git diff --exit-code -- docs/format/` must be clean, and
`scripts/format-freeze.sh --check` must be green.

| # | arm | perturbation | must redden |
| --- | --- | --- | --- |
| 1 | R2 positive | in the working copy of `registry-v1.md`, registry §7.1 key 0's **type** cell `bstr` → `uint` | `the_document_type_column_matches_the_mirror` **only** |
| 2 | R2 positive, mirror side | in the working copy of `registry-v1.json`, `maps[manifest_envelope].fields[0].type` → `"tstr"` | R2 only |
| 3 | R3 positive | registry §7.6 key 5's presence cell, replace the leading `**opt` with `req` | `the_document_presence_column_matches_the_mirror` **only** |
| 4 | R3 normalisation totality | registry §7.1 key 0's presence cell `req` → `mandatory` | R3, with the panic naming (map, key) and the raw cell — **not** a silent pass |
| 5 | R4 positive, document side | delete `, may be empty` from registry §7.6 key 4's presence cell | `the_document_may_be_empty_rule_matches_the_mirror`, reporting the one-sided (bundle, 4) |
| 6 | R4 positive, mirror side | set `maps[bundle].fields[4].rule` to `null` | R4, reporting the opposite one-sided difference — proves the symmetry |
| 7 | R5 positive | set `maps[full_reveal].fields[0].tier` from `"R"` to `"P"` while the `.md` cell still carries `[R]`/`[X]` | `the_document_tier_tags_are_consistent_with_the_mirror` |
| 8 | R5 anti-vacuity | null **one** `tier` that is currently in a both-present pair (e.g. `maps[covered_reveal].fields[0]`) — every surviving containment still passes | R5, on `both_present == 19` → 18. **This is the arm that proves the guard cannot go vacuous.** |
| 9 | R2 anti-vacuity | delete one §7.x table row from the working `.md` | R2 on `pairs_compared == 68`, **and** `the_document_map_tables_match_the_mirror` |
| **C1** | **control — the load-bearing one** | rewrite registry §7.6 key 3's `len/shape` **prose**: drop the `**` around `both`, and append `; anchor kind is positional`, changing no `\|`, no bracket tag and no other cell | **all four stay GREEN**, and so do the existing 24. This is the arm that demonstrates R2–R5 pin format facts and not editorial wording — `622f5fe` §1's concern, shown rather than asserted. |
| **C2** | control — mirror prose | append a sentence to `maps[bundle].fields[3].notes` | all 28 green |

Arms C1 and C2 are **required**, not optional: without them the lane has not
shown that its refusal of the prose check and its acceptance of the mechanical
one are the same judgement applied consistently.

**Note for the implementing lane:** C1 perturbs a sentence that
`format_freeze.rs`'s `every_erratum_quotes_its_frozen_sentence_verbatim`
quotes. That test will go red under C1 — **expected, and itself a useful
confirmation** that D108 R4's pin covers this exact sentence. Run C1 against
`--test format_registry_freeze` and record `format_freeze`'s red separately.

---

## 7. Frozen bytes — the explicit answer

**No frozen byte moves, and none needs to.** The brief's contingency —
*"if your check would go red on the tree as it stands … it cannot be landed as
a plain red"* — **does not arise**, and the reason is the ruling's central
finding:

> Q131 assumed a red because it assumed the comparison had to be prose⟷prose.
> The prose surfaces do diverge. The **structured** fields do not: 68/68 on
> type, 68/68 on presence, 8=8 on the emptiness rule, 19/19 on tier
> containment.

Consequently:

- **D108 §3.1's C1/C2/C3 are never tested**, because nothing in a frozen file
  is edited. There is no re-bless, no `#! status frozen` → `pre-freeze` flip,
  and `format-v1-freeze` (`d3345e1`) is unmoved.
- **No erratum entry is added.** §2(e): an exemption for a green check is an
  allow-list that a future real divergence could hide inside.
- The known §7.6 key 3 divergence stays where D108 R4 put it — two erratum
  entries, one per surface, each pinned verbatim to its frozen bytes, both
  queued for the next registry version.
- `format_registry_freeze.rs` is **not** a frozen entry (`FROZEN.sha256` pins
  `registry-v1.json` and `registry-v1.md` only), so adding tests to it is a
  free act.

---

## 8. What this does not do

1. **It does not compare the two prose surfaces**, and forbids doing so. R1
   records why, so the next lane does not re-derive it.
2. **It does not correct registry §7.3 key 6's misplaced tier** (tier letter in
   `rule`, `tier` null). Frozen. §9(i).
3. **It does not assert that the `.md` tags every tier the mirror declares.**
   21 keys are un-tagged in the `.md` by editorial choice; forcing them would
   require editing frozen bytes.
4. **It does not pin the mirror's `notes` field at all**, nor the `.md`'s
   `len/shape` prose, beyond the `[PXR]` tokens R5 reads. Those bytes remain
   covered by `FROZEN.sha256` and, where known to be over-read, by D108 R4's
   errata — which is the arrangement D108 §3.2 argues for.
5. **It does not touch `the_document_map_tables_match_the_mirror`**, including
   its `cells.len() == 5` assertion.
6. **It adds no vector, no fixture, no golden file and no new pin family.**

---

## 9. Discovered work — described, not numbered

*(The wave owner allocates and registers. No IDs are minted here.)*

**(i) The mirror puts one field's tier in the wrong field, and it is frozen.**
— M2 · XS · deps: F4, D111. At registry §7.3 key 6 (`units`),
`maps[file_entry].fields[6].tier` is **null** while the same object's `rule`
carries the literal string `at least one kind=normal unit [P] (D77)` — the
tier letter is present, in the neighbouring field. The `.md` states `[P]` in
its `len/shape` cell. It is the **only** pair in all 68 where the document tags
a tier and the mirror declares none, so R5's guard skips it and the
inconsistency survives. Both surfaces are frozen, so this is an erratum-or-
registry-v2 item on D108 §3.1's ladder, not an edit. Accept: either an errata
entry recording that this key's tier is `P` and lives in `rule`, or a recorded
finding that it is below the erratum bar.

**(ii) The D-family drops three more document columns than Q131 noticed.**
— M2 · S · deps: D111. Beyond `cells[2]` (closed by R2 here), the following
document columns reach no assertion: §6.2's `pubkey`, `signature` and `notes`
columns; §2's `fields` and `source` columns; §11's `applies to` column. §6.2's
`pubkey`/`signature` are the most interesting — they are **byte lengths per
signature algorithm**, a format fact of the same class R2 just closed, and
`code_sig_alg_mappings_match_the_registry_on_both_copies` pins the code
against the mirror without ever reading the document's own numbers. Accept:
each column is either asserted or named as a recorded non-assertion in the
D-family's header comment, per D8 §14's discipline that a non-assertion must
be named.

**(iii) `FROZEN.sha256`'s own bytes are pinned by nothing.** — M2 · S · deps:
Q14, Q27. Re-confirming D108 §1.4's table row from this lane's own grep over
`crates/`, `scripts/` and `.github/`: the manifest that pins the registry is
itself unpinned, so a hand-edited digest line plus a matching document edit
passes the whole suite. D108 recorded it in a table cell and it was not carried
into a row. Accept: either the manifest is pinned by something outside itself
(a tag, a signature, or a CI assertion against `format-v1-freeze`), or the
gap is recorded where a lane reaching for `--update` will meet it.

---

## Outcome

**RESOLVED, 2026-08-10.** Q131's Accept clause 2 is taken for the prose half —
the D-family records, in R1's verbatim block, why a prose cross-check must not
exist, carrying `622f5fe` §1's argument and naming the three mechanisms that
cover the gap instead. The lean is refused on **measurement**: the proposed
closed-vocabulary check is **green at registry §7.6 key 3**, the very
divergence that motivated Q131, because `UNANCHORED` is present in both
surfaces there; and it is **red at ~30 of 68 keys** that hold no defect,
because the tier letters are md-only at 25 occurrences and `may be empty`
lives in the `.md`'s presence cell rather than its prose cell. `622f5fe` §1
does say what Q131 quotes, and the closed-vocabulary form **does not escape it
— it renames it**: `[P]` against no `[P]` is *"every GGM cover seed" vs "GGM
cover seeds"*, 25 times over.

What the re-measurement found instead is that Q131 looked for its terms in the
mirror's **prose** when three of the four are **structured fields** — `type`,
`presence`, `rule` and `tier` — that **D108 §3.1 C1 names as format surface**
and that **nothing in `crates/` reads**. Compared against the document's own
columns they agree at **68/68**, **68/68**, **8 = 8** and **19/19**, so four
mechanical assertions land green, in the D-family's existing idiom, pinning
four format-surface fields that had only a SHA-256 behind them. Q131 also
understates its own gap: `cells[2]`, the **type** column, is read by no test
either and is not mentioned in the row.

**Zero frozen bytes move.** The brief's contingency for a red landing does not
arise, no erratum is added, and `format-v1-freeze` is unmoved — because the
prose diverges and the structure does not.

---

## Index row (orchestrator applies at merge)

`D111 — Q131: registry prose cross-check — RESOLVED 2026-08-10 — prose⟷prose closed-vocabulary check REFUSED (green at its own motivating instance, ~30 false positives); four mechanical checks land instead on type/presence/rule/tier, all green, zero frozen bytes moved.`

---

## Amendments — found by the implementing lane, 2026-08-10

Recorded here rather than left in a task report, per the standing rule that a
correction only the implementer saw is a correction the next reader never sees.
The ruling and all four riders' **semantics** survive unchanged; what follows
corrects figures and mechanics. Three of these sat inside blocks this document
marked *"verbatim, no paraphrase"*, so they would have been frozen into the
tree as source comments.

**A1 — §1.3 and R1: "twelve scalar keys" is five, and §1.3 contradicts §1.2.**
Measured: only **6** cells are a bare `32`/`16`, and only **5** of those face an
empty `notes`. Only **7** pairs have an empty `notes` at all — which is §1.2's
own figure (68 − 61 = 7), so §1.3 contradicted §1.2 within this document. §1.3's
enumeration lists six items and calls them twelve, and registry §7.5 key 4's
`notes` is not empty. The landed comment reads **"at 5 scalar keys"**.

**A2 — R1: "`may be empty` … not in `cells[4]` at all" is false**, and it
contradicts §1.4's own table, which records that phrase as `both: 2`. It is in
`cells[4]` at **2** keys (registry §7.2 keys 1 and 3). The landed comment reads
**"but in `cells[4]` at only 2, so hunting the phrase in the prose cell misses
three quarters of the sites"** — which preserves the argument and strengthens it.

**A3 — R1/§1.4: `25` is right, `occurrences` is the wrong unit.** Raw `[PXR]`
occurrences in `cells[4]` = **27**; distinct keys carrying at least one tag =
**20**; **25** is the sum of the per-letter md-only *key* counts (P:10, X:6,
R:9). The landed comment reads **"md-only at 25 of the (key, letter) pairs"**.
§1.4's per-letter table itself is exactly right.

**A4 — R6's helper signature does not compile.** As written it returns a
borrowed type from two input lifetimes (E0106, *missing lifetime specifier*),
and its doc comment describes a 3-tuple against a 4-tuple signature. The
4-tuple also cannot carry `doc_section`, which this project's citation
discipline requires in every failure message. Landed instead: a borrowed struct
`MapRow<'a> { map, section, key, cells, field }` returned as `Vec<MapRow<'a>>`
— the file's existing idiom (`CapRow<'a>` at `registry_caps`) — which compiles
and lets every failure cite `registry §7.6 key 3` **by section**.

**A5 — R5 specifies a regex and this workspace has no regex crate.** `regex` is
a dependency of neither `antseal-core` nor the workspace. Landed instead:
`tier_tags` as three literal token `contains` checks, verified set-equivalent
to `\[([PXR])\]` against a real regex run (identical 19 both-present / 49
skipped / 0 violations).

**A6 — §6's post-condition cites a flag that does not exist.**
`scripts/format-freeze.sh` accepts only `[--self-test | --update]` and exits 2
on `--check`. **The bare invocation is the check**; it reports
`format-freeze: GREEN`.

**A7 — §6 arm 9's stated failure mode is unreachable, and the shape is
general.** Arm 9 (delete one §7.x table row from the working `.md`) claims to
redden R2 on `pairs_compared == 68`. It cannot: R6 *mandates* that the helper
panic when a mirror field has no document row, so the panic fires first and the
count assertion is never reached — observed reddening **all four** new tests
plus `the_document_map_tables_match_the_mirror`, not R2 alone. **Arm 9b** was
added and is the arm that actually exercises the anti-vacuity floors: delete the
row from *both* surfaces together, whereupon all four count floors fire
independently (67/68, 57/58, 7/8, 67/68) while `the_document_map_tables_match_
the_mirror` stays **green**. The general lesson: a rider mandating a fail-fast
pairing panic and a rider planting an inconsistency to exercise a *count* are
mutually exclusive — the panic always wins — so count-floor arms must perturb
both surfaces together.

**A8 — §5's edit-set row 2 names two different places as one.** The banner
comment at `:1725-1733` and the `//!` module docs' `# D — document ⟷ mirror`
section are distinct, and only the latter *enumerates the D-family assertion
list by name*. Appending to the banner alone would have left that inventory
silently stale against D8 §14's discipline. Both were updated, both inside the
one authorised file.

**A9 — §6's literal post-condition `git diff --exit-code -- docs/format/` is
not achievable on a shared working tree** and was not this lane's to satisfy: a
concurrent A115/D110 lane was re-keying `docs/format/anchor-artifact-limits.md`
at the same time. The meaningful post-condition is the four frozen files
individually, and it holds — `registry-v1.md`, `registry-v1.json`,
`FROZEN.sha256` and `frozen-registry-errata.md` are byte-identical to HEAD.

**Confirmed rather than corrected.** Every assertion-critical figure reproduces
exactly: type **68/68** with multiset `{bstr:25, uint:20, array:14, map:5,
tstr:4}`; presence **58 required + 10 optional = 68** with zero unnormalisable
cells; `may be empty` **8 ⟺ 8** with an empty symmetric difference; tier
containment **19/19** with 19 + 49 = 68. Also 14 maps, 68 pairs, 61 non-empty
`notes`, 66 of 68 differing literally, and **zero** readers of `tier`/`rule` in
`crates/`. §9(i)'s misplaced tier at registry §7.3 key 6 is confirmed as the
**unique** such pair in all 68. The C1 control — rewriting registry §7.6 key 3's
prose — leaves all 28 green while reddening `format_freeze`'s erratum pin **and**
`format_freeze_pins_the_wire_registry` (this document's note named only the
first).
