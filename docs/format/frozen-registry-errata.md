# Frozen-registry errata — reading notes against text that cannot be edited

> **Owning task: Q129** (`tasks/Q.md`), milestone **M2**. **Source of truth:
> [`docs/decisions/D108-unanchored-in-frozen-registry-prose.md`](../decisions/D108-unanchored-in-frozen-registry-prose.md)**
> (RESOLVED 2026-08-09), rider **R4**; the maintainer's call on §8 is **option
> A — the frozen bytes are left untouched and this file lands instead**.
>
> **This file is not frozen and is not format surface.** Every entry in it is
> held to the frozen bytes it reads against by
> `crates/antseal-core/tests/format_freeze.rs`'s
> `every_erratum_quotes_its_frozen_sentence_verbatim`.

## 0. What an erratum is

> An erratum is a **reading note, never an amendment**. The frozen bytes
> govern the format; nothing here changes what a v1 decoder does, and no
> erratum may state, weaken or extend a rule. An entry says only: *this
> sentence, verbatim, in this frozen file, will be misread — as claiming
> more than it claims, or as claiming less — here is its scope.* Every
> entry is queued for correction in the next registry version and is
> deleted when that version lands.
>
> **Both directions, and the second is the easier one to miss.** The
> **over-read** case is a sentence that will be taken for a rule it does not
> state. The **under-read** case is a sentence whose rule is exactly right
> but whose *authority* is misattributed, so a reader who follows the
> citation lands somewhere weaker than the rule and may conclude the rule is
> weaker too. Neither direction lets an entry touch what the frozen bytes
> say: an erratum that shored a rule up would be an amendment. What an
> under-read note records is **where the rule's authority actually is** —
> and the rule stands at full strength on that authority whatever the frozen
> sentence cites.

A frozen document **cannot point at anything**. Every byte of
`registry-v1.md` and `registry-v1.json` is pinned by `FROZEN.sha256`, §14
included, so a sentence that will be over-read cannot carry its own
correction and no footnote can be added beside it. A correction is therefore
reachable only from outside, and the reachable-from-outside places are three:
the code, the decision record, and `ls docs/format/`. This file is the third,
and it is the only one of the three that a lane cutting the next registry
version passes without being told to.

**Why this file is named what it is.** Not `registry-v1-errata.md`.
`must_be_frozen` (`format_freeze.rs`) collects `registry-v<digits>.{md,json}`
only, so that name would not be **required** to be frozen — but the freeze
manifest's `EntryPolicy` (`required_name_prefix: "registry-v"`) would
**accept** it as an entry, so a later lane could freeze a reading note by
accident and make it exactly as unamendable as the text it annotates. A name
outside the prefix cannot enter the manifest at all: the parser rejects it
with a message naming the policy, which
`format_freeze_red_on_freezing_a_working_note` pins. Choose the name that
makes the mistake impossible rather than merely unlikely.

## 1. Entries

**Every `### ` heading in this file is an entry** — headings are not used for
anything else, and a fieldless one is a loud failure rather than a silent
non-entry. The gate reads three fields from each: `- file:` and `- quotes:`
as backtick spans, and `- scope:` as prose that must not be empty. Anything
else in an entry is free prose for the reader. `- queued for:` is prose and
nothing enforces it, because retirement is enforced from the other side: when
the sentence changes, the quotation stops matching and the gate goes red.

An entry **ends at the next heading of its level or above**, so its three
fields must sit inside its own section. Most of this file is deliberately
free prose — §2 below is a bulleted list — and without that boundary a
`- scope:` bullet written down here could retroactively complete an entry
that never gave one.

The quotation is compared **byte-for-byte against the frozen file**, so it is
the sentence as the file encodes it, not as a renderer displays it — markdown
emphasis markers included.

### registry-v1.md — §7.6 key 3 `ots_anchors`, the `len/shape` cell

- file: `registry-v1.md`
- quotes: `an UNANCHORED bundle is **both** anchor arrays empty`
- scope: **sense (d) of four** (D98 rider 3c, extended by D108 R2) — a true
  layer-1 statement about the **CBOR shape of a `.sealproof`**, at tier
  **[P]**, and not the verdict the same word names two layers up.
- queued for: the next registry version (D108 §3.3)

registry §7.6 key 3, the `len/shape` cell. **The cell's operative claim is
correct**, and it is the
reason the row reads `req, may be empty`: a bundle with no anchors at all is a
well-formed bundle, not a schema error. What over-reads is the gloss on the
end of it.

`MVP-SPEC.md:137` defines UNANCHORED as **zero headline-eligible anchors**,
and names the counterexample in the same sentence — *"a bundle carrying only a
`pending`/`attested` OTS"*, which is UNANCHORED with `ots_anchors`
**non-empty**. So the cell read as a biconditional is false; read as *"both
arrays empty ⇒ UNANCHORED"* it is true and weak; read as a local definition it
is coherent and collides with the word two layers up.

The harm is bounded, not absent. The registry points its own reader past this
gloss twice, in its own voice. At `:923`, exactly on the point: *"Nothing in
the schema requires two — an under-anchored bundle is a **verdict**, not a
parse error."* And at `:459-462`, on the neighbouring anchor-state field, it
hands the vocabulary upstairs by name — *"**No v1 parse rule and no v1 verdict
may read this field.** A verifier derives its own per-anchor state … and MAY
display the recorded value only as a *sealer-asserted claim*, with the
discipline **MVP-SPEC.md line 137** already prescribes for `claimed_time`."*
(That deferral is stated *for `claimed_time`*, which is narrower than the
whole vocabulary; what it establishes is that a reader of §7.8 has already
been sent to line 137 as the authority for anchor-state words.) A reader who
takes `:664`'s gloss for a verdict rule is contradicting the document they are
reading. What remains is a third-party verifier author who reads only this
table and carries sense (d) into a rendering decision; nothing in the tree can
prevent that before the next registry version.

**Do not "correct" this cell to state the spec's predicate** — that is a tier
violation, and §2.2 is why.

### registry-v1.json — §7.6 key 3 `ots_anchors`, the `notes` field

- file: `registry-v1.json`
- quotes: `ots_anchor elements; an UNANCHORED bundle is both anchor arrays empty. Anchor kind is positional — this key IS the OTS kind`
- scope: the same sense (d) as the entry above, in **independent words**. The
  erratum's subject is the middle clause; the rest of the `notes` value is
  quoted with it so the divergence is visible where it is recorded.
- queued for: the next registry version (D108 §3.3)

registry §7.6 key 3, the mirror's `notes` field. A **separate entry** rather
than a cross-reference,
because the mirror is not a copy of the document: it carries no bold, and it
carries a second clause the `.md` does not have. A reader who consults the
machine mirror — which is what a code generator reads — meets an
independently worded copy of the same claim.

And **nothing in this project compares the two prose surfaces, in either
direction**. `format_registry_freeze.rs`'s D-family compares the document's
mechanical tables against the mirror both ways — keys, names, presence,
reserved slots, bands, enums, scalar lengths, tuple arities, caps — and
compares neither the `.md`'s `len/shape` cells nor the `.json`'s `notes`
fields to anything at all. This key is the measured instance of a gap that
spans all **fourteen** of the mirror's maps, and closing it is not this
erratum's job: it needs an instrument, and a naive one is already ruled
against (§2.4).

### registry-v1.md — §0's freeze blockquote, the authority parenthetical

- file: `registry-v1.md`
- quotes: `format-version event, not an edit (MVP-SPEC.md line 123; the procedure is`
- scope: the **rule** is exactly right and unconditional — a byte change to
  this document IS a format-version event. Only the **citation** is wrong.
  Byte-immutability is imposed by **Q14's own freeze act**, which this same
  blockquote names in its own first sentence; `MVP-SPEC.md` line 123 is the
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

## 2. Why the frozen bytes were not corrected in place

Recorded here rather than only in D108, because the next lane to meet `:664`
will reach for the edit before it reaches for the decision record.

**2.1 The mechanism exists. The price is a tag event, not a sentence.** There
**is** an in-band re-bless, by design: flip `#! status frozen` to `pre-freeze`
in `FROZEN.sha256`, run `scripts/format-freeze.sh --update`, flip back, inside
**one** commit — and a committed `pre-freeze` is itself red
(`format_freeze_red_on_a_pre_freeze_status`), which is what forces the flip to
be transient. It has been used **once, on the record, for exactly this class
of change**: `622f5fe` (2026-07-28) corrected §14's overstated claim about
this project's own assertions and re-blessed the digest with the reason in the
commit message.

So the in-place edit is not blocked by a missing mechanism. It is blocked by
**the limit that commit set for itself**: *"done in one commit with the reason
stated, **before any tag exists**."* The tag `format-v1-freeze` (`d3345e1`,
2026-07-28, of which `622f5fe` is an ancestor) now exists. A byte change today
would make that tag name a registry the tree does not have — which is the harm
`d3345e1`'s own subject line was written to prevent, *"anchor the freeze
report to the tag, not to a rewritten hash"*. Re-pointing or superseding a
published tag is a repository-identity act, and D108 §3.1 makes the standard
explicit: an in-place byte change needs **C1** (nothing that is format surface
moves — cleared here), **C2** (the sentence is false *about this project's own
machinery*, not merely misleading about vocabulary — **not** cleared here; a
statement true at its own layer that borrows a word used differently elsewhere
is not in `622f5fe`'s class), and **C3** (an in-band re-bless with the tag
settled in the same act).

**2.2 "Correct it to state the spec's predicate" is dead on D78, freeze
aside.** D78, ratified, at registry §0's *Ratified rule*: *"**bundle schema
validation never consults the embedded manifest.** … Any rule needing both
sides is therefore **[R]**, not a schema error."* The cell sits in a table
whose rows are tier **[P]** — *"decidable from the **one entry** being
decoded"* (`:111`).

Headline-eligibility is neither [P] nor [X]. It is a per-anchor cryptographic
verdict computed layers up, which `verify::aggregate` counts from
`AnchorVerdict::is_headline_eligible()`. Writing the spec's predicate into
this cell would put a rule the schema layer must not evaluate into the schema
layer's own table, and would contradict `:459-460` and `:923` in the same
document. It would trade a scoped-name defect for a tier violation. This kill
is independent of the freeze and survives the next registry version: **v2 must
retire the word here, not redefine it.**

**2.3 What landed instead.** The correction went everywhere that is not
frozen, so the only remaining half of the defect is the half that cannot be
reached:

- `bundle/schema.rs` — the site an implementer of this codebase actually
  reads. The word is **retired** there, not annotated, and the shape fact is
  stated on its own.
- `docs/decisions/D98-status-anchor-state-vocabulary.md` **rider 3c** —
  extended from three senses to four, with a *layer* column, and **not**
  renumbered, so every existing citation of "rider 3c" still resolves. That
  rider is the single normative home for the four senses; this file is not a
  second one.
- The three editable senses — `verify::aggregate`'s `is_unanchored`,
  `NagState::Unanchored`, `WorkRow::unanchored` — each name the fourth and say
  why it cannot be the answer where they live.
- `anchor/verdicts/tests.rs` — the row that already reddens if senses (c) and
  (d) collapse gets the name and the citation that say so.

**2.4 What is deliberately still open.** The `.md`/`.json` prose gap named in
the second entry is **not** closed here, and the naive instrument for it is
already ruled against: `622f5fe` §1 held that *"a substring match on the prose
would pin editorial wording rather than format facts"*, and that ruling is
right. The tractable form is a **closed-vocabulary** check — a short list of
load-bearing words which, if they appear in one surface's prose for a key,
must appear in the other's — so that the check pins **terms** rather than
wording. It is its own task.

## 3. Retiring an entry

An entry is retired when the sentence it reads against is gone: the next
registry version states the fact without the borrowed word, or D108 §8's
option B is taken and the sentence is re-blessed in place. In either case the
quotation stops being byte-present and
`every_erratum_quotes_its_frozen_sentence_verbatim` goes **red**, in the same
commit that changed the text — which is the point of pinning an erratum to its
sentence. A stale erratum is exactly the "prose rots" failure the freeze exists
to catch one layer over, and this gate is what keeps a reading note from
becoming one.

**Delete the entry; do not update its quotation to match the new text.** An
erratum that follows its sentence into a new version has stopped being an
erratum. When the last entry goes, this file and its gate are retired
together — a gate over an entryless file is refused by name (`zero errata
entries`), so the two cannot drift apart either.
