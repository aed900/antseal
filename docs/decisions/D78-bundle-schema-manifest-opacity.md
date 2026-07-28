# D78 — May bundle schema validation open the embedded manifest?

- **Status: RESOLVED — NO.** At schema time the bundle treats `manifest` as
  an opaque `bstr`. The manifest layer decodes it and owns the `manifest-`
  and `cbor-` code families.
- **Date: 2026-07-28** (surfaced and ratified the same day, by the D8 bundle
  pass — registry §13 item 8; consumed immediately by F8/F9)
- **Record written: 2026-07-28, M0 wave 7.** Ratified in wave 5 and cited as
  normative in code ever since, but it had no record file: it existed only
  as an entry in `TODO.md`'s decision register. A rule that code enforces as
  a type witness, that fixes a permanent code family, and that freezes at
  Q14 needs a record. Promoted here verbatim in substance, with its code
  citations verified at `6b6ee17`.

## Context

`.sealproof` decoding is layered (F3, F6, F9): the bundle decodes, and the
manifest sits inside it as an embedded byte string that F6 keeps **as
received**, with no re-encode path anywhere in the verifier. The question is
whether the *bundle's* schema-validation pass may look inside that byte
string in order to decide whether the bundle is well-formed.

It reads like layering taste. It is not.

## Decision

**No.** Bundle schema validation never consults the embedded manifest.

## Rationale

1. **It fixes which error family a cross-side rejection lands in, and D30
   makes families permanent.** If bundle validation opened the manifest,
   manifest-level failures would surface inside the bundle's error family.
   The two families are `bundle-` and `manifest-`; under D30 they are
   append-only and never renamed, so the choice is unrecoverable after the
   first released verifier compares against one. F8's error enum needed the
   answer *before it was written*, which is why this was ratified the day it
   was raised.
2. **F3's layered decode already established the shape.** Outer and inner
   decode already produce distinct error classes, and a wrapped codec
   rejection surfaces its inner code **unchanged** at every layer
   (error-code contract §2). Opening the manifest from the bundle layer
   would contradict a rule the codec already implements.
3. **It keeps "is this reveal entry valid?" decidable at the layer that owns
   it.** Every bundle-side presence rule must be answerable from bundle
   bytes alone. This is what puts `covered_reveal.cover` at tier **[P]**
   (D75 rationale 1) and what makes `full_reveals ⊆ touched_files` express
   ible as a tier-[X] rule at all (D8, which is also why the explicit
   `file_id` in per-file bundle sections is *necessary*, not merely tidy).
4. **The consequence is stated, not hidden.** Under "no", an `s_root`
   present for a tree-less file (registry §7.14) is a **verify** failure,
   not a **schema** failure — and the two render differently to users. That
   is D74's code `full-reveal-s-root-without-fine-tree`, an R-family code,
   exactly as this decision predicts.

## Consequences

- Rules that need both sides are tier **[R]** by construction (registry §0).
  D80 is the worked example: "a revealed unit's owning file must appear in
  `touched_files`" needs the manifest, so D78 keeps the check out of F8 and
  R4/R5 own its spelling.
- `BundleError` has **no manifest arm**, and this is enforced as a type
  witness rather than by review: `crates/antseal-core/src/bundle/error.rs`
  (module docs; `:440` *"There is deliberately no manifest arm (D78)"*;
  `:1014` *"D78 as a type witness"*). There is no value of `BundleError`
  that can carry a manifest failure, so the layering cannot be violated by
  an ordinary edit.
- Bundle-side constants that would otherwise be read from the manifest are
  duplicated deliberately and pinned by test rather than shared (`:272`).

## Freeze status

Freezes at **Q14** with the rest of the code-family assignment. Reversing it
afterwards would re-home rejections between two permanent families, which is
the one thing D30 forbids outright.
