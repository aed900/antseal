# D22 — Blank-line definition for `--split blank-lines`

- **Status: RESOLVED — blank = empty or spaces/tabs only (CommonMark-aligned); separator attaches to the preceding unit**
- **Date: 2026-07-27**

## Context

`--split blank-lines` (spec line 84) splits text files on blank-line
paragraph boundaries, operating on the **canonical rendition** (LF-only by
D21, so the semantics are platform-stable). The spec does not define
"blank line"; G6 needs a frozen definition plus the separator-attachment
rule. Register entry D22; blocks G6 and G14.

Scope note: the verifier checks only the tiling invariant (sorted,
non-overlapping, exact tiling — spec line 121), **not** that boundaries
fall on blank lines. The definition is therefore seal-time CLI semantics,
not verification law — frozen by policy for reproducibility and
documentation stability, and changeable in a future app version without a
format bump. What *is* format-permanent is each seal's resulting unit
ranges.

## Decision

Over canonical bytes, a **line** is a maximal LF-terminated segment (the
final segment may be unterminated). A line is **blank** iff its content,
excluding the terminating LF, consists solely of ASCII space (0x20) and
horizontal tab (0x09) — the empty line included. No other bytes or
scalars qualify (U+00A0, U+3000, U+000B, U+000C, etc. make a line
non-blank).

A **paragraph boundary** is a maximal run of ≥ 1 blank lines between
non-blank content. Attachment (ratifying G6's drafted rule):

- a separating blank run attaches to the **preceding** unit (trailing
  separator included in the earlier unit);
- a leading blank run attaches to the **first** unit;
- a trailing blank run at EOF attaches to the **last** unit;
- no blank lines → one unit; all-blank file → one unit; empty file → one
  empty unit.

Outputs are sorted, non-overlapping, and exactly tile
[0, canonical_len) — leaf-aligned byte offsets usable directly as
fine-tree ranges.

## Rationale

1. **Disclosure-surprise minimization**: units are the reveal
   granularity. Treating a visually blank `"   \n"` line as content would
   silently merge two visually distinct paragraphs into one unit, so a
   user revealing "one paragraph" would disclose two. Trailing whitespace
   on separator lines is endemic in real documents.
2. **Determinism with a tiny frozen alphabet**: restricting blankness to
   0x20/0x09 keeps the rule byte-decidable with no Unicode-whitespace
   table to freeze. This matches CommonMark's blank-line definition —
   a well-tested precedent for "what users perceive as a paragraph
   break".
3. **Excluding exotic whitespace**: U+00A0/U+3000 are meaningful content
   in many scripts and survive NFC; classifying them as blank would need
   a frozen Unicode-class list for zero practical benefit.

## Consequences

- G6 implements exactly this rule; rustdoc reproduces the definition
  verbatim (reimplementable from docs alone) and cites this decision.
- G6 KATs must include: whitespace-only separator lines (space, tab,
  mixed), a U+00A0-only line asserted **non**-blank, leading/trailing
  runs, all-blank, empty.
- G14 assembly and the M1 `--split` E2E (S17) inherit the rule
  unchanged; U's flag docs cite it.
