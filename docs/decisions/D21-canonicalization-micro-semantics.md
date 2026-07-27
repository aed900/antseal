# D21 — Canonicalization micro-semantics (BOM, EOL, pipeline order)

- **Status: RESOLVED**
- **Date: 2026-07-27**

## Context

Canonicalization v1 (spec line 83: UTF-8, NFC, LF endings, no BOM) is
frozen at seal time and must be idempotent and total (G2 Accept: proptest
`canonicalize(canonicalize(x)) == canonicalize(x)` over **arbitrary** byte
inputs; spec line 170). The open micro-decisions: lone-CR handling, leading
BOM handling, and the fixed pipeline order.

## Decision

Text-mode `canonicalize_v` is the following fixed pipeline over the raw
bytes, in this order and no other:

1. **Decode** UTF-8 to a scalar sequence — strict for detected text, lossy
   (D20 maximal-subparts U+FFFD) under `--force-text`. (For detected text
   the two are identical.)
2. **BOM strip**: remove **all leading U+FEFF scalars** (see deviation
   note). U+FEFF anywhere after the first non-U+FEFF scalar is content
   (ZWNBSP) and is preserved.
3. **EOL normalize**: one left-to-right pass — CR LF → LF, then any
   remaining lone CR → LF. (Equivalently: CR consumes an immediately
   following LF; every CR becomes LF. CR CR LF → LF LF.)
4. **NFC** using the descriptor-recorded Unicode version's table (D25:
   `unicode-17.0.0` in v1), never "latest".
5. **Encode** UTF-8, no BOM prepended.

Binary kind: no rendition (identity/none) — the pipeline is text-mode only.

**Canonical-form invariant**: a canonical rendition never begins with
U+FEFF, contains no CR, and is NFC under the recorded version. Each
pipeline stage is idempotent on the previous stages' fixed points, and no
later stage reintroduces an earlier stage's target (NFC composition cannot
produce U+FEFF or CR; U+FEFF has ccc=0 so NFC's combining-mark reordering
cannot move one to the front), so the composite is idempotent.

## Deviation from the proposed semantics (recorded)

The open-decision entry proposed "strip exactly one leading BOM". That
proposal violates the normative idempotence property on multi-BOM inputs:
`"﻿﻿ x"` → pass 1 strips one BOM → pass 2 strips another —
`canonicalize(canonicalize(x)) ≠ canonicalize(x)`. Since idempotence is
frozen in G2's acceptance (and spec line 170) and the one-BOM proposal was
not, the strip rule is widened to **all leading U+FEFF scalars** — the
minimal change that restores idempotence. Multiple leading BOMs are
concatenation artifacts, not content; genuinely interior U+FEFF is
untouched. G3's corpus MUST include a double-BOM fixture pinning this.

## Rationale for the order

- BOM strip must precede NFC: it is defined on the raw scalar position,
  before any normalization could compose adjacent characters.
- EOL before NFC is safe and fixed by fiat (CR/LF are normalization-inert,
  but a single frozen order is what makes the golden vectors meaningful).
- Lone CR → LF (not just CRLF) because classic-Mac line endings must not
  leak into canonical bytes; the one-pass rule gives CR CR LF → LF LF a
  single defined answer.

## Consequences

- G2 implements exactly this pipeline; G3 fixtures pin: leading BOM,
  double leading BOM, interior U+FEFF, CRLF, lone CR, CR CR LF, NFD→NFC.
- R's raw-mirror recompute and any independent implementation (Q11) follow
  this document.
