# D75 — Does a full reveal ship per-unit covers **and** `s_root`?

- **Status: RESOLVED — BOTH. `covered_reveal.cover` is unconditionally
  required (registry §7.11 key 3, tier [P]); a fully revealed file's
  `s_root` (§7.14 key 2) is carried in addition, not instead**
- **Date: 2026-07-28** (resolved with F8)

## Context

Surfaced 2026-07-28 by D28's planning pass. On a *full* reveal of a
fine-tree file, the bundle as drafted carries **two independent routes to
the same `fine_root`**:

1. each covered unit's own leaf-exact GGM sub-cover + boundary path
   (registry §7.11 keys 3–4), and
2. the file's `s_root` — the full `[0, n)` cover (§7.14 key 2), from which
   the verifier rebuilds the whole fine tree over the revealed bytes
   (MVP-SPEC.md line 121: "using the bundled `s_root`, the verifier MUST
   rebuild the whole fine tree from those bytes and match `fine_root`").

D75 asks whether route 1 should be *omitted* when route 2 is present.
D28 holds either way; the key number and type are answer-neutral. Only
the presence rule of key 3 differs.

## Decision

**Both.** Key 3 is `req`, unconditionally, for every covered reveal —
including every unit of a fully revealed file.

## Rationale

1. **It keeps key 3 at tier [P], which D78 requires.** "`s_root` only"
   would make key 3's presence `opt: ¬full(F)` — a rule keyed on D28's
   *derived* full-reveal predicate, which needs the signed unit table.
   That is tier [R] by construction (registry §0). Under **D78** bundle
   schema validation never consults the embedded manifest, so F8 could no
   longer decide whether a covered reveal is well-formed. The
   alternative reading does not merely cost a check; it makes
   "is this reveal entry valid?" undecidable at the layer that owns it.
2. **It leaks nothing.** On a full reveal every leaf is disclosed anyway
   — which is precisely why MVP-SPEC.md line 114 can say `s_root`
   "discloses nothing" there. A per-unit cover holds only descendant
   seeds of revealed leaves; when *all* leaves are revealed, the covers
   and `s_root` are equally (un)revealing.
3. **One decode shape instead of two.** `CoveredReveal` has a single
   layout regardless of the enclosing file's reveal shape, so there is no
   "sometimes this key is here" branch in the decoder, the fixtures, or
   the golden vectors.

The cost is real and accepted: ~2·⌈log₂ n⌉ redundant cover entries per
unit once `s_root` is present. At the spec's own sizing (line 96, n = 10⁸)
that is ~1.7 KB per unit of avoidable bytes on full reveals only.

## Consequences

- **R4's `s_root` fine-tree rebuild is defence-in-depth, not
  load-bearing.** Each unit is already bound to `fine_root` through its
  own cover; the rebuild additionally proves *no extra leaves* exist. It
  is spec-mandated by line 121 either way — D75 changes its weight, not
  whether it runs.
- **The two routes must be required to AGREE, and that check needs an
  owner.** Leaf salts derived from `s_root` and leaf salts derived from
  the per-unit covers are the same values; a disagreement means the
  sealer shipped a cover that does not descend from the disclosed
  `s_root`, which is an equivocation attempt, not a bookkeeping slip.
  **Open action for R4/Q8**: a tamper row for "per-unit cover seed
  inconsistent with the bundled `s_root`" with its own distinct code.
  Without it, the redundancy D75 chose to keep buys nothing.
- No wire change: the key number, type, and tuple shape are what §7.11
  already recorded.
- F8 implements key 3 as `req` + non-empty; `tests/bundle_schema.rs`
  (`d75_full_reveal_carries_both_covers_and_s_root`) pins the
  co-presence.
