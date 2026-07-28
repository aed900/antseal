# D83 — A leaf-level cover seed's upper 16 bytes are inert: accept the malleability, canonicalize it, or shorten the wire form?

- **Status: OPEN — registered, not decided. Found by G20's proof-mutation
  property; nothing implemented beyond the test that pins the current
  behaviour. Any of the three options is a FORMAT event, so it belongs to
  F/G jointly and must land before the Q14 freeze**
- **Date: 2026-07-28** (found with G20)
- **Owner: G (semantics) + F (wire encoding); gate Q14**

## Context

A `.sealproof` range proof ships its GGM sub-cover as `(level, index,
seed)` triples with `seed` **exactly 32 bytes** (MVP-SPEC.md line 121's
length rule, enforced by `FineTreeError::BadSeedLength`).

A verifier turns each cover node's seed into the salts of the leaves that
node covers by descending `sub_depth = d − level` levels
(`fine_tree::verify::CoverSalts` → `ggm_walk::GgmWalker`). At the bottom,

> `salt_i = leaf_seed[..16]` (MVP-SPEC.md line 96)

When the cover node **is** a leaf — `level == d`, so `sub_depth == 0` —
there is no descent at all: the walker returns `seed[..16]` directly and
**bytes 16..32 of the disclosed seed are never read by anything**.

That case is not exotic. Every boundary-decomposed reveal ends in
deepest-single-leaf nodes: it is exactly G11's first normative KAT (`n = 6`,
reveal `{2}` → node `(3,2)`), and it occurs in most partial reveals.

## How it was found

G20's `mutated_proofs_never_panic_and_never_verify` asserted the natural
property "any change to the wire form must be rejected", and proptest
produced a counterexample at 1024 cases (persisted at
`crates/antseal-core/proptest-regressions/content_properties.txt`, shrunk
to `n = 101`, a single-leaf cover node `(7, 73)`, one bit flipped in the
seed's upper half). The proof still verified — correctly, by the rule
above.

## What is and is not at stake

**Not a soundness or confidentiality break.** The inert bytes convey
nothing about unrevealed leaves (they are the tail of a seed whose whole
subtree is a single revealed leaf), and no substitution of them can make a
different byte or a different `fine_root` verify. `salt_i` is unchanged, so
the leaf hash, the fold, and the root are unchanged.

**It is a canonical-form / malleability issue**, and antseal cares about
canonical forms:

1. **Bundle uniqueness.** Two byte-distinct `.sealproof` files can carry
   the same proof and both verify. Anything that treats bundle bytes as
   identifying — a content address, a de-duplication key, a "same bundle"
   comparison, a digest quoted in a report — inherits 2^128 equally valid
   spellings per leaf-level cover node.
2. **Tamper-matrix completeness.** The project's discipline is "every
   mutation fails with a distinct error" (working principles;
   `testdata/tamper/`). This mutation class fails with *no* error, so a
   future `bundle-cover-seed-bitflip` row would be unlandable as written
   and must be scoped to the significant bytes.
3. **Wire cost.** 16 wasted bytes per leaf-level cover node, on a format
   that is otherwise carefully minimal.

## Options

**A. Accept and document.** Record in `docs/format/registry-v1.md` §5 that
the upper 16 bytes of a `level == d` cover seed are not covered by
verification, and that bundle bytes are therefore not a canonical
identifier for a proof. Cheapest; leaves the malleability in the format
forever (line 123 makes v1 verifiable forever).

**B. Canonical padding.** Keep 32 bytes on the wire but require the
prover to emit the true derived seed and the verifier to reject a
`level == d` cover node whose tail is not… — the verifier *cannot* check
it against the truth (it has no way to derive the real seed), so the only
checkable rule is a **fixed** tail, e.g. all zeros. That restores
uniqueness and is a one-line verifier check, but it makes the wire value
no longer "the seed" for the leaf case, which is a semantic wrinkle worth
weighing.

**C. Shorten the wire form.** Encode a `level == d` cover node's payload
as **16 bytes** — which is what it actually is, a `salt_i` — and keep 32
bytes for every `level < d` node. Removes the malleability entirely,
shrinks bundles, and matches the semantics exactly. Costs a
length-by-level rule in F's decoder (`BadSeedLength` becomes
level-dependent) and a registry §5 change.

## Recommendation (not a decision)

**C**, with **A** as the fallback if F judges the level-dependent length
rule too sharp an edge for a strict decoder. C is the only option under
which the wire value and its meaning coincide, and it is the one that
makes the malleability *unrepresentable* rather than merely illegal.

## Consequences either way

- Whichever lands, `docs/format/registry-v1.md` §5 gains an explicit
  statement of the leaf-level cover node's payload length and its
  significant bytes; D9's node-address contract is untouched.
- G20's property is currently written against the **present** behaviour: it
  compares an *effective* projection of the wire (a `level == d` cover
  node's first 16 bytes only) and asserts that a change inside the inert
  tail still verifies. Resolving this as B or C flips that assertion, which
  is intentional — the test is the executable statement of whichever rule
  is chosen, and the committed regression case is the counterexample that
  forced the question.
- If B or C lands, R7/G19 gain a real tamper row for the previously-inert
  bytes.

## Status of any implementation

**None.** Only the test and this record; no format constant, no code path,
no length rule has been minted (project rule: an unresolved decision that
would freeze a format rule is registered, not implemented).
