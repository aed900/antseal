# D9 — GGM node-address representation

- **Status: RESOLVED — `(level, index)` pair of uints**
- **Date: 2026-07-28**

## Context

GGM sub-covers and boundary Merkle paths must name interior nodes of the
salt tree. The spec fixes only *leaf* addressing: "leaf `i` is reached from
`s_root` by the bits of `i` MSB-first (bit d−1 first)" (MVP-SPEC.md
line 96). Interior nodes need a canonical form, and that form is
format-visible — it is frozen forever in the bundle wire schema.

Register entry D9, co-owned by G8 (semantic form) and F4 (CBOR encoding),
due at the M0 freeze. Both candidates were drafted in
`docs/format/registry-v1.md` §5 with `(level, index)` recommended; G8's
implementation adopted the same form independently.

## Decision

A node address is **`(level, index)`**, two unsigned integers:

- `level` — child-derivation steps below `s_root`; root = 0, leaf slots at
  `level = d` where `d = ⌈log₂ n⌉`;
- `index` — 0-based position within the level, `index < 2^level`.

The node covers the leaf-slot interval
`[index · 2^(d−level), (index+1) · 2^(d−level))`.

Wire encoding (F4 §5, Candidate A): `cover_entry = [level, index, seed]`
and `path_node = [level, index, hash]`, each `uint, uint, bstr(32)`.

Validity is `level ≤ d` and `index < 2^level`; both are cheap, total
checks with no representation-dependent edge cases.

## Rationale

1. **It is the spec's own rule, generalized — not a second convention.**
   The bits of `index` taken MSB-first *are* the root-to-node path, so at
   `level = d` the address degenerates to exactly the spec's leaf rule.
   A reader who understands line 96 already understands interior
   addressing; there is no second mapping to get wrong.
2. **Canonical for free.** A bit-path representation needs an explicit
   rule for the unused low bits of its final byte (or a separate length
   field), and any such rule is a canonicality trap: two encodings of the
   same node would have to be rejected by a hand-written check. With
   `(level, index)`, canonical-CBOR uint encoding already makes the
   representation unique — no extra rejection class, no extra tamper row.
3. **Compact in practice.** Two small uints cost 2–4 bytes per address
   (`level ≤ 64`; `index` is small at the shallow levels where cover nodes
   actually sit), comparable to a packed bit-path and without its framing.
4. **Debuggable.** `(3, 5)` is readable in a hex dump, an error message,
   and a golden vector; a packed bit-path is not.

## Consequences

- G8's `NodeAddress` is the semantic type (`path_bits` derives the
  MSB-first path from `index`); G11/G12/G13 address covers and boundary
  paths with it.
- F4's registry rows for `cover` and `paths` move from `pending-D9` to
  decided, keeping the Candidate A tuple shapes; the §5 candidate
  comparison stays in the document as the recorded rationale.
- Both are **co-frozen with the registry at Q14**. Until then the shape is
  decided but not yet permanent.
- G15's fine-tree golden vectors pin concrete `(level, index)` values,
  including the unbalanced n = 6 case that pins MSB-first ordering.

## Amendment (2026-07-28, at G11/G12): two tie-break rules, deliberately

Implementing the fine tree surfaced a case this record did not cover. When
`n` is not a power of two, one real span can have **two** grid addresses.
At `n = 6` the span `[4, 6)` is both `(1, 1)` — whose slot interval `[4, 8)`
truncates to it, since slots ≥ n are unused — and `(2, 2)`, whose slot
interval *is* it.

The two proof lists break that tie **differently, on purpose**, because they
address different things:

- a **cover** address names a GGM **seed**. G11 emits the *shallowest* node
  whose real span fits inside the revealed range — `(1, 1)` — because that
  is what makes the cover minimal: one seed there derives every leaf salt
  below it. (Slots 6 and 7 are unused, so the extra reach discloses salts
  for leaves that do not exist.)
- a **boundary** address names a content-subtree **hash**, whose identity is
  its leaf interval alone. `docs/format/registry-v1.md` §5 fixes the
  *deepest* slot whose interval equals the span as that interval's normal
  form — `(2, 2)`, the registry's own worked example — so the address is
  unique and the verifier can recompute it.

This is safe because **no node ever appears in both lists**: cover nodes lie
inside the revealed range, boundary nodes outside it, and each list is
recomputed by the verifier under its own rule. It is nonetheless a
format-visible asymmetry, so it is recorded here rather than left to the
code, and `boundary_addressing_deliberately_differs_from_cover_addressing`
(`content/fine_tree/proof.rs`) pins both by name so neither can be
"corrected" into the other. **Ratified 2026-07-28; co-frozen with the
registry at Q14.**
