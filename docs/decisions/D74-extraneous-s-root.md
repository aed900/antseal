# D74 — Extraneous `s_root` on a `FineTree::Absent` full reveal

- **Status: RESOLVED — REJECT, with its own code
  `full-reveal-s-root-without-fine-tree`**
- **Date: 2026-07-28** (resolved with F8; the check itself is R4's)

## Context

Surfaced 2026-07-28 by D28's planning pass as the one **forced** second
choice: D28 froze four of the five arms of its biconditional, and R4's
typed classifier has nowhere to put the fifth.

D28 (registry §7.14) makes a full-reveal entry's presence and its
`s_root` a biconditional over a derived predicate:

```text
a §7.14 entry for F exists  ⟺  full(F)
its s_root is present       ⟺  full(F) ∧ F.fine_tree = Present
```

Four violation arms were assigned codes. The fifth —
`full(F) ∧ fine_tree = Absent`, `s_root` **present** — was left
deliberately unassigned. A `--no-fine-tree` file and an empty file have
no fine tree at all, so a bundled `s_root` for one is a 32-byte seed that
is the root of nothing.

## Decision

**Reject**, with a distinct R-domain error:

```rust
VerifyError::FullRevealSRootWithoutFineTree { file_id }
// code: "full-reveal-s-root-without-fine-tree"
```

A single code, not a `FullRevealMaterial`-discriminated pair: the
`FileSalt` arm would be unreachable (key 1 is required at schema level,
so a full-reveal entry without `file_salt` never reaches R4 — F8 rejects
it as `bundle-missing-key` first).

The permissive reading — silently dropping the stray seed — is **not**
implemented.

## Rationale

1. **C14's present-set-==-required-set precedent.** The signature layer
   already refuses a *present-but-unlisted* signature rather than
   ignoring it, for the same reason: a producer shipping material the
   schema has no use for is either confused or probing for a lenient
   verifier, and a verifier that quietly discards unexplained
   cryptographic material teaches senders that it will.
2. **Silence here is indistinguishable from a real bug.** The only ways
   to produce this state are a builder that lost track of a file's
   descriptor, or a hand-built bundle. Both are worth surfacing; neither
   is worth papering over.
3. **It is the reversible direction.** Rejecting now and relaxing later
   keeps every bundle that ever verified verifying. Tolerating now and
   tightening later breaks bundles already in the wild — the same
   asymmetry D28 turned on.
4. **The classifier is total either way**; assigning the arm costs one
   variant and buys a nameable tamper row instead of a silent branch.

## Consequences

- `VerifyError` gains one variant and one code (append-only per D30);
  the R-domain code count moves 71 → 72 and the variant count 21 → 22.
- **The check is [R], not [P]/[X]**: it needs the manifest's descriptor
  (`fine_tree`) *and* D28's derived predicate, so **F8 does not implement
  it** — the bundle schema layer keeps `s_root` optional and says nothing
  about whether it belongs. R4 owns the check; the code is minted now so
  R4 does not have to re-litigate the arm.
- Registry §7.14's violation table is now complete: all five arms
  assigned.
- Q8 owes a tamper row binding to the new code.
