# D75 — Does a full reveal ship per-unit covers **and** `s_root`?

- **Status: RESOLVED — BOTH. `covered_reveal.cover` is unconditionally
  required (registry §7.11 key 3, tier [P]); a fully revealed file's
  `s_root` (§7.14 key 2) is carried in addition, not instead. Outcome
  **ratified** at M0 wave 6 (2026-07-28); its stated *consequences* are
  corrected in three places below, and the discharged open action is now
  **contingent on D83** — see the amendment**
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

## Open action, discharged at R5 (2026-07-28)

**The agreement is already required, transitively — no extra check, and
deliberately no new code.** Both routes bind the *same signed*
`fine_root`: R2 folds each unit's cover-derived leaf salts and boundary
path up to it, and R4 rebuilds the whole tree from `s_root` and matches
it. A cover seed that does not descend from the disclosed `s_root`
derives different leaf salts, hence different leaves, hence a different
folded root — so R2 already rejects it (`fine-root-binding-failed`), and
reaching `fine_root` anyway would be a Merkle collision.

An explicit cover-vs-`s_root` byte comparison was considered and
rejected in both possible positions:

- **After R4** it is unreachable — R2's fold has already refused every
  input it could catch — so it would mint a permanent code (D30 §3) for
  a check that can never fire.
- **Before R4** it would change verdict precedence: a bundle that both
  leaks `s_root` for a partially revealed file *and* ships an
  inconsistent cover would report the new code instead of the
  spec-mandated `partial-reveal-salt-leak-s-root` (MVP-SPEC.md line 121).
  Displacing a line-121 verdict to gain a redundant one is the wrong
  trade.

What the redundancy buys is therefore real but is defence in depth, as
this record's first consequence already says: the `s_root` rebuild proves
*no extra leaves exist*, which no per-unit cover can.

**The Q8 half of the action is a recorded non-row**, not a row: the
mutation's observable outcome is `fine-root-binding-failed`, which G19's
pending `content-fine-root-binding-failed` row already claims, so
`check_registry` would correctly refuse the pair
(`testdata/tamper/MATRIX.json`, `non_rows` →
`full-reveal-cover-seed-not-descending-from-s-root`). Both directions are
pinned instead as named R5 pipeline tests with distinct codes from
distinct stages:
`d75_a_cover_seed_not_descending_from_s_root_is_rejected`
(`fine-root-binding-failed`) and
`d75_an_s_root_that_does_not_rebuild_fine_root_is_rejected`
(`fine-root-rebuild-mismatch`), in
`crates/antseal-core/src/verify/pipeline.rs`.

---

## Wave-6 ratification and corrections (2026-07-28)

M0 wave 6's planning round re-opened D75 with a mandate to overturn its own
lean, and to make sure this record and D74's cannot contradict each other.
**The outcome stands: BOTH.** But the record's *consequences* are wrong in
two places, and the second error hides a real hole.

### Reversibility, stated precisely — unlike D74, this one is not locked

D74's outcome is locked (reversing it would delete a landed code). D75's is
**not**. Relaxing key 3 from `req` to `opt` post-freeze is the strict →
permissive direction, which line 123 permits: bundles built under BOTH keep
verifying. So the option to drop covers on full reveals survives Q14 as a
legal future relaxation, and the reason not to take it is rationale 1 (tier
`[P]` / D78 decidability), not irreversibility. Recorded so nobody
mis-files this as settled-by-construction.

### Correction 1 — "the rebuild proves no extra leaves exist" is vacuous

This record's first consequence says the `s_root` rebuild "additionally
proves *no extra leaves* exist". It proves nothing of the kind, because
**both routes take the leaf count from the same place and neither can admit
a leaf the other excludes**:

- the cover route calls `verify_range(proof, bytes, n, fine_root)` with `n`
  from the manifest's signed `size`;
- the rebuild route calls `rebuild_fine_root(s_root, content)`
  (`crates/antseal-core/src/verify/file_stages.rs:917`), which derives the
  leaf count from `content.len()`;
- and `content.len() == size` is already forced before either runs — R3's
  tiling proves the non-mirror ranges tile `[0, size)` exactly, and R2's
  stage 3 proves each unit's `true_length` equals its range width.

`registry-v1.md` §7.11 repeats the same claim ("the rebuild additionally
proves no extra leaves") and inherits the same correction.

### Correction 2 — the rebuild is *not* merely defence-in-depth, and the
### binary framing is itself the error

The register entry framed D75 as deciding whether row 8 is "load-bearing"
or "defence-in-depth". It is **both, for two different properties**, and
saying only the first half is what makes the record read as if row 8 were
optional:

- **For the file's content binding it is defence-in-depth.** Correct as
  recorded: under BOTH, every unit is already bound to `fine_root` through
  its own cover.
- **For the disclosed material's own integrity it is load-bearing and
  sole.** `check_fine_root_rebuild`
  (`crates/antseal-core/src/verify/file_stages.rs:910`) is the **only**
  consumer of `FullRevealFineTree::Present::s_root` anywhere in the
  pipeline. Delete it and `s_root` becomes precisely what **D74** mints a
  permanent code to prevent: a bundle-side field the verifier reads, does
  not check, and does not report — 32 bytes any relay may fill with
  anything, in a format whose thesis is that the sealer is an adversary.

That is the sentence that makes the two records one rule instead of two
opinions:

> **A disclosed `s_root` is never unexamined.** Present-and-forbidden
> (`FineTree::Absent`) is D74's row 5,
> `full-reveal-s-root-without-fine-tree`. Present-and-required
> (`FineTree::Present`) is row 8's rebuild. Absent-and-required is D28's
> row 4. Absent-and-forbidden is the honest `--no-fine-tree` case. All four
> cells of the 2×2 are adjudicated, and none of them is "read it and shrug".

D74 and D75 are therefore not merely non-contradictory; D75-BOTH is only
*safe* from D74's own objection because the redundant route it keeps is
itself fully verified. A redundancy that were **not** checked would be the
exact material D74 rejects.

### Correction 3 — the discharged open action has an exception, and it is D83's

The **Open action, discharged at R5** section argues the two routes are
transitively required to agree: *"a cover seed that does not descend from
the disclosed `s_root` derives different leaf salts, hence different
leaves, hence a different folded root — so R2 already rejects it."*

**That sentence is false for leaf-level cover nodes.** When a cover node is
itself a leaf (`level == d`, so `sub_depth == 0`) the GGM walker performs
no descent at all and returns `seed[..16]` directly
(`crates/antseal-core/src/content/fine_tree/ggm_walk.rs:95, 207`). Bytes
`16..32` of that disclosed seed are read by nothing — this is exactly
**D83**, which is OPEN. Two consequences the discharge does not survive as
written:

1. **The routes are forced to agree only on the bytes some check reads.**
   A cover whose leaf-level seed differs from the `s_root`-derived one in
   its upper 16 bytes only still verifies, and so does the rebuild. The
   claimed derivation ("different leaf salts") does not occur, because the
   inert half never reaches a salt.
2. **The degenerate case ships the same seed twice, with independently
   unconstrained halves.** For a one-byte fine-tree file `d = 0`, so the
   full `[0, 1)` cover is the single node `(0, 0)` whose seed **is**
   `s_root` (`fine_tree/build.rs:525`: *"d = 0 → salt_0 = s_root[..16]"*).
   Under BOTH, such a full reveal carries that seed in §7.11 key 3 **and**
   in §7.14 key 2, and both upper halves are inert. R2's Accept list names
   the one-byte file as a required M0 edge vector, so this is a shipped
   shape, not a curiosity.

**The discharge's conclusion survives.** No extra check, no new code: the
disagreement is confined to bytes no check reads, so it cannot make a false
bundle verify, and both of the positional arguments against an explicit
comparison (unreachable after R4; verdict-displacing before R4) still hold.
Only the *reason* changes, to:

> The two routes are required to agree on **every byte any check reads**,
> transitively through the signed `fine_root`. The bytes they may disagree
> on are exactly D83's inert seed tails, which no check reads by
> construction.

### D75 widens D83's blast radius, and that is an ordering constraint

D83's context says leaf-level cover nodes arise in "most partial reveals".
Under D75-BOTH they arise in **full** reveals too, and the rule is exact:

> the `[0, n)` decomposition contains a size-1 (leaf-level) block **iff `n`
> is odd**, because the block sizes are the set bits of `n`.

So a full reveal of **any odd-length fine-tree file** ships a leaf-level
cover seed with 16 inert bytes — roughly half of all files, not a corner.
That is D75's direct contribution to D83 and it is not recorded in D83.

Two hard consequences for wave 6's ordering:

1. **D83 must land before this record can be closed.** If D83 resolves by
   shortening the wire form or canonicalizing the tail, the original
   discharge sentence becomes true as written and correction 3 is deleted.
   If D83 resolves by accepting the malleability, correction 3 becomes
   permanent and D75 carries the exception for good. Either way D75's
   amendment is written *after* D83, not before.
2. **No R6 fixture currently produces a leaf-level cover node**, which is
   why nothing has caught this. Every fixture content length and split
   boundary is even — `CRLF_TEXT` canonicalizes to 34 bytes,
   `data/blob.bin` is 30 split 10/10/10, `notes/split.md` is 34 split
   12/12/10 — so `n` is never odd and the decomposition never bottoms out
   at a leaf. This is also why R10's
   `the_unauthenticated_region_at_m0_is_exactly_the_storage_record` can
   assert its 88-byte equality: the third inert region simply is not
   present in the corpus it sweeps. Add one odd-length fine-tree file and
   that equality is false by 16 bytes. Registered as **R36** (the fixture
   gap and the D83-dependent boundary restatement) and **R37** (the
   one-byte / odd-`n` reveal shapes) in `tasks/R.md`.

### Verbatim artifacts

These are documentation corrections only. **No code changes, no check
changes, no row changes, no fixture bytes, and no committed digest moves.**

#### 1. `docs/format/registry-v1.md` §7.11, the paragraph beginning "**The consequence D75 actually decides**"

Replace the paragraph in full with:

```markdown
**The consequence D75 actually decides** is what R4's `s_root` tree
rebuild *is* — and it is two things at once, which the original framing
of this question missed. Under "both" the rebuild is **defence-in-depth
for the file's content binding** (each unit is already bound to
`fine_root` through its own cover) and simultaneously **load-bearing and
sole for the disclosed `s_root`'s own integrity**: `check_fine_root_rebuild`
is the only consumer of that field in the whole pipeline, so without it
`s_root` would be 32 bundle-side bytes the verifier reads, does not check
and does not report — exactly the material D74 mints a permanent code to
reject. Under "`s_root` only" the rebuild would instead be the sole
content binding. It is spec-mandated by line 121 either way. The rebuild
does **not** prove "no extra leaves": the leaf count comes from the
signed `size` on both routes, and R3's tiling plus R2's true-length
binding already force the concatenation's length to equal it. Under
"both" the two routes agree transitively through the signed `fine_root`
on every byte any check reads; the bytes they may disagree on are exactly
D83's inert leaf-level seed tails — see
`docs/decisions/D75-full-reveal-cover-shape.md`.
```

#### 2. `docs/format/registry-v1.md`, the table at §13 ("Registered decisions the bundle slice **feeds and must not resolve**")

Both the D74 and the D75 rows describe resolved decisions as open. Replace
the two rows verbatim:

```markdown
| **D74** — extraneous `s_root` on a fine-tree-absent full reveal | §7.14 key 2, the fifth violation row | **RESOLVED 2026-07-28: reject**, code `full-reveal-s-root-without-fine-tree`, checked at R4 (tier `[R]`). Ratified in wave 6. The draft's "the row is left unassigned" note is thereby discharged |
| **D75** — does a full reveal ship covers *and* `s_root`? | §7.11 key 3 presence | **RESOLVED 2026-07-28: both**, key 3 stays `req` at tier `[P]`. Ratified in wave 6, with the consequence restated: the `s_root` rebuild is defence-in-depth for content binding **and** the sole check of the disclosed `s_root` itself |
```

#### 3. `docs/format/registry-v1.md` §0, the bullet listing still-open decisions

The bullet currently reads *"Still open and **not** resolved here: **D77**
… **D76** (splitting `file_salt` — recommended NO for v1)."* Both are
RESOLVED (D76 and D77 records, 2026-07-28), and the same file's §13 table
already says so for D77 — an internal contradiction. Replace that sentence
with:

```markdown
  Fed here and resolved elsewhere the same day: **D77** (zero-non-mirror-unit
  file — **rejected at F5** as `manifest-empty-normal-units`; §7.14's
  anti-vacuity clause stays as defence-in-depth) and **D76** (splitting
  `file_salt` — **NO for v1**).
```

#### 4. `docs/format/registry-v1.json` — `fed_but_not_resolved_here[]`

Delete both the `"D74"` and the `"D75"` objects from
`fed_but_not_resolved_here[]` and append these two entries to the
`decisions_that_shaped_this` object, preserving that object's existing
key order (append at the end):

```json
    "D74": "RESOLVED 2026-07-28, ratified wave 6 — an extraneous s_root on a FineTree::Absent full reveal is REJECTED, code full-reveal-s-root-without-fine-tree, VerifyError::FullRevealSRootWithoutFineTree { file_id }, checked as row 5 of R4's frozen order (tier R — it needs the manifest descriptor and the derived full-reveal predicate, so D78 keeps it out of F8). A single code: there is no FileSalt counterpart, because file_salt is required on EVERY full reveal, so an unexpected file_salt is not a reachable state on one, and on a non-full reveal it is already partial-reveal-salt-leak-file-salt. docs/decisions/D74-extraneous-full-reveal-s-root.md",
    "D75": "RESOLVED 2026-07-28, ratified wave 6 — a full reveal ships per-unit covers AND s_root. covered_reveal key 3 stays req at tier P, so bundle schema validation stays decidable from the bundle alone (D78); on a full reveal the covers leak nothing, since every leaf is disclosed anyway. Consequence, corrected in wave 6: R4's s_root rebuild is defence-in-depth for the file's content binding and simultaneously the SOLE check of the disclosed s_root itself. The two routes agree transitively through the signed fine_root on every byte any check reads; the bytes they may disagree on are exactly D83's inert leaf-level seed tails, so closing D75 depends on D83. docs/decisions/D75-full-reveal-cover-shape.md"
```

Note for the implementer: `registry-v1.md` and `registry-v1.json` are
required to mirror each other 1:1 (§14), so items 1–4 land in **one**
commit and the mirror test must be run.

### Committed artifacts to re-emit

**None.** No wire field, key number, type, tier, presence rule, error code
or fixture byte changes. `scripts/vector-freeze.sh` must report zero
changed digests.

### What the implementer must report back

1. That the registry mirror test (`tests/format_registry_draft.rs`) passes
   after items 1–4, and that `fed_but_not_resolved_here[]` is left
   containing only genuinely open items — name what remains.
2. Zero changed digests from `scripts/vector-freeze.sh`.
3. **The D83 ordering, explicitly**: whether D83 had landed when this was
   applied. If it had, which of the two branches in "D83 must land before
   this record can be closed" is now true, and whether correction 3 was
   deleted or made permanent. If it had not, say so — D75 is then still
   provisional in that one respect and must not be listed as closed on
   Q14's checklist.
4. Whether adding an odd-length fine-tree fixture (R37) turns
   `the_unauthenticated_region_at_m0_is_exactly_the_storage_record` red as
   predicted. A red test there is the analysis confirmed, not a
   regression — report the measured size of the third region.
