# D74 — Extraneous `s_root` on a `FineTree::Absent` full reveal: reject

- **Status: RESOLVED — reject, with its own distinct code. Re-audited and
  **ratified** at M0 wave 6 (2026-07-28); three corrections and one
  residual appended below, none of them changing the outcome. The D28
  shape-totality clause that rationale 3 and the wave-6 audit inherited
  was corrected 2026-07-31 (adversarial review, finding 7) — dated notes
  in place below; outcome again unaffected**
- **Date: 2026-07-28**
- **Owning task: R4** (consumed by F8 bundle schema, R7 tamper rows, R13/R16
  builder, Q8 completeness)
- Surfaced by D28's planning pass as "the one genuinely forced second
  choice"; recommended there, decided here at implementation.

## Context

D28 froze the *missing* direction: a full reveal MUST carry `file_salt`, and
MUST carry `s_root` when the manifest's file entry records a fine tree
(MVP-SPEC.md lines 114, 121). It deliberately left the symmetric
*unexpected* direction open, because R4's typed classifier forces a choice
rather than permitting a default:

```rust
pub enum FullRevealFineTree<'a> {
    Absent,                                            // --no-fine-tree / empty file
    Present { s_root: Seed32, fine_root: &'a CommitmentDigest },
}
```

`Absent` has **no field** to put an `s_root` in. So a bundle that fully
reveals a `--no-fine-tree` (or empty) file and attaches an `s_root` anyway
must be either rejected or silently dropped. There is no third option, and
"silently drop" is not a default this project takes.

Note what is *not* in question. A `file_salt` arm of the same question does
not exist: `file_salt` is **always** required on a full reveal (D28), so an
"unexpected `file_salt`" state is unreachable on a full reveal, and on a
non-full reveal it is already the isolation arm
(`partial-reveal-salt-leak-file-salt`). The question is `s_root`-only.

## Options

### Option A — reject

A full reveal of a `FineTree::Absent` file carrying an `s_root` is a hard
failure with its own code.

### Option B — silently ignore

Classify as `Full` with `FullRevealFineTree::Absent`, drop the value, verify
clean.

## Decision

**Option A — reject.** `VerifyError::FullRevealSRootWithoutFineTree
{ file_id }` → **`full-reveal-s-root-without-fine-tree`**. One code; there
is no `FileSalt` arm, for the reason above.

## Rationale

1. **House precedent, twice over, on the identical question shape.** C14
   resolved it for signatures — MVP-SPEC.md line 97: "the **present
   signature set MUST equal the policy set** — the verifier validates every
   listed signature and hard-fails on any that is missing, invalid, *or
   present but unlisted*". D28 resolved the missing half of *this* field the
   same way. Accepting an unlisted extra here while rejecting an unlisted
   extra there would make "present set == required set" a rule the format
   applies inconsistently, decided per-field by whoever implemented it.
2. **An unverifiable field in an adversarial format is not inert.** A
   dropped `s_root` is a value the verifier read, did not check, and did not
   report. Nothing binds it: there is no `fine_root` for it to be wrong
   about. It is exactly the "signed, anchored field a sealer may fill with
   anything" that D28's rationale 1 refuses — with the aggravation that the
   bundle is *not* signed, so any relay can add one. Under Option B, adding
   48 bytes of arbitrary data to a valid bundle is undetectable; under
   Option A it is a named error.
3. **It closes the add-material direction of D28's material rules.** D28
   makes the *inconsistent* strips named errors — strip some of a file's
   units but leave the material and the leak arm fires; strip the material
   but leave the units and the missing arm fires. Option B would leave the
   symmetric hole: *add* material and nothing fires. With Option A the
   material rules are total over the 2×2 of (fine-tree state, `s_root`
   presence), which is how R4's classifier is literally written — an
   exhaustive match with all four combinations named. [Amended 2026-07-31
   — adversarial review, finding 7: this rationale originally opened by
   quoting D28 rationale 3's shape-totality claim as established. That
   claim was corrected the same day in both records: detection is total
   over *inconsistent* edits only, and a consistent whole-file narrowing
   (a file's reveal entries, `touched_files` entry and `full_reveals`
   entry removed together) fires nothing, by design and harmlessly — the
   unsigned bundle claims only what it discloses. See D28's 2026-07-31
   amendment. The add-material argument above stands unchanged.]
4. **Derived, never declared — applied consistently.** The bundle does not
   get to assert a shape (D28 rider 1). Tolerating an `s_root` the manifest
   says cannot exist would let the bundle contradict the signed manifest
   about the file's fine-tree state and have the verifier resolve the
   contradiction silently in the bundle's favour. The manifest is signed and
   anchored; the bundle is not. The signed side wins, and the disagreement
   is reported.
5. **The strictness direction is the reversible one** (D28 rationale 4).
   Line 123 makes format stability normative. Reject → tolerate is a legal
   future relaxation: bundles built under the strict rule keep verifying.
   Tolerate → reject is illegal. No honest builder emits this shape — C7's
   `FullFileRevealContext` and G11's cover rule release `s_root` only for a
   `[0, n)` cover of a file that *has* a tree — so the strict rule costs the
   honest sealer exactly nothing.

## Cost, stated honestly

It mints one permanent code (D30 append-only; permanent at Q14), for a
condition no honest bundle can reach. That is the whole price. The
alternative saves the code and buys a silent acceptance path in a format
whose thesis is that the sealer is an adversary.

## Consequences — what this freezes

- **F8 (bundle schema)**: the full-reveal entry stays `{file_salt, s_root?}`
  keyed by `file_id`, with `s_root` present **iff** the manifest's
  `FineTree` is `Present` — now enforced in both directions. F8 must not
  make `s_root` unconditionally optional-and-ignored.
- **R4**: the rule is row 5 of the frozen check order
  (`crates/antseal-core/src/verify/file_stages.rs` module docs), evaluated
  after D28's rows 1–4 and before the defensive length conversions. Rows 4
  and 5 are mutually exclusive (`Present` vs `Absent`), so their relative
  order is not observable; row 3 (missing `file_salt`) does precede row 5,
  and that ordering is asserted.
- **R7**: one new tamper row —
  `verify-full-reveal-s-root-without-fine-tree`, base
  `full-reveal-no-fine-tree-binary`, mutation "attach the file's `s_root`",
  expected `full-reveal-s-root-without-fine-tree`. Distinct from every D28
  row, so Q7's registry sweep accepts it.
- **R13/R16 (M3 builder)**: a full-file reveal emits `s_root` **iff** the
  file has a fine tree. R14's builder property tests should assert the round
  trip in both directions, not just the presence one.
- **Q8**: a project-added row (like D28's rows 1–2), not a spec-list row —
  MVP-SPEC.md line 168 names only the *leak* case. The 1:1 spec mapping
  stays honest.
- **No format impact beyond the above**: no new wire fields, no new HKDF
  labels, no new domain tags.

## Spec conformance

Consistent with the spec, not an extension of it. Line 114 enumerates a
fully revealed file's disclosures as `{file_salt, s_root}` where `s_root` is
"the full `[0, n)` cover" — a description that presupposes a tree. Line 121
phrases the rebuild as a MUST *using the bundled `s_root`*. A file with no
fine tree has no `[0, n)` cover and no rebuild to perform, so an `s_root`
for it is not a disclosure the format defines. Rejecting an undefined
disclosure is the reading in which the verifier's field set is closed —
the same closure F5 already applies to unknown manifest keys and C14 to
unlisted signatures.

## Residual risk

A future v1.1 that adds a *different* meaning for `s_root` on a fine-tree-less
file (there is no such meaning today) would need a new field or a version
bump rather than reusing the slot. Given that `s_root` is defined purely as
the GGM fine-seed root (line 96), that is the correct constraint, not a lost
option.

## Provenance: decided twice, independently (2026-07-28)

This record supersedes a second D74 write-up produced in the same wave.
F8/F9 and R4 ran as parallel agents and both resolved D74 without seeing
each other's work — F8 from the wire side (it minted the code), R4 from the
verification side (it implemented the check). They agreed on the outcome,
the variant, and the code spelling.

The independent agreement is itself worth recording, because the two
arguments are different and both survive:

- **F8's**: a `FileSalt` arm is unreachable, so this is one code rather than
  a `FullRevealMaterial`-discriminated pair — key 1 is required at schema
  level, so a full-reveal entry without `file_salt` never reaches R4 (F8
  rejects it as `bundle-missing-key` first). That layering fact is what
  makes the single-code shape correct rather than merely convenient.
- **R4's**: the permissive reading left a hole in D28's rationale 3. Strip
  some units but leave the material and the leak arm fires; strip material
  but leave the units and the missing arm fires; **add** material and
  nothing fired. The manifest is signed and anchored but the bundle is
  not, so any relay could append 48 bytes to a valid bundle with nothing
  in the report saying so. Rejecting makes the material rules total over
  §7.14 presence. [Amended 2026-07-31: as made, this argument closed by
  endorsing D28 rationale 3's shape-totality claim ("which is what D28
  already claimed to be true"); that claim was corrected the same day
  (adversarial review, finding 7 — see D28's amendment), and the
  endorsement is retired. The add-material argument stands without it.]

The superseded file (`D74-extraneous-s-root.md`) was removed rather than
kept as a duplicate; nothing in it is lost — F8's argument is quoted above.

---

## Wave-6 ratification and corrections (2026-07-28)

M0 wave 6's planning round re-opened D74 with a mandate to overturn its own
lean. **The outcome stands: reject.** Three corrections to the record, one
audit result, and one residual the record does not name.

### The window is closed, and that should be said plainly

The code `full-reveal-s-root-without-fine-tree` has landed
(`crates/antseal-core/src/verify/error.rs:722`), the check is row 5 of the
frozen order (`file_stages.rs:790-792`), and the tamper row
`verify-full-reveal-s-root-without-fine-tree` binds it
(`tamper_rows_structural.rs:595-601`). Reversing to "silently ignore" would
require **deleting** a code that a committed row binds, which error-code
contract §3 forbids outright, and it is the permissive direction, which
MVP-SPEC.md line 123 forbids as a format change. So ratification is the
only outcome still available. That is not a reason to skip the audit — it
is a reason to record that the audit was the last one that could have
changed anything.

### Correction 1 — the "Provenance" section mis-attributes F8's argument

F8's quoted claim is *"a `FileSalt` arm is unreachable … because key 1 is
required at schema level, so a full-reveal entry without `file_salt` never
reaches R4 (F8 rejects it as `bundle-missing-key` first)"*, and the record
calls that "the layering fact that makes the single-code shape correct".
It is not. That claim is about the **missing** direction — it explains how
row 3 is *realized*, not whether an extraneous-`file_salt` arm exists.

The correct reason there is no `FileSalt` arm is the one this record's own
**Context** section already gives, and it needs no layering fact at all:
`file_salt` is required on **every** full reveal (D28), so "unexpected
`file_salt` on a full reveal" is not a state the classifier can be in; and
on a non-full reveal an attached `file_salt` is row 1,
`partial-reveal-salt-leak-file-salt`. The 2×2 D74 completes is
(fine-tree state × `s_root` presence) — `file_salt` has no second axis to
be surprising on.

Verified against the code, not inferred: `FullReveal.file_salt` is a
`Salt16`, not an `Option<Salt16>`
(`crates/antseal-core/src/bundle/schema.rs:1277`), and `FullReveal::decode`
returns `missing(MAP, key::full_reveal::FILE_SALT)` when key 1 is absent.
The claim is true; it is simply about a different question.

### Correction 2 — F8's fact does have a consequence, and D74 did not draw it

Because key 1 is `req`, **row 3 is reachable only by removing the whole
§7.14 entry**, never by removing the key from an entry. An
entry-with-key-1-missing dies at F8 as a `bundle-` code and never reaches
R's namespace at all.

The landed row already does the right thing — base `r6-multi-file-all`,
mutation *"strip a fully revealed file's full-reveal entry"* — but nothing
records **why** it must be spelled that way. Recorded now: a future
contributor who "simplifies" that row into an
entry-with-`file_salt`-removed mutation will silently re-bind
`verify-full-reveal-missing-file-salt` from R's
`full-reveal-material-missing-file-salt` to F8's `bundle-missing-key`,
and the row will still pass its own weakened assertion. This is the
`(code, layer)` hazard F15 named, one section over.

### Correction 3 — the record names the wrong base fixture

This record's **Consequences** section says the R7 row has base
`full-reveal-no-fine-tree-binary`. The landed row's base is
`r6-multi-file-all` (`tamper_rows_structural.rs:597`), which is correct:
R6's `multi_file` work carries `archive/old.txt` as its `--no-fine-tree`
file, so the shape is present inside the shared base rather than needing a
dedicated one. The **code** is right and the **record** is what should
move; no row edit is implied.

### Audit — is the totality claim (rationale 3) actually total?

Rationale 3, as originally written (corrected 2026-07-31 — see the dated
note at the end of this section), claimed that after D74 shape-alteration
detection was total: no direction of third-party edit escapes. Re-audited
across the whole v1 bundle, not just §7.14:

- **§7.14, both directions** — closed by rows 1–5.
- **§7.13 `touched_files`, both directions** — closed by **D80**
  (`revealed-unit-file-not-touched`) and **D82**
  (`touched-file-without-revealed-unit`). D82 is the same add-material
  hole in a second section, found *after* this record claimed totality.
- **Duplicate entries in either section** — closed at F8, not at R:
  `check_ascending_ids` (`schema.rs:164`) enforces strict ascent over the
  `file_id` sort key of both lists, and strict ascent rejects duplicates.
  So "append a second entry for the same file" is not an open arm.
- **A §7.14 entry with no §7.13 entry** — closed at F8 as the tier-`[X]`
  `bundle-full-reveal-without-touched-file`.
- **Every other bundle-side byte** — `k_u` and ciphertext by the AEAD tag,
  `unit_salt` by `unit_commit`, `path_salt` by `path_commit`, `file_salt`
  by row 7, `s_root` by row 8, cover seeds and boundary node hashes by the
  fold.

So the generalisation D74 is one instance of is stronger than the record
states, and it is **asserted rather than argued**:

> **Every bundle-side byte is either bound by a check that can fail, or
> lies in a named, measured exempt region** —
> `the_unauthenticated_region_at_m0_is_exactly_the_storage_record`
> (`crates/antseal-core/tests/verify_fuzz.rs:176`), which pins the exempt
> set as an *equality*: 88 bytes of M3 storage record (32 address +
> 24 nonce + 32 key), exhaustively, with the complement strided.

**The one gap in that equality is not D74's to close, and it is open.**
D83's inert leaf-level cover-seed tails (16 bytes per cover node whose
`level == d`) are a third unauthenticated region that R10's equality does
not name. It does not currently falsify the test only because **no R6
fixture produces a leaf-level cover node** — the `[0, n)` decomposition
contains a size-1 block iff `n` is odd, and every fixture's content length
and split boundary is even (34, 30, 12/12/10, 10/10/10). See D75's wave-6
amendment for the full analysis and the ordering constraint it puts on
D83.

#### 2026-07-31 — the audit's answer was wrong: the claim is not total

(Adversarial code review, finding 7.) This audit swept per-section edits —
each direction of each section, plus the cross-section presence couplings
— and every bullet above is true. What it never enumerated is the
**coordinated** edit: remove one file's reveal entries, its
`touched_files` entry and its `full_reveals` entry *together*, and every
arm's precondition vanishes with the evidence — D80 has no revealed unit
of the file left to find untouched, D82 no touched entry left to find
unrevealed, rows 1–4 no material present and no `full(F)` — so the file
classifies `Untouched` and the bundle verifies clean. The byte-level
generalisation quoted above is unaffected: it quantifies over bytes
*present* in a bundle, not over coherent removals.

Consistent narrowing is **not a vulnerability**, and must not be re-opened
as one: the bundle is unsigned by design and claims only what it
discloses, and the narrowed bundle is byte-identical to an honest narrower
bundle of the same work (every bundle-side disclosed value is fixed per
work at seal time; the encoding is canonical) — indistinguishable in
principle, so no future check can close this short of signing bundles,
which v1 rejects by design. It is denial of evidence, the same family as
the union-not-closed residual below (R35): the wider original still
verifies, and only the sealer can widen a reveal. The corrected scope —
detection is total over **inconsistent** edits; a third party can make a
bundle claim less, never more, never differently — is stated in full in
D28's 2026-07-31 amendment, and rationale 3 above now carries the
corrected form.

### Residual this record does not name — `.sealproof` bundles are not union-closed

D28's strictness has a consequence in the *add-material* family that no
record states, and it is not a soundness break but it will bite at M3.

Take two honest bundles of the same work from the same sealer: bundle A
reveals units `{1, 2}` of a three-unit file `F`, bundle B reveals `{3}`.
Neither is a full reveal, so — correctly, per rows 1–2 — neither carries
`F`'s `file_salt` or `s_root`. Merge them (a relay can: the sections are
plain arrays that need only be re-sorted to satisfy strict ascent) and the
merged bundle reveals all of `N(F)`, so `full(F)` holds and **row 3 fires**:
`full-reveal-material-missing-file-salt`.

The verdict is correct — the merged bundle really does lack the material a
full reveal must carry, and the material is not derivable from the two
sources. But it means:

1. **The union of two valid bundles is not necessarily a valid bundle.**
   Nothing in the spec or in D28 says otherwise, and nothing says this
   either.
2. **A relay can turn two valid bundles into one invalid one.** That is a
   denial-of-evidence nuisance, not a forgery: both originals still verify,
   and the merged bundle fails loudly with a named code rather than
   verifying with a false claim. It is the *right* failure.
3. **An M3 "combine these bundles" affordance is not implementable
   client-side**, because producing the merged bundle's full-reveal
   material requires `W`. Only the sealer can widen a reveal. That is a
   product fact worth knowing before someone designs the UX around it.

Registered as **R35** in `tasks/R.md`.

### What this amendment changes in the tree

**Nothing executable.** No code, no check, no row, no fixture, no vector.
The corrections above are edits to this record; corrections 1–3 may also be
applied to the prose they describe, but no assertion changes and no
committed digest moves.

