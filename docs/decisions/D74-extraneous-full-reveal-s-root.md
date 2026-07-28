# D74 — Extraneous `s_root` on a `FineTree::Absent` full reveal: reject

- **Status: RESOLVED — reject, with its own distinct code**
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
3. **It completes D28's totality property.** D28 rationale 3 claims *a third
   party cannot alter a bundle's reveal shape undetected* — strip units and
   the leak arm fires, strip salts and the missing arm fires. Option B would
   leave one hole in that sentence: *add* material and nothing fires. With
   Option A the material rules are total over the 2×2 of (fine-tree state,
   `s_root` presence), which is how R4's classifier is literally written —
   an exhaustive match with all four combinations named.
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
