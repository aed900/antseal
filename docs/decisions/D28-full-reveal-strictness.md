# D28 — Full-reveal strictness: missing `file_salt`/`s_root` is a hard failure

- **Status: RESOLVED — strict (hard-fail); there is no "weaker full reveal" shape in v1**
- **Date: 2026-07-28**
- **Owning task: R4** (consumed by R5 orchestration, R6 fixtures, R7/R8 tamper
  rows, R13/R16 builder, R15/U28 disclosure preview, F8 bundle schema, Q8
  completeness)
- Index note: authored on the D28 planning branch; the
  `docs/decisions/README.md` index row lands at merge (same convention as
  D27; the index on `main` is currently behind by D9/D15/D20–D24/D27/D29).

## Context

A `.sealproof` bundle discloses, per **touched** file, `{path, path_salt}`,
and per **fully revealed** file, `{file_salt, s_root}` (MVP-SPEC.md line
114). Line 121 then makes the full-reveal cross-checks mandatory:

> on a full file reveal, the concatenated non-mirror unit bytes **must**
> hash to `canon_commit` (text) / `raw_commit` (binary) and, using the
> bundled `s_root`, the verifier **MUST** rebuild the whole fine tree from
> those bytes and match `fine_root`.

Both checks are keyed on material the *sealer* chooses whether to attach.
So the register asks: when a bundle reveals every non-mirror unit of a file
but omits `file_salt` (and `s_root` where a fine tree exists), is that a
**hard failure**, or a legitimate **weaker reveal** — "here is all the
content, but I am not opening the whole-file commitments"?

The question is freeze-permanent. It fixes what a v1 bundle means, which
`VerifyError` a v1 verifier raises, and — because MVP-SPEC.md line 123 makes
format stability normative ("every released manifest/bundle format version
remains verifiable by all future CLI and page releases") — it is not
revisable in the tightening direction after the first real seal exists.

The symmetric half is already settled by the spec and needs no decision:
**partial-reveal isolation** (line 121, and a named M0 tamper row at line
168) forbids `file_salt`/`s_root` on a partially revealed file. R1 shipped
both error variants in anticipation of this record
(`crates/antseal-core/src/verify/error.rs`).

### What the verifier can see

Detection is trivial, offline, and needs no secret. Everything the
predicate consumes is either signed-and-anchored manifest data or bundle
field presence:

| Input | Source | Already modelled |
|---|---|---|
| the file's complete non-mirror unit set | manifest unit table (`kind`, `file_id`) | `verify::structural::{UnitEntry, UnitKind}` |
| the revealed `unit_id` set | bundle; R3 already proved existence + no duplicates | `verify::structural::BundleView::revealed_unit_ids` |
| "a fine tree exists" | manifest file entry | `manifest::body::FineTree::{Absent, Present}` — presence is a *variant*, not a nullable field |
| "text vs binary" (which whole-file commit) | manifest file entry | `manifest::body::CanonMode::{Binary, Text}` |
| `file_salt`/`s_root` presence + length | bundle; R3 group 1 already length-checks both | `LengthField::{FileSalt, SRoot}` |

There is no ambiguity to arbitrate and no evidence a verifier lacks. This
is a policy choice, not a capability limit.

## Options

### Option A — strict: a full reveal missing its material is rejected

`full(F) ∧ ¬present(file_salt)` → hard error, and likewise `s_root` when
the manifest records a fine tree.

- Every whole-file commitment the sealer signed and anchored becomes
  falsifiable at the one moment enough information exists to falsify it.
- Costs the honest sealer 48 bytes (16 + 32) per fully revealed file, and
  one privacy residual on the `file_salt` half (below).
- Removes a shape from the format: v1 has no way to show all of a file's
  units without also opening `canon_commit`/`raw_commit`.

### Option B — permissive: omission is a legitimate weaker reveal

The bundle is accepted; the concat check, the tree rebuild, and the
mirror's `raw_commit` opening are silently skipped. (The raw-mirror ↔
canonical binding check is *not* skipped — it needs no salt, only the two
byte strings.)

- Lets a sealer show a file's whole content while withholding the
  `raw_commit` oracle described under residual risk.
- Makes `canon_commit` and `raw_commit` **permanently unfalsifiable**:
  no bundle can ever be constructed that forces either to be opened.
- Makes a 48-byte deletion in transit an undetectable proof downgrade.
- Cannot be tightened later without breaking line 123.

## Decision

**Option A — strict.** A bundle that reveals every non-mirror unit of a
file MUST carry that file's `file_salt`, and MUST additionally carry
`s_root` when the manifest's file entry records a fine tree. Omission is a
hard failure with a distinct, already-registered error code. There is no
"reveal every unit but withhold the whole-file openings" shape in format
v1.

Two structural riders make the rule enforceable rather than aspirational:

1. **Reveal shape is derived, never declared.** The bundle carries no
   "this is a partial/full reveal" discriminant. Shape is computed from the
   signed manifest's unit table and the bundle's revealed set. A declared
   shape would be a second, sealer-forgeable source of truth, and declaring
   "partial" while revealing everything would smuggle Option B back in
   through the wire format. **Binding constraint on F8.**
2. **The classification is one predicate with two consequences.** The
   partial-reveal leak check and the full-reveal missing check are the two
   arms of a single classification, so they stay in one place (R4) rather
   than being split across stages, which would duplicate the predicate and
   let the two arms drift.

## The predicate R4 must implement

### Inputs

From the **signed manifest body** (F5 types), and from the **bundle**
(F8 types), after R3 has run:

```text
manifest.files : [FileEntry]   // file_id, size, canon: CanonMode, fine_tree: FineTree
manifest.units : [UnitEntry]   // unit_id, file_id, kind: UnitKind
bundle.revealed        : Set<u64>          // R3: every id exists, no duplicates
bundle.full_material   : file_id ↦ { file_salt: Option<[u8;16]>, s_root: Option<[u8;32]> }
```

### Derived quantities, per file `F`, in **manifest file-table order**

```text
N(F)     = { u.unit_id : u ∈ manifest.units, u.file_id = F.file_id, u.kind = Normal }
R(F)     = N(F) ∩ bundle.revealed
full(F) ⟺ N(F) ≠ ∅  ∧  R(F) = N(F)
Req(F)   = ∅                        if ¬full(F)
         = { file_salt }            if full(F) ∧ F.fine_tree = Absent
         = { file_salt, s_root }    if full(F) ∧ F.fine_tree = Present { .. }
```

Three clauses are load-bearing and must not be simplified away:

- **`kind = Normal` only.** Raw-mirror units are exempt by `kind` (spec
  line 92; D23 explicitly forbids relying on placement). A file is fully
  revealed when its canonical-domain units are all revealed **whether or
  not its mirror is**; conversely a mirror-only reveal is *partial* and
  therefore carries no `file_salt`, which is exactly why line 92 says the
  mirror's `raw_commit` opening happens only "when proving exact original
  bytes".
- **`N(F) ≠ ∅` (anti-vacuity).** R3's tiling check accepts a hand-built
  `size = 0` file with **zero** units (`cursor == size` at 0). Without the
  non-emptiness clause such a file would be *vacuously* fully revealed by
  every bundle, including one revealing nothing, and the rule would demand
  `file_salt` for a file nobody touched. The clause mirrors
  `crypto::disclosure::FullFileRevealContext::attest`, which already
  refuses an empty `all_non_mirror_units`. An honest sealer never emits
  this shape (an empty file gets one `[0,0)` unit); the clause makes the
  adversarial one harmless rather than explosive.
- **`s_root` is conditional on `FineTree::Present`.** A `--no-fine-tree`
  file and an empty file have no fine tree (`manifest::body::FineTree`
  docs), so demanding `s_root` for them would reject every honest bundle
  of that shape.

### The rule, in frozen evaluation order

Files in manifest file-table order (matching `check_tiling`); within a
file, these four checks in this order; first failure wins (D27):

| # | Condition | Error |
|---|---|---|
| 1 | `¬full(F)` ∧ `file_salt` present | `PartialRevealSaltLeak { file_id, material: FileSalt }` |
| 2 | `¬full(F)` ∧ `s_root` present | `PartialRevealSaltLeak { file_id, material: SRoot }` |
| 3 | `full(F)` ∧ `file_salt` ∉ present | **`FullRevealMaterialMissing { file_id, material: FileSalt }`** |
| 4 | `full(F)` ∧ `s_root ∈ Req(F)` ∧ `s_root` ∉ present | **`FullRevealMaterialMissing { file_id, material: SRoot }`** |

File-major order (all four checks for one file, then the next file) is
frozen here, not check-major, because R4's checks are inherently per-file
and the report's per-file evidence is assembled file by file. Every input
therefore has exactly one first error.

### The distinct errors, with their stable codes

Both variants and both codes already exist in R1's shipped taxonomy
(`crates/antseal-core/src/verify/error.rs`); D28 mints nothing new and
renames nothing:

```rust
VerifyError::FullRevealMaterialMissing { file_id: u64, material: FullRevealMaterial }
```

| Discriminant | Stable code (D30 contract) |
|---|---|
| `FullRevealMaterial::FileSalt` | `full-reveal-material-missing-file-salt` |
| `FullRevealMaterial::SRoot` | `full-reveal-material-missing-s-root` |

and, for the already-spec-mandated isolation arm,
`partial-reveal-salt-leak-file-salt` / `partial-reveal-salt-leak-s-root`.
All four are R-domain (unprefixed) codes per the D30 prefix table.

**Cross-stage precedence note.** A *present but wrong-length* `file_salt`
is caught earlier, by R3 group 1, as `wrong-length-file-salt` — not by rule
1 or 3. The stages are R3 (structural) → R2 (per-unit) → R4 (file-level),
so length errors always precede shape errors, and a bundle with both a
broken ciphertext and a leaked salt reports the decrypt failure. This is
determinism bookkeeping, not a security ordering.

## Enforcement by construction

C7 already closes the generation side: `file_salt` bytes are reachable only
via `FullFileRevealDisclosure::file_salt_bytes`, which requires a
`FullFileRevealContext` witness, and `PartialRevealDisclosure` has no slot
for one (`crates/antseal-core/src/crypto/disclosure.rs` and
`material.rs`, `compile_fail` doc-test proofs on both misuses). R4 is the
verifier-side mirror of the same pattern: classification
is the single fallible point, and the material is carried **in the type**,
so no downstream check can be written that forgets it.

```rust
pub enum FileRevealShape<'a> {
    Untouched,
    Partial(PartialRevealEvidence<'a>),   // no file_salt / s_root slot exists
    Full(FullRevealEvidence<'a>),
}

pub struct FullRevealEvidence<'a> {
    file_id: u64,
    file_salt: &'a [u8; 16],              // not Option — a Full without it is unrepresentable
    fine: FullRevealFineTree<'a>,
}

pub enum FullRevealFineTree<'a> {
    Absent,                                            // --no-fine-tree / empty file
    Present { s_root: &'a [u8; 32], fine_root: &'a CommitmentDigest },
}
```

This mirrors F5's manifest-side shapes exactly — `CanonMode::Text` carries
`canon_commit`, `FineTree::Present` carries `root`, so "canon_commit on a
binary file" and "fine tree without a root" are states the types cannot
hold. The one new obligation the pattern creates is named as Candidate 1
below: with `FullRevealFineTree::Absent` having nowhere to put a stray
`s_root`, the classifier must decide what to do with one, and silently
dropping it is not an option this project takes.

Consumers take `&FullRevealEvidence`: the concat→`canon_commit`/`raw_commit`
check, the `s_root` tree rebuild, and the mirror's `raw_commit` opening
cannot be invoked without the material, so "we forgot to run the cross-check"
is a compile error rather than a silent acceptance.

## R7 tamper rows

In the shape `crates/antseal-core/src/test_util/tamper.rs` consumes
(`TamperRow { id, base, mutation, expected, exercise }`), following the
landed `verify-*` id convention with unprefixed R codes:

| `id` | `base` | `mutation` | `expected` (`ErrorCode`) |
|---|---|---|---|
| `verify-full-reveal-missing-file-salt` | `full-reveal-fine-tree-text` | delete the fully revealed file's `file_salt` | `full-reveal-material-missing-file-salt` |
| `verify-full-reveal-missing-s-root` | `full-reveal-fine-tree-text` | delete the fully revealed file's `s_root`, keep `file_salt` | `full-reveal-material-missing-s-root` |
| `verify-partial-reveal-salt-leak-file-salt` | `partial-reveal-two-of-three-units` | attach the file's `file_salt` to a partial reveal | `partial-reveal-salt-leak-file-salt` |
| `verify-partial-reveal-salt-leak-s-root` | `partial-reveal-two-of-three-units` | attach the file's `s_root` to a partial reveal | `partial-reveal-salt-leak-s-root` |

Rows 3 and 4 are the spec's own line-168 row ("`file_salt`/`s_root` present
for an only-partially-revealed file") split per material, since each has its
own code. Rows 1 and 2 are R7's addition — see the spec-conformance note.

**Deliberately NOT a fifth row.** Dropping one revealed unit from a
full-reveal bundle (leaving `file_salt` attached) is the third-party
downgrade attack, and it surfaces as `partial-reveal-salt-leak-file-salt` —
the *same* expected outcome as row 3. `check_registry` rejects two rows
claiming one outcome, correctly: the two mutations are one observable
failure. Assert it as an **R10 property** ("no single-unit deletion from a
full-reveal bundle verifies"), not a registry row. A naive R7 implementation
that adds it will break the harness; that is the harness working.

### Positive fixtures (R7 Notes precedent: prove the rule is not over-broad)

| Fixture | Shape | Must verify because |
|---|---|---|
| `full-reveal-fine-tree-text` | all units + `file_salt` + `s_root` | the base case |
| `full-reveal-no-fine-tree-binary` | all units + `file_salt`, **no** `s_root` | the `s_root` clause is conditional on `FineTree::Present` |
| `full-reveal-empty-file` | size 0, one `[0,0)` unit, `file_salt` only | R4 Accept: the empty file is a full reveal |
| `full-reveal-via-enumerated-units` | every non-mirror `unit_id` listed explicitly | R4 Accept: `--units <all>` ≡ `--all` |
| `full-reveal-without-mirror` | all canonical units + material, mirror withheld | the mirror is not part of the predicate |
| `partial-reveal-two-of-three-units` | neither material present | absence is *correct* on a partial reveal |
| `degenerate-zero-unit-file` | size-0 file with no units, no material | the anti-vacuity clause: not full, so nothing is demanded |

## Rationale

1. **`canon_commit` and `raw_commit` have no other verification path.**
   `fine_root` and `unit_commit` are checked per unit (R2), `path_commit`
   per touched file (R3), byte ranges by the tiling invariant (R3). The two
   whole-file content commitments are checked *only* by R4's full-reveal
   concat. Making that check optional does not weaken it — it deletes it:
   no bundle could ever be constructed that forces either field to be
   opened, and two signed, anchored, permanently stored fields would become
   decoration the sealer may fill with anything.
2. **It is the only place line 96's normative binding is checkable.** Line
   96 declares it normative that "fine-tree leaf `i` commits byte `i` of
   the exact same bytes committed by `canon_commit` (text) / `raw_commit`
   (binary)", precisely to stop a sealer equivocating between a per-unit
   reveal and a v1.1 byte-range reveal of one `work_id`. That cross-binding
   is verifiable at exactly one moment: a full reveal holding both
   `file_salt` and `s_root`. Under Option B it is never checked by anyone,
   ever — an honour-system clause in a document whose thesis is that the
   sealer is an adversary.
3. **Option B makes proof downgrade a silent 48-byte deletion.** The
   manifest is signed and anchored; the bundle is not. Under Option B any
   relay, mail gateway, or opposing party can strip `file_salt` (and
   `s_root`) from a valid full-reveal bundle and hand the recipient a
   weaker proof that still verifies clean, with nothing in the report
   saying so. Under Option A that deletion is a named hard error. Together
   with the isolation arm the property becomes total: **a third party
   cannot alter a bundle's reveal shape undetected** — strip units and the
   leak arm fires, strip salts and the missing arm fires.
4. **The freeze is one-directional, and strict is the reversible choice.**
   Line 123 makes format stability normative. Strict → permissive is a
   legal future relaxation (bundles built under the strict rule keep
   verifying, and v1.1 could add an explicit weaker-reveal shape with its
   own discriminant if a real use case ever appears). Permissive → strict
   is illegal: bundles built under the permissive rule would start failing.
   Under uncertainty about a permanent format, take the direction that can
   be undone.
5. **The cost to the honest sealer is 48 bytes and one bounded residual.**
   Both values are HKDF-derivable from `W` at reveal time; the sealer
   always has them. `s_root`'s disclosure cost is provably *zero* on a full
   reveal (below). Only `file_salt` carries a residual, and it is metadata
   about line endings, not content.
6. **House precedent points the same way twice.** C14 resolved the
   structurally identical question for signatures — "the present signature
   set MUST equal the policy set… hard-fails on any that is missing,
   invalid, *or present but unlisted*" — rather than accepting a partially
   satisfied policy as a weaker-but-valid proof. D24 chose a hard error
   over a silent weaker outcome for the same permanence reason. A format
   that accepts "I did most of the proof" has no crisp verdict to render,
   and R18's single authoritative verdict wording depends on there being
   one.

### What strictness does *not* buy (stated honestly)

- **It never forces a sealer to issue a full reveal.** A sealer who only
  ever issues partial reveals leaves `canon_commit`/`raw_commit` unfalsified
  regardless. The guarantee is conditional, and that is the strongest one
  available: *if a bundle shows a file's whole content, it also proves the
  whole-file commitments.*
- **For fine-tree files, the `s_root` rebuild is mostly defense in depth.**
  Given R2's shape (`ContentBinding::FineTreeCovered` supplies a per-unit
  cover and boundary path for every covered unit), each leaf is already
  bound to `fine_root`, and re-opening a leaf under a different salt is a
  SHA-256 second preimage. The rebuild's unique contributions are (a)
  proving the salts really are one GGM tree from one root — the line-96
  puncturable-PRF story and v1.1 range-reveal consistency — and (b) an
  independent second computation reaching the same root, which catches
  implementation bugs on either path. If F8 later decides a full reveal
  ships `s_root` *instead of* per-unit covers (Candidate 3), `s_root`
  becomes load-bearing rather than redundant.
- **`s_root`'s zero-disclosure claim is inherited from R3, not independent.**
  "All units revealed ⇒ all leaves revealed" holds *because* R3 already
  proved the non-mirror units tile `[0, size)` exactly. Stage order R3 → R4
  is therefore load-bearing for the privacy claim, not merely for
  determinism.
- **Strictness matters most in the degenerate case.** For an empty file the
  unit and tiling checks say almost nothing about content; the `file_salt`
  opening of `canon_commit`/`raw_commit` over zero bytes is a large share of
  the evidence that the file entry means what it claims.

## Consequences — what this freezes

- **Format v1 has exactly three reveal shapes per file**: untouched,
  partial, full — derived, never declared. F8 must not add a shape
  discriminant to the bundle schema; the full-reveal entry is
  `{file_salt, s_root?}` keyed by `file_id`, with `s_root` present iff the
  manifest's `FineTree` is `Present`.
- **Four stable codes are bound to reveal-shape outcomes**:
  `full-reveal-material-missing-file-salt`,
  `full-reveal-material-missing-s-root`,
  `partial-reveal-salt-leak-file-salt`, `partial-reveal-salt-leak-s-root`.
  Append-only from here (D30); permanent at Q14.
- **The predicate itself** — `kind = Normal` only, `N(F) ≠ ∅`, `s_root`
  conditional on `FineTree::Present`, file-major evaluation order — is the
  frozen definition of "fully revealed" for v1 bundles.
- **R13/R16 (M3 builder)**: a full-file reveal always emits both materials.
  C7's `FullFileRevealContext` is the generation-side gate; this record is
  its verifier-side counterpart, and R14's builder property tests should
  assert the round trip (anything the builder calls a full reveal must
  classify as `Full` and carry `Req(F)`).
- **R15/U28 (disclosure preview + consent gate)**: revealing a file's *last*
  remaining unit **promotes** the reveal to a full reveal and ships
  `file_salt` (+`s_root`). The preview must surface that promotion, because
  a user selecting "one more unit" is also, irreversibly for that bundle,
  choosing to open the whole-file commitments.
- **No format impact beyond the above**: no new wire fields, no new HKDF
  labels, no new domain tags.

### Tasks unblocked

R4 (implementable as specified), R5 (stage order confirmed unchanged), R6
(the positive-fixture table is the classifier's shape matrix), R7 (rows
fixed above), R8/R10 (the downgrade property), Q8 (row list), F8 (the
derived-shape constraint), R15/R16/U28 (the promotion warning).

## Residual risk

### Of the decision taken (Option A)

**`file_salt` salts both content commitments, so a canonical-only full
reveal leaks the file's raw form.** Spec line 95 uses one `file_salt` for
`raw_commit = SHA-256(0x03 ‖ file_salt ‖ raw_bytes)` *and*
`canon_commit = SHA-256(0x04 ‖ file_salt ‖ canonical_bytes)`. A recipient
of a full reveal that does **not** include the mirror therefore holds
`file_salt`, `raw_commit`, and the canonical bytes — and the pre-image
space of raw forms that canonicalize to known canonical bytes is tiny
(line ending × BOM × normalization form ≈ a dozen plausible candidates).
They can brute-force `raw_commit` and recover the original's line-ending,
BOM, and normalization form even though the raw bytes were never revealed.

Bounding it honestly: this is authoring-platform metadata, not content; the
mirror unit's mere presence in the manifest already discloses that raw ≠
canonical, so the residual narrows "differs" to "differs how"; and the
bundle already discloses the full canonical content, file sizes, and unit
boundaries by design. Strictness converts this from avoidable-by-omission
to unconditional, which is the honest price of the decision. Eliminating it
is Candidate 2 and is a spec-level change, not R4's.

The `s_root` half carries **no** residual: on a full reveal every leaf is
revealed, so the GGM seeds are pseudorandom over an empty set of
unrevealed leaves (spec line 114's "discloses nothing").

Second-order: the rule creates a mild incentive to withhold one unit to
avoid promotion. That is not an evasion — withholding a unit means genuinely
not showing it, and the redaction view (R19) renders it as a sized blackout.

### Of the rejected option (Option B), stated plainly

Had we accepted omission as a weaker reveal:

1. `canon_commit` and `raw_commit` would be **permanently unfalsifiable**
   in format v1. No bundle could force either open, so a sealer could
   commit to one document in the fine tree and a different one in
   `canon_commit`, ship per-unit reveals to one counterparty and disclose
   `file_salt` out of band to another, and no verifier would ever contradict
   either. This is the file-level analogue of the line-94 equivocation the
   single-authoritative-commitment rule exists to prevent — and unlike that
   one, it would sit inside a *signed, anchored* manifest.
2. Line 96's normative leaf-`i`-equals-`canon_commit`-byte-`i` binding
   would have no verification path at all.
3. Proof downgrade in transit would be a silent 48-byte deletion, invisible
   in the report.
4. It could never be tightened: bundles built under it would stop verifying,
   breaking line 123's normative format-stability promise. The mistake would
   be permanent in a way the strict rule's mistakes are not.

The privacy gain that would have bought — letting a sealer avoid the
raw-form fingerprint above — is a metadata leak an order of magnitude
smaller than the guarantee surrendered.

## Spec conformance

- **Consistent with the spec.** Line 121 phrases both full-reveal
  cross-checks as MUSTs on the verifier, and line 114 lists `{file_salt,
  s_root}` as the contents of a fully revealed file entry. Strictness is
  the reading in which a verifier that cannot perform a MUST-check fails
  rather than proceeds.
- **One recorded superset, not a divergence.** The spec's M0 tamper-matrix
  list (line 168) names only the *leak* row ("`file_salt`/`s_root` present
  for an only-partially-revealed file"); it does not enumerate the
  *missing-material* row. R7's task text adds it. D28 ratifies that
  addition — line 168's own framing is "every mutation fails with a
  distinct error", and its list is illustrative of that rule rather than
  exhaustive of it. Q8's completeness check must therefore treat rows 1–2
  above as project-added rows, not as spec-list rows, so the 1:1 spec
  mapping stays honest.
- **Complements C19** (adversarial confirmation-attack doc-tests): C19
  demonstrates the attack against an *unsalted* file-hash variant, i.e. why
  `canon_commit` is salted at all. D28 governs when that salt is disclosed
  and checked. The two do not overlap; C19 should cite this record for the
  disclosure rule.

## New decision candidates surfaced (not resolved here)

Numbers are the orchestrator's to assign.

1. **Extraneous full-reveal material** — a fully revealed file whose
   manifest says `FineTree::Absent` but whose bundle entry carries an
   `s_root` anyway. D28 settles the *missing* direction; this is the
   symmetric *unexpected* direction, and the typed classifier has nowhere
   to put such a value, so R4 must reject or silently drop it. **Recommend
   reject**, following C14's present-set-equals-required-set precedent and
   the project's refusal to carry unverifiable fields in an adversarial
   format; suggested new variant `FullRevealSRootWithoutFineTree { file_id }`
   → code `full-reveal-s-root-without-fine-tree` (single code — a
   `FileSalt` arm would be unreachable, since `file_salt` is always required
   on a full reveal). Owner R4 with F8; freeze-permanent (mints a code,
   permanent at Q14). **This is the one genuinely forced second choice**,
   which is why it is named rather than made here.
2. **Split `file_salt` into two independent salts** (one for `raw_commit`,
   one for `canon_commit`), eliminating the residual above. **Recommend no
   for v1**: spec line 95 froze one salt, and a second salt means a new
   HKDF label against C2's frozen 8-label registry plus a registry change —
   large blast radius for a line-ending fingerprint. Record it so v1.1 can
   revisit deliberately rather than rediscover it. Owner C6/F4.
3. **Does a full reveal ship per-unit GGM sub-covers *in addition to*
   `s_root`, or does `s_root` replace them?** Owner F8/F9 with R2/R4.
   Bundle-size question on its face, but it decides whether the `s_root`
   rebuild is defense in depth (covers also present, R2's current shape) or
   load-bearing (covers omitted, `s_root` the sole binder). D28 holds under
   either answer; the strength claim in "what strictness does not buy"
   changes.
4. **Should a file with zero non-mirror units be a structural rejection?**
   R3's tiling currently accepts a size-0 file with no units. D28 is safe
   without a change thanks to the anti-vacuity clause, so this is a
   tightening-for-tidiness question (new R3/F5 code, permanent at Q14),
   not a blocker. Owner R3/F5. Lowest priority of the four.
