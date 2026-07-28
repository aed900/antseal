# D77 — Zero-non-mirror-unit file: **reject at F5 (schema)**

- **Status: RESOLVED — reject, at the manifest schema layer, with its own
  distinct code `manifest-empty-normal-units`**
- **Date: 2026-07-28**
- **Owning task: F5** (consumed by R3/R4 as defence-in-depth, F4 registry
  §7.3, Q7/Q8 rows)
- Surfaced 2026-07-28 by D28's planning pass (candidate 4,
  `docs/decisions/D28-full-reveal-strictness.md` lines 502–506), registered
  as the lowest-priority of the four.

## Context

D28's full-reveal predicate carries an anti-vacuity clause:

```text
full(F) ⟺ N(F) ≠ ∅ ∧ R(F) = N(F)
```

The `N(F) ≠ ∅` half exists because R3's tiling accepts a size-0 file with no
units, which would otherwise be *vacuously* fully revealed by every bundle
including one revealing nothing
(`crates/antseal-core/src/verify/file_stages.rs:36–42`, predicate at `:733`).
D28 was therefore safe without a fix, and registered the question as
tightening-for-tidiness.

D77 asks whether that shape should be rejected outright, and where.

## What the code does today

**The tiling hole is real and narrow.** `tile` runs a sortedness pre-pass,
then bounds, then a coverage sweep
(`crates/antseal-core/src/verify/structural.rs:318–346`). On an empty range
list all three loops are no-ops and the sweep ends at `cursor == 0`, so
`tile(&[], 0)` returns `Ok`. For `size > 0` it returns
`TilingViolationKind::Gap`. The hole is exactly `size == 0`.

**`check_tiling` filters by kind, so the hole is about *non-mirror* units.**
It collects `unit.kind == UnitKind::Normal` only
(`verify/structural.rs:277–281`); raw mirrors are exempt by kind, never by
position (`verify/structural.rs:36–45`; D23).

**F5 already rejects a file with zero units.** The unit table is nested
inside the file entry (registry §7.3 key 6), and `FileEntry::new` refuses an
empty one with `ManifestError::EmptyContainer { field: ContainerField::Units }`
→ code `manifest-empty-units`
(`crates/antseal-core/src/manifest/body.rs:686–690`;
`crates/antseal-core/src/manifest/error.rs:544`). `FileEntry::decode` routes
through `new` (`manifest/body.rs:870`), so constructible ≡ decodable — the
check cannot be bypassed by a decoded manifest.

**G5 never produces the shape.** `FileUnitPlan`'s normal-unit list is "never
empty — an empty file is one empty unit (MVP-SPEC.md line 78)"
(`crates/antseal-core/src/content/unit.rs:325`), and an empty `ranges` list
is coerced to `vec![ByteRange::empty()]` "rather than a unit-less file,
**which the format does not allow**" (`content/unit.rs:358–363`). Even the
degenerate BOM-only file — canonical rendition empty, mirror present — gets
**two** units, Normal `[0,0)` then the mirror
(`crates/antseal-core/src/content/mirror.rs:376–388`).

**C7 already treats "≥1 non-mirror unit" as an invariant.**
`FullFileRevealContext::attest` refuses an empty `all_non_mirror_units`,
documented as "every file tiles `[0, size)` with at least one unit, spec line
121; an empty attestation is vacuous and refused"
(`crates/antseal-core/src/crypto/disclosure.rs:262–264`).

## The registered shape is already closed. The live hole is a different one.

Both TODO.md and D28 describe the shape as "a hand-built **size-0 file with
zero units**". That shape **cannot reach R3 from a decoded manifest** — F5
rejects it as `manifest-empty-units` (above). D28's positive fixture
`degenerate-zero-unit-file` and R4's `zero_unit_file_is_not_vacuously_full`
(`verify/file_stages.rs:1451`) exercise it by hand-populating R's view types
(`verify/structural.rs:47–53`), not by decoding a manifest.

The hole that genuinely survives every layer is **a file whose entire unit
table is raw mirrors**:

| layer | verdict on `size = 0`, units = `[RawMirror]` |
|---|---|
| F5 `FileEntry::new` | **accepts** — `units` is non-empty; the coverage loop is satisfied because `is_covered(_, RawMirror) = false` (`manifest/body.rs:925–931`), so the mirror just needs a `unit_commit` |
| R3 `check_tiling` | **accepts** — the Normal filter yields `[]`, and `tile(&[], 0) = Ok` |
| R4 `classify_file_reveal` | **safe** — `total_non_mirror = 0` ⇒ `full = false` for every bundle (`verify/file_stages.rs:733`) |

`N(F) = ∅` with a non-empty unit table is what no record names, and it is the
only version of the question that is still open. Everything below is about
that shape.

## Can a legitimate sealer output reach it? No — doubly.

- A mirror exists **iff** raw ≠ canonical (`content/mirror.rs:104`,
  property-tested at `:566`). So the mirror asserts the file is *not* byte-empty.
- G5 emits the Normal `[0,0)` unit *as well as* the mirror for exactly this
  case (`content/mirror.rs:376–388`).
- Binary files never need a mirror at all (`content/mirror.rs:96–98`), so a
  mirror-only binary file is incoherent twice over.

The shape is unreachable by construction on the seal side and is therefore,
like D74's extraneous `s_root`, a state only a hand-built or relay-modified
manifest can occupy.

## What tolerating it actually costs

### 1. It re-creates, permanently, the exact condition D28 removed

With `N(F) = ∅`, `full(F)` is false for **every** bundle, forever. So
`canon_commit` and `raw_commit` for that file can never be opened by anyone:
rows 1–2 forbid `file_salt` on a `¬full` file
(`verify/file_stages.rs:58–59`), and row 7's concat is the only path to
either commitment (`verify/file_stages.rs:64`, D28 rationale 1).

That is verbatim the condition D28 called unacceptable — "two signed,
anchored, permanently stored fields a sealer may fill with anything"
(`docs/decisions/D28-full-reveal-strictness.md` lines 283–290). D28 removed
it for ordinary files by making full reveal strict. A mirror-only file
re-introduces it as a standing, per-file exemption, reachable by anyone who
can hand-build a manifest.

### 2. The report would be actively wrong, not merely empty

`FileReveal` carries `revealed_spans` and `unrevealed_spans` over non-mirror
units (`crates/antseal-core/src/verify/report.rs:313–319`). Both are empty
here, so the file renders with **no spans at all** — no content, no sized
blackout. Meanwhile `size = 0` makes the placeholder ("size only, path
withheld", `verify/report.rs:348–358`) say *empty file*, while the same
manifest's mirror carries `true_length = N > 0`
(`content/mirror.rs:20–24`; `manifest/body.rs:736–742`).

The report's structural guardrail is that "spans carry positions, files carry
total sizes, placeholders carry sizes — a renderer cannot omit what it does
not have" (`verify/report.rs:282–284`). This shape defeats it by supplying a
size that is a lie rather than by omitting one.

### 3. Three layers already paper over it

F5's `units.is_empty()`, C7's `attest` refusal, and D28's anti-vacuity clause
are three independent guards against a shape the schema permits. That is the
signature of a missing schema rule, not of a rule correctly placed.

## Options

- **A — reject at schema level (F5).** A file entry must contain at least one
  `kind = normal` unit.
- **B — reject at structural level (R3).** `check_tiling` rejects an empty
  Normal set.
- **C — tolerate and document.**

## Decision

**Option A — reject at F5**, with `ContainerField::NormalUnits` →
**`manifest-empty-normal-units`**.

## Rationale

1. **It is a manifest-only malformation, so it belongs to `manifest-`.**
   Deciding it needs the one file entry being decoded and nothing else — the
   same tier the registry assigns to "non-empty container", **[P]**
   (`docs/format/registry-v1.md:89`). D30 §2 makes `manifest-` mean
   "the embedded manifest is malformed on its own bytes"
   (`docs/testing/error-code-contract.md:29–49`); putting a bundle-free rule
   into R's unprefixed namespace would misfile it.
2. **Option B would not close the hole, only guard one path.** R3 consumes a
   hand-populated `ManifestView` projection (`verify/structural.rs:47–53`).
   A check there leaves F5 still *accepting and encoding* the body, so
   `work_id = SHA-256(manifest body)` could be computed over a body the
   format nominally allows and a mirror-only file could be signed and
   anchored. Rejecting at F5 makes the shape unrepresentable in any decoded
   manifest, which is the stronger location and is where the sibling
   `units.is_empty()` check already lives.
3. **It closes a gap between what the code claims and what it enforces.**
   `content/unit.rs:358–363` already asserts that a unit-less file is
   something "the format does not allow". F5 enforces that on the whole unit
   list; because mirrors are tiling-exempt by kind, it does not enforce it on
   the tiling domain. Option A makes the enforced rule match the stated one.
4. **House precedent, on the same question shape.** D74 rejected an
   unverifiable extra field in a format whose thesis is that the sealer is an
   adversary; D24 chose a hard error over a silent degenerate outcome. A file
   entry that contributes no canonical-domain evidence while carrying two
   unopenable content commitments is the same class of object.
5. **The strictness direction is the reversible one.** MVP-SPEC.md line 123
   makes format stability normative. Reject → tolerate is a legal future
   relaxation; tolerate → reject is not. No honest sealer emits this shape
   (above), so the strict rule costs the honest sealer exactly nothing.

## Cost, stated honestly

One permanent code (D30 §3, permanent at Q14), for a condition no honest
manifest can reach — the same price D74 paid, for the same reason. It also
falsifies a note in the registry's JSON mirror that assumed D77 needed no
registry change (below), which must be corrected rather than left stale.

## The patch instruction — implement exactly this

Docs-only decision; the edits below are the whole of the implementation and
carry no design freedom.

### 1. `crates/antseal-core/src/manifest/error.rs`

- **`ContainerField` (lines 198–207)** — append a fifth variant:

  ```rust
  /// A file's `kind = normal` units — a file must have at least one unit
  /// in its tiling domain (D77). Raw mirrors are tiling-exempt by kind
  /// (spec line 92), so a mirror-only file has no tiling domain at all
  /// and its `canon_commit`/`raw_commit` would be permanently unopenable.
  NormalUnits,
  ```

- **`ContainerField::ALL` (line 211)** — `[Self; 4]` → `[Self; 5]`, append
  `Self::NormalUnits` last (the array is order-significant only for test
  readability).
- **`Display` (lines 216–221)** — add `Self::NormalUnits => "normal units"`.
- **`code()` (lines 543–546)** — add
  `ContainerField::NormalUnits => "manifest-empty-normal-units"`.

The exemplar list picks the variant up automatically through
`ContainerField::ALL` (line 616), so the layer-1 pairwise-distinctness and
banned-prefix meta-tests (lines 662, 695) cover the new code with no edit.

### 2. `crates/antseal-core/src/manifest/body.rs` — `FileEntry::new`

Insert **immediately after** the existing `units.is_empty()` block (which
ends at line 690) and **before** the coverage loop (which begins at line 691):

```rust
if !units.iter().any(|unit| unit.kind() == UnitKind::Normal) {
    return Err(ManifestError::EmptyContainer {
        field: ContainerField::NormalUnits,
    });
}
```

`UnitKind` and `ContainerField` are already in scope (lines 46, 49); no new
imports.

**The position is frozen and observable, in both directions:**

- It must come **after** `units.is_empty()`, so a genuinely unit-less file
  reports `manifest-empty-units` and not the new code. Two codes for one
  input would break "one code per outcome a mutation can be pinned to"
  (`docs/testing/error-code-contract.md:26–27`).
- It must come **before** the coverage loop, so a mirror-only file reports
  the shape error rather than whichever per-unit `unit_commit` error a
  malformed mirror happens to trip first.

Extend the `# Errors` doc block (lines 667–677) with the new class.

### 3. `docs/format/registry-v1.md` — §7.3 key 6 (line 457)

Amend the presence/shape cell to read: `non-empty (empty file = one empty
unit, line 78); **at least one `kind = normal` unit [P]** — a mirror-only
file has no tiling domain (D77)`.

### 4. `docs/format/registry-v1.json`

The `fed_but_not_resolved_here` entry for D77 currently records
`"contribution": "... no registry change either way"`. That is now false.
Move D77 into `resolved_decisions` with the outcome and the registry-row
change, and drop it from `fed_but_not_resolved_here`.

### 5. `docs/testing/error-code-contract.md` §7

Append a dated line recording one new `manifest-` code
(`manifest-empty-normal-units`) and F's incremented count.

### 6. Tests

- One reject row in `crates/antseal-core/tests/manifest_schema.rs`, beside
  the existing `ContainerField::Units` cases (lines 646, 1067): a file entry
  whose only unit is a raw mirror, expecting
  `ManifestError::EmptyContainer { field: ContainerField::NormalUnits }`.
- One Q8 registry row in `testdata/tamper/MATRIX.json`, owned by F15,
  mutation "delete the file's only normal unit, leaving its raw mirror",
  expected `manifest-empty-normal-units`. It is a **project-added** row, not
  a spec-list row — MVP-SPEC.md line 168 does not enumerate it — so Q8's 1:1
  spec mapping stays honest, exactly as for D28's rows 1–2.

No existing fixture is a mirror-only file (`manifest/fixtures.rs:188` and
`verify/pipeline.rs:1195` both pair a mirror with Normal units), so nothing
breaks.

### 7. Do **not** remove the downstream guards

D28's anti-vacuity clause (`verify/file_stages.rs:733`) and R4's
`zero_unit_file_is_not_vacuously_full` test (`verify/file_stages.rs:1451`)
**stay**, and become defence-in-depth. R's view types are hand-populated
projections that no F5 check can constrain, so R must remain correct against
a view F5 would have rejected. Likewise C7's `attest` refusal
(`crypto/disclosure.rs:262–264`) is unchanged.

## Consequences — what this freezes

- **Every file in a decodable v1 manifest has ≥1 `kind = normal` unit.**
  Downstream code may rely on it for *reasoning*, but not for *safety* —
  see item 7.
- **One new permanent code**, `manifest-empty-normal-units`, in F's
  `manifest-` family. Verified new and pairwise distinct: no occurrence of
  `empty-normal` / `no-normal` / `normal-unit` / `NormalUnits` exists
  anywhere in the tree today, and it collides with none of the four existing
  `manifest-empty-*` codes nor with any `bundle-`/`crypto-`/`content-`/
  `fine-root-`/unprefixed-R code.
- **R3's `tile` is unchanged.** `tile(&[], 0) == Ok` stays true; it is simply
  no longer reachable from a decoded manifest. Changing it would alter the
  meaning of `TilingViolationKind::Gap` for no gain.
- **D28's predicate is unchanged.** `N(F) ≠ ∅` remains in the definition of
  `full(F)`; it merely stops being load-bearing.
- **No other format impact**: no new wire key, no new HKDF label, no new
  domain tag, no manifest field.

## Interaction with D82 (being decided in parallel)

They are **independent, and neither constrains the other's outcome** — but
D82's implementer should know the ordering.

- **D82** asks whether a *bundle's* `touched_files` may name a file with no
  revealed unit (path disclosed, nothing revealed). Bundle-side, R's
  unprefixed namespace.
- **D77** asks whether a *manifest's* file entry may have no unit in its
  tiling domain. Manifest-side, F's `manifest-` namespace.

The overlap is in the **report**, and it argues for rejecting D77 under
either D82 outcome:

- If **D82 resolves permissive** (path-only disclosure is legitimate), a
  tolerated D77 file would be a second, strictly worse spelling of the same
  shape: it also proves "a file by this path was part of the work", but its
  asserted `size = 0` is contradicted by its own mirror's `true_length`, so
  the placeholder carries a false size rather than a true one. D82 would be
  blessing a shape *by decision* while D77 admitted a degenerate variant *by
  omission*.
- If **D82 resolves reject**, tolerating D77 leaves a route to nearly the
  same disclosure through the manifest instead of the bundle.

**After D77 lands, D82's question gets cleaner**: every file reaching a
`touched_files` check has ≥1 normal unit, so the "no revealed unit" case
always has a real, non-empty, sized blackout to render — the degenerate
"nothing to show" case is gone from D82's option space before D82 chooses.
Rejecting D77 therefore *helps* D82 and forecloses nothing in it.

## Spec conformance

Consistent with the spec, not an extension of it. Line 78 says an empty file
is one empty unit; line 92 makes the raw mirror an *additional* unit in a
different byte domain, exempt from tiling; line 121 states the tiling
invariant over the non-mirror ranges. A file with no non-mirror unit has no
tiling domain for line 121 to speak about and contradicts line 78's rule that
even the empty file has a unit. Rejecting it is the reading in which the file
entry's unit table is required to be meaningful — the same closure F5 already
applies to unknown keys and D74 to unlisted material.

## Recorded outcome

**2026-07-28 — RESOLVED: reject at F5**, code `manifest-empty-normal-units`
(`ContainerField::NormalUnits`), inserted in `FileEntry::new` after the
`units.is_empty()` check and before the coverage loop.

The recorded lean ("hardening, not a blocker") is **confirmed as to urgency**
but **corrected as to substance**: the shape TODO.md and D28 describe — a
size-0 file with *zero units* — is already closed by F5's existing
`manifest-empty-units` check and never reaches R3 from a decoded manifest.
The shape that genuinely survives every layer is the **mirror-only** file
(`N(F) = ∅` with a non-empty unit table), which no record had named, and
which permanently un-opens two signed, anchored commitments — the precise
condition D28 rationale 1 exists to prevent. It is still not a blocker, but
it is a hole rather than tidiness, and the code is format-permanent at Q14,
so it must land before then.
