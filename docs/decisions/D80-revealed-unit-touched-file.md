# D80 — Must a revealed unit's owning file appear in `touched_files`?

- **Status: RESOLVED — YES, mandatory. Decided on spec evidence
  (MVP-SPEC.md line 95, corroborated by lines 121, 36, 38, 149).
  The rule is tier [R] — R4/R5 owns it, not F8**
- **Date: 2026-07-28** (decided with F8)

## Context

Surfaced 2026-07-28 from the D8 bundle pass (registry §13 item 10).
`full_reveals ⊆ touched_files` is already settled mandatory and is tier
[X] — both lists sit in the bundle, so F8 decides it without the
manifest. D80 is the weaker per-*unit* case: if a bundle reveals unit `u`
of file `F`, must `F` have a `touched_files` entry (path + `path_salt`)?

The framing on the register was a genuine trade-off — requiring it was
said to kill "path-hiding selective disclosure" (proving a paragraph
existed without disclosing which file held it). The evidence below shows
that framing overstates what path-hiding could actually hide, and that
the spec answers the question directly.

## Evidence

**1. The spec states the rule, using its own defining sentence for the
term `touched` (line 95):**

> `path_salt = HKDF(W, "path-salt", file_id)` (16 B) salts only
> `path_commit = SHA-256(0x05 ‖ path_salt ‖ path_utf8)` and **ships
> whenever any reveal *touches* the file** (so the recipient can verify
> the path).

`touches` is italicised at its defining use, and it is the same word
line 114 uses to name the bundle section ("per **touched** file {path,
`path_salt`}"). A reveal that discloses a unit of `F` touches `F`. The
parenthetical gives the purpose: the recipient of a reveal is expected to
be *able to verify the path* of what they received.

**2. The rendering taxonomy is binary, with no third state (line 121):**

> Every reveal displays position + total size (anti-out-of-context
> guardrail); unrevealed units render as sized blackout blocks;
> **unrevealed files render as committed placeholders (size only, path
> withheld)**.

Path is withheld for **unrevealed** files. A file with a revealed unit is
not unrevealed, so the spec provides no rendering for "revealed content,
path withheld" — a permissive reading would require inventing one.
Line 95 says the same thing from the other side: "bundle recipients see
**unrevealed** files only as committed placeholders".

**3. The product's own vocabulary is file-scoped.** `reveal` prints
"exactly which units (**file**, byte-range, size, snippet) will be
irreversibly disclosed" (line 36); `show` lists "every unit: **file**,
byte-range, size" (line 149); `verify` reports "what content is proven,
**its position in the sealed whole**" (line 38). The consent gate the
user passes to authorise a unit reveal names the file.

**4. Path-hiding would hide far less than the framing suggests.** The
plaintext manifest is embedded in **every** bundle, and its unit table is
nested inside file entries — so `unit_id → file_id` is visible to every
recipient, as are file count, sizes, and unit boundaries. The spec says
so explicitly (line 95): "Structure metadata (file count, sizes, unit
boundaries) *is* visible to bundle recipients — docs state this."
Omitting a `touched_files` entry therefore hides only the **filename**,
not the file's identity, size, or the revealed unit's position within it.
That is a thin privacy gain to buy with an explicit spec sentence.

## Decision

**Required.** For every revealed unit — covered or non-covered, normal or
raw-mirror — the owning file MUST have a `touched_files` entry.
Equivalently: `{ file_id(u) : u ∈ bundle.revealed } ⊆ touched_files`.

Recommended error (R's unprefixed namespace; **R4/R5 mints the final
name**, this record fixes the rule, not the spelling):
`revealed-unit-file-not-touched`, payload `{ unit_id, file_id }`.

## Rationale

Beyond the evidence: the direction is also the reversible one, and this
is the **opposite** asymmetry to D28's. **Adding** the requirement later
breaks bundles built without it; **dropping** it later breaks nothing.
Tolerant-now is the irreversible choice here. With the spec pointing the
same way, there is no reason to take the irreversible branch.

## Consequences

- **Tier [R], not [X] — F8 does not implement it.** Deciding a revealed
  unit's *owning file* requires the manifest's unit table, and **D78**
  forbids bundle schema validation from consulting the embedded manifest.
  So this cannot be a `bundle-` code: it is a verify-pipeline outcome,
  checked by R4/R5 after layer 2 decodes. F8 leaves the seam and nothing
  else.
- Distinct from the settled `full_reveals ⊆ touched_files` rule, which
  stays tier [X] and keeps its own `bundle-full-reveal-without-touched-file`
  code. The two are not redundant: a file may be *touched by a unit
  reveal* without being fully revealed.
- R5's bundle builder must add a `touched_files` entry for every file it
  reveals a unit of — the CLI already surfaces the file at the consent
  gate (line 36), so nothing new is disclosed that the user did not
  already approve.
- Q8 owes a tamper row: "revealed unit whose file has no `touched_files`
  entry".
- **Not** revisited for v1.1's `reveal --range`: a range reveal is a
  narrower disclosure of the same unit, so the same rule applies.
- If a genuine path-hiding product requirement ever appears, it needs
  more than dropping this rule — it needs the manifest to stop exposing
  the file/unit structure, which is a format-version-scale change and a
  documented deliberate disclosure (line 95).
