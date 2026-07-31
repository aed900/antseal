# D23 — Raw-mirror entry placement in manifest order

- **Status: RESOLVED — appended after the file's normal units (mirror is the file's last unit)**
- **Date: 2026-07-27**

## Context

A raw mirror is a full unit-table entry with its own work-global
`unit_id` "assigned in manifest order like any unit" (spec line 92), so
its placement inside the file's unit table determines id assignment and
therefore every per-unit derivation (`k_u`, `unit_salt`, AAD). Placement
is format-visible and **frozen forever** once the first real seal exists.
Register entry D23 (proposal: append after the file's normal units);
blocks G5, G7, G14; the F4 registry draft already records this form.

## Decision

Within each file's unit table:

1. all **normal** (canonical-domain for text / raw-domain for binary)
   units first, in ascending byte-range order — id order ≡ range order;
2. the **raw-mirror entry, if present, is the file's last unit**;
3. at most one mirror per file (mirror existence is the per-file
   predicate `raw_bytes ≠ canonical_bytes`).

The work-global `unit_id` counter walks files in manifest order and
units in the per-file order above, assigning strictly increasing
ordinals with no gaps.

## Rationale

1. All placements are cryptographically equivalent (ids only need
   global uniqueness — spec line 76), so the tiebreaker is structural
   simplicity: appending keeps the tiling set's id order identical to
   its range order, giving R3 and human readers one ordering to reason
   about instead of two.
2. Construction-order match: the mirror decision (`needs_mirror`) is
   computed from the finished canonical rendition, i.e. after the
   normal units are known — appending is the natural, allocation-free
   construction order for G14's assembly.
3. Ratifies the spec proposal and the committed F4 registry draft —
   zero divergence cost.

## Consequences

- G5's assignment algorithm and G7's entry construction implement this
  order; a G5 regression test pins interleaving across multiple files
  (normal…normal, mirror, then the next file's units).
- F5 documents the order in the manifest schema; the registry note in
  docs/format/registry-v1.md stands. Frozen at Q14 with the registry.
- R3's structural checks may rely on kind-exemption only (the tiling
  check ignores mirrors by `kind`, never by position) — position is a
  seal-side construction rule, not a verifier assumption, so a v1
  verifier stays correct even against hand-built manifests that violate
  the placement rule (they fail signature/commitment checks only if
  actually inconsistent).

## Amendment (2026-08-01, F40): clause 3 was unenforced, and the last bullet over-claimed

The 2026-07-31 adversarial code review (findings 1–3, `high`;
`docs/reviews/2026-07-31-adversarial-code-review.md`) found clause 3
("at most one mirror per file") **decided here, repeated as prose on
`FileEntry::raw_mirror`, and implemented by no layer** — while every
fixture and generation strategy produced 0 or 1 mirrors, so the suites
were structurally blind to it.

The final Consequences bullet's parenthetical — hand-built manifests
violating this decision's rules "fail signature/commitment checks only if
actually inconsistent" — was thereby **false for the multiplicity
dimension**: a file with units `{Normal, RawMirror, RawMirror}` failed
*nothing*. Verification rows 9–10 bind exactly one mirror to
`raw_commit`/canonicalization; tiling exempts mirrors by `kind`
(deliberately, per that same bullet); and the second mirror's own
sealer-chosen `unit_commit` opens fine — so a second, contradictory
"original" sat signed and anchored inside a clean-verifying bundle,
precisely what MVP-SPEC.md line 121's MUST exists to prevent. The
parenthetical is true of clause 1–2 (placement) violations only.

Since **F40**, clause 3 is enforced at F5: `FileEntry::new`
(`crates/antseal-core/src/manifest/body.rs`) rejects a second
`kind = raw-mirror` unit as `manifest-multiple-raw-mirrors` — a routine
post-freeze code append under D30 §3, positioned after D77's normal-units
check and before the coverage loop (the position argument is recorded at
the check site and pinned by
`the_mirror_count_rule_is_ordered_after_d77_and_before_coverage`).
Clauses 1–2 remain seal-side construction rules exactly as recorded
above: the verifier still locates the mirror by `kind`, never by
position — but the `find` is now total rather than first-wins, because
the multi-mirror shape is unrepresentable in any constructed or decoded
manifest. Consumer-side reconciliation of the two pickers that disagreed
while the shape was representable is **R53**.
