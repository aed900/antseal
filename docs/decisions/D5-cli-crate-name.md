# D5 — CLI crate published name

- **Status: RESOLVED (recorded deferral)**
- **Date: 2026-07-27**

## Context

The spec tree (MVP-SPEC.md lines 44–58) is normative: crate
`crates/antseal-cli` with binary target `antseal`. But `cargo install
antseal` UX argues for eventually publishing the CLI *as* the bare product
name. tasks/P.md P2 Notes direct: record the disagreement only (spec tree
stays normative), reserve both names either way.

## Decision

1. **The spec tree stays normative now**: the workspace crate is
   `antseal-cli` with `[[bin]] name = "antseal"` (implemented in P5,
   commit `3d3fe64`).
2. **BOTH `antseal` and `antseal-cli` get reserved at P2** (the bare name
   is in the P2 reservation set regardless of how this resolves).
3. **Whether the CLI publishes under the bare name is deferred to release
   (Q31 / M4)** — the decision has zero cost until first real publish,
   because reservation covers both names and the binary name (`antseal`,
   what users actually type) is identical under either choice.
4. Per P2's Notes, this is recorded as a **spec disagreement note, not a
   spec change**: if at Q31 the CLI publishes as bare `antseal`, that is a
   deliberate divergence from the spec tree's crate naming, flagged then.

## Evidence

- Research memo (13:44:34Z–13:44:39Z): both `antseal` and `antseal-cli`
  free on crates.io — reserving both is possible today (pending D1-final).
- Precedent: publishing a CLI under the bare product name while the library
  family keeps `-core`/`-net` suffixes is common Rust practice; nothing in
  the spec's formats or flows depends on the CLI *crate* name (only the
  binary name `antseal` appears in user-facing docs/flows).

## Consequences

- **P2**: the reservation set is five crates — `antseal`, `antseal-core`,
  `antseal-anchor`, `antseal-net`, `antseal-cli` — encoded in
  `scripts/reserve-crates.sh` and the P2 runbook.
- **Q31 (M4 release)**: makes the final call. If bare-name publish is
  chosen, the placeholder `antseal` 0.0.0 is superseded by the CLI's real
  versions; if not, `antseal` remains a reserved placeholder (or becomes a
  facade/doc crate pointing at `antseal-cli`).
- **Propagation checklist**: the CLI *binary* name row (U) is independent
  of this decision; only the crates row (P) carries the deferral note.
