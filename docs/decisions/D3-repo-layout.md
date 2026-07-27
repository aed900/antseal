# D3 — Repo root layout

- **Status: RESOLVED**
- **Date: 2026-07-27**

## Context

The spec's Architecture tree (MVP-SPEC.md lines 44–58) is rooted at
`antseal/`, while the greenfield directory is `/home/deb/Documents/code0`.
P4/P5 needed the call: is `/home/deb/Documents/code0` itself the workspace
root, or does it *contain* an `antseal/` subdirectory?

## Decision

**`/home/deb/Documents/code0` is the repo root AND the Cargo workspace
root; the repo root IS the spec tree's `antseal/`; no nested subdirectory.**
The GitHub repo name is `antseal` (since 2026-07-27 under the `aed900`
account), so the checkout directory name supplies the `antseal/` of the
spec tree wherever a fresh clone lands.

## Evidence

- Implemented in P4/P5 (commits `2d95f50`…`3d3fe64`): root `Cargo.toml`
  with `crates/antseal-{core,anchor,net,cli}`, `verifier-web/`, `testdata/`
  directly at the repo root — matching spec lines 44–58 with the root
  directory itself playing the `antseal/` role.
- A nested `antseal/` subdir inside the repo would have doubled the name in
  every path (`antseal/antseal/crates/…` on clone) for zero benefit.

## Consequences

- All tooling (CI, scripts, docs) addresses paths from the repo root;
  `rust-toolchain.toml`, `Cargo.lock`, `.github/` sit at the root.
- A D1 rename touches the GitHub repo name (redirects preserved) and
  nothing about the internal layout.
- The spec tree remains satisfied verbatim; no spec disagreement to record.
