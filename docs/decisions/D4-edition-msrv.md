# D4 — Rust edition, toolchain pin, MSRV policy

- **Status: RESOLVED**
- **Date: 2026-07-27**

## Context

P6 required committing an exact stable toolchain pin (chosen at execution
time), the Rust edition, and the MSRV policy, with toolchain bumps governed
like dependency bumps (the M3 reproducible wasm-pack build makes the
toolchain version format-provenance-relevant).

## Decision

- **Edition 2024** (`[workspace.package] edition = "2024"`).
- **Toolchain pinned exactly to `1.92.0`** in `rust-toolchain.toml`
  (components `rustfmt` + `clippy`, target `wasm32-unknown-unknown`) —
  current stable at execution time.
- **MSRV = the pinned toolchain** (`rust-version = "1.92.0"` in
  `[workspace.package]`). The MSRV moves **only** via the deliberate-event
  bump procedure in
  [`docs/dependency-policy.md`](../dependency-policy.md) §4/§5 (see also
  [`docs/toolchain.md`](../toolchain.md)): `rust-toolchain.toml`,
  `rust-version`, and `clippy.toml` move together in one reviewed commit —
  never drive-by.

## Evidence

- Research memo (13:45:16Z–13:45:21Z): `ed25519-dalek` 3.0.0 declares MSRV
  **1.85**, 2.2.0 declares **1.81** — both ≤ 1.92, so the P11 decision
  (2.x vs 3.0.0) is unconstrained by our pin either way.
- Research memo (13:44:55Z–13:44:56Z): `ant-core` declares **no MSRV**
  (`rust_version: null` on every published version) — our own toolchain pin
  is the only MSRV authority in the graph.
- Edition 2024 is fully supported by 1.92.0; no dependency in scope
  requires a newer edition or toolchain.

## Consequences

- Implemented in P6 (commit `040566f`): `rust-toolchain.toml` +
  `docs/toolchain.md`; workspace manifests inherit
  `edition`/`rust-version`.
- CI takes the toolchain exclusively from `rust-toolchain.toml` (verified —
  no hardcoded version in `ci.yml`; see `docs/ci-verification.md`).
- R/Q consume the pin for the M3 reproducible wasm-pack build recipe; any
  toolchain bump before M3 re-verifies WASM bit-match per policy.
- P2 note: the placeholder reservation crates are standalone (outside this
  workspace) and deliberately use edition 2021 so they build on any ambient
  toolchain; the placeholders are metadata-only and get replaced by real
  publishes that inherit the workspace edition.
