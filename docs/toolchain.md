# Toolchain policy (P6)

## The pin

`rust-toolchain.toml` at the repo root pins the toolchain **exactly**:

- **channel = "1.92.0"** — an exact stable version, never a floating channel
  like `stable`. Local rustup and CI both resolve the toolchain from this
  file (CI runs `rustup show` after checkout so the file drives the
  install — no toolchain version is hardcoded in workflow YAML).
- **components** — `rustfmt`, `clippy` (the fmt/clippy CI lanes depend on
  them).
- **targets** — `wasm32-unknown-unknown` (the `wasm32-core` CI lane builds
  `antseal-core` for it from the stub stage onward; since P14 the
  `wasm32-core-tests` lane also **executes** antseal-core's unit tests on it
  — [wasm-toolchain.md](wasm-toolchain.md)).

## Edition

Rust edition **2024**, declared once in `[workspace.package]` in the root
`Cargo.toml` and inherited by every member crate.

## MSRV policy

**MSRV = the pinned toolchain (1.92.0), exactly.** For the MVP we support
building with precisely one toolchain version: the pin above. It is declared
as `rust-version = "1.92.0"` in `[workspace.package]` (inherited by all
crates) and mirrored in `clippy.toml` (`msrv`). The three declarations —
`rust-toolchain.toml`, `rust-version`, `clippy.toml` — must always move
together, in one commit.

MSRV moves **only** via a toolchain bump, and a toolchain bump is a
deliberate, reviewed event following the same bump procedure as dependency
pins — see [dependency-policy.md](dependency-policy.md) (release-notes
review, full CI including golden-vector re-runs once vectors exist, and an
explicit PR — never a drive-by).

## Why the toolchain version is format-provenance-relevant

At M3 the verifier web page ships `antseal-core` compiled to WASM via a
**reproducible wasm-pack build** whose output hash is published as page
provenance (MVP-SPEC.md — page provenance / reproducible build). The
compiler version is an input to that hash: change the toolchain and the
artifact changes. From M3 onward a toolchain bump therefore changes a
published, user-checkable artifact hash and must be treated with the same
care as a format change.

Consumers of this pin:

- **R** — the M3 reproducible wasm-pack build recipe pins this toolchain
  version (together with the wasm-pack/wasm-bindgen-cli pins, which P14
  deliberately did **not** land: the M0 wasm lanes use no wasm-bindgen at
  all, and pinning it would pre-empt D18 — rationale and the standing
  enforcement check in [wasm-toolchain.md](wasm-toolchain.md) §4).
- **Q** — CI lanes (including the native↔WASM bit-match lane) take the
  toolchain exclusively from `rust-toolchain.toml`.

## Cross-references

- [dependency-policy.md](dependency-policy.md) — pin governance and the
  bump procedure this policy defers to (P7).
- [wasm-toolchain.md](wasm-toolchain.md) — the wasm32 side: getrandom
  recipe, wasm32 test execution, the bit-match lane (P14/Q5).
- `.github/workflows/ci.yml` — CI honoring the pin via `rustup show` (P8).
