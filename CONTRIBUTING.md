# Contributing (stub — pre-M0)

The full guide lands with Q's M4 documentation work. What already binds
today:

## Ground rules

- `MVP-SPEC.md` is authoritative. Code/spec disagreements are flagged,
  never silently diverged from.
- The toolchain is pinned (`rust-toolchain.toml`,
  [docs/toolchain.md](docs/toolchain.md)) — build with the pin; CI does.
- No secret material (master secrets, unit keys, salts, wallet keys) in
  code, logs, error messages, or test fixtures. Ever.

## PR checklist

- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
      `cargo test --workspace --locked` green locally
- [ ] `cargo build -p antseal-core --target wasm32-unknown-unknown` green —
      antseal-core stays WASM-safe (no I/O, async-runtime, or network
      crates in its normal dependency graph)
- [ ] No version requirement outside `[workspace.dependencies]`;
      `Cargo.lock` updated and committed together with any manifest change
- [ ] **Does the PR touch any dependency version, the toolchain pin, or a
      pinned dev-tool version?** Then it is a bump PR: follow the
      deliberate-bump procedure and complete the checklist in
      [docs/dependency-policy.md](docs/dependency-policy.md) §4 (changelog
      review, RUSTSEC check, golden-vector re-run, devnet E2E for
      ant-core; toolchain bumps per
      [docs/toolchain.md](docs/toolchain.md))
- [ ] New or changed formats come with golden vectors and tamper-matrix
      cases (binding from M0 onward)

Commit messages: prefix with the owning task ID from `TODO.md`
(e.g. `P7: ...`).
