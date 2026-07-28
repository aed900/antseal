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

## CI lanes

`.github/workflows/ci.yml` runs on every PR and on push to `main`. Every
job `name:` is a (future) **required status context** — the branch-protection
runbook in [docs/ci-verification.md](docs/ci-verification.md) lists the
exact context set — so lanes are **never renamed** once landed. Extend CI by
**adding** small named jobs, never by folding steps into an existing lane
(convention in the workflow header).

Live lanes (P8):

| Lane | What it asserts |
| --- | --- |
| `fmt` | `cargo fmt --check` |
| `clippy` | `cargo clippy --all-targets --locked -- -D warnings` |
| `test` | `cargo test --workspace --locked` |
| `wasm32-core` | `antseal-core` builds for `wasm32-unknown-unknown` |
| `core-dep-graph` | `antseal-core`'s normal dep graph stays I/O/async/network-free |

Live lanes (Q1):

| Lane | What it asserts |
| --- | --- |
| `cross-os-linux` / `cross-os-macos` / `cross-os-windows` | The cross-platform-sensitive suites (naming convention below) pass identically on all three GitHub-hosted OSes. Populated since Q4 (the `vector_` golden-vector suite); grows further with G3 (`corpus_`). |

Live lanes (wave 2 — Q2/Q4/P13):

| Lane | What it asserts |
| --- | --- |
| `golden-vectors` | Q4 — the native runner discovers (directory walk, no hardcoded lists) and executes **every** committed vector under `testdata/vectors/<format-version>/`; malformed or unclassifiable files and empty discovery fail loudly. Schema + add-a-vector procedure: `testdata/vectors/README.md`. Q6 adds the append-only freeze guard. |
| `secret-guard` | Q2 — no vault-export/wallet-key file signatures anywhere in the checkout (PEM private keys, EVM keystore JSON, age/minisign secret keys, the reserved `ANTSEAL VAULT EXPORT` magic); self-tests each run by planting fakes in a temp dir (testdata/README.md, secret-material convention). |
| `audit-deny` | P13 — **cargo-deny only** (D19; pinned `=0.19.8`): `check advisories bans sources` against the committed `deny.toml` (licenses stubbed until Q29). Weekly no-push sweep: `.github/workflows/advisory-cron.yml`. Q10 owns permanent operation. |

Live lanes (wave 4 — P14):

| Lane | What it asserts |
| --- | --- |
| `wasm32-core-tests` | P14 — **NEW required context.** `antseal-core`'s `--lib` unit tests **execute** on `wasm32-unknown-unknown` (a libtest binary for that target has zero imports, so `scripts/wasm-test-runner.mjs` runs it under plain `WebAssembly.instantiate` in node; wired as cargo's `runner` in `.cargo/config.toml`). Because the target has no stdio, the runner also asserts an in-memory **execution witness** — "all tests passed" and "zero tests ran" are otherwise indistinguishable. Second step: `scripts/wasm-toolchain-audit.sh` (getrandom recipe per wasm32 graph + wasm-bindgen crate↔CLI pin equality). Doc: [docs/wasm-toolchain.md](docs/wasm-toolchain.md). |

Mount-point lanes (Q1 — placeholder jobs whose content lands with the named
task; **a green mount-point lane asserts nothing until then**):

| Lane | Content lands at |
| --- | --- |
| `wasm-bitmatch` | Q5 — WASM verification output byte-matches native over every vector |
| `tamper-matrix` | Q7 — every registered mutation fails with its distinct expected error; no panics (Q8 tracks completeness) |
| `fuzz-smoke` | Q9 — fixed-budget per-PR cargo-fuzz smoke (nightly long run is a separate scheduled workflow) |

### Cross-OS suite naming (reserved test-name markers)

A test belongs to the cross-OS suite **by name**: any test whose
fully-qualified libtest name (module path + fn name) contains

- `corpus_` — UTF-8 canonicalization corpus tests (G3), or
- `vector_` — golden-vector runs (Q4)

is run by the `cross-os-*` lanes on linux, macOS, and Windows via

```
cargo test -p antseal-core --locked -- corpus_ vector_
```

(libtest substring filters, OR-combined) and **must be byte-deterministic
across OSes**. The markers are reserved: do not use `corpus_`/`vector_` in
the name of any test outside these two suites — a matching name *is*
membership. Zero matches is a passing state for the *cross-os* lane by
design (`corpus_` is empty until G3); the dedicated `golden-vectors` lane
by contrast **fails** on an empty `vector_` set — the Q4 runner must
always match.

Cross-OS suites live in `antseal-core` — canonicalization and vector
verification are core by architecture, and the 3-OS lane deliberately does
not build the net/anchor dependency stacks. A future suite that cannot live
in `antseal-core` extends the lane's package list; that edit belongs to the
task landing the suite.

Fixture bytes under `testdata/` are checkout-stable on every OS via
`.gitattributes` (`testdata/** -text`) — required because the Windows
runner image sets `core.autocrlf=true`. Never remove that guard.

### Claiming a mount point

The owning task (remaining: Q5/Q7/Q9 — Q4 and P13 claimed theirs):

1. replaces the placeholder step body of its job in `ci.yml` with the real
   steps (checkout → rustup-from-toolchain-file → `rust-cache` → content,
   matching the existing lane pattern);
2. keeps the job id and `name:` **byte-identical** — the name is a
   required-status context;
3. moves the lane from "mount-point" to "live" in the tables above and
   records the change in [docs/ci-verification.md](docs/ci-verification.md);
4. adds any genuinely new check as a **new** job instead of folding it into
   an existing lane.

## PR checklist

- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
      `cargo test --workspace --locked` green locally
- [ ] `cargo build -p antseal-core --target wasm32-unknown-unknown` green —
      antseal-core stays WASM-safe (no I/O, async-runtime, or network
      crates in its normal dependency graph)
- [ ] `cargo test -p antseal-core --lib --target wasm32-unknown-unknown
      --locked` green (needs node ≥ 18) and
      `./scripts/wasm-toolchain-audit.sh` green — antseal-core's unit tests
      still **run** on the verifier's target and no unconfigured `getrandom`
      entered a wasm32 graph ([docs/wasm-toolchain.md](docs/wasm-toolchain.md))
- [ ] No version requirement outside `[workspace.dependencies]`;
      `Cargo.lock` updated and committed together with any manifest change
- [ ] `cargo deny --locked check advisories bans sources` green with the
      pinned cargo-deny (`=0.19.8`, docs/dependency-policy.md §5) — new
      advisories need an assessment, never a silent ignore
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
