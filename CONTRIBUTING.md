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
| `golden-vectors` | Q4 — the native runner discovers (directory walk, no hardcoded lists) and executes **every** committed vector under `testdata/vectors/<format-version>/`; malformed or unclassifiable files and empty discovery fail loudly. Schema + add-a-vector procedure: `testdata/vectors/README.md`. The append-only freeze guard is the separate `vector-freeze` lane (Q6). |
| `secret-guard` | Q2 — no vault-export/wallet-key file signatures anywhere in the checkout (PEM private keys, EVM keystore JSON, age/minisign secret keys, the reserved `ANTSEAL VAULT EXPORT` magic); self-tests each run by planting fakes in a temp dir (testdata/README.md, secret-material convention). |
| `audit-deny` | P13 — **cargo-deny only** (D19; pinned `=0.19.8`): `check advisories bans sources` against the committed `deny.toml` (licenses stubbed until Q29). Weekly no-push sweep: `.github/workflows/advisory-cron.yml`. Q10 owns permanent operation. |

Live lanes (wave 4 — P14/Q5):

| Lane | What it asserts |
| --- | --- |
| `wasm32-core-tests` | P14 — **NEW required context.** `antseal-core`'s `--lib` unit tests **execute** on `wasm32-unknown-unknown` (a libtest binary for that target has zero imports, so `scripts/wasm-test-runner.mjs` runs it under plain `WebAssembly.instantiate` in node; wired as cargo's `runner` in `.cargo/config.toml`). Because the target has no stdio, the runner also asserts an in-memory **execution witness** — "all tests passed" and "zero tests ran" are otherwise indistinguishable. Second step: `scripts/wasm-toolchain-audit.sh` (getrandom recipe per wasm32 graph + wasm-bindgen crate↔CLI pin equality). Doc: [docs/wasm-toolchain.md](docs/wasm-toolchain.md). |
| `wasm-bitmatch` | Q5 — every committed golden vector executed through `antseal_core::test_util::vectors` produces a **byte-identical** transcript (report bytes + per-vector recomputed digests, SHA-256 included) natively and under wasm32. Harness: `crates/wasm-bitmatch` (test-only, no wasm-bindgen); its `build.rs` embeds vectors by walking `testdata/vectors/`, so **new vectors need no lane change**. The lane **self-tests first, every run**: an injected wasm32-only divergence must turn the comparison red before a green comparison is trusted (`./scripts/wasm-bitmatch.sh --self-test`). **[R22/D18, 2026-08-12]** This row used to add "D18 stays free"; D18 is resolved, and this job now carries a **second, unrelated property** at no new required context: the shipped page module's **import allow-list** (`scripts/wasm-imports.mjs`, D18 §5 R7). The bit-match proves the two builds agree; the allow-list proves `crates/antseal-wasm` cannot ask the browser for anything R22 says it must not. It self-tests first too — a planted `env.fetch` import must be refused by name. |

Live lanes (wave 5 — Q6):

| Lane | What it asserts |
| --- | --- |
| `vector-freeze` | Q6 — **NEW required context.** Per format version, `testdata/vectors/v<n>/FROZEN.sha256` pins the exact bytes of every committed vector **and** is that version's must-exist list: `golden-vectors` can only fail on files it finds, so a **deleted** vector is caught here, as is a committed vector left *outside* the manifest. Two independent layers: coreutils `sha256sum -c` (no shared code with antseal) and `crates/antseal-core/tests/vector_freeze.rs` (directives, misfiled/unfrozen/stray classes, per-version retention, `#! pending` must-exist obligations). **Self-tests first, every run**: a mutated and a deleted vector must both turn the digest check red (`./scripts/vector-freeze.sh --self-test`). Add a vector with `./scripts/vector-freeze.sh --update`. Contract: `testdata/vectors/README.md`; retention policy: `testdata/README.md`. |
| `tamper-matrix` | Q7 + Q8 — **mount point claimed** (job id and name unchanged). Q7: every registered mutation row produces exactly its expected stable code / verdict state, outcomes are pairwise distinct across domains, no row panics. Q8: `testdata/tamper/MATRIX.json` maps MVP-SPEC.md line 168's enumeration **1:1** onto implemented rows — each family's `spec_quote` must be a literal substring of that spec line, every spec case is implemented or carries a `pending` marker naming its owning task, every implemented row is mapped or declared in `project_added` with a justification, and deliberate non-rows are recorded. **Zero pending is Q14's gate condition**, printed every run. See `testdata/tamper/README.md`. |

Live lanes (wave 6 — F14):

| Lane | What it asserts |
| --- | --- |
| `cross-check` | F14 (D31) — **NEW required context**, and an input to the Q14 format freeze. Entry point `./scripts/cross-check.sh`; Q11 adds the non-CBOR surfaces to the same script. Today: a **second implementation** is run over every committed vector that carries a diagnostic sidecar and must agree with the **committed bytes** — render-and-compare per strict-decode layer, re-encode, `SHA-256` of the envelope's key-0 byte string == `work_id`, `SHA-256` of the whole envelope == `anchor_digest`. **D31's role split is the point**: `cbor2 ==6.1.3` **decodes only** (its canonical mode is RFC 7049 length-first key order, coinciding with §4.2.1 only over today's uint keys), while the **RFC 8949 §4.2.1 encoder and the canonicality judgement are ours**, written in the checker. It never runs our Rust encoder: an expectation produced by our own codec would make the check a tautology. That is tier **T1**, which cannot see a *shared misreading of the spec* — so each run opens with a **T0 oracle**, the RFC 8949 Appendix A worked examples in both directions. It also confirms F15's `testdata/tamper/format/` fixtures are non-canonical **for the reason they claim**, and that the schema-level ones are perfectly good CBOR. **Self-tests first, every run**: the checker sweeps **every in-scope document**, planting seven mutations of a real committed case in each — including a sidecar whose entries are correct but **reordered** — plus one wrong RFC expectation per run, and every one must go red (`./scripts/cross-check.sh --self-test`). Q130 made the totals **computed from the run**, so they scale with the in-scope set and are stated only by the checker's printed summary, never here. `cbor2` is hash-pinned in `requirements-crosscheck.txt` and never enters a Cargo manifest (enforced by a test). Locally an unprovisioned cbor2 is a visible SKIP with the fix printed (`--setup` needs no pip); in CI `--require` makes it a failure. **New vectors need no lane change** — discovery is a directory walk, scope is "commits a diagnostic sidecar", and the script iterates `testdata/vectors/v*/`. Contract: [docs/testing/cbor-cross-check.md](docs/testing/cbor-cross-check.md). |

Live lanes (wave 6 — F17/Q9):

| Lane | What it asserts |
| --- | --- |
| `fuzz-smoke` | Q9 — **mount point claimed** (job id and name unchanged, so the required-status context set is unchanged at 16). Builds the four cargo-fuzz targets — F17's `manifest_decode` / `bundle_decode` / `codec_round_trip` and R10's `verify_bundle` — and fuzzes each for 90 s over the committed seed corpora (`testdata/fuzz-seeds/`). **Self-tests first, every run**: `scripts/fuzz.sh selftest` arms a permanent env-gated tripwire so each target panics on its first input, and the lane fails unless the crash is caught *and* a reproducer artifact is written — only then is a clean run evidence. Crash artifacts upload on failure. Nightly long run with corpus persistence: `.github/workflows/fuzz-nightly.yml` (scheduled, never a PR context). Driver `scripts/fuzz.sh`; doc [`docs/testing/fuzzing.md`](docs/testing/fuzzing.md). |

**No mount-point lanes remain**: every Q1 placeholder has been claimed.
cargo-fuzz needs nightly, so a second dated toolchain pin lives in
`fuzz/rust-toolchain.toml` and governs `fuzz/` only — the workspace pin
(= the MSRV) is untouched.

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

The owning task (remaining: Q7/Q9 — Q4, P13 and Q5 claimed theirs):

1. replaces the placeholder step body of its job in `ci.yml` with the real
   steps (checkout → rustup-from-toolchain-file → `rust-cache` → content,
   matching the existing lane pattern);
2. keeps the job id and `name:` **byte-identical** — the name is a
   required-status context;
3. moves the lane from "mount-point" to "live" in the tables above and
   records the change in [docs/ci-verification.md](docs/ci-verification.md);
4. adds any genuinely new check as a **new** job instead of folding it into
   an existing lane.

### Gate feature policy (S22)

`scripts/local-gate.sh` no longer runs `--all-features`. Since P16 landed
`devnet-launcher/devnet` and S5 landed `antseal-net/ant-backend`, that flag
pulled the whole upstream stack — **475 packages against the default 120**,
the two numbers `./scripts/ci-lanes.sh dep-graph` prints on every run — into
a gate that has to stay minutes long on a 2-core host, for every change
including a docs-only one. That is the cost the containment design exists to
avoid, paid back in the one place it was supposed to be avoided.

The heavy paths are **moved, not dropped**:

| Tier | What | When | Cost |
| --- | --- | --- | --- |
| 1 | `--workspace` with every **light** feature (`GATE_LIGHT_FEATURES` in `local-gate.sh`) | always | minutes |
| 2 | each **heavy** feature path per package: `antseal-net --features ant-backend`, `antseal-cli --features ant-backend`, `devnet-launcher --features devnet` (clippy + tests) | when a storage-touching path changed — the same list as the devnet E2E gate below | tens of minutes |
| 3 | the devnet E2E gate (`scripts/e2e-devnet.sh`) | same trigger | tens of minutes + a booted devnet |

Tier 2 is decided from the diff against `main`, not from memory:
`scripts/gate-features.sh --needs-heavy`. Force it with
`ANTSEAL_GATE_HEAVY=1` (or off with `=0`) and change the base with
`ANTSEAL_GATE_BASE`. If it cannot decide (no such ref), it says so and the
gate prints a visible SKIP — never a quiet pass.

**Adding a feature to any crate is a gate change.** `gate-features.sh
--check-partition` runs on every gate and fails unless every feature declared
by every workspace member is compiled by some tier: put it in
`GATE_LIGHT_FEATURES` (tier 1) or in `HEAVY_FEATURES` + `HEAVY_LANES` (tier
2). It also fails on a stale gate entry and on a `HEAVY` entry whose feature
no longer exists. That guard is the whole safety argument for dropping
`--all-features`, so it self-tests four planted faults first, every run.

Two things this policy deliberately does **not** rely on:

- **`--all-features` as a proof.** It compiles the *union* of features, which
  is not the same as compiling each configuration: workspace feature
  unification can hide a package that does not build with only its own
  feature on — the shape a consumer actually gets. Tier 2 is both cheaper
  when it runs and a stricter statement.
- **`dep-graph` as a substitute for tier 2.** P20's containment rules read
  `cargo tree`/`cargo metadata`: they prove the heavy graph stays *out of the
  default build*, and they never compile a line of feature-gated code. Keep
  them (they cost seconds); they cannot see a feature-gated path that stopped
  building.

### No real anchor network in tests (Q16)

**No automated test in this workspace may contact a real anchor endpoint** —
no TSA, no OpenTimestamps calendar, no esplora, no Arbitrum RPC. These are
other people's rate-limited services (SwissSign ~10/day, Sectigo ~15 s
spacing, `zeitstempel.dfn.de` non-commercial only), and a per-PR lane firing
on every push is an abuse problem before it is a flakiness problem.

This is **enforced**, not requested. `antseal_anchor::http::offline` refuses
any endpoint that is not a loopback IP literal from inside the HTTP
substrate, before DNS. Two arms:

- in `antseal-anchor`'s own unit tests the compiler arms it and there is **no
  off switch**;
- everywhere else — notably `antseal-cli/tests/*.rs`, which link the crate's
  ordinary build — `ANTSEAL_NO_REAL_ANCHOR_NETWORK` arms it. Every workflow
  sets it at workflow level and `scripts/local-gate.sh` exports it;
  `scripts/ci-lanes.sh anchor-net-policy` is red if either stops.

Practical consequences:

- **Drive stubs, not endpoints.** `antseal_anchor::testing::stub` binds
  `127.0.0.1:0` and `testing::replay` serves committed captures. A test that
  reaches a production default URL now fails with `RealNetworkDenied`
  naming the endpoint — that is the gate working, not a broken test.
- **Adding a URL to an existing endpoint constant** needs nothing: the gate's
  walk covers it by value.
- **Adding a new URL-valued `pub const`** turns the lane red until it is named
  in `crates/antseal-anchor/src/http/offline.rs`'s `every_default_endpoint()`.
- **Adding a second HTTP client** anywhere in the workspace is refused: it
  would route around the gate, and no other lane would see it.
- **Need a real run?** It is a maintainer protocol, never a test and never
  `#[ignore]`d: [docs/anchors/real-smoke-runbook.md](docs/anchors/real-smoke-runbook.md).
  Consent, rate-limit spacing and fixture recording are all mandatory there.

Policy in full:
[docs/testing/anchor-ci-policy.md](docs/testing/anchor-ci-policy.md).

### Devnet E2E gate (D52)

The M1 storage E2E does **not** run as a per-PR CI job. Decision
[D52](docs/decisions/D52-devnet-e2e-venue.md) puts it in two places:

| Venue | What | Enforcement |
| --- | --- | --- |
| `./scripts/e2e-devnet.sh` | **Required local gate** before merging a storage-touching change. Boots the P16 devnet ([docs/devnet/local-devnet.md](docs/devnet/local-devnet.md)), runs the registered suites, captures node + Anvil logs (redacted) and writes a dated evidence line under `target/e2e-devnet/`. | Convention + recorded evidence, on the Q14 format-freeze model |
| `devnet-e2e-cron` | **Scheduled, non-required** hosted job (weekly + `workflow_dispatch`), reduced node count, same script bytes. | Never a PR status context; the required-context set stays at 19 |

**A change is storage-touching — and the gate is mandatory — when it touches
any of:**

- `crates/antseal-net/**` (the adapter, EVM half, quote/receipt/live paths);
- `crates/antseal-cli/src/pipeline/**` (seal, journal, resume, consent) or
  `crates/antseal-cli/src/vault/wallet.rs`;
- `crates/devnet-launcher/**`, `scripts/devnet/**`, or
  `scripts/e2e-devnet.sh` itself (a change to the gate is a change the gate
  must survive);
- any pin move in the upstream payment stack — `ant-core`, `ant-protocol`,
  `alloy`, `evmlib` (dependency-policy §4 already lists "devnet E2E for
  ant-core" in the bump checklist).

Run it, and record the evidence line it prints in the PR/wave record:

```bash
./scripts/e2e-devnet.sh                 # default 14 nodes, boots and tears down
./scripts/e2e-devnet.sh --nodes 5       # smoke preset on a loaded host
./scripts/e2e-devnet.sh --plan          # what would run; no devnet, no cargo
ANTSEAL_GATE_E2E=1 ./scripts/local-gate.sh   # the whole gate, E2E included
```

`scripts/local-gate.sh` always runs the gate's **self-test** (seconds, no
devnet) and prints a SKIP line for the gate itself; the SKIP is the reminder,
not permission.

**PENDING is not a pass — and since S32 it is a failure.** Every registry row
is live (S17/S18/S19 landed 2026-08-02), so the latch is **armed by default**:
a `PENDING` verdict exits 1. The declaration is still checked in both
directions — a suite that exists while its row says pending is a hard failure
("move the row to `live` in the commit that lands the suite"), and so is a row
that says `live` for a suite that has vanished.

Declaring a row *before* writing its suite is still the right thing to do, and
`--allow-pending` is how you do it:

```bash
./scripts/e2e-devnet.sh --allow-pending  # a row is declared, its suite is not written yet
```

That flag is typed on purpose, which is the whole difference from a default.
`--require-suites` still works and still means "armed"; it is now a no-op
restatement of the default rather than the thing that switches it on.

**Triage of the scheduled leg** (D52 residual risk 2): a red scheduled run
gets a tracking note in the next wave's bookkeeping; **two consecutive reds
block storage-wave starts** until diagnosed.

**Promote-to-required trigger** (D52 Decision 3 / Adversarial test 4): a plan
upgrade (Pro) or the Q65-gated public flip makes required contexts real;
then, after **≥ 20 clean scheduled runs with warm runtime ≤ 15 min**, the
scheduled lane may be added to the branch-protection payload
([docs/ci-verification.md](docs/ci-verification.md), Maintainer runbook).
Not before — and no self-hosted runner unless a second, non-dev machine
materialises, and then only for the scheduled slot.

## PR checklist

- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
      `cargo test --workspace --locked` green locally
- [ ] `cargo build -p antseal-core --target wasm32-unknown-unknown` green —
      antseal-core stays WASM-safe (no I/O, async-runtime, or network
      crates in its normal dependency graph)
- [ ] `./scripts/wasm-tests.sh --check` green (needs node ≥ 18) — antseal-core's
      unit tests still **run** on the verifier's target, and no unconfigured
      `getrandom` entered a wasm32 graph
      ([docs/wasm-toolchain.md](docs/wasm-toolchain.md)). **Q125: the local
      gate now runs this for you** as its `wasm32-tests` lane whenever the diff
      touches anything that can move wasm32 behaviour — force it with
      `ANTSEAL_GATE_WASM=1`, suppress it with `=0`. The gate's other wasm32
      lane, `wasm32-build`, is a `cargo build` and proves nothing about
      execution; that conflation cost a CI red at `6f69e1a`
- [ ] `./scripts/wasm-bitmatch.sh` green — the WASM build still bit-matches
      native verification over every committed golden vector. **Any PR that
      adds a vector or touches a verification path must show this lane
      green**; a byte difference is a format-correctness incident, not a
      flake ([crates/wasm-bitmatch/README.md](crates/wasm-bitmatch/README.md)).
      **Q128: the local gate now runs this for you** as its `wasm-bitmatch`
      lane — force it with `ANTSEAL_GATE_BITMATCH=1`, suppress it with `=0`.
      The trigger is this checkbox's own sentence turned executable: "adds a
      vector" is `testdata/vectors/`, "touches a verification path" is
      `crates/antseal-core/`, plus the harness, the lockfile and the wasm32
      toolchain config. Note it is a **separate** predicate from
      `wasm32-tests` above and asymmetric to it on purpose — a vectors-only
      change fires this lane and not that one, because `build.rs` walks
      `testdata/vectors/` and the PQC suite does not read a vector. The gate
      runs the lane's injected-divergence `--self-test` first, exactly as CI
      does, and runs the *trigger's* own guard
      (`./scripts/wasm-bitmatch.sh --trigger-self-test`, milliseconds)
      unconditionally — a path list that stopped matching would otherwise
      render the lane `n/a` for ever and silence its own guard
- [ ] **Storage-touching change?** (the path list under "Devnet E2E gate")
      Then `./scripts/e2e-devnet.sh` green locally and its evidence line
      recorded. `PENDING` is not a pass
- [ ] **Anchor-touching change?** `./scripts/ci-lanes.sh anchor-net-policy`
      green (seconds, no cargo) — no test reaches a real TSA, calendar,
      esplora or Arbitrum RPC, and the arming is still in place
      ([docs/testing/anchor-ci-policy.md](docs/testing/anchor-ci-policy.md))
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
