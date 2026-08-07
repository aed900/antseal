# The no-real-anchor-network policy

> **Owning task: Q16** (`tasks/Q.md`), milestone **M2**.
> Enforcement: `crates/antseal-anchor/src/http/offline.rs` (runtime) and
> `scripts/check-anchor-net.py` (static, via `scripts/ci-lanes.sh
> anchor-net-policy`).
> The real-endpoint protocol this policy carves out is
> [`../anchors/real-smoke-runbook.md`](../anchors/real-smoke-runbook.md).

**No automated test in this workspace may contact a real anchor endpoint.**
Not in CI, not on a contributor's machine, not "just this once to check the
fixture is still valid".

## 1. Why this is a control and not a courtesy

The endpoints an anchor test would reach are other people's rate-limited
services, most of them free-of-charge and several with terms that a CI system
hammering them would breach (MVP-SPEC.md line 189, Risks):

| endpoint | recorded constraint |
| --- | --- |
| SwissSign | ~10 requests/day |
| Sectigo | ~15 s minimum spacing |
| `zeitstempel.dfn.de` | non-commercial use only |
| FreeTSA, DigiCert | free tier, no published quota — which is not the same as no quota |
| OTS calendars | free public infrastructure aggregating for everyone |

A per-PR lane firing on every push multiplies whatever a single run costs by
the project's commit rate. That is an abuse problem first and a flakiness
problem second — and the flakiness half is not small either: a suite that
depends on someone else's uptime goes red for reasons no contributor can fix
or reproduce.

## 2. Why prose was not enough — the recorded violation

Before Q16 the policy existed in at least five places
(`crates/antseal-anchor/src/testing.rs`, `.../testing/stub.rs`,
`.../testing/replay.rs`, `testdata/anchors/README.md`, and
`crates/antseal-cli/tests/config_file.rs`), every one of them arguing that it
held **by construction**: the stubs bind `127.0.0.1:0`, and a loopback
listener cannot reach a public host.

That argument is true about the stubs and says nothing about the tests. A
test is not obliged to use a stub. The violation is on the record at
`crates/antseal-anchor/src/ots/engine.rs`, on the `upgrade_pending_with`
seam: the suite drove the **production** upgrade path with the committed
`.ots` artifact, whose pending URIs are the real calendar hostnames, and
A42's allowlist admits them by design. The suite contacted live calendars on
every run, in CI and on every contributor's machine, and **every assertion
passed**. It was fixed with a `#[cfg(test)]` seam — a convention, which
constrains the call site that was fixed and nothing else.

So the policy needed a mechanism that makes the call *fail*.

## 3. The mechanism

### 3.1 The gate (runtime — this is the enforcement)

`antseal_anchor::http::offline` is consulted inside `HttpClient::attempt`,
the single function in this workspace that hands a URL to `ureq`. When the
gate is armed, an endpoint whose host is not a loopback **IP literal**
(`127.0.0.0/8`, `::1` — never the *name* `localhost`) is refused with
`AnchorHttpError::RealNetworkDenied` **before any address is resolved**: no
DNS query, no TCP connection, no TLS handshake.

The refusal is classified `RetryVerdict::Stop`. That arm matters as much as
the refusal itself — a `Retry` would turn one refused request into three
against exactly the endpoints least able to absorb it.

Two arms:

| build | armed by | disarmable? |
| --- | --- | --- |
| `cfg(test)` — antseal-anchor's own unit tests | the compiler | **no** |
| everything else | `ANTSEAL_NO_REAL_ANCHOR_NETWORK` | yes: unset it, or set it to `0` |

The `cfg(test)` arm reads no environment and has no escape, deliberately: an
arming CI has to remember to switch on is an arming CI can forget, and a lane
that forgot it would be green and vacuous.

The environment arm covers what `cfg(test)` structurally cannot — **other
crates' integration-test binaries**, which link antseal-anchor's ordinary
build. `crates/antseal-cli/tests/anchor_gate_prepay.rs` drives the real
submission gate through the real pipeline and `cfg(test)` never reaches it.
It **fails closed**: any value but a literal `0` arms the gate, so a typo
over-protects.

**Three venues arm it, not two** (D99 R4, 2026-08-06). The workflows and
`scripts/local-gate.sh` arm a whole *run*; neither covers a bare
`cargo test -p antseal-cli`, which is what a contributor actually types. That
configuration was **measured** disarmed — `deny_reason() == None`, and a probe
request compiled into `crates/antseal-cli/tests/` **reached freetsa.org**:
real DNS, real TCP, real TLS, a real 403 from its nginx. The same probe with
the variable set is refused in 0.00 s before any address is resolved. So the
harness itself is the third venue: every construction of the `antseal` binary
in this workspace's tests goes through
`crates/antseal-cli/tests/common/spawn.rs`, which sets the variable, and
`check-anchor-net.py` R4 refuses a construction anywhere else.

A test **cannot** arm its own process, which is why the in-process CLI entry
is banned outright rather than used carefully: `std::env::set_var` is `unsafe`
in edition 2024 and `[workspace.lints.rust]` denies `unsafe_code` (both
confirmed by compiling them), and it would be racy across libtest's threads
even if it were not. `env_clear()` gets its own rule for the same reason in
reverse — it is the one call that strips the arming even when CI supplied it.

### 3.2 The static half

`scripts/check-anchor-net.py` checks the three things the runtime gate cannot
see about itself:

- **R1 — the arming is armed.** Every committed workflow sets
  `ANTSEAL_NO_REAL_ANCHOR_NETWORK: "1"` at *workflow* level (so a job added
  later inherits it), and `scripts/local-gate.sh` exports it.
- **R4 — the harness guarantees it too** (D99 R4.3). The third venue above:
  the only read of `CARGO_BIN_EXE_antseal` in the workspace is inside
  `crates/antseal-cli/tests/common/spawn.rs`; that helper sets the variable;
  no test source calls `main_entry` in-process; and no test source calls
  `env_clear()` without re-arming.
- **R5 — `test-util` rides dev edges only** (D99 R5). `antseal-anchor`'s
  `test-util` carries `upgrade_pending_with` and
  `UpgradeTarget::loopback_for_tests`, which bypass A42's allowlist. No
  workspace manifest may enable it on a normal-dependency edge, or through a
  package feature that reaches one.
- **R2 — exactly one HTTP client.** A second client anywhere in the workspace
  routes around the gate entirely, and no other lane would see it:
  `ci-lanes.sh dep-graph`'s forbidden-crate scan covers `antseal-core`'s
  graph only, so `reqwest` in `antseal-cli`'s dev-dependencies is invisible
  to it. All three Cargo spellings are checked — inline, `[dev-dependencies.x]`
  table header, and a renamed `{ package = "x" }` edge.
- **R3 — inventory closure.** The gate's headline test walks the default
  endpoint constants *by value*, so a calendar added to an existing list is
  covered automatically. A brand-new constant is what a value-walk cannot
  see, so every URL-valued `pub const` in antseal-anchor must be named in the
  gate's test module.

Six planted faults run before every green verdict.

## 4. What CI actually runs

The anchor test surface is **not** a separate lane and does not need one: the
existing required `test` context runs `cargo test --workspace --locked`, and
per D90 the anchor crate is deliberately **ungated** (no feature hides its
network half), so every anchor test compiles and runs there already. Adding a
job would have cost a 20th required status context and a branch-protection
change for coverage that already existed.

What Q16 added to CI is a **step** on the existing `traceability` job —
Python only, no cargo, no network, seconds — beside `ci-shell` and
`fuzz-budget`, which ride there for the same reason. **The required-context
set stays at 19 (17 jobs, `cross-os` contributing 3).**

## 5. Doing a real-endpoint run anyway

You are not forbidden from talking to real endpoints — you are forbidden from
doing it *from a test*. The protocol, its consent requirement and its
fixture-refresh procedure are
[`../anchors/real-smoke-runbook.md`](../anchors/real-smoke-runbook.md).

The escape hatch is deliberately **not** `#[ignore]`. An ignored test is one
`--include-ignored` away from stamping a rate-limited TSA from CI; the same
reasoning keeps the devnet E2E gate a separately-invoked script (D52 option
C). The smoke path is a script driving the shipped CLI, in an environment
that simply does not set the variable.

## 6. If you need to add an endpoint

Adding a URL to an existing constant needs nothing here — the gate's walk
covers it. Adding a **new** URL-valued constant turns R3 red until it is
named in `crates/antseal-anchor/src/http/offline.rs`'s
`every_default_endpoint()`. That is the intended workflow, not an obstacle:
the red is what stops an endpoint from existing outside the proof that it is
refused.
