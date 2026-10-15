# The no-real-anchor-network policy, and its storage twin

> **Owning tasks: Q16** (`tasks/Q.md`, milestone **M2**) for the anchor gate;
> **S40** (`tasks/S.md`, milestone **M4**) and D173 for the storage gate, its
> twin, covered in §3.3.
> Enforcement: `crates/antseal-anchor/src/http/offline.rs` and
> `antseal_net::network::storage_gate` (`crates/antseal-net/src/network.rs`)
> at runtime, and `scripts/check-anchor-net.py` (static, via
> `scripts/ci-lanes.sh anchor-net-policy`) for both.
> The real-endpoint protocol this policy carves out is
> [`../anchors/real-smoke-runbook.md`](../anchors/real-smoke-runbook.md); a
> real storage-network run is a script over the release binary in an unarmed
> environment (§3.3).

**No automated test in this workspace may contact a real anchor endpoint,
and no automated test or CI job may dial an Autonomi storage peer that is
not loopback.** Not in CI, not on a contributor's machine, not "just this
once to check the fixture is still valid".

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

### 3.1 The anchor gate (runtime — this is the enforcement)

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

`scripts/check-anchor-net.py` checks the things the runtime gates cannot see
about themselves. R1 and R4 hold **both** variables — the anchor gate's and
the storage gate's (§3.3) — to the same rules through the same code, so the
storage arming can never be checked by a weaker copy (D173 §2 R11); R2, R3
and R5 belong to the anchor gate alone, the only one with an HTTP client,
URL-valued constants and a test-only bypass feature.

- **R1 — the arming is armed.** Every committed workflow sets both
  `ANTSEAL_NO_REAL_ANCHOR_NETWORK: "1"` and
  `ANTSEAL_NO_REAL_STORAGE_NETWORK: "1"` at *workflow* level (so a job added
  later inherits them), and `scripts/local-gate.sh` exports both.
- **R4 — the harness guarantees it too** (D99 R4.3; D173 §2 R11). The third
  venue above: the only read of `CARGO_BIN_EXE_antseal` in the workspace is
  inside `crates/antseal-cli/tests/common/spawn.rs`; that helper sets both
  variables; no test source calls `main_entry` in-process; and every
  `env_clear()` call under `crates/*/tests/` re-sets both variables **on the
  statement that clears**. That last rule is **call-level**: the check names
  the file and line of the call that does not, and a re-arm elsewhere in the
  same file does not count. It was file-level until D173 §2 R11, and a
  file-level rule passed a second, unarmed `env_clear()` in a file that
  re-armed once.
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

The checker's own self-test runs before every green verdict: each rule's
planted faults — for R1 and R4 one per variable, plus a planted shape that
must stay green — are applied to an in-memory copy of the tree, and each
must go red by its own rule's message. `scripts/check-anchor-net.py
--self-test` lists them; the count is its output, not this page's.

### 3.3 The storage gate (D173) — the anchor gate's twin

`antseal_net::network::storage_gate` refuses, when armed, any bootstrap peer
that is not a loopback IP literal, as the **first fallible step** of both
storage constructors — the payer and the reader — before the payer's
`eth_chainId` call and before `Client::connect` (D173 §2 R9, R10). The
loopback devnet is admitted. An empty set is not this gate's business:
`resolve_peers` refuses it with usage 2 — for `seal` before any passphrase is
read, for `restore` after the unlock (§2 R7). A refusal names the variable
and the number of refused peers, never an address.

Its arms (D173 §2 R9):

| build | `ANTSEAL_NO_REAL_STORAGE_NETWORK` | gate |
| --- | --- | --- |
| `cfg(test)` of `antseal-net` | anything | armed — no off switch |
| any | `0` | disarmed — the only off switch |
| any | any other value, including empty | armed — fails closed |
| debug assertions on | unset | **armed** |
| release | unset | disarmed |

The debug-assertions arm is what reaches the tests no venue can arm — the
in-process library suites, which no spawn helper constructs and which cannot
arm themselves — so a bare `cargo test` of any devnet suite is armed. It is a
profile property, not a feature, so feature unification can neither arm nor
disarm anything; the reason D99 refused a compile-time arm for the anchor
gate does not transfer, because no storage test may ever need a public
network. The release binary is unaffected unless the variable is set, and
the gate is consulted per connect, never cached.

Its venues are the anchor gate's (D173 §2 R11): every workflow sets it at
workflow level, `scripts/local-gate.sh` exports it,
`crates/antseal-cli/tests/common/spawn.rs` sets it on every spawned binary,
and an `env_clear()` child re-arms it on the statement that clears.
`check-anchor-net.py` R1 and R4 hold it to the anchor variable's rules
through the same code (§3.2).

**What the gate does NOT cover** (D173 §2 R13). A green says nothing about:

- **peers learned from the DHT after bootstrap** — the gate classifies the
  bootstrap set and nothing after it; safe only because an all-loopback set
  makes the adapter bind loopback (§2 R8), so a peer learned later cannot be
  reached either;
- **the payer's EVM RPC** — for `arbitrum-one` and `arbitrum-sepolia` the
  `eth_chainId` call and the payment leg go to evmlib's compiled-in public
  RPC (only `devnet` threads its definition's endpoint, the export's; `U94`);
  the gate runs before that call and stops the storage dial, and the RPC
  itself is outside both gates;
- **UPnP gateway discovery** — the pinned transport starts an IGD mapping
  service on every connect and may ask the router for a port mapping; no
  `ClientConfig` field or feature switches it off at the pin (D173 §1.4);
- **upstream's `client_adaptive.json`** — `Client::connect` reads it and
  every dropped client writes it, under `$XDG_DATA_HOME/ant` or
  `~/.local/share/ant`, and a client panics with neither `HOME` nor
  `XDG_DATA_HOME` set (`S42`).

A real storage-network run is a script run with the **release binary in an
unarmed environment** — never a test, never `#[ignore]`d, and from a debug
build only with `ANTSEAL_NO_REAL_STORAGE_NETWORK=0` set on purpose.
`scripts/e2e-sepolia.sh` consumes a prebuilt release-candidate binary and
never builds one; `Q34`'s one mainnet smoke seal needs the maintainer's
consent at the gate (D173 §2 R16). `CONTRIBUTING.md`'s "No real storage
network in tests" section is the contributor-facing statement of this one.

## 4. What CI actually runs

The anchor test surface is **not** a separate lane and does not need one: the
existing required `test` context runs `cargo test --workspace --locked`, and
per D90 the anchor crate is deliberately **ungated** (no feature hides its
network half), so every anchor test compiles and runs there already. Adding a
job would have cost a 20th required status context and a branch-protection
change for coverage that already existed.

What Q16 added to CI is a **step** on the existing `traceability` job —
Python only, no network, seconds — beside `ci-shell` and `fuzz-budget`, which
ride there for the same reason. That job's cargo-freeness, which is what makes
riding there free, is **asserted on every run** by `scripts/cargo-free.sh` and
stated once in that script's header (D124/Q182); this paragraph cites it
rather than repeating it. **The required-context set stays at 19 (17 jobs,
`cross-os` contributing 3).** **[20 since D168 §2 R1 (2026-09-13), which added
`reproducible-build` in its own workflow; the set now comes from four workflows,
so regenerate it from `scripts/check-ci-paths.py`'s `REQUIRED_CONTEXTS` rather
than recounting jobs — `docs/ci-verification.md`, C2.]**

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
