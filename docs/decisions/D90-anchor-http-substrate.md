# D90 — The anchor network substrate: HTTP client, execution model, and where it sits in the dependency graph

- **Status: RESOLVED — `antseal-anchor` takes a direct, exact-pinned
  `ureq = "=3.3.0"` (`default-features = false`, `features = ["rustls"]`),
  **blocking**, **ungated**, declared by that crate alone. Measured: the
  default `--workspace` graph goes **129 → 144** (+15 names, 25-package
  closure, 4 names new to `Cargo.lock`); the `ant-backend` graph 447 → 451
  and the devnet graph 475 → 479. `antseal-anchor` creates **no** runtime,
  borrows none, and requires no async context: `AnchorGate::run` keeps its
  frozen `async fn` signature and its M2 body blocks — **executed: it
  completes in exactly one poll under the project's own noop-waker
  executor**, so it runs unchanged under `test_util::block_on` and under
  `rt.block_on`. Independence across endpoints comes from
  `std::thread::scope`, not from a runtime (**executed: 1.503 s wall for a
  1.5 s-slow + fast pair, the fast one answering in 1.59 ms**). The
  register-implied lean — that a P task pins an HTTP client and that
  `reqwest` is the natural choice because it is "already in the tree" — is
  **overturned on both halves**: reqwest is in the *lock*, not in the
  *default graph*, and taking it ungated costs **+64 to +72** packages,
  four to five times ureq; taking it gated costs the D89 coverage cliff
  instead. Three of ureq's behaviours were found by executed probe and
  none of them is guessable: `.limit(N)` accepts at most **N−1** bytes,
  `max_redirects(0)` **returns the 3xx rather than erroring**, and
  `Config::default()` **reads `HTTP_PROXY`/`ALL_PROXY` from the
  environment** — which would silently collapse A16's must-agree pair onto
  one origin. A fourth was found by a cross-lane report and corrected here:
  a non-2xx response must carry its **body**, because OpenTimestamps
  calendars signal upgrade state through the body of a `404` (measured),
  and the draft's bare-status-code error would have made A14
  unimplementable on its own substrate. Two receive caps were likewise
  corrected against sibling-lane measurements: a calendar reply is capped
  at **64 KiB**, not at `MAX_OTS_BYTES` — that constant bounds the
  *merged* artifact, a different quantity, and the largest of 18 real
  replies is 220 bytes, so 1 MiB would have frozen a permanent 4 766x
  ceiling under F4's raise-only rule — while the Arbitrum RPC cap rises
  from 64 KiB to **512 KiB**, because D37's 256-transfer maximum makes a
  188 328-byte receipt and the draft would have failed A17 on exactly the
  large seals it exists to corroborate.**
- **Date: 2026-08-02** (M2 planning round; decision minted in this wave —
  it did not exist in the register before it)
- **Owner: A3**, consumed by A10, A13, A14, A15, A16, A17, A24, A28
- **Blocks: A3 → A10/A13/A16/A17 → A14/A15/A20/A25**

---

## Amendment, 2026-08-02 — what executing this decision falsified (A3 lane)

The A3 lane implemented this document and found **one functional defect and
seven specification errors**. The defect would have shipped a
double-submission; it is recorded first.

### A. The timeout table would have retried a *delivered* calendar POST

**§3's ladder is increasing across a boundary where `ureq`'s model requires
it to decrease.** `ureq` does not evaluate one deadline per phase:
`CallTimings::next_timeout` (`timings.rs:157-176`) takes the **minimum over
the current phase and its immediate predecessors**, and `record_time`
(`run.rs:430,528,588`) starts a predecessor's clock when that predecessor
*ends*. §3 put `send_request = 4 s` inside `recv_response = 8 s`, so the
send-request deadline expires **while awaiting the response**. Executed
against a stub that reads the request and then stalls:

```
SendTimeout { endpoint: "http://127.0.0.1:39199", phase: "send-request" }
```

**§6.3's retry table then classifies `Timeout(SendRequest)` under
"headers/body incomplete → retry"**, so an `AtMostOnceAfterSend` calendar
POST is retried after the calendar already has it — producing **three**
pending attestations where A13's Accept row 1 asserts two. §6.3's rows for
`Timeout(SendRequest)` and `Timeout(SendBody)` are wrong **independently of
the constants**: both can fire against a delivered request.

Fixed twice over in the implementation: a strictly **decreasing** ladder
(10 s global; 9/8/7/6/5/4), and — the load-bearing half — **phase placement
derived from `ureq`'s predecessor graph rather than from the phase names**,
so only `Resolve` and `Connect` are pre-send. Deriving retryability from a
phase *name* is what made this look correct.

### B. A test instrument that could not fail

§7's stub server serves connections **serially**, which makes this document's
own `post_is_not_retried_after_the_request_was_delivered` **incapable of
failing**: the retry sits unaccepted in the backlog, is never read, never
recorded, and `requests().len()` is 1 whether or not the bug is present. Each
connection now gets its own thread. §7's `StubReply` also cannot express two
obligations this document sets — write accounting for the streaming-cap test,
and a peer that accepts without reading.

### C. Six specification errors

1. **`HTTP_OPPORTUNISTIC_CONNECT = 1500 ms` cannot be the connect rung** under
   any decreasing ladder inside a 3 s global that also leaves room for the
   1.772 s TTFB **this document itself measured**. Retained as an asserted
   floor instead; a naive `within(3000)` tenths ladder would have given
   recv-response 1.5 s and timed out on a *healthy* calendar.
2. **`MAX_TSA_TOKEN_BYTES as u64` / `MAX_OTS_BYTES as u64`** — both constants
   are already `u64` (`caps.rs:229,232`), so the casts trip
   `clippy::unnecessary_cast`, which is in the default set and **fatal** under
   CI's `-D warnings`.
3. **Name inconsistency**: `OTS_RESPONSE_CAP_BYTES` in the status and
   verification-obligation sections vs `OTS_CALENDAR_RESPONSE_CAP_BYTES` in
   §6.8's table and §3's verbatim block. The verbatim block's name is used.
4. **`get_is_retried_on_pre_send_failure_and_succeeds` is not deterministically
   constructible** as specified — one listener cannot refuse connections and
   later answer on the same port without a rebind race. Split into two
   deterministic tests.
5. **§6.6** says "the URL's host must be an `https` scheme". A host has no
   scheme.
6. Two response caps were already corrected before implementation, by
   orchestrator arbitration under F4's raise-only rule: the calendar reply cap
   from `MAX_OTS_BYTES` (1 MiB) down to 65 536 — it conflated the merged
   bundle-embedded artifact with one HTTP reply, and the largest of 18 real
   replies is **220 B** — and the RPC cap from 64 KiB up to 512 KiB, since
   D37 permits 256 transfers in one transaction (≈188 328 B) and 64 KiB
   truncates at 89 logs, making A17 report `Unavailable` for exactly the large
   seals it exists to corroborate.

**Everything else in this document stands**, including the pin, the ungated
placement, the D89 coverage argument, the execution model, and the three
undocumented `ureq` behaviours — all of which the lane confirmed.

## Context — the decision that was missing

`tasks/A.md:35` states A3's dependency as

> `Deps: P: workspace scaffold + HTTP-client crate pin`

**No such P task exists.** `tasks/P.md` runs P2–P22; the only HTTP-adjacent
entry is P18, which pins `opentimestamps = "=0.2.0"` *as a codec only* and
explicitly excludes networking ("the calendar HTTP client … is A's committed
in-house M2 work, and no networking surface of the crate may be used",
tasks/P.md:228). None of the nine M2 decisions (D53–D61, TODO.md:565-573)
covers a client, an execution model, or a graph position. So A3's `Do` —
three sentences describing "a small HTTP substrate" — was to be executed
against a dependency that nobody had chosen, in a crate whose gating nobody
had decided, on an execution model that contradicts the one thing already
frozen in the crate.

Everything network in M2 sits on it: A10 (TSA POSTs), A13/A14/A15 (calendar
submit, upgrade poll, opportunistic engine), A16 (the must-agree esplora
pair), A17 (the two-RPC Arbitrum confirmation), A24 (the servers CI replays
against), A28 (the receive-side byte caps).

The framing A3 hands an implementer contains two load-bearing errors, and
correcting them changes the answer.

### Correction 1 — this is not a P decision, and "already in the tree" is not true of the graph that would pay

The workspace manifest documents `reqwest` at `Cargo.toml:436-437`:

> `CustomNetwork.rpc_url_http` is `reqwest::Url`, which IS `url::Url`
> re-exported (reqwest-0.12.28/src/lib.rs:280)

That is accurate and it is about the **lock**, not the default graph.
Measured today with the `dep-graph` lane's own command and counting method:

```
$ cargo tree --workspace -e normal,build,dev --prefix none --locked | grep -E '^(reqwest|hyper|rustls|native-tls) '
(no output)
```

The default graph contains **no** HTTP client, **no** hyper, **no** TLS
stack. `reqwest` reaches the lockfile only through `ant-core` /
`ant-node` / `alloy` / `saorsa-transport`, every one of which is behind
`antseal-net/ant-backend` or `devnet-launcher/devnet` (P20 rule 1,
`scripts/ci-lanes.sh:305-355`). "Already a dependency" is therefore true
of a graph 447 packages wide that no required CI context builds, and false
of the 129-package graph that every required context builds. The honest
question is the one this record answers: **which graph pays, and when.**

Second: the pin is not P-class work. `docs/dependency-policy.md` §1 admits
to the exact-pin class what is "format-, crypto-, or network-consensus-
affecting". No byte an HTTP client produces is hashed, signed, stored or
paid for as an output format — the DER `TimeStampReq` is built in
`antseal-core` (A4), the token and `.ots` bytes are opaque payloads. The
client is transport, chosen for and by the one crate that uses it. It is
still exact-pinned, for the `rpassword` row's reason rather than the
`minicbor` row's: see Decision 2.

### Correction 2 — the execution model is already half-frozen, and A3's text does not know it

`crates/antseal-anchor/src/gate.rs:129-145` already ships:

```rust
#[allow(async_fn_in_trait)]
pub trait AnchorGate {
    async fn run(&self, anchor_digest: [u8; 32])
        -> Result<AnchorSubmissionOutcome, AnchorGateError>;
}
```

with the recorded rationale "Native `async fn` (the M2 gate performs network
submissions)". It has a live consumer (`crates/antseal-cli/src/seal_run.rs:70`)
and a shipped implementation (`NoAnchorGate`). So "async or blocking" is not
an open field: the *interface* is async and frozen. What was never decided —
and what an implementer cannot guess — is whether that async-ness implies an
async **client**, and who supplies the reactor. Section 3 shows the answer is
no, and nobody.

## 1. What the tree already contains, measured

All figures below come from commands run on 2026-08-02 against the committed
`Cargo.lock`, with the `dep-graph` lane's own counting method
(`sed 's/ .*//' | sort -u | grep -c .`).

| graph | command | packages |
| --- | --- | --- |
| default | `cargo tree --workspace -e normal,build,dev --prefix none --locked` | **129** |
| `antseal-net/ant-backend` | same + `--features antseal-net/ant-backend` | **447** |
| `devnet-launcher/devnet` | same + `--features devnet-launcher/devnet` | **475** |

Reproduces D89's three numbers exactly.

Two facts about the heavy graph that no document records and that bear on
every option below:

- **There are two reqwest generations in the lock, not one.**
  `reqwest 0.12.28` ← `ant-core 0.5.0`; `reqwest 0.13.4` ←
  `alloy-provider` / `alloy-rpc-client` / `alloy-transport-http` /
  `ant-node 0.15.0` / `saorsa-transport 0.35.1`.
- **There are already two TLS stacks in the lock.** Resolved features:

```
reqwest v0.12.28 FEAT[__tls,charset,default,default-tls,h2,http2,json,stream,system-proxy]
reqwest v0.13.4  FEAT[__rustls,__rustls-aws-lc-rs,__tls,json,rustls]
```

  `default-tls` on 0.12 is `native-tls` → `openssl 0.10.81`; 0.13's `rustls`
  is `rustls 0.23.43` over `aws-lc-rs 1.17.3`. `cargo tree -i native-tls`
  names `reqwest v0.12.28` as its only workspace-reachable parent. So the
  question "does adding X introduce a second TLS stack" is already answered
  in the affirmative by upstream, in a graph we do not control — which
  removes it as a discriminator between candidates and leaves the *default*
  graph, which has none, as the only place the answer is still ours.

`attohttpc 0.30.1` is also already locked, via `igd-next 0.17.1`.

## 2. The candidates, measured

Method (D89's, verbatim): one scratch crate per candidate outside the
workspace, `cargo tree -e normal,build --prefix none`; package **names**
deduplicated and differenced against each workspace graph's name set.
`-e normal,build` rather than `-e normal` because the workspace metric the
lane prints counts build-script closures too, and `aws-lc-sys` is a
build-script-heavy C library — measuring at `-e normal` understates
reqwest 0.13 by 8 packages.

| candidate | shape | closure | +default (129) | default after | +`ant-backend` (447) | names not in `Cargo.lock` |
| --- | --- | --- | --- | --- | --- | --- |
| **`ureq =3.3.0`, `df=false`, `["rustls"]`** | **blocking** | **25** | **+15** | **144** | **+4** | **4** |
| `ureq 3.3.0`, default (`rustls`+`gzip`) | blocking | 30 | +20 | 149 | +4 | 4 |
| `ureq 3.3.0`, `rustls-no-provider`+`platform-verifier` | blocking | 20 | +16 | 145 | +3 | — |
| `hyper =1.11.0` + `hyper-util` + `hyper-rustls` + `tokio` + `http-body-util` | async | 40 | +26 | 155 | +1 | 1 |
| `attohttpc =0.30.1`, `tls-rustls-webpki-roots` | blocking | 57 | +45 | 174 | +1 | 1 |
| `reqwest =0.12.28`, `df=false`, `["rustls-tls"]` | async | 85 | +64 | 193 | +1 | 1 |
| `reqwest =0.12.28`, `+["blocking"]` | blocking-on-tokio | 88 | +66 | 195 | +1 | 1 |
| `reqwest =0.13.4`, `df=false`, `["rustls"]` | async | 87 | +70 | 199 | **+0** | **0** |
| `reqwest =0.13.4`, `+["blocking"]` | blocking-on-tokio | 90 | +72 | 201 | +0 | 0 |

Verified by set union rather than by subtraction alone:
`|default ∪ ureq| = 144`, `|ant-backend ∪ ureq| = 451`,
`|devnet ∪ ureq| = 479`.

Four consequences:

- **`reqwest` is the most expensive option in the graph that matters and
  the cheapest in the graph that does not.** +70 default (a 54 % increase)
  against +0 heavy. That shape is exactly what makes the gating question
  (§4) the whole decision rather than a footnote.
- **`reqwest`'s "blocking" is not blocking.** `blocking = [… "tokio/sync"]`
  (reqwest-0.12.28/Cargo.toml) — the blocking client spawns a background
  tokio runtime. It costs 2–3 packages *more* than the async client and
  still requires the runtime this decision is trying not to require.
- **`attohttpc`, the apparently-lean blocking option, is not lean**: 57
  packages, because its rustls path drags `rustls-platform-verifier` and
  the native-certs subtree.
- **`ureq` costs no version generation.** Every crate in its closure that
  the lock already carries resolves to the *same* version:
  `rustls 0.23.43`, `ring 0.17.14`, `rustls-webpki 0.103.13`,
  `rustls-pki-types 1.15.1`, `http 1.5.0`, `bytes 1.12.1`,
  `httparse 1.10.1`, `itoa 1.0.18`, `base64 0.22.1`, `log 0.4.33`,
  `once_cell 1.21.4`, and — the two that matter to the pin governance —
  **`subtle 2.6.1` and `zeroize 1.9.0`, which are the project's own exact
  pins** (`Cargo.toml:398,405`). It brings **no `digest`, no `sha2`, no
  second RustCrypto generation** (rustls hashes through `ring`), so the
  brief's "a nominee that drags a second `sha2`/`digest` is a finding"
  clause is discharged with a measurement, not a hope. Its `getrandom 0.2.17`
  (via `ring`) is a third getrandom generation in the *default* graph but
  not in the lock, where it already sits; `deny.toml` sets
  `bans.multiple-versions = "warn"`, so no lane changes verdict.

The four genuinely new lockfile names are `ureq`, `ureq-proto`,
`utf8-zero`, `webpki-roots`.

### 2.1 Advisory sweep (RUSTSEC **and** GHSA/osv.dev, per D19)

`POST https://api.osv.dev/v1/query`, ecosystem `crates.io`, retrieved
**2026-08-02T19:32:36Z** and **19:33:01Z**:

| crate | advisories on record | affects our version? |
| --- | --- | --- |
| `ureq`, `ureq-proto`, `utf8-zero`, `webpki-roots`, `httparse`, `flate2`, `reqwest`, `attohttpc`, `aws-lc-rs`, `hyper-util`, `native-tls` | **0** | — |
| `rustls` | 4 (latest RUSTSEC-2024-0399, fixed 0.23.18) | no — locked 0.23.43 |
| `rustls-webpki` | 10 (latest RUSTSEC-2026-0104, fixed **0.103.13**) | no — locked **0.103.13**, i.e. exactly the fix |
| `ring` | 3 (RUSTSEC-2025-0009 fixed 0.17.12; -0010 = "<0.17 unmaintained") | no — locked 0.17.14 |
| `hyper` | 14, all fixed ≤ 0.14.12 | no — locked 1.11.0 |
| `tokio` | 10, all fixed ≤ 1.44.2 | no — locked 1.53.1 |
| `aws-lc-sys` | 5 (RUSTSEC-2026-0044…0048, fixed 0.38.0/0.39.0) | no — locked 0.43.0 |
| `openssl` | 28, latest RUSTSEC-2025-0022 fixed 0.10.72 | no — locked 0.10.81 |
| `h2` | 6, latest fixed 0.4.4 | no — locked 0.4.15 |
| `idna` | RUSTSEC-2024-0421, fixed 1.0.0 | no — locked 1.1.0 |

No live advisory blocks any candidate. `rustls-webpki` sitting *exactly* on
its newest fix is worth naming: it is one release behind an advisory at all
times by construction, and it is in the closure of every candidate that does
TLS in-process.

Licence: `ureq 3.3.0` is `MIT OR Apache-2.0`, `rust-version = "1.85"`,
`edition = "2024"` — inside the pinned toolchain 1.92.0 and inside the
allowlist D6 already enumerates for Q29. No `deny.toml` change is required
for it or for any of its four new names.

## 3. Async or blocking — and who owns the runtime

### 3.1 The runtime that exists today

- `crates/antseal-cli/Cargo.toml:47-49`: `ant-backend =
  ["antseal-net/ant-backend", "dep:tokio"]`. tokio is **optional** and
  reachable only through that non-default feature.
- `crates/antseal-cli/src/backend.rs:206-212`: `runtime()` builds
  `tokio::runtime::Builder::new_multi_thread().enable_all()`.
- `crates/antseal-cli/src/commands.rs:243-244`: `seal` calls it once —
  `let rt = runtime()?; let result = rt.block_on(async { … })`.
- `crates/antseal-anchor/src/gate.rs:157-166`: the crate's own tests drive
  `async fn run` through a hand-rolled `Waker::noop()` loop, sanctioned in
  a comment as "no runtime dep is wanted before M2 needs one".

So: **a default build has no runtime at all, and cannot acquire one without
compiling `ant-backend`.** Meanwhile A15/U24 requires an opportunistic
upgrade attempt on **every** CLI invocation — `verify`, `list`, `status`,
`init` — none of which has, or should have, a tokio runtime.

An async client therefore forces one of two bad outcomes: tokio in the
default graph for every command (+10 packages *and* an executor spun up to
run `antseal list`), or an upgrade hook that is dead in the build most
contributors run. Neither is acceptable, and neither is stated anywhere in
A3, A15 or U24.

### 3.2 The resolution, executed

A blocking body inside an `async fn` returns `Poll::Ready` on the first
poll. That is not an argument, it is a measurement — probe 6 of
`plannerF/ureqlive/tests/probe.rs`, transcribing `gate.rs`'s own executor:

```
PROBE 6 polls to completion = 1
PROBE 6 blocking-inside-async under noop waker: OK
```

The frozen `AnchorGate::run` signature is satisfied with **zero** runtime,
under the project's existing noop-waker `block_on`, and equally under
`rt.block_on` on `seal`'s multi-thread runtime (where `block_on` drives the
future on the *calling* thread while worker threads keep ant-core's I/O
moving).

Independence across endpoints — A10's "one TSA's failure never aborts or
**delays** the others", A16's two-endpoint pair, A13's per-calendar
independence — comes from `std::thread::scope`. Probe 7:

```
PROBE 7 wall=1.503239188s results=[("fast","fast",1.590218ms), ("slow","slow",1.503035287s)]
```

Two stub endpoints, one deliberately 1.5 s slow: total wall 1.503 s and the
fast endpoint answered in 1.59 ms. Sequential execution would have delayed
the fast one by 1.5 s and failed A10's Accept row 2 on its own words.

### 3.3 Who owns the runtime: **nobody**

**`antseal-anchor` creates no runtime, borrows no runtime, and requires no
async context.** It is callable from `main`, from a `#[test]`, from inside
`rt.block_on`, and from the U24 hook in a build with no tokio compiled in.
That is the property that makes A15/U24 implementable at all, and it is the
single most important consequence of choosing a blocking client.

**One residual coupling, and its guard.** Blocking inside `rt.block_on` is
safe because `runtime()` is `new_multi_thread` (backend.rs:206): spawned
ant-core tasks progress on worker threads while the main thread blocks on a
socket. On a `new_current_thread` runtime they would starve. That invariant
is currently unwritten and unasserted — see Q84.

## 4. Where it sits in the graph — the D89 lens

D89 (`docs/decisions/D89-wallet-primitives-below-the-gate.md`) settled the
analogous question for wallet primitives and its Evidence 3 is the reason
this section exists: **required CI is default-features-only**, so
feature-gated code can be compiled by no gate at all, and cfg-inactive code
is not even type-checked.

### 4.1 First, the premise D89 established, re-verified

A default build already cannot seal, and already says so: `ant-backend` is
non-default (`antseal-cli/Cargo.toml:46-48`), `SealBackend` and the vault→
`WalletKey` bridge are behind it, and U36's typed refusal
(backend.rs:96-101) tells the user to rebuild with the feature. That is
unchanged by this record and is **not** a reason to gate anything else: it
is a statement about *Autonomi storage*, not about HTTP.

### 4.2 The two options, both measured

| ruling | default graph | `ant-backend` graph | which required CI context compiles A3/A10/A13/A16/A17 |
| --- | --- | --- | --- |
| **ungated `ureq` in `antseal-anchor`** | **129 → 144** | 447 → 451 | `clippy` (ci.yml:122) **and** `test` (ci.yml:148) — both, on every PR |
| gated behind `antseal-net/ant-backend` (with `reqwest =0.13.4`) | 129, unchanged | 447, unchanged | **none** |
| gated behind a new non-default `antseal-anchor/net` | 129, unchanged | 447 (+4 if ureq) | **none** — a new required lane would have to be built and required first |

The required contexts are `cargo clippy --all-targets --locked`
(`.github/workflows/ci.yml:122`) and `cargo test --workspace --locked`
(`ci.yml:148`). Neither passes `--features`. S30 records this as an open
problem in the project's own words (TODO.md:319). The local heavy tier
fires from a path list that does not contain `crates/antseal-anchor/`
(`scripts/gate-features.sh:88-95`).

So under either gated option, **every Accept row of A3, A10, A13, A16 and
A17 would be compiled by nothing** in the ordinary course of work:

- A3: "unit tests against a local stub server exercise timeout, retry, and
  each error class" (tasks/A.md:39);
- A10: "Against A24's mock TSA: success path … HTTP failure, timeout, and
  non-granted PKIStatus each produce distinct outcomes" (:124);
- A13: "Mock-calendar test: two calendars → one `.ots` …" (:—, A13 Accept 1);
- A16: "Stub-server tests: agreement passes; one endpoint down …
  differing headers → distinct disagreement outcome";
- A17: "Stub-RPC tests: agree / one-down / disagree / tx-absent each produce
  distinct typed outcomes".

Every one of those is a *unit test against a local stub*. They are the
cheapest tests in M2 and the ones that most need to run on every PR, because
they are the only executable statement that the anchor error classification
is distinct. Gating them is the D89 failure repeating with a larger blast
radius, and the brief's stop-condition forbids it.

### 4.3 The independent argument, which reaches the same place

Gating is also **semantically wrong**, and this holds even if the coverage
problem were fixed. `ant-backend` means "this build can reach Autonomi and
pay on Arbitrum". `--online` verification (A16 esplora, A17 RPC) is a
property of the **verifier**, not of the storage client: spec line 137 puts
the two must-agree endpoint pairs in the *verifier web page*'s feature set,
and MVP-SPEC.md line 38 makes `--online` promotion a verify-time step.
D89's Correction 3 established that a default build is "an
inspect-and-verify build"; gating the anchor network half behind
`ant-backend` would produce an inspect-and-verify build that **cannot
verify online** — a strictly worse product, obtained by coupling two
unrelated capabilities under one flag.

And `antseal-anchor` is *defined* as the network crate: "network side only"
(MVP-SPEC.md:52-53), "the sole home of anchor network I/O — the
churn-isolation boundary" (tasks/A.md:37). A network crate with an optional
network is incoherent; the containment argument that justifies
`antseal-net`'s gate (355 packages of ant-node) has no analogue at 15.

### 4.4 What 129 → 144 buys and what it does not license

D89 spent 9 packages on a coverage property and closed with "does not
license a tenth without the same measurement". This record spends 15 on a
**functional** requirement — without it the product cannot anchor, cannot
poll upgrades, and cannot verify online — plus the same coverage property.
The measurement, the enumeration and the argument are all here; the 355-
package cliff P20 rule 1 exists to guard sits untouched at 475 → 479.

The `dep-graph` lane's **verdict is unchanged**: rule 1 is a scan for
`^(ant-node|ant-core|ant-protocol|evmlib|alloy) v` (ci-lanes.sh:307,
:341-346), and none of ureq's 25 names matches. Rule 4 (S23 manifest
exclusivity, `^(ant-core|ant-protocol|alloy|bytes)$`, ci-lanes.sh:141-186)
is a scan of **declared** edges in `cargo metadata --no-deps`:
`antseal-anchor` declares `ureq`, never `bytes`, so although `bytes 1.12.1`
enters its transitive closure via `ureq-proto → http`, no new declared edge
matches and the verdict is unchanged. Rules 2, 3 and 5 have no partner
here. What changes is one **printed** number, 129 → 144, and one recorded
sentence in the dependency policy — the same documentation consequence
D89 §6 handled, handled the same way (Decision 6).

## 5. The `core-dep-graph` lane — and a defect found in it

A3's Accept row 2 is "`antseal-core` has no HTTP/network dependency
(dependency-graph assertion; CI enforcement wired by Q)". The lane exists:
`scripts/ci-lanes.sh:188-206`, run by the `core-dep-graph` required context
(ci.yml:203-214). Its assertion is a **name scan**, exactly as D89 found for
rule 1 — not a package count:

```bash
local forbidden='^(tokio|async-std|smol|hyper|reqwest|mio|socket2|getrandom|rand|rand_chacha) ' tree offenders
tree="$(cargo tree -p antseal-core -e normal --prefix none --locked)" || return 1
```

**Yes, a new rule is required — and it is necessary but not sufficient,
which is the part that matters.**

1. **`ureq` is not in the list.** Under this ruling the workspace acquires
   an HTTP client whose name the lane cannot see. The list must name the
   client we actually adopt, together with the transport crates that could
   arrive without it. `cargo tree --prefix none` prints the closure flat,
   so a name on the list is caught however deep it arrives — the denylist's
   weakness is not depth, it is coverage.

2. **This is the one check in the whole lane with no self-test, and that is
   a latent defect independent of D90.** Every other rule in
   `lane_dep_graph` self-tests first, on a planted violation, with a comment
   saying why: P15/D35 (:100-107), S23 (:154-160), S6 (:239-247), P20 rule 1
   (:325-340), rule 3 (:376-381), D89 rule 5 (:424-436). The
   forbidden-crate scan has none, so a typo in the regex — a missing `^`, a
   dropped alternation bar, a lost trailing space — makes it green forever,
   which is precisely the failure mode the file's own comments say the
   self-tests exist to prevent. It is corrected here because this record is
   the first thing to touch the pattern.

3. **A denylist cannot discharge A3's Accept row 2 at all, and this record
   does not pretend otherwise.** The lane *announces* "antseal-core's
   NORMAL dependency graph must be I/O-free and RNG-free" and then asserts
   a nine-name regex. Those are two different claims. Executed here
   2026-08-02, against both the current rule and the extended one proposed
   below:

   ```
   crate                 OLD-rule   D90-extended
   env_logger             passes     passes
   libc                   passes     passes
   is-terminal            passes     passes
   regex                  passes     passes
   termcolor              passes     passes
   ureq                   passes     CAUGHT
   tokio                  CAUGHT     CAUGHT
   ```

   Adding twelve names moves `ureq` from `passes` to `CAUGHT` and moves
   nothing else. `libc` — a direct route to every syscall there is — still
   passes both. **So "the lane will catch it" is not an argument available
   to this record**, and §4's ruling does not rest on it. What actually
   keeps `antseal-core` HTTP-free under D90 is structural and checkable by
   inspection: the dependency edge runs `antseal-anchor → antseal-core` and
   never the reverse (`crates/antseal-anchor/Cargo.toml`), and
   `antseal-core`'s manifest names only pure crates. The lane is a
   **regression detector for the specific crate we adopted**, not the
   guarantee.

   The structurally correct assertion is the inverse of what is there: a
   committed **allowlist** of the package names permitted in
   `cargo tree -p antseal-core -e normal`, so that *any* new name — however
   it is spelled, whoever pulls it in — fails until reviewed. That is the
   shape S6's file allowlist already uses in this same lane
   (ci-lanes.sh:234-240) and the shape D89 cites approvingly. **That work is
   Q74's**, already minted by the D58 planner; this record neither
   duplicates it nor performs it.

**Ordering: D90 and A3 are adjacent to Q74, not blocked by it.** A3 can
land with Decision 5's extension, because that extension is what makes the
lane say anything at all about the client D90 adopts, and because the
property it protects is already true structurally. What Q74 changes is
whether A3's Accept row 2 is a *machine-checked fact* rather than a
reviewed one — so the honest status is: **A3 Accept row 2 remains
review-enforced until Q74 lands, and Decision 5's extension is the interim
regression guard, not the discharge.** If the wave plan can run Q74 before
A3, that is strictly better and costs A3 nothing; if it cannot, A3 is not
blocked.

The verbatim interim text is in Decision 5, verified in both directions
(§ Verification, `core-dep-graph` row).

## 6. The substrate's own design

Every behaviour below was **executed** against `ureq =3.3.0` on toolchain
1.92.0 (`plannerF/ureqlive`, 8 + 5 probes, all passing). Three of them
contradict what the API documentation implies, and an implementer working
from docs alone would have got each one wrong.

### 6.1 The response byte ceiling — and the off-by-one A28 must not inherit

A28 carries the derived constraint `receive_cap <= MAX_TSA_TOKEN_BYTES` /
`<= MAX_OTS_BYTES` and requires the cap to fire at **submission** time, not
at bundle-build time. ureq enforces limits **while streaming**:
`LimitReader::read` (ureq-3.3.0/src/body/limit.rs:21-34) errors as soon as
the allowance is exhausted, so nothing over-sized is ever allocated. That is
the right primitive.

But `read_to_end` must observe an `Ok(0)` to stop, and `LimitReader` returns
`Err` instead of `Ok(0)` once `left == 0`. Executed through the real API
(probe 2):

```
PROBE 2 body=1023 limit=1024 -> ok=true
PROBE 2 body=1024 limit=1024 -> ok=false
PROBE 2 body=1024 limit=1025 -> ok=true
```

**`.limit(N)` accepts at most `N − 1` bytes.** A literal
`.limit(MAX_TSA_TOKEN_BYTES)` would reject a token of exactly 1 048 576
bytes — a token that *is* embeddable — turning A28's `≤` into `<`. The
substrate therefore takes the true ceiling from the caller and applies the
`+ 1` itself, in exactly one place (Decision 3), so A28's call sites read
`receive_cap = MAX_TSA_TOKEN_BYTES` and mean it.

The exact classifier arm, executed:

```
LIMIT-DEBUG BodyExceedsLimit(1024)
LIMIT-DISPLAY the response body is larger than request limit: 1024
LIMIT matches ureq::Error::BodyExceedsLimit(1024) = true
```

Note `Error::BodyExceedsLimit` is **overloaded** — its own doc comment
describes the *send* side ("A send body … is larger than the
`content-length` header") while `limit.rs` uses it for the receive side.
We always send bodies of known length, so a send-side occurrence is a
programming error; the substrate maps the variant to the receive-side
`OversizeBody` class and documents why.

Compression is disabled by construction, not by accident:
`default-features = false` drops `gzip` (and with it `flate2`,
`miniz_oxide`, `crc32fast`, `adler2`, `simd-adler32` — 5 of the 20 packages
the default feature set would cost), and the substrate sets
`accept_encoding(AutoHeaderValue::None)` so no encoding is negotiated even
if a future feature default changes. A streaming byte ceiling on a
*compressed* body bounds the wrong number; this closes that path rather
than reasoning about it.

### 6.2 Timeouts — A3's ~10 s confirmed, with the phase split it did not ask for

Round-trip measurements against the real M2 endpoints, retrieved
**2026-08-02T19:40:57Z**:

| endpoint | connect | TLS | TTFB | total |
| --- | --- | --- | --- | --- |
| `https://blockstream.info/api/blocks/tip/height` | 0.352 s | 0.579 s | 0.794 s | **0.794 s** |
| `https://mempool.space/api/blocks/tip/height` | 0.601 s | 0.697 s | 0.779 s | **0.779 s** |
| `https://freetsa.org/tsr` | 0.277 s | 0.504 s | 0.711 s | **0.711 s** |
| `https://a.pool.opentimestamps.org` | 0.268 s | 0.656 s | 0.937 s | **0.937 s** |
| `https://alice.btc.calendar.opentimestamps.org` | 0.479 s | 1.047 s | 1.772 s | **1.996 s** |
| `http://timestamp.digicert.com` | 0.275 s | — | 0.460 s | **0.460 s** |

**A3's ~10 s is confirmed** as the per-attempt wall-clock ceiling: 5.0× the
slowest observed round trip, with the largest single component (a 1.047 s
TLS handshake) an order of magnitude inside it. No redirect was observed at
any endpoint (`num_redirects=0` everywhere).

What A3 did not specify, and what the retry classifier turns on, is that a
**global-only** timeout destroys the information the classifier needs.
Probe 3, with `timeout_global` alone:

```
PROBE 3 elapsed=1.204705384s err=Timeout(Global)
```

`Timeout(Global)` cannot say which phase stalled, so it cannot say whether
the request reached the server. With per-phase timeouts set (probes
PHASE-A/B/C):

```
PHASE-C elapsed=601.265829ms  err=Timeout(Connect)
PHASE-A elapsed=735.236810ms  err=Timeout(RecvResponse)
PHASE-B elapsed=720.950916ms  err=Timeout(RecvBody)
```

Each phase names itself. The substrate therefore sets **all** per-phase
timeouts strictly inside a 10 s global backstop, and classifies
`Timeout(Global)` as *ambiguous* — the conservative direction — because by
construction it only fires when no single phase did.

### 6.3 Retry, and the double-submit question

A calendar submission is a network **write**: A13 POSTs `anchor_digest` and
the calendar returns a pending attestation. Re-submitting the same digest
yields a *second* pending attestation from that calendar, which would make
A13's Accept row 1 ("two calendars → one `.ots` containing two pending
attestations") observe three. A TSA POST is stateless and safe to repeat
cryptographically, but A10's own notes record hard rate limits
(tasks/A.md:122: "Sectigo ~15 s spacing, SwissSign ~10/day") — three
attempts burns 30 % of SwissSign's daily quota on one failure.

So retry is not a single policy. The dividing line is **whether the request
bytes reached the server**, and ureq's phase-typed errors make that
decidable rather than guessed:

| ureq outcome | request delivered? | `Idempotency::SafeToRepeat` | `Idempotency::AtMostOnceAfterSend` |
| --- | --- | --- | --- |
| `Error::Io(_)` with `ErrorKind::ConnectionRefused` / `HostUnreachable` / `NetworkUnreachable` | no | retry | retry |
| `Error::HostNotFound`, `Error::ConnectionFailed`, `Error::Tls(_)`, `Error::Rustls(_)` | no | retry | retry |
| `Timeout(Resolve)`, `Timeout(Connect)`, `Timeout(SendRequest)`, `Timeout(SendBody)` | no (headers/body incomplete) | retry | retry |
| `Timeout(RecvResponse)`, `Timeout(RecvBody)`, `Timeout(Global)`, `Timeout(PerCall)` | **unknown** | retry | **stop** |
| any other `Error::Io(_)` | **unknown** | retry | **stop** |
| status `429`, `503` | no (server declined) | retry | retry |
| other `5xx` | **unknown** | retry | **stop** |
| `4xx` (other than 429), `3xx`, `Protocol`, `BadUri`, `Http`, `RedirectFailed`, `TooManyRedirects`, `BodyExceedsLimit`, `RequireHttpsOnly` | n/a — deterministic | **never** | **never** |

Probe 4 established that the pre-send class actually arrives as
`Error::Io`, not as the `ConnectionFailed` variant its doc comment
suggests:

```
PROBE 4 err=Io(Custom { kind: ConnectionRefused, error: "Connection refused" })
```

so the classifier reads `io::ErrorKind`, not the ureq variant alone. An
implementer matching on `Error::ConnectionFailed` would have written a
retry rule that never fires.

**Call-site assignment.** `AtMostOnceAfterSend`: A13 calendar submit, A10
TSA POST. `SafeToRepeat`: A14 upgrade GET, A16 esplora GET, A17
`eth_getTransactionReceipt` (a POST by transport, a read by semantics).

**Backoff is deterministic and un-jittered** — 200 ms then 600 ms. We
contact two to five named endpoints, never a fleet, so thundering-herd is
not our failure mode; determinism keeps the timeout tests exact and keeps
an RNG out of the retry path. Worst case per endpoint under
`HttpPolicy::seal()` is 3 × 10 s + 0.8 s = **30.8 s**, which is why §3.2's
concurrency is load-bearing: that is a per-endpoint bound, not a per-seal
one.

**A15/U24 gets its own profile**, `HttpPolicy::opportunistic()`: one
attempt, 3 s global, no backoff. A finding for A15/U24 rather than a rule
this record can impose: at 3 s per calendar even a single attempt is a
user-visible delay on `antseal list`, so "never delays the host command"
(TODO.md, U24) is only achievable if the hook runs **after** the host
command's output is flushed. A pre-output hook cannot satisfy that wording
at any timeout this substrate can offer.

### 6.4 Redirects — and why `max_redirects(0)` is not enough on its own

`max_redirects(0)` does **not** produce an error. Probe 5:

```
PROBE 5 max_redirects(0) -> returns the 302 itself, status=302 Found
```

confirmed by `Config::max_redirects_do_error()`
(ureq-3.3.0/src/config.rs:202-204), which is
`self.max_redirects > 0 && self.max_redirects_will_error` — with zero
redirects it can never be true. So the caller receives a 302 with an empty
body, and a client that only checked "did I get a response" would hand an
empty buffer to the DER parser. **The substrate must classify 3xx as an
error itself**, which is why `AnchorHttpError::Redirected` exists as its
own variant rather than folding into `Status`.

Redirects are refused, not followed, for three reasons and the third is the
one that matters:

1. On a 301/302 ureq would rewrite our POST to a GET and drop the DER
   `TimeStampReq` body; on 307/308 it raises `RedirectFailed`. Neither is a
   behaviour we want to depend on.
2. Our endpoints are exact pinned URLs (spec line 109 for TSAs, A-OD2/D54
   for calendars, A16 for esplora). A redirect means the endpoint moved,
   which should be a loud typed error a human reads, not a silent hop.
3. **A16's must-agree pair loses its entire security property under
   redirects.** Two endpoints that both redirect to a common origin are one
   endpoint wearing two names, and "both must succeed and agree" becomes a
   tautology — while still reporting agreement. No test would catch it,
   because the results really would agree.

   (A16's own wording, "agreed result is byte-identical from both
   endpoints", is correct **for esplora only** — the 80-byte block header
   has no representational freedom. It does not generalise to A17: see
   §6.9.)

### 6.5 Proxies — a default that would have silently defeated A16

`ureq::Config::default()` sets `proxy: Proxy::try_from_env()`
(ureq-3.3.0/src/config.rs:872), reading `ALL_PROXY`, `HTTPS_PROXY`,
`HTTP_PROXY` and `NO_PROXY` from the environment (src/proxy.rs:213-232).

That is a live hazard here, not hygiene:

- it routes **both** halves of A16's must-agree pair through one on-path
  intermediary, which is §6.4's failure mode arriving through the
  environment instead of through a `Location:` header;
- it is an **ambient environment channel**, which D41 rejected for the CLI
  and which U21's secret-hygiene harness reads `/proc/<pid>/environ` to
  police;
- it makes A25's recorded fixtures depend on the operator's shell.

The substrate sets **`.proxy(None)` unconditionally**. Should a proxy ever
be wanted, it becomes an explicit field in U4's endpoint config under its
own recorded decision — never an ambient default.

### 6.6 TLS, plain HTTP, and what transport security actually buys

**DigiCert's timestamp service has no HTTPS at all.** Retrieved
**2026-08-02T19:35:19Z** and **19:35:51Z**:

```
https://timestamp.digicert.com   http=000   curl: (28) Connection timed out after 20001 ms
http://timestamp.digicert.com    http=400   (live; 400 is the expected reply to an empty TimeStampReq)
port 443  -> connection times out          port 80 -> OPEN
https://freetsa.org/tsr          http=200
```

So a TLS-only substrate cannot talk to one of the spec's two default TSAs
(MVP-SPEC.md line 109). Plain HTTP is not a concession; it is a
requirement, and the ruling is that it is **safe for RFC 3161 and unsafe
for everything else**. The asymmetry is exact and it is about signatures,
not about hosts:

- **RFC 3161 (A10) — payload is signed and nonce-bound.** A on-path
  attacker cannot forge a token (no TSA key), cannot replay an old one (A8
  checks nonce equality on the capture path), and cannot substitute another
  digest's token (`TSTInfo.messageImprint` must equal `anchor_digest`).
  What it can do is deny service — which A10 already treats as a per-TSA
  failure — and **observe the `anchor_digest`**, which is the one real
  cost: a passive observer learns that this host stamped this 32-byte value
  at this time, and can link it to a bundle published later. That is a
  privacy leak, not an integrity one, it is inherent to DigiCert's
  offering, and it is exactly what tasks/A.md:127 already records
  ("acceptable because token validity is established cryptographically and
  the nonce prevents stale-token replay").
- **esplora and Arbitrum RPC (A16/A17) — payload is unsigned.** Their
  results are trusted *because two independent endpoints agree*. Over plain
  HTTP a single on-path attacker forges both and the must-agree primitive
  reports agreement on a lie. **Transport security is the only integrity
  control these two have**, so HTTPS is mandatory for them.

The enforcement point matters, because A24's stub esplora and stub RPC
serve `http://127.0.0.1:<port>` and a naive "HTTPS required" rule would
make A16's own Accept rows untestable. The rule is therefore
**`TlsPolicy::RequiredExceptLoopback`**: the URL's host must be an
`https` scheme **unless** it is an IP literal in `127.0.0.0/8` or `::1`.
Not `localhost` — a name, however conventionally resolved, is not an IP
literal, and our stub binds `127.0.0.1:0`. An attacker who can make our
process resolve a loopback literal already owns the process, so the
carve-out weakens nothing. It is enforced in the substrate, applies to
user-supplied overrides from U4, and is the subject of A49.

ureq's own `https_only` refuses before any socket work (probe HTTPS-ONLY:
`RequireHttpsOnly("http://192.0.2.1:80/")` in **200 µs**), so the loopback
test is ours and the scheme test is delegated.

**Root store: `webpki-roots` (ureq's `rustls` feature default), not the OS
store.** The `platform-verifier` route measures one package cheaper on
Linux (§2) but ties TLS acceptance to whatever three CI runners and every
user's machine happen to trust — variance in the one part of the stack
this project pins everywhere else, and variance that would show up as
cross-OS flake in A25's fixtures. A compiled, versioned Mozilla root
snapshot is the same discipline as A6's pinned TSA root store, one layer
down. Its failure mode is liveness (a root rotation the snapshot predates),
caught by A25 and fixed by a lockfile bump.

### 6.7 A non-2xx response is a failure **with a body**, not a bare status code

Corrected after a cross-lane finding from the planner who resolved D58,
re-verified here. The draft of this record returned
`AnchorHttpError::Status { endpoint, status }` and discarded the body. That
would have made **A14 unimplementable on top of its own substrate.**

OpenTimestamps calendars signal upgrade state through the *body* of a 404,
not through the status line. D58's measurement: a known-but-unconfirmed
commitment returns `404` with a 42-byte `Pending confirmation in Bitcoin
blockchain`; an unknown one returns `404` with a `Not found` body. Verified
independently here, retrieved **2026-08-02T20:06:34Z**:

```
alice.btc.calendar.opentimestamps.org/timestamp/<all-zero>   404, 9 bytes,  "Not found"
a.pool.opentimestamps.org/timestamp/<short>                  404, 10 bytes, "Not found\n"
```

So the discriminator A14 needs is **three-way and body-separated** —
`200`+attestation / `404`+pending-text / `404`+not-found-text — and the two
404s are indistinguishable by status. A substrate that collapses non-2xx to
a code cannot express it.

Two consequences, both normative:

1. **`AnchorHttpError::Status` carries the body**, bounded by
   `HTTP_ERROR_BODY_CAP_BYTES` (4 KiB) rather than by the request's
   artifact cap. Keeping it in the *error* arm rather than returning
   `Ok(HttpResponse)` for every status is deliberate: it preserves A10's
   "HTTP failure … distinct outcome" for free, and it makes it structurally
   impossible for a caller to hand a 500's body to the DER parser by
   forgetting a status check.
2. **The two 404 bodies differ in length between calendars** (9 vs 10
   bytes — one has a trailing newline), so any matcher built on this must
   compare **trimmed content**, never length and never a byte-exact
   literal. Recorded here because the measurement is here; the matcher
   itself is A14's.

This also removes the last reason the substrate might have wanted a wire
codec: D58 rules that **no `opentimestamps` crate is adopted** — the `.ots`
codec is in-house in `antseal-core` at +0 packages — so A13/A14 speak raw
HTTP to calendars and the substrate carries opaque bytes in both
directions, which is exactly the shape ruled above. Where §Context cites
P18 as "the only HTTP-adjacent P entry", read it historically: D58
supersedes P18's pin.

### 6.8 The four receive caps, and the two the draft got wrong

Corrected after the D54/D55/D57 lane's measurements. **F4's raise-only rule
is the arbitrator, not preference**: a cap set too high can never be walked
back, a cap set too low costs one commit. That asymmetry points in opposite
directions for the two caps below, and the draft had each on the wrong
side.

**A calendar response is not a `.ots` artifact.** The draft set
`OTS_RESPONSE_CAP_BYTES = MAX_OTS_BYTES` — 1 MiB — on the reasoning that
A28's constraint is `receive_cap <= MAX_OTS_BYTES`. That satisfies the
constraint and conflates two quantities:

| quantity | what it bounds | value | owner |
| --- | --- | --- | --- |
| `MAX_OTS_BYTES` | the **merged** `.ots` embedded in the bundle — every calendar, every upgrade, accumulated | 1 048 576 (D10 row, frozen) | `antseal_core::codec::caps` |
| A28's merge-side cap | the merge step, carrying `merge_cap <= MAX_OTS_BYTES` | A28's | A28 |
| **`OTS_CALENDAR_RESPONSE_CAP_BYTES`** | **one HTTP reply from one calendar** | **65 536** | this record |

Largest of 18 real calendar responses measured 2026-08-02: **220 bytes**.
64 KiB is a 298× margin, comfortably above an upgraded attestation's
Bitcoin merkle path; 1 MiB is 4 766× and permanent. The distinction is
stated here because A28's `≤` constraint reads as if one number served both
and a reader would otherwise assume it does.

**An Arbitrum receipt is bigger than a round number.** The draft's
`RPC_RESPONSE_CAP_BYTES = 64 KiB` is **below this project's own payment
shape**. D37 permits 256 transfers in one transaction; a measured receipt
log is 731 B:

```
256 logs x 731 B          = 187 136 B
+ receipt envelope        ≈   1 192 B
                          = 188 328 B   the largest receipt A17 must read
64 KiB / 731 B            =      89 logs   where the draft would truncate
512 KiB / 188 328 B       =    2.78x       the ruling
```

At 64 KiB, A17 fails on **exactly the large seals it exists to
corroborate**, and it fails as `OversizeBody` — which reads as an endpoint
problem and would be attributed to one. Since this cap is not an F4 row
(§ the constants block: an RPC reply is advisory evidence, not an
embeddable artifact) it is freely adjustable in both directions, so the
raise-only asymmetry does not bind it — but the *misattribution* cost of
being too low does, and it is much the worse failure. 512 KiB also absorbs
the per-endpoint key-set variance §6.9(a) documents.

The other two are unchanged: `TSA_RESPONSE_CAP_BYTES` is an identity with
`MAX_TSA_TOKEN_BYTES` because one response *is* one embedded token, and
`ESPLORA_RESPONSE_CAP_BYTES = 16 KiB` bounds a reply whose payload is 160
hex characters.

### 6.9 Three things the substrate deliberately does **not** provide

Corrected and extended after the D54/D55/D57 lane reported measurements
that reach into this record. Each of the three is a negative ruling, and
each exists because the obvious affirmative version would be actively
misleading.

**(a) No response-comparison helper — agreement is never over bytes, except
where the payload has no representational freedom.** The two Arbitrum RPC
endpoints D55 ruled in return **different JSON key sets for the same
receipt** (`timeboosted` on one, `blobGasUsed` on the other) while the
values A17 actually compares are identical. A generic
`must_agree(a: &[u8], b: &[u8])` in the substrate would therefore report
disagreement — the *alarming* outcome, "a lying endpoint" — for two honest
endpoints, on every A17 call. The substrate offers no such helper at all.
Agreement is defined per source, by the consumer, over an **extracted
value**: for A16 the 80 raw header bytes (a fixed-width object with no
encoding freedom, so byte equality is the extraction); for A17 the
four-field tuple A17's own `Do` already names — presence, success status,
`blockNumber`, `blockHash`. This is the reading under which A16's
"byte-identical" and A17's "agree on … blockNumber, and blockHash" are both
correct, and the one under which a shared byte-comparator would have broken
A17 silently.

**(b) No generic liveness or health probe.** `publicnode` answers
`eth_blockNumber` in 0.75 s and then rejects `eth_getTransactionReceipt`
with `"Archive requests require a personal token"` (D55 lane measurement).
A probe on a cheap method therefore *certifies an endpoint that cannot
serve the only query A17 makes* — it converts an authorization failure into
an endorsement. The substrate provides no `ping`/`is_alive` surface, and
the rule for A25's runbook and any future endpoint check is: **probe with
the method the caller actually issues, against a real argument.** A liveness
check that does not is worse than none, because it produces a false
positive that survives review.

**(c) No browser reachability claim.** `antseal-anchor` is never compiled
to wasm32 (the verifier page performs its own fetches in JS and feeds
results to WASM-safe core through A2's `OnlineEvidence`), so nothing here
speaks for the page. Recorded because the boundary is this record's and the
hazard is real: `1rpc.io/arb` returns `Access-Control-Allow-Origin: *` on
the **CORS preflight** and none on the **POST**, so a browser passes
preflight and then discards the response. **Preflight agreement is not
evidence of browser reachability**, and any endpoint list the page inherits
from A16/A17 must be re-verified from a browser with the real request
before it is called page-usable.

### 6.10 A note on the host clock, and why no constant here depends on it

The machine this record was measured on runs **~129 s slow**. Nothing in
Decision 3 is derived from a wall-clock comparison: every constant is a
`Duration`, and every measurement behind it is an interval —
`Instant::elapsed()` in the probes, `curl`'s own `time_*` counters for the
endpoint table. A skewed clock cannot move any of them. The one place
absolute time enters M2 is TSA `genTime` and OTS attestation time, and
those are read from signed artifacts and evaluated in `antseal-core`
against a caller-supplied verification time (A9: "core never reads a system
clock") — not from this host.

## Decision

### 1. The dependency, verbatim

`Cargo.toml` (`[workspace.dependencies]`), placed after the `url` entry:

```toml
# HTTP client for anchor acquisition (A3; decision D90,
# docs/decisions/D90-anchor-http-substrate.md). Declared by
# `antseal-anchor` ALONE and UNGATED: required CI is default-features-only
# (ci.yml:122, :148), so a feature-gated network half would leave every
# Accept row of A3/A10/A13/A16/A17 — all of them local-stub unit tests —
# compiled by nothing, the D89 coverage cliff one milestone later. Measured
# 2026-08-02: default `--workspace` graph 129 -> 144 (+15 names, 25-package
# closure); ant-backend 447 -> 451; devnet 475 -> 479; four names new to
# Cargo.lock (ureq, ureq-proto, utf8-zero, webpki-roots). Every other crate
# in the closure resolves to the version the lock ALREADY carries —
# including `subtle 2.6.1` and `zeroize 1.9.0`, the project's own exact
# pins — and it brings no `digest`/`sha2`, so no second RustCrypto
# generation enters (rustls hashes through `ring`).
#
# BLOCKING, deliberately. `antseal-anchor` creates no runtime, borrows
# none, and requires no async context: `AnchorGate::run` keeps its frozen
# `async fn` signature and completes in ONE poll under the noop-waker
# executor `gate.rs` already uses (D90 probe 6). That is what makes A15/U24
# — an upgrade attempt on EVERY CLI invocation, in builds where tokio is
# not compiled in at all — implementable. reqwest's `blocking` feature is
# not an alternative: it is `tokio/sync` plus a background runtime, and
# costs +72 default packages against ureq's +15.
#
# EXACT-PINNED though it is outside dependency-policy §1's format/crypto/
# consensus class — the `rpassword` row's reason: it is the sole path by
# which adversary-controlled bytes enter the process before any parser of
# ours sees them, and three of its behaviours are load-bearing contracts a
# minor bump could move silently (`.limit(N)` accepts N-1 bytes;
# `max_redirects(0)` RETURNS the 3xx instead of erroring; `Config::default`
# reads HTTP_PROXY/ALL_PROXY from the environment). NO lockstep with
# anything.
#
# default-features = false drops `gzip` (flate2/miniz_oxide/crc32fast/
# adler2/simd-adler32 — 5 packages) and, with it, the whole
# decompression-bomb path under A28's streaming byte ceiling: a limit on a
# compressed body bounds the wrong number. `rustls` = rustls 0.23 over
# `ring` with the compiled `webpki-roots` snapshot — pinned trust, not the
# OS store, the same discipline as A6's pinned TSA roots one layer down.
# `webpki-roots` is NOT declared directly: it arrives through ureq and is
# frozen by Cargo.lock §3; an ureq bump review must state which
# webpki-roots it moves to.
#
# RUSTSEC + GHSA/osv.dev sweep 2026-08-02T19:32:36Z: zero advisories on
# record for ureq, ureq-proto, utf8-zero, webpki-roots and httparse; rustls
# 0.23.43, ring 0.17.14 and rustls-webpki 0.103.13 are each past every
# advisory on record (rustls-webpki sits exactly on RUSTSEC-2026-0104's
# fix). Licence MIT OR Apache-2.0; rust-version 1.85 <= the 1.92.0 pin.
ureq = { version = "=3.3.0", default-features = false, features = ["rustls"] }
```

`crates/antseal-anchor/Cargo.toml` — the only manifest that names it:

```toml
[features]
default = []
# A24's stub servers, exported for other crates' tests the way
# antseal-net exports MockBackend (antseal-cli/Cargo.toml dev-deps).
# Activates no optional dependency: it only compiles the module.
test-util = []

[dependencies]
antseal-core.workspace = true
thiserror.workspace = true
ureq.workspace = true
```

`crates/antseal-cli/Cargo.toml`, `[dev-dependencies]`, so the stub servers
compile in the default test lane exactly as `MockBackend` does:

```toml
antseal-anchor = { workspace = true, features = ["test-util"] }
```

### 2. Module layout and type names

| path | contents |
| --- | --- |
| `crates/antseal-anchor/src/http.rs` | the substrate — `HttpClient`, `HttpPolicy`, `HttpRequest`, `HttpResponse`, `AnchorHttpError`, all constants |
| `crates/antseal-anchor/src/http/retry.rs` | `Idempotency`, `RetryVerdict`, `classify` |
| `crates/antseal-anchor/src/http/endpoint.rs` | `Endpoint`, `TlsPolicy`, `EndpointError` |
| `crates/antseal-anchor/src/testing/stub.rs` | A24's `StubServer`, `StubReply`, `StubScript` (`#[cfg(any(test, feature = "test-util"))]`) |
| `crates/antseal-anchor/src/lib.rs` | `pub mod http;` + `#[cfg(any(test, feature = "test-util"))] pub mod testing;` |

Public surface, exact:

```rust
pub struct HttpClient { /* ureq::Agent + HttpPolicy */ }
pub struct HttpPolicy {
    pub timeouts: HttpTimeouts,
    pub max_attempts: u32,
    pub tls: TlsPolicy,
}
pub struct HttpTimeouts {
    pub global: Duration,
    pub resolve: Duration,
    pub connect: Duration,
    pub send_request: Duration,
    pub send_body: Duration,
    pub recv_response: Duration,
    pub recv_body: Duration,
}
pub enum TlsPolicy { Optional, RequiredExceptLoopback }
pub enum Idempotency { SafeToRepeat, AtMostOnceAfterSend }
pub struct HttpRequest<'a> {
    pub endpoint: &'a Endpoint,
    pub method: HttpMethod,          // Get | Post
    pub content_type: Option<&'a str>,
    pub accept: Option<&'a str>,
    pub body: &'a [u8],
    pub receive_cap_bytes: u64,      // the TRUE ceiling; the +1 is ours
    pub idempotency: Idempotency,
}
pub struct HttpResponse { pub status: u16, pub body: Vec<u8> }

impl HttpClient {
    pub fn new(policy: HttpPolicy) -> Self;
    pub fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, AnchorHttpError>;
}
impl HttpPolicy {
    pub fn seal() -> Self;           // A10, A13 — the pre-pay gate
    pub fn verify() -> Self;         // A16, A17 — `--online`
    pub fn opportunistic() -> Self;  // A15/U24 — one attempt, 3 s
}
```

`HttpClient::new` builds the agent exactly once, with exactly this
configuration — no call site may construct a bare `ureq::Agent`:

```rust
ureq::Agent::config_builder()
    .timeout_global(Some(policy.timeouts.global))
    .timeout_resolve(Some(policy.timeouts.resolve))
    .timeout_connect(Some(policy.timeouts.connect))
    .timeout_send_request(Some(policy.timeouts.send_request))
    .timeout_send_body(Some(policy.timeouts.send_body))
    .timeout_recv_response(Some(policy.timeouts.recv_response))
    .timeout_recv_body(Some(policy.timeouts.recv_body))
    .max_redirects(0)                                   // §6.4
    .http_status_as_error(false)                        // we classify, not ureq
    .proxy(None)                                        // §6.5 — NOT the default
    .https_only(false)                                  // per-request, from TlsPolicy
    .accept_encoding(ureq::config::AutoHeaderValue::None) // §6.1
    .user_agent(HTTP_USER_AGENT)
    .max_response_header_size(HTTP_MAX_RESPONSE_HEADER_BYTES)
    .build()
    .into()
```

`send()` applies the receive cap as
`response.body_mut().with_config().limit(request.receive_cap_bytes + 1).read_to_vec()`
— **the `+ 1` appears here and nowhere else**, with the probe-2 transcript
quoted in the doc comment.

The **non-2xx** path is different and must not copy that line, because
`.limit()` **errors, it does not truncate** (§6.1), and §6.7's `Status`
body is best-effort evidence rather than a payload we require in full. A
500 with a 1 MiB body must still produce `Status`, not `OversizeBody`. So
the error path reads through `Read::take`, which stops cleanly at the
ceiling:

```rust
use std::io::Read as _;
let mut evidence = Vec::new();
let _ = response
    .body_mut()
    .with_config()
    .limit(HTTP_ERROR_BODY_CAP_BYTES + 1)   // never trips; `take` stops first
    .reader()
    .take(HTTP_ERROR_BODY_CAP_BYTES)
    .read_to_end(&mut evidence);            // best-effort: a read failure
                                            // yields a short body, never an
                                            // error that hides the status
```

Two properties this shape has and the naive one does not: an over-long
error body is **truncated**, and a mid-body transport failure still
surfaces the status code rather than replacing it with a transport error.

### 3. Constants, verbatim, in `crates/antseal-anchor/src/http.rs`

```rust
/// Per-attempt wall-clock backstop. A3 proposed ~10 s; confirmed against
/// measured round trips (slowest real endpoint 1.996 s, 2026-08-02) — 5x
/// the worst observed. `Timeout(Global)` is classified AMBIGUOUS because
/// it cannot name a phase (D90 probe 3).
pub const HTTP_TIMEOUT_GLOBAL: Duration = Duration::from_secs(10);
/// Per-phase timeouts, all strictly inside the global so that an ordinary
/// stall reports its phase and the retry classifier can decide whether the
/// request was delivered (D90 probes PHASE-A/B/C).
pub const HTTP_TIMEOUT_RESOLVE: Duration = Duration::from_secs(3);
pub const HTTP_TIMEOUT_CONNECT: Duration = Duration::from_secs(4);
pub const HTTP_TIMEOUT_SEND_REQUEST: Duration = Duration::from_secs(4);
pub const HTTP_TIMEOUT_SEND_BODY: Duration = Duration::from_secs(4);
pub const HTTP_TIMEOUT_RECV_RESPONSE: Duration = Duration::from_secs(8);
pub const HTTP_TIMEOUT_RECV_BODY: Duration = Duration::from_secs(8);

/// 1 initial attempt + 2 retries. Worst case per endpoint under
/// `HttpPolicy::seal()`: 3 x 10 s + 0.8 s = 30.8 s, which is a
/// PER-ENDPOINT bound only because endpoints run on `std::thread::scope`.
pub const HTTP_MAX_ATTEMPTS: u32 = 3;
/// Deterministic and un-jittered: two to five named endpoints is not a
/// fleet, and an RNG in the retry path would make the timeout tests
/// approximate.
pub const HTTP_BACKOFF: [Duration; 2] =
    [Duration::from_millis(200), Duration::from_millis(600)];

/// A15/U24's hook fires on EVERY CLI invocation and must never delay the
/// host command: one attempt, no backoff.
pub const HTTP_OPPORTUNISTIC_GLOBAL: Duration = Duration::from_secs(3);
pub const HTTP_OPPORTUNISTIC_CONNECT: Duration = Duration::from_millis(1_500);
pub const HTTP_OPPORTUNISTIC_ATTEMPTS: u32 = 1;

/// Honest identification to volunteer calendars and commercial TSAs with
/// abuse controls. Replaces ureq's default `ureq/3.3.0`, which would tell
/// an observer of a plain-HTTP DigiCert request exactly which HTTP-client
/// bugs to aim at.
pub const HTTP_USER_AGENT: &str = concat!("antseal/", env!("CARGO_PKG_VERSION"));
/// Bounded before any body is read. ureq's own default is 64 KiB.
pub const HTTP_MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

/// The ceiling on a body carried inside `AnchorHttpError::Status` (§6.7).
/// Deliberately far smaller than any artifact cap: the bodies this exists
/// to preserve are discriminators, and the largest observed is 42 bytes.
/// A non-2xx body is never an anchor artifact, so it never approaches
/// `MAX_TSA_TOKEN_BYTES`/`MAX_OTS_BYTES` and must not be able to.
pub const HTTP_ERROR_BODY_CAP_BYTES: u64 = 4 * 1024;

// ── Receive-side ceilings (§6.8) ───────────────────────────────────────
// The substrate applies the `+ 1` that ureq's `LimitReader` requires
// (§6.1); every constant below is the TRUE ceiling.

/// A single TSA `TimeStampResp` **is** the artifact that gets embedded —
/// one response, one token — so the receive cap and the embed cap are the
/// same quantity, and A28's `receive_cap <= MAX_TSA_TOKEN_BYTES` becomes
/// an identity rather than an assertion that can drift. Consumed by name
/// from `antseal_core::codec::caps`, never redefined (D84 §5).
pub const TSA_RESPONSE_CAP_BYTES: u64 = antseal_core::codec::caps::MAX_TSA_TOKEN_BYTES as u64;

/// **A calendar's per-response body is NOT the embedded artifact**, and
/// this constant must not be confused with `MAX_OTS_BYTES` (§6.8).
/// `MAX_OTS_BYTES` = 1 MiB caps the *merged* `.ots` that goes into the
/// bundle, over every calendar and every upgrade; this caps one HTTP
/// reply. Measured across 18 real calendar responses (D54/D55/D57 lane,
/// 2026-08-02): the **largest was 220 bytes**. 64 KiB is a 298x margin
/// over that and leaves room for an upgraded attestation's Bitcoin merkle
/// path; 1 MiB would have frozen a ceiling **4 766x** above anything
/// observed, and under F4's raise-only rule a too-high cap can never be
/// walked back while a too-low one costs a follow-up commit.
/// A28's separate merge-side cap is the one that carries
/// `merge_cap <= MAX_OTS_BYTES`.
pub const OTS_CALENDAR_RESPONSE_CAP_BYTES: u64 = 65_536;

/// Advisory online evidence, not embeddable artifacts — no F4 registry row
/// (D84 F1-F4 govern anchor artifacts; an esplora reply is neither), so
/// these are freely adjustable network-path policy (A28 Notes).
pub const ESPLORA_RESPONSE_CAP_BYTES: u64 = 16 * 1024;

/// Sized from this project's own payment shape, not from a round number.
/// D37 permits **256 transfers in one transaction**; a measured Arbitrum
/// receipt log is 731 B, so the largest receipt A17 must be able to read
/// is 256 x 731 = 187 136 B of logs plus a ~1 192 B envelope = **188 328
/// B**. A 64 KiB cap would truncate at **89 logs** — i.e. A17 would fail
/// on exactly the large seals it exists to corroborate, and the failure
/// would surface as an endpoint problem and be attributed to one. 512 KiB
/// is 2.78x the D37-maximum receipt, absorbs the key-set variance between
/// endpoints (§6.9(a)), and costs at most 1 MiB resident across a must-agree
/// pair.
pub const RPC_RESPONSE_CAP_BYTES: u64 = 512 * 1024;
```

### 4. The typed error, verbatim

`AnchorHttpError` carries the endpoint URL and a failure class in every
arm, per A3's `Do`. It deliberately has **no `code()`**: the error-code
contract (`docs/testing/error-code-contract.md` §1) governs errors *a
verifier can surface*, and an acquisition failure never appears in a
`.sealproof` verdict. It reaches a user through `CliError`'s existing
classes, which already include `anchor-gate-abort`
(`crates/antseal-cli/src/error.rs:373`).

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AnchorHttpError {
    #[error("{endpoint}: not a usable endpoint URL ({reason})")]
    InvalidEndpoint { endpoint: String, reason: &'static str },
    #[error("{endpoint}: this endpoint must be https (only loopback literals are exempt)")]
    TlsRequired { endpoint: String },
    #[error("{endpoint}: DNS resolution failed after {attempts} attempt(s)")]
    Resolve { endpoint: String, attempts: u32 },
    #[error("{endpoint}: connection failed after {attempts} attempt(s): {detail}")]
    Connect { endpoint: String, attempts: u32, detail: String },
    #[error("{endpoint}: TLS handshake failed: {detail}")]
    Tls { endpoint: String, detail: String },
    #[error("{endpoint}: timed out sending the request ({phase})")]
    SendTimeout { endpoint: String, phase: &'static str },
    #[error("{endpoint}: timed out awaiting the response ({phase}); the request may have been delivered")]
    ReceiveTimeout { endpoint: String, phase: &'static str },
    /// A complete response arrived with a non-2xx status. **The body is
    /// carried, not discarded** — see §6.7: A14's pending/not-found
    /// discriminator is a 404 *body*, and collapsing this arm to a bare
    /// status code makes A14 unimplementable on top of the substrate.
    /// Bounded by `HTTP_ERROR_BODY_CAP_BYTES`, not by the request's own
    /// `receive_cap_bytes`.
    #[error("{endpoint}: HTTP {status} ({} body byte(s))", body.len())]
    Status { endpoint: String, status: u16, body: Vec<u8> },
    #[error("{endpoint}: HTTP {status} redirect to {location:?} — endpoints are pinned and redirects are never followed")]
    Redirected { endpoint: String, status: u16, location: Option<String> },
    #[error("{endpoint}: response exceeds the {cap_bytes}-byte receive ceiling")]
    OversizeBody { endpoint: String, cap_bytes: u64 },
    #[error("{endpoint}: malformed HTTP response: {detail}")]
    MalformedResponse { endpoint: String, detail: String },
    #[error("{endpoint}: transport failure: {detail}")]
    Transport { endpoint: String, detail: String },
}
```

The `endpoint` field carries a URL only. Calendar upgrade URLs embed a
commitment derived from `anchor_digest` — public manifest-identity data,
never `W`, a unit key or a salt — so project rule 6 is satisfied by
construction and the field needs no redaction.

### 5. The `core-dep-graph` rule — the interim extension, verbatim, and where it goes

**Scope note.** This is the *interim regression guard* of §5 item 3, not the
structural fix. The structural fix — replacing the denylist with a
committed allowlist of `antseal-core`'s permitted normal-graph names — is
**Q74's**, minted elsewhere in this wave, and is deliberately not attempted
here. If Q74 lands first, the two new names below are subsumed by its
allowlist and this edit reduces to the self-test.

In `scripts/ci-lanes.sh`, **replace line 197** and insert the self-test
between it and the current line 198:

```bash
  local forbidden='^(tokio|async-std|smol|hyper|reqwest|ureq|ureq-proto|attohttpc|isahc|curl|rustls|native-tls|openssl|webpki-roots|httparse|http|mio|socket2|getrandom|rand|rand_chacha) ' tree offenders
  # Self-test FIRST, in BOTH directions (D90, 2026-08-02). Until this
  # record, the forbidden-crate scan was the ONE rule in this lane without
  # a self-test — every other one plants a violation first (P15/D35 :100,
  # S23 :154, S6 :239, P20 rule 1 :325, rule 3 :376, D89 rule 5 :424) —
  # so a dropped `^`, a lost alternation bar or a missing trailing space
  # would have made it green forever, which is exactly the failure mode
  # those self-tests exist to prevent.
  if ! printf 'ureq v3.3.0\n' | grep -qE "$forbidden"; then
    printf '::error::core-dep-graph self-test FAILED: the forbidden-crate pattern does not match a planted `ureq v3.3.0` line in the shape `cargo tree --prefix none` emits — fix it before trusting any green verdict\n'
    return 1
  fi
  if printf 'rand_core v0.10.1\n' | grep -qE "$forbidden"; then
    printf '::error::core-dep-graph self-test FAILED: the forbidden-crate pattern ALSO matches `rand_core`, the pinned pure-trait crate this rule deliberately permits (the `^rand ` entry trailing space is what keeps them apart) — it can never be green for the right reason\n'
    return 1
  fi
```

`ureq` joins the list because it is the client this record adopts;
`rustls`/`native-tls`/`openssl`/`webpki-roots`/`httparse`/`http` join it so
a transport crate cannot enter `antseal-core` without one. This is an
**addition**: no existing assertion is relaxed, removed or re-scoped, and
the real `antseal-core` normal graph is green under the new pattern
(verified 2026-08-02).

It does **not** close the hole §5 item 3 measured — `libc`, `regex`,
`env_logger`, `is-terminal` and `termcolor` still pass — and the comment
above the pattern must say so in the file, so the next reader is not misled
by a rule that reads like a guarantee:

```bash
  # SCOPE (D90, 2026-08-02): this is a DENYLIST. It catches the crates
  # named and nothing else — `libc`, `regex`, `env_logger`, `is-terminal`
  # and `termcolor` all pass it today, measured. The lane's headline
  # ("must be I/O-free") is therefore stronger than this assertion, and
  # closing that gap with a positive allowlist of antseal-core's permitted
  # normal-graph names is Q74's work. Until then, treat a green verdict as
  # "none of the named offenders is present", not as "the graph is pure".
```

### 6. Documentation edits that land with the code

- `docs/dependency-policy.md` §1 — a new row for `ureq` with the
  exact-pin rationale of Decision 1 (`rpassword` class: no format byte, but
  the rawest adversary-facing surface in the product), **no lockstep**, and
  the note that `webpki-roots` moves with it under §3.
- `docs/dependency-policy.md` — the rule-1 paragraph at :87-96 gains a
  dated amendment: "129 → 144 (D90, 2026-08-02); 475 → 479 with
  `devnet-launcher/devnet`". This is the only place the number is recorded
  as a claim rather than printed as evidence.
- `Cargo.toml:150-162` (the tokio entry) — its closing sentence, "Every
  product edge is feature-gated non-default, so the default `--workspace`
  graph resolves no tokio at all", is **false as the `dep-graph` lane
  measures**: that lane uses `-e normal,build,dev`, and
  `cargo tree -i tokio --workspace -e normal,build,dev` reports
  `antseal-net v0.0.0` as tokio's parent via its DEV edge. The claim is
  true only of `-e normal` (default normal graph: 100 packages, no tokio).
  Correct it to say so; D90 changes nothing about it, but the sentence is
  quotable and wrong.

### 7. A24 — the test-side substrate

**Hand-rolled `std::net::TcpListener`, zero dependencies, in
`crates/antseal-anchor/src/testing/stub.rs`.** No stub-server crate is
nominated, and the reason is capability rather than package count:

- A3 requires a **timeout** test — a server that accepts and then never
  answers, and separately one that sends headers and then stalls. Probes
  PHASE-A and PHASE-B are exactly those, in nine lines of `std`.
- A5/A21 require **malformed framing** (a BER-transcoded token, a truncated
  body, a `Content-Length` that lies). A correct HTTP server crate cannot
  emit those; a raw listener writes the bytes.
- A16 requires **disagreement** and **one-endpoint-down** — two listeners
  with scripted, differing replies, one of them dropping the connection.
- A10 requires an oversized token to exercise A28's cap.

All of it is proven working: probes 1–7 build the mock TSA / stall / drop /
oversize / redirect / concurrent-pair shapes on `TcpListener` alone, on
`http://127.0.0.1:0`, with no network access (Q16 satisfied by
construction — a loopback listener cannot reach a real endpoint). Because
no dev-dependency is added, there is nothing new for `deny.toml` to admit:
its `advisories`/`bans`/`sources` checks see no new crate, and the stubbed
`licenses` check is untouched.

```rust
pub struct StubServer { /* JoinHandle + SocketAddr */ }
pub enum StubReply {
    Body { status: u16, content_type: &'static str, bytes: Vec<u8> },
    Raw(Vec<u8>),                       // byte-exact, for malformed framing
    StallBeforeHeaders(Duration),
    StallAfterHeaders(Duration),
    DropConnection,
    Redirect { status: u16, location: String },
}
pub struct StubScript { /* replies in order; requests recorded */ }
impl StubServer {
    pub fn spawn(script: StubScript) -> Self;
    pub fn base_url(&self) -> String;   // always http://127.0.0.1:<port>
    pub fn requests(&self) -> Vec<Vec<u8>>;
}
```

The mock TSA's *signing* half (test CA, RSA + ECDSA P-384 signer,
controllable genTime/PKIStatus) stays A24's own work on top of this
transport; D90 rules only on what carries the bytes.

## Verification obligations — exact test names, and what makes each fail

Every one lives in `crates/antseal-anchor/`, runs in the **default** lane
(`cargo test --workspace --locked`), and needs no network.

| test | fails when |
| --- | --- |
| `http::tests::receive_cap_accepts_exactly_the_ceiling_and_rejects_one_more` | the `+ 1` compensation is dropped or duplicated. Asserts a body of exactly `receive_cap_bytes` succeeds and `receive_cap_bytes + 1` returns `OversizeBody`. Under a literal `.limit(cap)` the first half fails — which is the bug this test exists for. |
| `http::tests::receive_cap_is_enforced_before_the_body_is_buffered` | the cap moves to a post-hoc length check. Stub sends a `Content-Length: 64 MiB` header and then streams; the test asserts the call returns `OversizeBody` having read no more than `cap + 1` bytes (measured by the stub's own write accounting). |
| `http::tests::each_timeout_phase_reports_its_own_phase` | per-phase timeouts are dropped in favour of a global one. Three stubs (stall before headers / after headers / unroutable `192.0.2.1`) must yield `SendTimeout`/`ReceiveTimeout` with distinct `phase` strings, never all-`global`. |
| `http::retry::tests::post_is_not_retried_after_the_request_was_delivered` | `Idempotency` collapses to one policy. Stub counts requests; a `RecvResponse` stall under `AtMostOnceAfterSend` must leave the count at **1**. Under a naive "retry all transport errors" it is 3, and A13 double-submits. |
| `http::retry::tests::get_is_retried_on_pre_send_failure_and_succeeds` | retry is silently disabled. Stub refuses the first two connections and answers the third; must succeed with count 3. |
| `http::retry::tests::deterministic_failures_are_never_retried` | a 4xx or `OversizeBody` enters the retry loop. Request count must be 1 for each of 400/404/`OversizeBody`. |
| `http::tests::a_redirect_is_an_error_not_a_response` | the 3xx-classification of §6.4 is removed on the assumption that `max_redirects(0)` errors. Stub returns 302 with an empty body; must be `Redirected`, never `Ok { status: 302, body: [] }`. |
| `http::tests::a_non_2xx_response_carries_its_body` | someone "simplifies" `Status` to a bare code — the draft defect of §6.7, which would make A14 unimplementable. Stub returns `404` with body `Pending confirmation in Bitcoin blockchain`; the test asserts `Status { status: 404, body, .. }` where `body` is that exact 42-byte text, **and** a second case where a `404` with `Not found` yields a *different* body from the same status. A one-sided test that only checks `status == 404` would pass under the defect, so both bodies must be asserted. |
| `http::tests::a_non_2xx_body_is_capped_independently_of_the_artifact_cap` | `HTTP_ERROR_BODY_CAP_BYTES` is dropped and an error path inherits a 1 MiB ceiling. Stub returns `500` with a 64 KiB body; the carried body must be at most `HTTP_ERROR_BODY_CAP_BYTES`, and the call must still return `Status` rather than `OversizeBody` — an over-long *error* body is truncated evidence, not a failed request. |
| `http::endpoint::tests::tls_required_rejects_plain_http_for_public_hosts` | `TlsPolicy` is not enforced. `http://example.org/api` under `RequiredExceptLoopback` must be `TlsRequired`; `https://example.org/api` must pass. |
| `http::endpoint::tests::tls_required_exempts_loopback_literals_only` | the carve-out widens. `http://127.0.0.1:9/` and `http://[::1]:9/` pass; `http://localhost:9/` and `http://127.0.0.1.evil.example/` are `TlsRequired`. |
| `http::tests::plain_http_is_permitted_under_the_optional_policy` | a later hardening pass makes the substrate TLS-only and silently kills DigiCert. Asserts a `http://127.0.0.1` POST under `TlsPolicy::Optional` succeeds. |
| `http::tests::the_agent_never_takes_a_proxy_from_the_environment` | `.proxy(None)` is dropped. Sets `HTTP_PROXY` to a listener that would answer, points the request at a *different* stub, and asserts the request arrived at the second — i.e. the proxy was ignored. **This is the test that would have caught ureq's default**, and it must be run single-threaded or with a process-scoped env guard. |
| `http::tests::the_client_sends_our_user_agent_and_no_accept_encoding` | the UA or `accept_encoding` setting is lost. Stub asserts the raw request bytes contain `antseal/` and contain no `accept-encoding` header. |
| `gate::tests::a_blocking_gate_body_completes_under_the_noop_waker_executor` | someone converts the substrate to async and the crate silently acquires a runtime requirement. Drives an `AnchorGate` impl whose body performs a real stub-server call through the existing `block_on`, and asserts completion. It fails to **compile or complete** the moment a reactor is needed. |
| `http::tests::endpoints_run_concurrently_not_sequentially` | the scoped-thread fan-out is replaced by a loop. Two stubs, one 1.5 s slow; asserts total wall < 2.4 s **and** that the fast endpoint's own elapsed is < 900 ms. The second assertion is the non-vacuous half: a sequential implementation that happens to query the fast one first would pass a wall-clock check alone. |
| `core-dep-graph` lane (`scripts/ci-lanes.sh`) | the two new self-tests fail if the pattern stops matching `ureq v3.3.0` or starts matching `rand_core v0.10.1`. Both directions verified 2026-08-02 against the real `antseal-core` tree, which stays green. |

| `http::tests::the_rpc_cap_admits_a_maximum_size_arbitrum_receipt` | `RPC_RESPONSE_CAP_BYTES` is lowered back toward a round number and A17 starts failing on large seals. Stub returns a synthetic receipt of **188 328 bytes** (D37's 256-transfer worst case, §6.8); the call must succeed. A cap of 64 KiB fails it — which is the regression this test exists for — and the test must also assert that `RPC_RESPONSE_CAP_BYTES >= 188_328` as a `const` assertion, so the arithmetic is pinned even if the stub is later shrunk for speed. |
| `http::tests::the_ots_response_cap_is_not_the_merged_artifact_cap` | someone "simplifies" `OTS_CALENDAR_RESPONSE_CAP_BYTES` to `MAX_OTS_BYTES`, re-conflating the two quantities of §6.8. A `const` assertion that `OTS_CALENDAR_RESPONSE_CAP_BYTES < antseal_core::codec::caps::MAX_OTS_BYTES as u64` — strict inequality, because equality *is* the conflation. Cheap, and it fails at compile time. |

**One anti-vacuity note, since this project keeps finding tests that cannot
fail.** `http::tests::receive_cap_accepts_exactly_the_ceiling_and_rejects_one_more`
must use a **small synthetic cap** (e.g. 1 024) rather than
`MAX_TSA_TOKEN_BYTES`; a 1 MiB body per assertion is slow enough that the
test will eventually be "optimised" into a single-sided check, and the
single side that would survive is the one the off-by-one already passes.

## Consequences for the gated tasks

- **A3 — unblocked, and its `Do` is now executable.** Its `Deps` line must
  lose "P: … HTTP-client crate pin" and gain "P29 (the pin lands in
  `[workspace.dependencies]`); D90". Accept row 2's "dependency-graph
  assertion" is Decision 5.
- **A10 — the plain-HTTP DigiCert path is ruled safe, with the reason
  recorded** (§6.6), which is the "record this rationale for Q's docs" its
  Notes already ask for. Its retry policy is `AtMostOnceAfterSend`.
- **A13 — protected from double-submission by construction**
  (`AtMostOnceAfterSend`), which its Accept row 1 depends on without saying
  so.
- **A14 — `SafeToRepeat`, and its three-way upgrade discriminator is
  expressible** because `AnchorHttpError::Status` carries the body (§6.7).
  Caution it inherits from the measurement: the two 404 bodies differ in
  length between calendars (9 vs 10 bytes), so the matcher compares trimmed
  content, never length and never a byte-exact literal.
- **A15/U24 — `HttpPolicy::opportunistic()`**, and one finding it must act
  on: at any timeout this substrate can offer, "never delays the host
  command" requires the hook to run **after** output is flushed (§6.3).
- **A16 — gains a hard requirement it did not have**: both esplora
  endpoints must be `https`, redirects are refused, and no proxy is read
  from the environment. Without all three, "both must succeed AND agree" is
  satisfiable by one attacker. This is A49.
- **A17 — same TLS requirement**, same reason: `eth_getTransactionReceipt`
  replies are unsigned.
- **A24 — its transport is decided and proven** (Decision 7); its
  remaining work is the TSA signing half and the recorded-exchange
  fixtures. No dev-dependency, so no `deny.toml` change.
- **A28 — inherits the exact constant expressions and the `+ 1`
  encapsulation** (Decision 3), and one correction it must carry: the TSA
  side is an identity (`TSA_RESPONSE_CAP_BYTES = MAX_TSA_TOKEN_BYTES` —
  one response *is* one embedded token, so the relation cannot drift), but
  the OTS side is **two distinct caps**, not one (§6.8). A28 owns the
  merge-side cap carrying `merge_cap <= MAX_OTS_BYTES`; this record owns
  the per-response cap at **65 536**, and A28's Accept row 3
  ("a compile-time or test-time assertion pins `receive_cap <= MAX_*_BYTES`
  for both") must assert the merge cap against `MAX_OTS_BYTES` and the
  response cap against the merge cap — a chain of two, not one relation
  reused.
- **A17 — its receive cap is sized from D37, not from a round number**
  (§6.8): 512 KiB against a 188 328 B worst-case receipt at D37's
  256-transfer maximum. And its agreement predicate is the four-field
  tuple its own `Do` names, never response bytes — the two ruled-in
  endpoints return different JSON key sets for identical values (§6.9(a)).
- **Q74 — adjacent, not blocking** (§5 item 3). A3 lands with Decision 5's
  interim extension; A3's Accept row 2 is review-enforced until Q74
  replaces the denylist with an allowlist, at which point the two names
  D90 adds are subsumed. Running Q74 first is strictly better and costs A3
  nothing.
- **P18 — superseded by D58** (no `opentimestamps` crate is adopted), which
  is why §Context cites it only historically. The substrate is unaffected:
  it carries opaque bytes in both directions either way.
- **Containment lanes — which verdicts change: none.** Rule 1's five-name
  scan, rule 2 (self_encryption, both halves), rule 3 (alloy lockstep),
  rule 4 (S23 declared-edge owners) and rule 5 (one k256) all keep their
  current verdicts (§4.4). Two things move, both additive: the **printed**
  default count 129 → 144, and the forbidden-crate list plus its new
  self-test.
- **`audit-deny`** — `[graph] all-features = true` will now sweep ureq's
  closure; zero advisories (§2.1). `bans.multiple-versions = "warn"` gains
  `getrandom 0.2.17` alongside the existing 0.3.4/0.4.3 pair — a warning,
  not a verdict.
- **`wasm32-core` / `wasm32-core-tests` / `getrandom` audit — untouched.**
  The dependency edge runs anchor → core, never the reverse, and
  `scripts/wasm-toolchain-audit.sh:54-58` audits only `antseal-core` and
  `wasm-bitmatch`. `antseal-anchor` is never built for wasm32: the verifier
  page performs its own online fetches in JS and feeds results to
  WASM-safe core through A2's `OnlineEvidence` (tasks/A.md:25).
- `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

## Residual risks

1. **The default graph is 144 and the next request will cite this record.**
   Stated plainly, as D89 did: 15 packages bought a functional capability
   *and* a coverage property, with the closure enumerated and every version
   shown to be one the lock already carries. It licenses no sixteenth
   without the same measurement.
2. **`webpki-roots` is a trust input that arrives transitively.** It is
   frozen by `Cargo.lock` and CI builds `--locked`, so it cannot move
   silently — but a `cargo update` moves it without any lane commenting.
   Mitigation is procedural: the ureq bump row in the dependency policy
   requires stating which `webpki-roots` the bump moves to. If that proves
   too weak, the fix is a direct exact-pinned declaration, deliberately not
   pre-committed here.
3. **A stale root snapshot is a liveness failure with a confusing
   signature.** If a TSA or esplora host rotates to a root the snapshot
   predates, A10/A16 report `Tls`, which reads like an attack. A25 is the
   detector; the error text names TLS explicitly so the triage is short.
4. **The multi-thread-runtime coupling** (§3.3). Latent today, guarded by
   Q84.
5. **`ureq 3.3.0`'s behaviours are contracts we discovered, not contracts
   it publishes.** The `.limit` off-by-one and `max_redirects(0)`'s
   non-erroring return are emergent from its implementation. Both are
   pinned by named tests here, so a bump that changes either goes red — but
   the tests are ours, not upstream's, and an ureq bump review must run
   them deliberately.
6. **Plain HTTP to DigiCert leaks the `anchor_digest` to a passive
   observer.** Integrity is unaffected (§6.6). If this ever matters to a
   user, the mitigation is configuration — drop DigiCert from the TSA list
   under U26 — and no code change; recorded so the option is visible.
7. **A retry can still double-submit in one case**: a calendar that
   processes a request and then fails *before* sending any response byte,
   presenting as `Timeout(RecvResponse)`. `AtMostOnceAfterSend` stops
   there, so this record's failure direction is a *missed* stamp, not a
   duplicated one — the correct direction, because A13 already tolerates a
   per-calendar failure ("≥1 success ⇒ a pending OTS anchor exists") and
   has no mechanism to tolerate a duplicate.

## Revisit triggers

- **An ant-core bump that puts a `reqwest`/`hyper` client in the *default*
  graph** — would change §4.2's arithmetic completely and should re-open
  the client choice, not just the pin.
- **A15/U24 finding 3 s unacceptable even post-flush** — the answer is a
  smaller `HTTP_OPPORTUNISTIC_GLOBAL` or a background upgrade path, not an
  async runtime; re-read §3 before reaching for tokio.
- **`antseal-anchor` ever needing to run in a browser** — it does not
  today (A2 routes online evidence through the host), but if that changed,
  ureq is not a wasm32 client and the whole shape is re-opened.
- **DigiCert offering HTTPS** (port 443 refused connections on
  2026-08-02T19:35:51Z) — would let A10's default TSA list move to
  `https://`, removing risk 6. It would *not* justify making the substrate
  TLS-only: user-configured TSAs under U26 may still be plain HTTP, and
  §6.6's argument is about signatures, not about DigiCert.
- **A required CI lane appearing that compiles non-default features** —
  would weaken §4.2's decisive argument, though not §4.3's. S30 is the
  open task; if it lands, this record's gating conclusion should be
  re-read, not automatically reversed.

## Register entry text (orchestrator pastes into `TODO.md`)

Under **M2 — Anchors**, in the decision register block beside D53–D61:

```
- [x] **D90** Anchor network substrate: HTTP-client pin, execution model, and dependency-graph position — **RESOLVED 2026-08-02** — `ureq = "=3.3.0"` (`default-features = false`, `features = ["rustls"]`), **blocking**, **ungated**, declared by `antseal-anchor` alone; default `--workspace` graph 129 → 144, ant-backend 447 → 451, devnet 475 → 479. No runtime is created, borrowed or required — `AnchorGate::run` keeps its frozen `async fn` and completes in one poll under the existing noop-waker executor; endpoint independence is `std::thread::scope`. Gating it behind `ant-backend` was refused on D89's ground: required CI is default-features-only, so every Accept row of A3/A10/A13/A16/A17 — all local-stub unit tests — would be compiled by nothing. Also settled: per-phase timeouts (10 s global, confirming A3), `Idempotency::AtMostOnceAfterSend` for the calendar/TSA writes so a retry can never double-submit, `max_redirects(0)` **plus** our own 3xx classification (ureq returns the 3xx rather than erroring), `.proxy(None)` (ureq's default reads `HTTP_PROXY`, which would collapse A16's must-agree pair onto one origin), HTTPS mandatory for esplora/RPC and plain HTTP permitted for RFC 3161 (DigiCert has no port 443 at all — measured), a streaming receive ceiling whose `.limit(N)` accepts only N−1 bytes, **four receive caps sized from measurement** (calendar reply 64 KiB, not `MAX_OTS_BYTES` — largest of 18 real replies is 220 B and F4 makes a too-high cap permanent; Arbitrum RPC 512 KiB, not 64 KiB — D37's 256-transfer maximum is a 188 328 B receipt, so 64 KiB would fail A17 on exactly the large seals it corroborates), and **a non-2xx failure that carries its body** (D58's three-way calendar discriminator is a 404 *body*; the draft discarded it and would have made A14 unimplementable). Found: the `core-dep-graph` forbidden-crate scan is the one rule in that lane with **no self-test**, and its denylist is measurably weaker than its headline — D90 adds the client name + the self-test as an interim guard and is **adjacent to Q74, not blocked by it**. Discovered: **A49**, **P29**, **Q83**, **Q84** — gates A3 → A10/A13/A16/A17 → A14/A15/A20/A25
```
