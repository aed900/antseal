# D54 — The default OpenTimestamps calendar set

- **Status: RESOLVED — the default list is the upstream OTS client's own
  four defaults, verbatim and in upstream's order, and they are NOT the
  hosts this project has been using. Upstream stamps at four *aggregator*
  endpoints (`otsclient/cmds.py:186-189`) — `a.pool.opentimestamps.org`,
  `b.pool.opentimestamps.org`, `a.pool.eternitywall.com`,
  `ots.btc.catallaxy.com` — never at the `*.btc.calendar.opentimestamps.org`
  hosts the A25 bootstrap capture used. That distinction is the whole
  decision: `finney.btc.calendar.opentimestamps.org`, whose death the brief
  cites as the motivating failure, **was never in upstream's default list**,
  and the pool aliases are precisely the operator-controlled indirection
  layer that makes a calendar's death invisible to us. Submit to all four
  concurrently; **≥2 DISTINCT calendars** (deduplicated by the pending
  attestation's URI, not by the URL we posted to) is a normal outcome, 1 is
  a named degradation, 0 is an OTS-absent degradation — and **none of the
  three ever blocks a seal**, because A20's gate is TSA-only and a
  seal-time OTS anchor is `pending`, which A18 makes non-headline-eligible.
  Calendars have no public key and none is pinned: OTS is unforgeable under
  calendar impersonation by construction, so this is a liveness decision,
  not a trust decision. What IS pinned is an **upgrade-URI host allowlist**
  (three suffixes), which is append-only where the submit list is freely
  mutable — replacing a dead default is not a format event and touches no
  byte of `antseal-core`.**
- **Date: 2026-08-02** (M2 planning round; register `TODO.md:566`, "A-OD2")
- **Owning tasks: A13** (submission client), **A14** (upgrade polling),
  **A20** (degradation reporting), **A25** (real-endpoint runbook);
  new **A42** (allowlist), **A44** (rot watch), **U44** (config slot)
- **Blocks: A13, A14, A20, A25, U22, U24**

## Context — what the register asked, and what was actually wrong

The register entry (`TODO.md:566`) carries a requirement, not a lean:
"Default OTS calendar set (≥2; liveness-verified)". There was therefore no
recommendation to overturn. What there *was* is an operating assumption,
embodied in the committed evidence: `testdata/anchors/A25-bootstrap/CAPTURE.log`
stamps at `alice`, `bob`, `finney` and `catallaxy` under
`*.btc.calendar.opentimestamps.org`, and records

```
curl: (6) Could not resolve host: finney.btc.calendar.opentimestamps.org
submit digest=A calendar=finney url=https://finney.btc.calendar.opentimestamps.org http=000 …
```

I re-verified that host twice — `2026-08-02T19:21:38Z` and
`2026-08-02T19:23:03Z`, both NXDOMAIN, `getent ahosts` and `curl` agreeing.
It is dead.

**It is also not, and appears never to have been, one of the OTS client's
defaults.** The defaults are hardcoded in
`opentimestamps-client/otsclient/cmds.py` (retrieved
`2026-08-02T19:23:37Z`), lines 184–189:

```python
    if not args.calendar_urls:
        # Neither calendar nor wallet specified; add defaults
        args.calendar_urls.append('https://a.pool.opentimestamps.org')
        args.calendar_urls.append('https://b.pool.opentimestamps.org')
        args.calendar_urls.append('https://a.pool.eternitywall.com')
        args.calendar_urls.append('https://ots.btc.catallaxy.com')
```

mirrored by `DEFAULT_AGGREGATORS` in `python-opentimestamps/opentimestamps/calendar.py:156-160`
(retrieved `2026-08-02T19:23:40Z`). The brief's framing — "one of the four
standard public OTS calendars failed DNS resolution" — is therefore true of
a host we chose ourselves and false of upstream's default set, every member
of which is alive. Correcting that is what produced the ruling.

## 1. What the pool endpoints actually are (measured)

A pool endpoint is a thin aggregator in front of exactly one calendar. I
submitted throwaway digests derived from the documented fixed test seed
(`testdata/README.md`: `W = 00 01 … 1f`; digest =
`SHA-256(label ‖ W)`, the `alternate_test_secret` formula at
`crates/antseal-core/src/test_util/mod.rs:261`) and read back the pending
attestation URI each returned.

Submissions at `2026-08-02T19:27:31Z` (label `antseal/D54 calendar-liveness probe`,
digest `529ac53a68a69a6c62388cf338a1cc6b15b658efb3d8a1057402fc2b23d1fc33`)
and three more rounds at `19:30:14Z`–`19:30:32Z` (labels
`antseal/D54 pool-stability probe 1..3`):

| submit URL | HTTP | pending attestation URI | rounds agreeing |
| --- | --- | --- | --- |
| `https://a.pool.opentimestamps.org` | 200 | `https://alice.btc.calendar.opentimestamps.org` | 4/4 |
| `https://b.pool.opentimestamps.org` | 200 | `https://bob.btc.calendar.opentimestamps.org` | 4/4 |
| `https://a.pool.eternitywall.com` | 200 | `https://finney.calendar.eternitywall.com` | 4/4 |
| `https://ots.btc.catallaxy.com` | 200 | `https://btc.calendar.catallaxy.com` | 4/4 |
| `https://alice.btc.calendar.opentimestamps.org` | 200 | `https://alice.btc.calendar.opentimestamps.org` | 1/1 |
| `https://bob.btc.calendar.opentimestamps.org` | 200 | `https://bob.btc.calendar.opentimestamps.org` | 1/1 |

Three consequences, all load-bearing:

1. **The pool alias is a stable 1:1 indirection**, not a load balancer —
   twelve submissions, zero variation.
2. **`a.pool.eternitywall.com` resolves to a live host named `finney`** —
   `finney.calendar.eternitywall.com`, IP `51.158.62.115`, HTTP 200,
   OpenTimestamps Calendar Server v0.7.1. The dead `finney` and the live
   `finney` are different machines run by different people (Peter Todd's
   `*.btc.calendar.opentimestamps.org` versus Riccardo Casatta's
   `*.calendar.eternitywall.com`). Anyone reasoning about "finney" without
   the full hostname will reach the wrong conclusion.
3. **Posting to a pool and posting to its calendar yields the same
   attestation.** `a.pool.opentimestamps.org` and
   `alice.btc.calendar.opentimestamps.org` both return a pending
   attestation for `alice`. A list containing both would look like two
   calendars and merge into one. This is why the success count below is
   defined over *pending URIs*, not submit URLs.

### Why the pool aliases are the right default

The indirection is the rot mitigation, and the project's own capture is the
case study: had antseal shipped `finney.btc.calendar.opentimestamps.org` as
a default constant, it would today have a dead default requiring a release
to fix. A client that shipped `a.pool.opentimestamps.org` would have needed
nothing, because the operator repoints the alias.

The indirection costs nothing in evidentiary strength, because a calendar
cannot forge time even if wholly controlled by an attacker (§4).

## 2. Liveness of the ruled set (measured, `2026-08-02T19:22:59Z`–`19:30:32Z`)

All four defaults, plus the two calendars behind the opentimestamps pools:

| host | DNS | `GET /` | server version | pending commitments | latest tx broadcast |
| --- | --- | --- | --- | --- | --- |
| `a.pool.opentimestamps.org` | `167.99.188.103` | 200 | (alias of alice) | — | — |
| `b.pool.opentimestamps.org` | `35.168.1.55` | 200 | (alias of bob) | — | — |
| `a.pool.eternitywall.com` | `51.158.62.115` | 200 | (alias of finney/EW) | — | — |
| `ots.btc.catallaxy.com` | `170.75.171.61` | 200 | v0.6.0 | 32 506 | none |
| `alice.btc.calendar.opentimestamps.org` | `167.99.188.103` | 200 | v0.7.1 | 4 922 | `74059ec8…` (3 prior versions) |
| `bob.btc.calendar.opentimestamps.org` | `35.168.1.55` | 200 | v0.7.1 | 4 791 | `beaa48b5…` (6 prior versions) |
| `finney.calendar.eternitywall.com` | `51.158.62.115` | 200 | v0.7.1 | 4 322 | none |
| `finney.btc.calendar.opentimestamps.org` | **NXDOMAIN** | — | — | — | — |
| `b.pool.eternitywall.com` | **NXDOMAIN** | — | — | — | — |

All four reported the same Bitcoin best-block
(`00000000000000000001b83907fc15e2a095293fed51dd26caf36466b215cd47`, height
960 764), so the pending-commitment figures are comparable. Submit
latencies across 18 real submissions: **0.657 s – 2.619 s**; response
bodies **115 – 220 B**.

**One observation to carry into the rot watch, not into an exclusion**:
catallaxy runs the older v0.6.0 and shows ~6.6× the pending backlog of the
other three on the same block, with no unconfirmed timestamp transaction —
consistent with a calendar that is not clearing. This is a single snapshot
and is not grounds to drop it (it answered every submission, and its
backlog affects *upgrade latency*, never correctness); it is grounds to
make backlog a monitored signal (A44).

## 3. The ruling on counts, failure and the gate

**Submit to all four, concurrently.** No m-of-n early exit: we are inside a
seal about to spend money, not on an interactive latency budget, and every
extra pending attestation is free redundancy for the eventual upgrade.
Bound the stage by the A3 per-request timeout (10 s) and an overall
deadline of 30 s — ~11× the worst latency measured.

**Distinct-success counting.** The outcome is keyed on the number of
*distinct normalized pending-attestation URIs* collected, never on the
number of HTTP 200s:

| distinct pending URIs | outcome | seal proceeds? | report |
| --- | --- | --- | --- |
| ≥ 2 | `Ots::Complete` | yes | normal |
| 1 | `Ots::Thin` | yes | **degradation note naming the failed endpoints and their failure class** |
| 0 | `Ots::Absent` | yes | **degradation note; the anchor set carries no OTS artifact** |

**No OTS outcome ever fails a seal, and none is silent.** Both halves are
deliberate:

- *Never fails*: A20's gate is "proceed iff ≥1 TSA token passed full core
  verification" (`tasks/A.md`, A20 Do). At seal time an OTS anchor is
  `pending`, and `pending` is not headline-eligible (spec line 133). Gating
  a paid, irreversible seal on evidence that carries no time would trade a
  permanent cost for zero evidentiary gain. **OTS contributes exactly zero
  to A20's minimum-anchor gate.** A13's existing text already says this
  ("the abort gate is TSA-based"); this record ratifies it and states the
  reason.
- *Never silent*: every per-endpoint failure appears verbatim — URL,
  failure class, elapsed — in A20's degradation report and in the U22 seal
  summary. Spec line 189's "anchor failures downgrade the seal report
  loudly, never silently" is the governing rule.

**Spec line 106's "≥2 public calendars" is a submission requirement**, and
the ruled list satisfies it with margin (four). It is not a success
requirement; reading it as one would make an outage of two third-party
services abort a paid seal.

## 4. Trust: there is no calendar key to pin, and that is fine

The brief asks whether a calendar's public key / whitelist identity is
pinned or trusted on use. **Neither, because neither exists.** An OTS
calendar signs nothing. A pending attestation is a URI plus a commitment; a
Bitcoin attestation is a merkle path. There is no key in the protocol to
pin.

That is not a gap, because a fully impersonated calendar cannot manufacture
a false time:

- It can return a bogus pending attestation that never upgrades → the
  anchor stays `pending` forever, which is a visible, correctly-labelled
  non-claim.
- It can return ops that commit a *different* digest → A11 re-parses the
  merged `.ots` and confirms it commits `anchor_digest` (A13 Do), so this
  is caught locally and offline.
- It can return a merkle path to a real Bitcoin block that does not commit
  our digest → the ops-derived root will not equal the fetched header's
  merkle root, which A14 requires to match before recording.
- It can return a path to a *forged* header → A16's must-agree esplora
  fetch rejects it, and offline the anchor is `attested`, never
  headline-eligible (spec line 132).
- It **cannot** return a path to an *earlier* block than the honest one:
  that would require our digest to be committed by a block mined before it
  was submitted, i.e. a SHA-256 preimage. Since the claim antseal makes is
  "existed **no later than** T", a malicious calendar's only remaining
  freedom is to return a *later* T — a strictly weaker claim, never a false
  one.

**So calendar compromise is a denial-of-service, not a forgery, and the
calendar set is chosen for availability and independence of operator, not
for trust.** Three operators (Peter Todd, Riccardo Casatta / Eternity Wall,
Bull Bitcoin / Catallaxy) across four endpoints is the availability
argument; there is no corroboration argument to make.

### What IS pinned: the upgrade-URI host allowlist

A14 issues `GET <pending-uri>/timestamp/<hex>` against a URI read out of a
stored `.ots`. That artifact lives on disk in the vault and is
attacker-writable under a vault-tamper threat, so an unconstrained fetch is
a server-side request-forgery and deanonymisation surface: an attacker who
edits a pending URI to `https://attacker.example` learns the moment a
victim runs any CLI command (the U24 opportunistic hook fires on *every*
invocation).

Upstream defends this with `DEFAULT_CALENDAR_WHITELIST`
(`calendar.py:150-154`), three `fnmatch` globs. antseal pins the same three
operator domains but matches them **as strict lowercase host suffixes with
a dot boundary, `https` scheme, empty path, no port, query or fragment** —
which is strictly narrower than upstream's `fnmatch`, whose `*` also
matches the empty string and is case-sensitive against a case-insensitive
DNS name.

Every pending URI measured in §1 lands inside these three suffixes,
including all four defaults.

**Append-only.** Removing a suffix would strand every already-stored `.ots`
whose pending attestation names it — those anchors could never upgrade.
Adding one is a reviewed, additive change. The *submit* list carries no
such constraint (§5).

## 5. Rot policy — and why it is not a format event

Nothing in the v1 wire format, in `SealProof`, or in `antseal-core` names a
calendar. The submit list is a submission-time constant in
`antseal-anchor`; an existing bundle carries its own `.ots` with its own
pending URIs and is unaffected by any change to it. **Replacing a dead
default is an ordinary code change in a release, requiring no format
version, no store version, and no vector re-emission.** (Contrast D57's
root store, which is compiled into `antseal-core` and *is*
verification-bearing — the two decisions sit at opposite ends of the
permanence scale, and it is worth being explicit about which is which.)

Detection is **A44**: a non-gating scheduled lane that, per default
endpoint, resolves DNS and performs `GET <url>/` asserting HTTP 200 and the
literal marker `OpenTimestamps Calendar Server` in the body. It submits
nothing (Q16 keeps real anchor traffic out of CI; this is a liveness read,
not an anchor operation). Two consecutive red runs for one endpoint opens
an issue; the fix is a reviewed edit to `DEFAULT_OTS_CALENDARS`. The lane
also records each calendar's pending-commitment count, so the catallaxy
backlog noted in §2 becomes a trend rather than an anecdote.

## 6. Constants, paths and config keys the implementer uses

### 6.1 Module `crates/antseal-anchor/src/ots/calendars.rs`

```rust
/// The four default calendar endpoints, in upstream's own order
/// (`opentimestamps-client/otsclient/cmds.py:186-189`, retrieved
/// 2026-08-02T19:23:37Z). These are aggregator aliases, not calendar
/// hostnames: the operator repoints them when a calendar is retired,
/// which is why antseal ships them rather than the calendars behind
/// them (docs/decisions/D54-default-ots-calendars.md §1).
pub const DEFAULT_OTS_CALENDARS: [&str; 4] = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
];

/// Host suffixes a pending attestation's URI may name for A14 to contact
/// it. Strict lowercase suffix match with a dot boundary; scheme MUST be
/// `https`, path MUST be empty, and port/query/fragment MUST be absent.
/// APPEND-ONLY: removing a suffix strands every stored `.ots` naming it.
pub const OTS_UPGRADE_HOST_SUFFIXES: [&str; 3] = [
    ".calendar.opentimestamps.org",
    ".calendar.eternitywall.com",
    ".calendar.catallaxy.com",
];

/// Submission path appended to a calendar base URL
/// (`python-opentimestamps/opentimestamps/calendar.py:62`).
pub const OTS_SUBMIT_PATH: &str = "digest";

/// Upgrade path prefix; the hex commitment is appended
/// (`calendar.py:80-81`).
pub const OTS_UPGRADE_PATH_PREFIX: &str = "timestamp/";

/// `Accept` header upstream's client sends (`calendar.py:55`).
pub const OTS_ACCEPT_HEADER: &str = "application/vnd.opentimestamps.v1";

/// Distinct pending-attestation URIs required for a non-degraded OTS
/// outcome. Never a seal precondition — A20's gate is TSA-only.
pub const OTS_MIN_DISTINCT_CALENDARS: usize = 2;

/// Wall-clock bound on the whole concurrent submission stage.
/// ~11x the worst of 18 measured real submissions (2.619 s).
pub const OTS_SUBMIT_DEADLINE_SECS: u64 = 30;

/// Per-response body cap for ONE calendar HTTP exchange (submit or
/// upgrade). Distinct from `antseal_core::codec::caps::MAX_OTS_BYTES`
/// (1 MiB), which caps the merged artifact inside a bundle; four
/// responses at this cap still fit that ceiling with 4x margin.
pub const MAX_OTS_CALENDAR_RESPONSE_BYTES: usize = 65_536;
```

`MAX_OTS_CALENDAR_RESPONSE_BYTES` is a **new limit** and takes an F4
registry row per `docs/format/anchor-artifact-limits.md` (see §7). It is
not one of the eight limits that document leaves open at M2 — all eight are
*artifact-parse* limits; this is a *network-stage* limit and did not
previously exist anywhere. Margin: 65 536 / 220 = **298×** against the
largest of 18 measured real submit responses. The upgrade response is
larger (it carries a Bitcoin merkle path) and has **not** been measured;
A25's two-day protocol must record it and the F4 row must be completed with
that figure before M2 closes.

### 6.2 The selection function

```rust
/// The effective calendar list: config override if present (replacing the
/// defaults wholesale, matching U26's `tsa_urls` semantics), else
/// `DEFAULT_OTS_CALENDARS`.
pub fn effective_calendars(config: Option<&[String]>) -> Vec<String>;

/// True iff `uri` may be contacted for an upgrade. Accepts the pinned
/// suffixes, plus — for a user-configured calendar — that calendar's own
/// host and any subdomain of it, so a private calendar stays usable
/// without widening the pinned set.
pub fn upgrade_uri_allowed(uri: &str, configured: &[String]) -> bool;
```

### 6.3 Config key (new — **the slot does not exist today**)

`crates/antseal-cli/src/config.rs` reserves `[anchors] tsa_urls`,
`[verify] bitcoin_endpoints` and `[verify] arbitrum_endpoints`
(`config.rs:480-488`). **There is no OTS calendar slot**; `grep -n
"calendar\|ots_" crates/antseal-cli/src/config.rs docs/config.md` returns
nothing. Add, in the existing `[anchors]` section and with the existing
`expect_url_array` validation so no second convention is invented:

```toml
[anchors]
tsa_urls     = ["https://freetsa.org/tsr", "http://timestamp.digicert.com"]
ots_calendars = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"]
```

Parser arm, beside the existing one:

```rust
(["anchors"], "ots_calendars") => {
    config.ots_calendars = Some(expect_url_array(value, "ots_calendars")?);
}
```

field `pub ots_calendars: Option<Vec<String>>` on the config struct, doc
comment `/// `[anchors] ots_calendars` (consumer: U44 at M2).` Precedence is
U4's: flag > config > built-in. There is no CLI flag for the calendar list
in the canonical surface and none is added. Wired by **U44**.

## 7. Verbatim rows to add

**`docs/format/anchor-artifact-limits.md` §5 (the F4 registry):**

| limit | initial value | date set | fixture measured against | margin | lowered |
| --- | --- | --- | --- | --- | --- |
| `MAX_OTS_CALENDAR_RESPONSE_BYTES` | 65 536 | 2026-08-02 | largest of 18 real submit responses, 220 B (`testdata/anchors/A25-bootstrap/A-catallaxy.timestamp`) | 298× | never |

**`docs/config.md`**, in the reserved-slot table and the URL-shape
paragraph (`docs/config.md:77-78`), add `ots_calendars` to the list of keys
whose entries must start with `http://` or `https://`.

## 8. Tests that must exist, and what makes each fail

| test | lives in | fails when |
| --- | --- | --- |
| `default_calendar_list_is_upstreams_verbatim` | `antseal-anchor` unit | `DEFAULT_OTS_CALENDARS` is edited without updating this record — the test pins all four literals **and their order**. Fails on any reorder, addition, removal or typo. |
| `distinct_success_count_dedupes_by_pending_uri` | `antseal-anchor` unit, mock calendars | two mock endpoints returning the *same* pending URI are counted as 2 instead of 1 — the exact bug a submit-URL count would have. Positive twin: two different URIs count as 2. |
| `one_calendar_down_still_records_the_others` | `antseal-anchor` unit, mock | a per-calendar failure aborts the stage or removes a sibling's attestation. |
| `zero_calendar_success_never_blocks_the_seal` | `antseal-anchor` unit + U22 pipeline | the OTS outcome reaches `evaluate_seal_gate` as anything other than a report field — asserted by driving `evaluate_seal_gate` with `Ots::Absent` and ≥1 verified TSA and requiring `proceed`. Fails if any future edit makes the gate read the OTS outcome. |
| `every_failed_endpoint_appears_in_the_degradation_report` | `antseal-anchor` unit, mock | a failure is swallowed: the assertion is that each mock-failed URL appears **verbatim** in the report string, so a summarising "1 calendar failed" message fails it. |
| `upgrade_uri_outside_the_allowlist_is_refused` | `antseal-anchor` unit | A14 would fetch `https://attacker.example/timestamp/…`. Table-driven over: a bare-suffix host (`calendar.catallaxy.com` — must be **refused**, no dot boundary), an uppercase host (must be **accepted**, normalised), `http://` (refused), a URI with a path/port/query/fragment (refused), and each of the four real pending URIs from §1 (accepted). |
| `configured_calendar_widens_the_allowlist_only_to_itself` | `antseal-anchor` unit | configuring `https://cal.example.com` makes `https://other.example.org` acceptable, or makes `https://cal.example.com.evil.net` acceptable. |
| `calendar_response_over_cap_is_a_typed_error_not_a_truncation` | `antseal-anchor` unit, stub server | the client truncates at the cap and then fails deserialization with a parse error — upstream's own bug shape (`calendar.py:70-72` reads exactly 10 000 bytes and then tests `len(resp_bytes) > 10000`, which can never be true). The assertion is on the **error variant**, so a truncating implementation fails. |
| `vector_ots_submit_replay_is_byte_stable` | CI replay lane (Q16) | the committed A25 responses stop parsing, or a code change alters the merged `.ots` bytes for a fixed input set. |

## 8b. Conflict with D90 (same wave) — the OTS response cap

D90, resolved concurrently, lands the HTTP substrate this decision assumed
was missing, and sets

```rust
pub const OTS_RESPONSE_CAP_BYTES: u64 = antseal_core::codec::caps::MAX_OTS_BYTES as u64; // 1 MiB
```

**That conflates two different limits.** `MAX_OTS_BYTES` caps the *merged
`.ots` artifact* carried inside a bundle; this caps *one calendar's reply
to one request*. The largest of 18 real submit responses measured for this
decision is **220 B**, so 1 MiB is a 4 766× ceiling and lets four calendars
hand `antseal-anchor` 4 MiB per seal.

**The raise-only rule decides it, not preference.** `docs/format/anchor-artifact-limits.md`
rule F4 makes limits raise-only after M2's first release: 65 536 can be
raised later if a real artifact ever needs it; 1 MiB can **never** be
lowered. Choosing the measured value now is the only reversible direction,
which is D84's own stated guidance read in the direction it actually cuts.

Resolution for the orchestrator: keep D90's substrate and its
`receive_cap_bytes` parameter, and set the OTS request's cap to
`MAX_OTS_CALENDAR_RESPONSE_BYTES = 65_536` rather than to `MAX_OTS_BYTES`.
Note D90's measured `ureq` off-by-one (`.limit(N)` accepts at most N−1
bytes, so it passes `cap + 1`) applies unchanged.

## 9. Findings handed to other tasks

1. ~~**`tasks/A.md` A3** — the HTTP substrate has no response-body cap.~~
   **Superseded within the wave**: D90 lands exactly that parameter. The
   residual finding is the *value*, in §8b above.
2. **`tasks/A.md` A13** — `Do` says "POST `anchor_digest` to ≥2 configured
   public calendars (defaults per A-OD2 …)". With this ruling the default
   is four; the text should read "to every calendar in the effective list
   (four by default)". Its "≥1 success ⇒ a pending OTS anchor exists" is
   ratified, with the added distinctness rule.
3. **`tasks/A.md` A25** — the runbook must record the **upgrade** response
   size, which no capture has yet measured and which the F4 row in §7
   needs.
4. **`testdata/anchors/A25-bootstrap/`** — the committed captures were
   taken against calendar hostnames, not the ruled default list. They stay
   valid as *response-shape* fixtures (the wire format is identical) but
   must not be read as evidence about the defaults; a `README.md` in that
   directory should say so, and A25's full run should re-capture against
   `DEFAULT_OTS_CALENDARS`.

## Revisit triggers

- Two consecutive A44 red runs on any default → reviewed constant change.
- Upstream changing `cmds.py:186-189` → re-read this record; the *reason*
  to track upstream is the alias indirection, so a change there is exactly
  the event we are subscribed to.
- A new calendar operator entering the OTS default set → a fourth allowlist
  suffix, append-only.
- Any proposal to make OTS success a seal precondition → §3's argument must
  be defeated first.

## Index row (orchestrator applies at merge)

| [D54](D54-default-ots-calendars.md) | Default OTS calendar set — **upstream's own four defaults verbatim** (`a.pool.opentimestamps.org`, `b.pool.opentimestamps.org`, `a.pool.eternitywall.com`, `ots.btc.catallaxy.com`, `otsclient/cmds.py:186-189`), which are **aggregator aliases, not the calendar hostnames the A25 bootstrap used** — and the alias indirection is the whole point: the dead `finney.btc.calendar.opentimestamps.org` was never an upstream default, while every real default is live (measured, 18 submissions). Success is counted over **distinct pending-attestation URIs** (a pool and its calendar return the same one, measured 4/4 rounds), ≥2 normal / 1 thin / 0 absent — **none ever blocks a seal**, because A20's gate is TSA-only and a seal-time OTS anchor is `pending`. No calendar key exists to pin and none is needed: an impersonated calendar can deny service or return a *later* time, never an earlier one, so this is a liveness decision. What is pinned is an **append-only upgrade-URI host allowlist** (3 suffixes, strict dot-boundary, `https`-only), closing an SSRF the U24 every-invocation hook would otherwise expose. Replacing a dead default is **not** a format event — no byte of `antseal-core` names a calendar | RESOLVED (A13/A14/A20/A25 + new A42/A44/U44 implement) | 2026-08-02 |
