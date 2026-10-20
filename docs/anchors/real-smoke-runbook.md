# Real-endpoint anchor smoke runbook

> **Owning tasks: Q16** (this document) and **A25** (executing it and
> committing the fixtures), `tasks/A.md` / `tasks/Q.md`, milestone **M2**.
> The policy that excludes all of this from gating CI is
> [`../testing/anchor-ci-policy.md`](../testing/anchor-ci-policy.md).
> Root-store changes are **not** in scope here — they are
> [`root-store-update.md`](root-store-update.md).

This is the one sanctioned way real anchor endpoints are contacted from this
project. It is a **maintainer-run, out-of-band protocol**, never a CI lane
and never a test.

The entry point is **`scripts/anchor-smoke`** (A25; committed 2026-08-11,
the same change that deleted this document's §0 status section per Q99's
rule). One subcommand per §3 step — `submit`, `upgrade`, `tsa`,
`must-agree` — plus a loopback-only `selftest`. It drives **antseal's own
clients**, never `curl`: A13's `submit_to_calendars`, A14's
`pending_refs`/`poll_upgrade` behind A42's allowlist, A10's `capture_one`
verified against `TsaRootStore::pinned()`, and A16/A17's must-agree rounds,
all through the dev-only `anchor-smoke-driver` binary
(`crates/antseal-anchor/src/bin/`, built with `--features test-util`, absent
from every default build). A capture made with `curl` proves the endpoints
and not the client — that distinction is D118 §1.5 and verification-matrix
row `V7.1`, and it is why the driver exists.

What *has* been executed is on disk under `testdata/anchors/` — four
campaigns, inventoried with their provenance in
[`../../testdata/anchors/README.md`](../../testdata/anchors/README.md).
Those captures are what the offline suite replays.

## 1. Consent — required before any request leaves the machine

Contacting a third party's service is an external action. It requires
**express, in-the-moment maintainer confirmation naming the action, the
destination and the account**, obtained before the run and recorded in the
run's `CAPTURE.log`. A task list, a runbook (including this one), or a
previous authorisation is **not** consent for a new run.

The bootstrap capture recorded its authorisation this way — *"Maintainer
authorisation for real-endpoint submission was given in-session on
2026-08-02 (reads **and** submissions to public TSAs and OTS calendars,
throwaway test digests only)"* — and that is the form to reproduce.

A **read-only** campaign records the same form and says so explicitly, so
the absence of a submission is on the record rather than inferred. The
2026-08-07 header capture is the worked example
(`testdata/anchors/A25-upgrade-headers/CAPTURE.log:3-7`): it names the
heights, the two endpoints, and *"Reads only — no submission, no account, no
credentials, no digest sent."* A read-only run still needs its own consent;
being read-only is not an exemption.

Two standing constraints on what may be sent:

- **Only throwaway or already-public digests.** The bootstrap stamped two
  `anchor_digest` values that were already committed golden-vector material,
  so stamping disclosed nothing new. Never anchor a real user's work-id
  during a smoke run: a public calendar submission is permanent and
  correlatable.
- **Never any secret material** (project rule 6). Digests only.

## 2. Respect the rate limits — they are the reason this is not a lane

Space requests deliberately. Treat every row below as hard — but note which
are **measured** and which are **published by the operator and never tested
here**. The bootstrap issued one request per endpoint spaced ≥ 3 s, so
Sectigo's spacing and SwissSign's quota "were not approached"
(`testdata/anchors/A25-bootstrap/D60-CAPTURE.log:47-49`): this project has not
measured them and must not present them as if it had.

| service | endpoint | constraint | source |
| --- | --- | --- | --- |
| FreeTSA | `https://freetsa.org/tsr` | default TSA (MVP-SPEC.md line 109); ECDSA P-384 | measured |
| DigiCert | `http://timestamp.digicert.com` | default TSA; **port 443 refuses connections** — plain HTTP is required, not a shortcut | measured (D90 §6.6) |
| SwissSign | alternate — root **quarantined**, counts zero | **~10 requests/day** | published |
| Sectigo | alternate | **~15 s minimum spacing** | published |
| DFN | `zeitstempel.dfn.de` | **non-commercial use only** | published (terms) |
| OTS calendars | `DEFAULT_OTS_CALENDARS` | free shared public infrastructure | — |

`timestamp.entrust.net` and `timestamp.sectigo.com` are **one TSA behind two
names**: the same signer certificate signs both captures — issuer `CN=Sectigo
Public Time Stamping CA R41`, serial `0xE74EF255B0504FFADBA6DFF7FC8BA315`
(`testdata/anchors/A25-bootstrap/D60-CAPTURE.log:51-54`). Sectigo's spacing
constraint therefore applies across **both** names, and stamping both is not
two independent anchors.

Answering is not counting: Apple (`http://timestamp.apple.com/ts01`) is refused
outright for its SHA-1 signer, and GlobalSign and Certum return tokens that
verify against roots antseal does not pin, so — like quarantined SwissSign —
they count zero toward the anchor gate (`docs/user/timestamp-authorities.md`
§3).

Run the whole protocol **once** per capture campaign. If a step fails,
diagnose from the log before re-firing; a retry loop against a TSA is the
thing this document exists to prevent. `scripts/anchor-smoke` enforces both
mechanically — ≥ 3 s between consecutive non-loopback requests, one pass, no
campaign-level retries. (Within one request the substrate applies D90's
bounded, idempotency-aware attempt policy: a TSA or calendar POST that may
already have been delivered is never re-sent, nor is one answered `429`
(A140); one answered `503` is re-sent at most twice, 0.2 s and then 0.6 s
later.)

## 3. The protocol

`scripts/anchor-smoke` is the entry point for every step below: it records
§1's consent before the first request, enforces §2's spacing and one-pass
rule, and emits §4's per-request fields, refusing to finish without them.

Endpoint lists are read from the code, never re-typed here — they are
`DEFAULT_TSA_URLS`, `DEFAULT_OTS_CALENDARS`, `DEFAULT_ESPLORA_ENDPOINTS` and
`ARBITRUM_ONE_VERIFY_RPCS` in `crates/antseal-anchor/src/`. If this document
and the code disagree, the code is right and this table is stale. The script
follows the same rule: its defaults come from the driver's `defaults` mode,
which prints those constants.

### 3.1 OTS: submit, then upgrade

1. **Submit.** `POST <calendar>/digest`, body = the **32 raw digest bytes**,
   `Accept: application/vnd.opentimestamps.v1`. Store each reply verbatim as
   the pending capture.
2. **Wait — on the calendar, not on Bitcoin.** These are two different
   latencies and the tree measured only one of them for four days. Both are
   now measured, and they differ by an order of magnitude:
   - **Bitcoin confirmed within the hour.** The blocks carrying the
     bootstrap's attestations are 960767 / 960768 / 960771, and their `nTime`
     fields read 2026-08-02T20:15:46Z, 20:27:11Z and 20:59:44Z — **59 to 103
     minutes** after the 19:16Z submission. Read from the committed header
     bytes (`testdata/anchors/A25-upgrade-headers/`), not from an endpoint's
     JSON.
   - **The calendar served the upgrade 13 h 47 m after submission**, at
     2026-08-03T09:03Z. That gap is the calendar's aggregation-and-serving
     cadence, and it — not the block interval — is the figure to quote for
     "how long until an anchor is provable".

   **Do not plan on a fixed interval and do not record one as authoritative.**
   `OTS-BOOTSTRAP.md` already corrected its own ~48 h draft down to 13 h 47 m;
   the header capture shows even that figure is not Bitcoin's. Planning at
   48 h is prudent; writing any single number down as *the* figure teaches
   the tree a number the network does not owe it — least of all the block
   interval, which is the one that looks like an answer and is not.
3. **Upgrade.** `GET <calendar>/timestamp/<commitment-hex>` — a **GET**, not
   a POST (`python-opentimestamps/opentimestamps/calendar.py` issues a GET,
   and that is what the capture log records).
4. Verify the upgraded artifact reaches `attested` **offline**, then promote
   to `proven` with `--online` against the esplora pair. The headers for the
   bootstrap's own three attesting blocks are captured
   (`testdata/anchors/A25-upgrade-headers/`), each verified offline by
   `double-SHA256(header) == claimed block hash`, so this step's *evidence*
   is reproducible with no network at all. Its CLI half is
   **`antseal verify --online <bundle>`** (U30), in every build:
   `crates/antseal-cli/src/run.rs:92-96` hands `Command::Verify` to
   `commands::verify` (`crates/antseal-cli/src/commands.rs:973`), whose
   `--online` arm (`crates/antseal-cli/src/commands.rs:1045-1057`) takes the
   esplora pair from `[verify] bitcoin_endpoints`, or from
   `DEFAULT_ESPLORA_ENDPOINTS` when the config sets none
   (`crates/antseal-cli/src/verify_host.rs:332-342`), and asks both endpoints
   for the header at every height in the bundle's probe plan
   (`crates/antseal-cli/src/verify_host.rs:172-183`). Only agreement crosses
   into the evidence (`crates/antseal-anchor/src/esplora.rs:142-156`): an
   `attested` OTS anchor whose embedded header both endpoints return byte for
   byte becomes `proven`, timed by the **agreed** header's `nTime` (D56 rule
   O3, `crates/antseal-core/src/anchor/verdicts.rs:782-825`), and a pair that
   disagrees or does not answer promotes nothing.

   It reads a `.sealproof` bundle, not a raw `.ots`. The bundle to run it on
   is `attested-ots-960767.sealproof`, which carries the bootstrap's own
   upgraded artifact and block 960767's header. It is assembled from frozen
   vectors and is not committed: run from the repository root,
   `ANTSEAL_EMIT_PAGE_FIXTURES=<absolute dir> cargo test -p antseal-core --locked --test page_fixtures`
   writes it into that directory
   (`crates/antseal-core/tests/page_fixtures.rs:587-620`, D133), and
   `scripts/verifier-page-browser.sh` materialises it the same way at
   `target/verifier-web-fixtures/attested-ots-960767.sealproof`
   (`scripts/verifier-page-browser.sh:72`, `:108-109`). Offline,
   `antseal verify` on it exits 43 with `ots-1: attested`. With both
   endpoints agreeing, `--online` prints, in its online section,
   `ots-1: Bitcoin block 960767 agreed by both endpoints — time 1785701746 (bitcoin-block-960767 — online-confirmed)`
   (1785701746 is block 960767's `nTime`, 2026-08-02T20:15:46Z — step 2's
   figure), `--json` classes the anchor `promoted`, and the run exits 0; with
   the second endpoint answering block 960768's header instead, that line reads
   `ots-1: the two endpoints disagreed about block 960767 — no promotion; the offline state stands`
   and the run exits 43. Both outcomes were measured on 2026-10-19 against
   two loopback servers replaying the committed captures, not against the
   endpoints. `crates/antseal-cli/tests/verify_online_promotion.rs` (R100)
   now asserts both outcomes and the offline 43 under `cargo test`, running
   the `antseal` binary on the same bundle, assembled in the test, against
   loopback stubs that serve the same captures. A real run contacts both
   endpoints, so §1's consent and §6's rule on
   `ANTSEAL_NO_REAL_ANCHOR_NETWORK` apply to it.

Three calendar behaviours the bootstrap measured, all of which the capture
must preserve because A14's classifier is graded on them:

- `404` + a 42-byte `Pending confirmation in Bitcoin blockchain` — still
  pending, re-pollable.
- `404` + a 9-byte `Not found` — the hard error (observed against a
  deliberately corrupted commitment).
- **no answer at all** (`http=000`, connection failed) — a transport failure,
  which must stay re-pollable and must **never** be promoted to the hard
  error, or one flaky endpoint permanently condemns an honest anchor.

`finney.btc.calendar.opentimestamps.org` **failed DNS resolution** at
bootstrap and is not in upstream's default list; D54 owns the calendar set
and the rot policy this implies.

### 3.2 TSA tokens

Obtain and fully verify a real FreeTSA (ECDSA P-384) and DigiCert token
against the **pinned** root store — not against the system trust store, which
would prove something else entirely. Confirm each reaches `proven`, and
record the `TSA_ROOT_STORE_VERSION` the verdict reports.

### 3.3 Live must-agree rounds

One round each for esplora (`blockstream.info` / `mempool.space`) and the
Arbitrum RPC pair, to confirm both halves are live and that agreement is
reached over the *extracted tuple* — the two ruled-in RPCs return different
JSON key sets for identical values, so byte comparison would report a
disagreement between two honest endpoints (D55 §3).

### 3.4 Endpoint liveness findings

Record every default URL/path that has rotted. Hand the findings to Q26's
alternates table. Endpoint rot is the expected outcome of this run, not an
anomaly — the bootstrap found one of four default calendars dead on its first
attempt.

**Q26's alternates table is §3 of
[`timestamp-authorities.md`](../user/timestamp-authorities.md).** Q26
delivered that page on 2026-08-17, and it carries all five TSA findings this
protocol handed over on 2026-08-11 (D126 §3.2): the Sectigo/Entrust identity,
DigiCert's refused port 443, the four live endpoints outside the list, token
`genTime` running ahead of the capture host's clock, and the
published-versus-measured labels. Findings still live in the campaign logs and
are cited from there; the calendar-rot half stays with D54/A14/A44, as above.

## 4. Recording the run

Per campaign, under `testdata/anchors/<task>-<purpose>/`:

- every request/response **verbatim**, as captured;
- a `CAPTURE.log` with URL, HTTP status, byte count, SHA-256 and UTC instant
  per request — plus the §1 consent record;
- a short `README.md` stating what was submitted, what was found, and what is
  now **unreproducible**.

**Three of the five logs on disk meet the middle bullet in full**
(`A25-bootstrap/CAPTURE.log`, `.../upgraded/UPGRADE-CAPTURE.log`,
`A25-upgrade-headers/CAPTURE.log` — 8, 9 and 12 requests, each with all four
fields). The other two do not, and the gap is recorded rather than quietly
tolerated: `A25-bootstrap/D60-CAPTURE.log` gives a per-request table with URL,
status, byte count and UTC but **no per-file SHA-256**, and
`A16-A17-live/CAPTURE.log` gives statuses and byte counts with **no SHA-256
and no per-request UTC at all** — only `utc_start`/`utc_end`. Both predate
this document. The SHA-256 is the field whose absence bites: it is what lets a
later reader confirm the committed file is the byte string the endpoint
actually returned, and without it "verbatim" rests on the capturer's word.
A capture script must emit all four per request, and should refuse to finish
otherwise. `scripts/anchor-smoke` is that script: it hashes each body from
the bytes antseal's client surfaced, before any file is written — never
back-filled from disk — and refuses to finish over a missing field (its
selftest proves the refusal by message). Its logs carry two notations,
each explained in the log header: successes record `http=2xx`, because the
typed client returns carry the response class rather than the exact code;
and outcomes whose bodies antseal's own classifier consumed — the two D58
§7.4 404s, an unverifiable TSA reply — record `bytes=- sha256=-`, because
by design those bytes are not surfaced past the classification.

That last point is not bookkeeping. A pending `.ots` capture can never be
re-taken: once a commitment is upgraded, those calendars will never serve the
pending body for it again, and a fresh stamp is a different and later one.
The `pending` state is a required fixture (the same-day-reveal case, spec
line ~136), so the committed pending captures are irreplaceable evidence.
Treat them as append-only.

**Guard against the silent-success failure.** The bootstrap's first attempt
submitted an **empty** body — `xxd` was absent on the host, so hex→binary
decoding produced a zero-byte file — and the calendars answered `200`. The
responses were discarded, not committed. Any capture script must hard-fail
unless the digest file is exactly 32 bytes: a submit path that does not check
its own request length can stamp nothing and look successful.

## 5. Refreshing fixtures and pinned roots

- **Fixtures**: re-run the relevant §3 step under a fresh §1 consent, and
  commit the new capture **beside** the old one, never over it. Old captures
  are what prove aging bundles still verify.
- **Pinned roots**: not this document's business. Follow
  [`root-store-update.md`](root-store-update.md) — roots are append-only, a
  rotation is an append, `TSA_ROOT_STORE_VERSION` bumps monotonically, and
  every root needs its A7 provenance record before it is compiled in.
- **After any refresh**, the offline suite must stay green with no expected
  values edited. If a golden vector had to change, the change is a finding to
  explain, not a fixture to update.

## 6. Running it without tripping the gate

`ANTSEAL_NO_REAL_ANCHOR_NETWORK` must be unset, or set to `0`, in the shell
that executes the smoke. `scripts/local-gate.sh` exports `=1` for its own
duration only, so a normal gate run does not leak the arming into your shell.

Never run the smoke by removing the arming from a workflow or from
`local-gate.sh`; `scripts/ci-lanes.sh anchor-net-policy` will go red, and it
is right to.

`scripts/anchor-smoke` enforces this section's rule from its own side: a
network mode refuses to start when the variable is set to anything but `0`
**and** any planned target is not a loopback IP literal, naming this policy
in the refusal. Its loopback `selftest` runs with the gate armed — the
runtime gate admits loopback literals, which is the sanctioned test path —
so proving the script needs no disarming anywhere.
