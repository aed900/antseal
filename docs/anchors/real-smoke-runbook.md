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

## 0. Status — what is executable today

**The protocol below is not yet executable end-to-end.** Two halves are
missing and this document does not pretend otherwise:

- **U22** has not wired the anchor gate into the product: `seal_run.rs` still
  passes `&NoAnchorGate`, so the shipped CLI cannot perform a real anchor
  submit. Until it does, §2 and §3 have no command to run.
- **A25** owns the capture script and the fixture commits. `scripts/` carries
  no `anchor-smoke` entry point yet.

What *has* been executed is the bootstrap capture, and it is on disk:
`testdata/anchors/A25-bootstrap/` (six pending calendar timestamps over two
committed golden-vector digests, their day-2 upgrades, nine live TSA
request/response pairs, five root certificates with provenance) and
`testdata/anchors/A16-A17-live/` (esplora and Arbitrum RPC pairs). Each
carries a `CAPTURE.log` recording URL, status, byte count, SHA-256 and UTC
instant per request. Those captures are what the offline suite replays.

This runbook exists now, ahead of its script, for the reason F19 and A27
exist ahead of theirs: a protocol that lives only in a task entry is a
protocol the implementing task rediscovers or contradicts. §1's consent rule
in particular binds the bootstrap capture that already happened and every
capture that follows.

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

Two standing constraints on what may be sent:

- **Only throwaway or already-public digests.** The bootstrap stamped two
  `anchor_digest` values that were already committed golden-vector material,
  so stamping disclosed nothing new. Never anchor a real user's work-id
  during a smoke run: a public calendar submission is permanent and
  correlatable.
- **Never any secret material** (project rule 6). Digests only.

## 2. Respect the rate limits — they are the reason this is not a lane

Space requests deliberately. These are the recorded constraints; treat them
as hard:

| service | endpoint | constraint |
| --- | --- | --- |
| FreeTSA | `https://freetsa.org/tsr` | default TSA (MVP-SPEC.md line 109); ECDSA P-384 |
| DigiCert | `http://timestamp.digicert.com` | default TSA; **port 443 refuses connections** — plain HTTP is required, not a shortcut (D90 §6.6) |
| SwissSign | alternate | **~10 requests/day** |
| Sectigo | alternate | **~15 s minimum spacing** |
| DFN | `zeitstempel.dfn.de` | **non-commercial use only** |
| OTS calendars | `DEFAULT_OTS_CALENDARS` | free shared public infrastructure |

Run the whole protocol **once** per capture campaign. If a step fails,
diagnose from the log before re-firing; a retry loop against a TSA is the
thing this document exists to prevent.

## 3. The protocol

Endpoint lists are read from the code, never re-typed here — they are
`DEFAULT_TSA_URLS`, `DEFAULT_OTS_CALENDARS`, `DEFAULT_ESPLORA_ENDPOINTS` and
`ARBITRUM_ONE_VERIFY_RPCS` in `crates/antseal-anchor/src/`. If this document
and the code disagree, the code is right and this table is stale.

### 3.1 OTS: submit, then upgrade

1. **Submit.** `POST <calendar>/digest`, body = the **32 raw digest bytes**,
   `Accept: application/vnd.opentimestamps.v1`. Store each reply verbatim as
   the pending capture.
2. **Wait.** The calendar aggregates and commits its aggregate root to
   Bitcoin. **Do not plan on a fixed interval and do not record one as
   authoritative**: the bootstrap's day-2 poll succeeded after **13 h 47 m**,
   not the ~48 h its own first draft asserted. Planning at 48 h is prudent;
   writing 48 h down as *the* figure teaches the tree a number the network
   does not owe it.
3. **Upgrade.** `GET <calendar>/timestamp/<commitment-hex>` — a **GET**, not
   a POST (`python-opentimestamps/opentimestamps/calendar.py` issues a GET,
   and that is what the capture log records).
4. Verify the upgraded artifact reaches `attested` **offline**, then promote
   to `proven` with `--online` against the esplora pair.

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

## 4. Recording the run

Per campaign, under `testdata/anchors/<task>-<purpose>/`:

- every request/response **verbatim**, as captured;
- a `CAPTURE.log` with URL, HTTP status, byte count, SHA-256 and UTC instant
  per request — plus the §1 consent record;
- a short `README.md` stating what was submitted, what was found, and what is
  now **unreproducible**.

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
